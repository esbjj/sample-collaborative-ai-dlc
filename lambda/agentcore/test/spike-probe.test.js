import { describe, it, expect } from 'vitest';
import {
  probeCli,
  PreconditionError,
  DEFAULT_TIMEOUT_MS,
} from '../spike/credential-resolution/probe-cli.js';
import { runSpike, serializeVerdict } from '../spike/credential-resolution/run-spike.js';
import { VERDICTS } from '../spike/credential-resolution/classify.js';

// A stub driver whose envForAuth omits the bearer (the well-behaved production case).
// When `leakBearer` is set it UNCONDITIONALLY injects the bearer — simulating a buggy
// driver that reintroduces the token the probe stripped, the harness-defect case the
// SEC-01/BR-2.3 precondition guard exists to catch.
const makeDriver = ({ leakBearer = false } = {}) => ({
  envForAuth: (env) => {
    const out = { CLAUDE_CODE_USE_BEDROCK: '1', AWS_REGION: env.AWS_REGION || 'us-east-1' };
    if (leakBearer) out.AWS_BEARER_TOKEN_BEDROCK = 'reintroduced-by-buggy-driver';
    return out;
  },
  buildInvocation: () => ({
    command: 'stub',
    args: [],
    env: {},
    prompt: 'ping',
    promptViaStdin: true,
  }),
});

describe('probeCli (bearer-strip, precondition, classification)', () => {
  it('strips the bearer token from the child env before invoking (BR-2.1 / SEC-01)', async () => {
    let seenEnv;
    const res = await probeCli({
      cli: 'claude',
      baseEnv: { AWS_BEARER_TOKEN_BEDROCK: 'should-be-stripped', AWS_REGION: 'us-east-1' },
      getDriverFn: () => makeDriver(),
      invoke: async ({ env }) => {
        seenEnv = env;
        return { exitCode: 0, stdout: '{"ok":true}', stderr: '', timedOut: false };
      },
    });
    expect(seenEnv.AWS_BEARER_TOKEN_BEDROCK).toBeUndefined();
    expect(res.classification.verdict).toBe(VERDICTS.ROLE_NATIVE);
  });

  it('throws PreconditionError when the constructed cliEnv still carries the bearer (BR-2.3)', async () => {
    await expect(
      probeCli({
        cli: 'claude',
        baseEnv: { AWS_BEARER_TOKEN_BEDROCK: 'leaked', AWS_REGION: 'us-east-1' },
        getDriverFn: () => makeDriver({ leakBearer: true }),
        invoke: async () => ({ exitCode: 0, stdout: '', stderr: '', timedOut: false }),
      }),
    ).rejects.toBeInstanceOf(PreconditionError);
  });

  it('classifies an AccessDenied that reached Bedrock as SigV4 → role-native (blocked-on-grant)', async () => {
    const res = await probeCli({
      cli: 'codex',
      baseEnv: { AWS_REGION: 'us-east-1' },
      getDriverFn: () => makeDriver(),
      invoke: async () => ({
        exitCode: 1,
        stdout: '',
        stderr: 'AccessDeniedException: not authorized to perform bedrock:InvokeModel',
        timedOut: false,
      }),
    });
    expect(res.classification.verdict).toBe(VERDICTS.ROLE_NATIVE);
    expect(res.classification.note).toBe('blocked-on-grant');
  });

  it('classifies a bearer-demand error → fallback-required', async () => {
    const res = await probeCli({
      cli: 'opencode',
      baseEnv: { AWS_REGION: 'us-east-1' },
      getDriverFn: () => makeDriver(),
      invoke: async () => ({
        exitCode: 1,
        stdout: '',
        stderr: 'Error: AWS_BEARER_TOKEN_BEDROCK must be set',
        timedOut: false,
      }),
    });
    expect(res.classification.verdict).toBe(VERDICTS.FALLBACK_REQUIRED);
  });

  it('honours the SPIKE_CLI_TIMEOUT_MS override (default otherwise)', async () => {
    let seenTimeout;
    await probeCli({
      cli: 'claude',
      baseEnv: { AWS_REGION: 'us-east-1', SPIKE_CLI_TIMEOUT_MS: '5000' },
      getDriverFn: () => makeDriver(),
      invoke: async ({ timeoutMs }) => {
        seenTimeout = timeoutMs;
        return { exitCode: 0, stdout: 'ok', stderr: '', timedOut: false };
      },
    });
    expect(seenTimeout).toBe(5000);
    expect(DEFAULT_TIMEOUT_MS).toBe(120_000);
  });
});

describe('runSpike (serial ordering + fail-closed gate)', () => {
  it('probes CLIs serially in order and records terminal verdicts', async () => {
    const order = [];
    const record = await runSpike({
      baseEnv: { AWS_REGION: 'us-east-1' },
      probe: async ({ cli }) => {
        order.push(cli);
        return {
          classification: { verdict: VERDICTS.ROLE_NATIVE, fallbackRequired: false, note: null },
          evidence: { errorClass: 'none' },
        };
      },
      producedAt: '2026-09-04T00:00:00.000Z',
    });
    expect(order).toEqual(['claude', 'opencode', 'codex']);
    expect(record.buildGateSatisfied).toBe(true);
    expect(record.oq02Conclusion).toBe('fallback-not-needed');
  });

  it('an inconclusive CLI records no entry, leaving the gate CLOSED and noting the skip', async () => {
    const record = await runSpike({
      baseEnv: {},
      probe: async ({ cli }) => ({
        classification:
          cli === 'codex'
            ? { verdict: VERDICTS.INCONCLUSIVE, fallbackRequired: null, note: null }
            : { verdict: VERDICTS.ROLE_NATIVE, fallbackRequired: false, note: null },
        evidence: { errorClass: cli === 'codex' ? 'environmental' : 'none' },
      }),
    });
    expect(record.buildGateSatisfied).toBe(false);
    expect(record.complete).toBe(false);
    expect(record.skipped.map((s) => s.cli)).toContain('codex');
  });

  it('a PreconditionError is discarded (skip), never recorded, leaving the gate CLOSED', async () => {
    const record = await runSpike({
      baseEnv: {},
      probe: async ({ cli }) => {
        if (cli === 'opencode') throw new PreconditionError('bearer present');
        return {
          classification: { verdict: VERDICTS.ROLE_NATIVE, fallbackRequired: false, note: null },
          evidence: { errorClass: 'none' },
        };
      },
    });
    expect(record.buildGateSatisfied).toBe(false);
    expect(record.skipped.find((s) => s.cli === 'opencode').reason).toMatch(/precondition-failed/);
  });

  it('serializeVerdict emits secret-free allow-listed JSON', () => {
    const record = {
      producedAt: '2026-09-04T00:00:00.000Z',
      buildGateSatisfied: true,
      oq02Conclusion: 'fallback-not-needed',
      fallbackRequired: false,
      fallbackRequiredFor: [],
      cliVerdicts: [
        {
          cli: 'claude',
          verdict: 'role-native',
          fallbackRequired: false,
          note: null,
          evidence: { errorClass: 'none' },
        },
      ],
      skipped: [],
    };
    const json = JSON.parse(serializeVerdict(record));
    expect(json.unit).toBe('unit-credential-resolution-spike');
    expect(json.requirement).toBe('fr-sts-validation-spike');
    expect(json.cliVerdicts[0].cli).toBe('claude');
    expect(json.buildGateSatisfied).toBe(true);
  });
});
