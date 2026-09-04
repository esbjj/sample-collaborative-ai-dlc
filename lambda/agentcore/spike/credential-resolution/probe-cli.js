// Credential-resolution spike — per-CLI probe.
//
// THROWAWAY HARNESS (unit-credential-resolution-spike). The thin I/O edge that runs one
// CLI against Bedrock under a ROLE-ONLY environment and classifies the outcome. It
// CONSUMES, never modifies, two production seams (security-design SEC-05):
//   • driver.envForAuth (cli/drivers.js) — builds the per-CLI auth env exactly as
//     production would when the resolver has NOT populated the bearer token; and
//   • captureChild (cli/spawn.js) — the timed child-capture with SIGKILL watchdog.
// Both seams are injectable so the probe is fully unit-testable with the child mocked.
//
// The 7-step algorithm mirrors business-logic-model "Core Workflow":
//   1. strip AWS_BEARER_TOKEN_BEDROCK from the base env,
//   2. build cliEnv via the CLI's own envForAuth,
//   3. assert the no-bearer precondition (SEC-01 / BR-2.3) — a bearer-present cliEnv is
//      a harness defect: throw PreconditionError, discard, re-run (NEVER record),
//   4. spawn a minimal headless invocation with a per-invocation timeout,
//   5. reduce the raw outcome to a bounded, secret-free signal,
//   6. classify,
//   7. return a { cli, classification, evidence } probe result (NOT yet a recorded entry).

import { getDriver } from '../../cli/drivers.js';
import { captureChild } from '../../cli/spawn.js';
import { BEARER_ENV_VAR, resolveRegion } from './cli-scope.js';
import { classify, ERROR_CLASS, categorizeError } from './classify.js';
import { buildEvidence } from './evidence.js';

// Default per-invocation timeout — the load-bearing correctness control
// (performance-design REQ-PERF-01). Overridable via SPIKE_CLI_TIMEOUT_MS.
export const DEFAULT_TIMEOUT_MS = 120_000;

// Thrown when the constructed cliEnv still carries the bearer token. Per BR-2.3 /
// SEC-01 this is a HARNESS DEFECT, not a CLI verdict: the run is discarded and re-run.
export class PreconditionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PreconditionError';
  }
}

const timeoutMs = (env) => {
  const raw = Number(env.SPIKE_CLI_TIMEOUT_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_TIMEOUT_MS;
};

// The smallest prompt that forces a single InvokeModel call — the spike measures
// credential resolution, not agent quality, so token spend is minimised (BR-6.1).
const PROBE_PROMPT = 'ping';

// Detect whether the child reached Bedrock as an authenticated SigV4 caller. An
// AccessDenied naming an IAM action/principal only arrives AFTER SigV4 auth succeeded,
// so it is proof the credentials resolved (business-logic-model BR-3.2). Pure text
// heuristic over the (already-bounded) child output; never stores the text.
const reachedBedrockAsSigV4 = (text = '') => {
  const t = String(text).toLowerCase();
  return (
    t.includes('accessdenied') ||
    t.includes('not authorized to perform') ||
    t.includes('bedrock:invokemodel') ||
    t.includes('user:') || // IAM principal ARN in a denial message
    t.includes('assumed-role')
  );
};

// probeCli — run one probe. Seams (`invoke`, and the driver via `getDriverFn`) are
// injected for tests; production uses the real captureChild + getDriver.
//
// `invoke` signature: async ({ command, args, env, prompt, promptViaStdin, timeoutMs })
//   → { exitCode, stdout, stderr, timedOut }   (matches cli/spawn.js captureChild)
export const probeCli = async ({
  cli,
  baseEnv = {},
  invoke = captureChild,
  getDriverFn = getDriver,
} = {}) => {
  const driver = getDriverFn(cli);

  // Step 1 — role-only base env: strip the bearer token so the SigV4 path is exercised.
  const roleOnlyEnv = { ...baseEnv };
  delete roleOnlyEnv[BEARER_ENV_VAR];

  // Step 2 — build the per-CLI auth env through the CLI's OWN envForAuth (BR-2.2).
  const cliEnv = driver.envForAuth(roleOnlyEnv);

  // Step 3 — no-bearer precondition (SEC-01 / BR-2.3). A bearer-present cliEnv is a
  // harness defect: discard, re-run, never record.
  if (BEARER_ENV_VAR in cliEnv) {
    throw new PreconditionError(
      `${BEARER_ENV_VAR} present in cliEnv for "${cli}" — harness defect (BR-2.3); discard and re-run`,
    );
  }

  // Step 4 — minimal headless invocation with the per-invocation watchdog.
  const region = resolveRegion(baseEnv);
  const {
    command,
    args,
    env: invocationEnv,
    prompt,
    promptViaStdin,
  } = driver.buildInvocation({
    prompt: PROBE_PROMPT,
  });
  const { exitCode, stdout, stderr, timedOut } = await invoke({
    command,
    args,
    env: { ...cliEnv, AWS_REGION: region, ...invocationEnv },
    prompt,
    promptViaStdin,
    captureStderr: true,
    timeoutMs: timeoutMs(baseEnv),
  });

  // Step 5 — reduce raw output to a bounded, secret-free signal (SEC-04). The combined
  // output is used ONLY to derive a class + SigV4 signal, then discarded.
  const combined = `${stdout ?? ''}\n${stderr ?? ''}`;
  const invocationSucceeded = exitCode === 0 && !timedOut;
  const errorClass = timedOut
    ? ERROR_CLASS.TIMEOUT
    : invocationSucceeded
      ? ERROR_CLASS.NONE
      : categorizeError(combined);
  const sigv4 = reachedBedrockAsSigV4(combined);

  // Step 6 — classify.
  const classification = classify({
    invocationSucceeded,
    reachedBedrockAsSigV4: sigv4,
    errorClass,
    timedOut,
  });

  // Step 7 — assemble a secret-free probe result (evidence + classification). NOT yet a
  // recorded entry — the runner records only terminal verdicts (BR-3.4).
  const evidence = buildEvidence({
    exitCode,
    errorClass: classification.errorClass,
    reachedBedrockAsSigV4: sigv4,
    timedOut,
  });

  return Object.freeze({ cli, classification, evidence });
};
