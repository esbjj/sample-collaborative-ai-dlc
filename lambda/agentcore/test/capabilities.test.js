import { describe, it, expect, vi } from 'vitest';
import { capabilities } from '../commands/capabilities.js';
import { parseKiroModels } from '../cli/drivers.js';

// A trimmed real `kiro-cli chat --list-models --format json` payload.
const KIRO_LIST_JSON = JSON.stringify({
  models: [
    { model_name: 'auto', model_id: 'auto', description: 'Auto mode' },
    {
      model_name: 'claude-sonnet-4.6',
      model_id: 'claude-sonnet-4.6',
      description: 'Latest Sonnet',
    },
  ],
  default_model: 'auto',
});

describe('parseKiroModels', () => {
  it('maps the kiro list payload to {id,name,description} + default', () => {
    expect(parseKiroModels(KIRO_LIST_JSON)).toEqual({
      models: [
        { id: 'auto', name: 'auto', description: 'Auto mode' },
        { id: 'claude-sonnet-4.6', name: 'claude-sonnet-4.6', description: 'Latest Sonnet' },
      ],
      default: 'auto',
    });
  });
  it('returns an empty list for unparseable stdout', () => {
    expect(parseKiroModels('not json')).toEqual({ models: [], default: null });
  });
});

describe('capabilities command', () => {
  it('marks a CLI available only when installed AND authed', async () => {
    const res = await capabilities(
      {},
      {
        discoverInstalledClis: async () => ['claude', 'kiro', 'opencode'],
        captureChild: async () => ({ stdout: KIRO_LIST_JSON }),
        env: { KIRO_API_KEY: 'k' }, // claude has NO bearer token → not authed
      },
    );
    expect(res.ok).toBe(true);
    const byCli = Object.fromEntries(res.clis.map((c) => [c.cli, c]));
    expect(byCli.claude).toMatchObject({ installed: true, authed: false, available: false });
    expect(byCli.kiro).toMatchObject({ installed: true, authed: true, available: true });
    expect(byCli.opencode).toMatchObject({ installed: true, authed: false, available: false });
    expect(res.kiroModels.models.map((m) => m.id)).toContain('claude-sonnet-4.6');
  });

  it('uses the same Bedrock bearer token as Claude for OpenCode and Codex auth', async () => {
    const res = await capabilities(
      {},
      {
        discoverInstalledClis: async () => ['opencode', 'codex'],
        env: { AWS_BEARER_TOKEN_BEDROCK: 'token' },
      },
    );
    const byCli = Object.fromEntries(res.clis.map((c) => [c.cli, c]));
    expect(byCli.opencode).toMatchObject({ installed: true, authed: true, available: true });
    expect(byCli.codex).toMatchObject({ installed: true, authed: true, available: true });
  });

  it('does not probe kiro models when kiro is not installed', async () => {
    const capture = vi.fn(async () => ({ stdout: '' }));
    const res = await capabilities(
      {},
      {
        discoverInstalledClis: async () => ['claude'],
        captureChild: capture,
        env: { AWS_BEARER_TOKEN_BEDROCK: 't' },
      },
    );
    expect(capture).not.toHaveBeenCalled();
    expect(res.kiroModels).toEqual({ models: [], default: null });
    const byCli = Object.fromEntries(res.clis.map((c) => [c.cli, c]));
    expect(byCli.claude).toMatchObject({ available: true });
    expect(byCli.kiro).toMatchObject({ installed: false, available: false });
  });

  it('degrades to no CLIs when discovery throws', async () => {
    const res = await capabilities(
      {},
      {
        discoverInstalledClis: async () => {
          throw new Error('probe failed');
        },
        env: {},
      },
    );
    expect(res.ok).toBe(true);
    expect(res.clis.every((c) => !c.installed && !c.available)).toBe(true);
  });

  // The 'role' auth path deliberately leaves AWS_BEARER_TOKEN_BEDROCK unset — the
  // execution role's SigV4 credentials are the auth. Reading the absent bearer as
  // "unauthed" would report the Bedrock CLIs unavailable and, because AgentTab
  // gates selection on `available`, make the role path disable exactly the CLIs
  // it enables. Proven live on dev before this was fixed.
  it('treats the Bedrock CLIs as authed on the role path, with no bearer token', async () => {
    const res = await capabilities(
      {},
      {
        discoverInstalledClis: async () => ['claude', 'opencode', 'codex', 'kiro'],
        captureChild: async () => ({ stdout: KIRO_LIST_JSON }),
        env: { BEDROCK_AUTH_METHOD: 'role', KIRO_API_KEY: 'k' },
      },
    );
    const byCli = Object.fromEntries(res.clis.map((c) => [c.cli, c]));
    for (const cli of ['claude', 'opencode', 'codex']) {
      expect(byCli[cli], cli).toMatchObject({ installed: true, authed: true, available: true });
    }
    expect(byCli.kiro).toMatchObject({ authed: true, available: true });
  });

  it('does not mask a missing Kiro API key on the role path', async () => {
    const res = await capabilities(
      {},
      {
        discoverInstalledClis: async () => ['claude', 'kiro'],
        captureChild: async () => ({ stdout: KIRO_LIST_JSON }),
        env: { BEDROCK_AUTH_METHOD: 'role' }, // no KIRO_API_KEY
      },
    );
    const byCli = Object.fromEntries(res.clis.map((c) => [c.cli, c]));
    expect(byCli.claude).toMatchObject({ authed: true, available: true });
    expect(byCli.kiro).toMatchObject({ installed: true, authed: false, available: false });
  });

  it('still requires a bearer token when the method is api-key or absent', async () => {
    for (const env of [{ BEDROCK_AUTH_METHOD: 'api-key' }, {}]) {
      const res = await capabilities(
        {},
        { discoverInstalledClis: async () => ['claude', 'opencode', 'codex'], env },
      );
      const byCli = Object.fromEntries(res.clis.map((c) => [c.cli, c]));
      for (const cli of ['claude', 'opencode', 'codex']) {
        expect(byCli[cli], `${cli} with ${JSON.stringify(env)}`).toMatchObject({
          authed: false,
          available: false,
        });
      }
    }
  });
});
