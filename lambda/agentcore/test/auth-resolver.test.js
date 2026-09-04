import { describe, it, expect } from 'vitest';
import { resolveAgentAuth, resolveAuthMethod } from '../auth-resolver.js';

describe('resolveAgentAuth', () => {
  it('loads the bearer token + kiro key from their SSM paths into env', async () => {
    const env = {
      BEDROCK_BEARER_TOKEN_SSM_PATH: '/p/bedrock',
      KIRO_API_KEY_SSM_PATH: '/p/kiro',
      AWS_REGION: 'us-east-1',
    };
    const store = { '/p/bedrock': 'bearer-xyz', '/p/kiro': 'kiro-abc' };
    const resolved = await resolveAgentAuth({ env, getParam: async (n) => store[n] ?? '' });
    expect(env.AWS_BEARER_TOKEN_BEDROCK).toBe('bearer-xyz');
    expect(env.KIRO_API_KEY).toBe('kiro-abc');
    expect(resolved.toSorted()).toEqual(['AWS_BEARER_TOKEN_BEDROCK', 'KIRO_API_KEY']);
  });

  it('never overwrites an already-set env var', async () => {
    const env = {
      AWS_BEARER_TOKEN_BEDROCK: 'preset',
      BEDROCK_BEARER_TOKEN_SSM_PATH: '/p/bedrock',
    };
    const resolved = await resolveAgentAuth({ env, getParam: async () => 'from-ssm' });
    expect(env.AWS_BEARER_TOKEN_BEDROCK).toBe('preset');
    expect(resolved).not.toContain('AWS_BEARER_TOKEN_BEDROCK');
  });

  it('skips a target whose SSM path is not configured', async () => {
    const env = { KIRO_API_KEY_SSM_PATH: '/p/kiro' }; // no bedrock path
    const resolved = await resolveAgentAuth({ env, getParam: async () => 'k' });
    expect(env.AWS_BEARER_TOKEN_BEDROCK).toBeUndefined();
    expect(resolved).toEqual(['KIRO_API_KEY']);
  });

  it('skips a path that resolves empty (SSM miss/error) without throwing', async () => {
    const env = { BEDROCK_BEARER_TOKEN_SSM_PATH: '/p/missing' };
    const resolved = await resolveAgentAuth({ env, getParam: async () => '' });
    expect(env.AWS_BEARER_TOKEN_BEDROCK).toBeUndefined();
    expect(resolved).toEqual([]);
  });
});

// ── Bedrock STS role auth path (unit-credential-resolution-adapter) ──
// The role path is selected by a non-secret `bedrockAuthMethod` SSM value and is
// achieved by OMISSION: on 'role' the resolver leaves AWS_BEARER_TOKEN_BEDROCK
// unpopulated so the CLI signs invokes with task-role SigV4 credentials.
describe('resolveAuthMethod (bedrockAuthMethod selector)', () => {
  it('defaults to api-key when no selector path is configured', async () => {
    const method = await resolveAuthMethod({ env: {}, get: async () => 'role' });
    expect(method).toBe('api-key');
  });

  it('returns api-key on an explicit "api-key" value', async () => {
    const env = { BEDROCK_AUTH_METHOD_SSM_PATH: '/p/method' };
    const method = await resolveAuthMethod({ env, get: async () => 'api-key' });
    expect(method).toBe('api-key');
  });

  it('returns role on an explicit canonical "role" value', async () => {
    const env = { BEDROCK_AUTH_METHOD_SSM_PATH: '/p/method' };
    const method = await resolveAuthMethod({ env, get: async () => 'role' });
    expect(method).toBe('role');
  });

  it('canonicalizes (trim + lowercase) before matching "role"', async () => {
    const env = { BEDROCK_AUTH_METHOD_SSM_PATH: '/p/method' };
    for (const raw of ['Role', ' role ', 'ROLE', '\trole\n']) {
      expect(await resolveAuthMethod({ env, get: async () => raw })).toBe('role');
    }
  });

  it('fails safe to api-key on non-canonical / unrecognized values', async () => {
    const env = { BEDROCK_AUTH_METHOD_SSM_PATH: '/p/method' };
    for (const raw of ['1', 'roles', 'sts', '', '   ']) {
      expect(await resolveAuthMethod({ env, get: async () => raw })).toBe('api-key');
    }
  });

  it('fails safe to api-key when the SSM read throws (never throws itself)', async () => {
    const env = { BEDROCK_AUTH_METHOD_SSM_PATH: '/p/method' };
    const method = await resolveAuthMethod({
      env,
      get: async () => {
        throw new Error('ssm boom');
      },
    });
    expect(method).toBe('api-key');
  });
});

describe('resolveAgentAuth — role path (bearer omission + precedence)', () => {
  it('api-key default: bearer populated exactly as v1 (zero regression)', async () => {
    const env = {
      BEDROCK_BEARER_TOKEN_SSM_PATH: '/p/bedrock',
      KIRO_API_KEY_SSM_PATH: '/p/kiro',
    };
    const store = { '/p/bedrock': 'bearer-xyz', '/p/kiro': 'kiro-abc' };
    const resolved = await resolveAgentAuth({ env, getParam: async (n) => store[n] ?? '' });
    expect(env.AWS_BEARER_TOKEN_BEDROCK).toBe('bearer-xyz');
    expect(env.KIRO_API_KEY).toBe('kiro-abc');
    expect(resolved.toSorted()).toEqual(['AWS_BEARER_TOKEN_BEDROCK', 'KIRO_API_KEY']);
  });

  it('explicit api-key selector: bearer populated', async () => {
    const env = {
      BEDROCK_AUTH_METHOD_SSM_PATH: '/p/method',
      BEDROCK_BEARER_TOKEN_SSM_PATH: '/p/bedrock',
    };
    const store = { '/p/method': 'api-key', '/p/bedrock': 'bearer-xyz' };
    const resolved = await resolveAgentAuth({ env, getParam: async (n) => store[n] ?? '' });
    expect(env.AWS_BEARER_TOKEN_BEDROCK).toBe('bearer-xyz');
    expect(resolved).toContain('AWS_BEARER_TOKEN_BEDROCK');
  });

  it('explicit role selector: bearer NOT populated even when a stored key + path exist (precedence)', async () => {
    const env = {
      BEDROCK_AUTH_METHOD_SSM_PATH: '/p/method',
      BEDROCK_BEARER_TOKEN_SSM_PATH: '/p/bedrock',
      KIRO_API_KEY_SSM_PATH: '/p/kiro',
    };
    const store = { '/p/method': 'role', '/p/bedrock': 'bearer-xyz', '/p/kiro': 'kiro-abc' };
    const resolved = await resolveAgentAuth({ env, getParam: async (n) => store[n] ?? '' });
    // Role wins: the bearer is left unused (never populated), stored key untouched.
    expect(env.AWS_BEARER_TOKEN_BEDROCK).toBeUndefined();
    expect(resolved).not.toContain('AWS_BEARER_TOKEN_BEDROCK');
    // Kiro remains fully independent of the Bedrock auth path.
    expect(env.KIRO_API_KEY).toBe('kiro-abc');
    expect(resolved).toContain('KIRO_API_KEY');
  });

  it('role path: SSM error on the selector fails safe to api-key (bearer populated)', async () => {
    const env = {
      BEDROCK_AUTH_METHOD_SSM_PATH: '/p/method',
      BEDROCK_BEARER_TOKEN_SSM_PATH: '/p/bedrock',
    };
    const getParam = async (n) => {
      if (n === '/p/method') throw new Error('ssm boom');
      return n === '/p/bedrock' ? 'bearer-xyz' : '';
    };
    const resolved = await resolveAgentAuth({ env, getParam });
    expect(env.AWS_BEARER_TOKEN_BEDROCK).toBe('bearer-xyz');
    expect(resolved).toContain('AWS_BEARER_TOKEN_BEDROCK');
  });

  it('non-canonical selector value fails safe to api-key (bearer populated)', async () => {
    const env = {
      BEDROCK_AUTH_METHOD_SSM_PATH: '/p/method',
      BEDROCK_BEARER_TOKEN_SSM_PATH: '/p/bedrock',
    };
    // An unrecognized value (not exactly 'role' after trim+lowercase) → api-key.
    const store = { '/p/method': 'sts', '/p/bedrock': 'bearer-xyz' };
    const resolved = await resolveAgentAuth({ env, getParam: async (n) => store[n] ?? '' });
    expect(env.AWS_BEARER_TOKEN_BEDROCK).toBe('bearer-xyz');
    expect(resolved).toContain('AWS_BEARER_TOKEN_BEDROCK');
  });

  it('Kiro key is populated independently of bedrockAuthMethod in the role branch', async () => {
    const env = {
      BEDROCK_AUTH_METHOD_SSM_PATH: '/p/method',
      KIRO_API_KEY_SSM_PATH: '/p/kiro',
    };
    const store = { '/p/method': 'role', '/p/kiro': 'kiro-abc' };
    const resolved = await resolveAgentAuth({ env, getParam: async (n) => store[n] ?? '' });
    expect(env.KIRO_API_KEY).toBe('kiro-abc');
    expect(resolved).toEqual(['KIRO_API_KEY']);
  });
});
