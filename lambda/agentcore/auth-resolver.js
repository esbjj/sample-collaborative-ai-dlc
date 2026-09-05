// Auth resolver — at container startup, fetch the agent CLI's Bedrock bearer
// token + Kiro API key from SSM and expose them as the env vars the CLI drivers
// read (AWS_BEARER_TOKEN_BEDROCK / KIRO_API_KEY).
//
// Why: terraform passes the SSM *paths* (BEDROCK_BEARER_TOKEN_SSM_PATH /
// KIRO_API_KEY_SSM_PATH), not the secrets. The drivers' envForAuth() only forward
// AWS_BEARER_TOKEN_BEDROCK / KIRO_API_KEY if already present — so without this
// step the token is never set and Claude Code silently falls back to task-role
// SigV4 (which the execution role is not granted), yielding a 403.
//
// Bedrock auth PATH (api-key vs role) — the additive least-privilege STS path:
// an admin can select a short-lived, role-based Bedrock credential path instead
// of the long-lived bearer token (AWS Well-Architected SEC02-BP02). The choice is
// a non-secret `bedrockAuthMethod` value ('api-key' | 'role') at the SSM path in
// BEDROCK_AUTH_METHOD_SSM_PATH (wired by the terraform IAM/SSM unit). On the
// 'role' path we simply DO NOT populate AWS_BEARER_TOKEN_BEDROCK — the drivers'
// envForAuth() then omits it, and each CLI resolves temporary SigV4 credentials
// from the task execution role via the standard AWS credential chain (which the
// scoped bedrock:InvokeModel grant now authorizes). Correctness is by OMISSION:
// no new bearer forward, no invoke-path change. Selection fails safe to 'api-key'
// so a misconfiguration or SSM fault can never regress a working deployment.
//
// Best-effort + idempotent: a missing path or an SSM miss is skipped (the CLI may
// be configured another way, or only one CLI is installed); an already-populated
// env var is never overwritten. Pure-ish: the SSM getter is injected for tests.

import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';

// Map of target env var → the env var holding its SSM path.
const SSM_PATH_ENV = {
  AWS_BEARER_TOKEN_BEDROCK: 'BEDROCK_BEARER_TOKEN_SSM_PATH',
  KIRO_API_KEY: 'KIRO_API_KEY_SSM_PATH',
};

// Fetch one decrypted SSM SecureString; returns '' on any miss/error.
const defaultGetParam = (client) => async (name) => {
  try {
    const res = await client.send(new GetParameterCommand({ Name: name, WithDecryption: true }));
    return res.Parameter?.Value ?? '';
  } catch {
    return '';
  }
};

// Resolve the selected Bedrock auth method ('api-key' | 'role') from the
// non-secret `bedrockAuthMethod` SSM value at env.BEDROCK_AUTH_METHOD_SSM_PATH.
//
// Fail-safe by design: only an EXPLICIT, canonicalized 'role' selects the role
// path — the stored value is trimmed and lowercased before comparison. An unset
// path, a missing parameter, an SSM error, or any non-canonical value all resolve
// to 'api-key' so the deployment degrades TOWARD the existing (v1) bearer path,
// never away from it. Never throws. The getter is injected for tests.
export const resolveAuthMethod = async ({ env = process.env, get } = {}) => {
  const path = env.BEDROCK_AUTH_METHOD_SSM_PATH;
  if (!path) return 'api-key'; // no selector configured → default
  let value;
  try {
    value = (await get(path)).trim().toLowerCase();
  } catch {
    return 'api-key'; // ANY SSM error → fail-safe default
  }
  return value === 'role' ? 'role' : 'api-key';
};

// Resolve the auth secrets into `env` in place. Returns the list of target env
// vars that were populated (for a startup log line — never the values).
//
// On the 'role' auth path the Bedrock bearer token is intentionally skipped
// (left unpopulated) so the CLI uses task-role SigV4 credentials. This also
// realizes the both-configured precedence rule (role wins, informational): a
// stored bearer key is left unused, never deleted or rewritten.
export const resolveAgentAuth = async ({ env = process.env, getParam } = {}) => {
  const get = getParam ?? defaultGetParam(new SSMClient({ region: env.AWS_REGION || 'us-east-1' }));
  const method = await resolveAuthMethod({ env, get });
  // Publish the resolved method as a NON-SECRET marker on the same env object.
  // The capabilities probe reports per-CLI `authed` from the presence of an auth
  // secret, but on the 'role' path there is deliberately no bearer token to find
  // — the execution role's SigV4 credentials are the auth. Without this marker
  // capabilities would report claude/opencode/codex as unauthed, and the project
  // Agent settings UI gates selection on that flag (AgentTab.tsx `isCliAvailable`),
  // so the role path would make exactly the CLIs it enables unselectable.
  env.BEDROCK_AUTH_METHOD = method;
  const resolved = [];
  for (const [target, pathEnv] of Object.entries(SSM_PATH_ENV)) {
    // Role path: omit the Bedrock bearer token entirely (precedence + role auth).
    // envForAuth then forwards only region + CLI flags, so the CLI signs invokes
    // with the execution role's temporary SigV4 credentials.
    if (target === 'AWS_BEARER_TOKEN_BEDROCK' && method === 'role') continue;
    if (env[target]) continue; // already set — never overwrite
    const path = env[pathEnv];
    if (!path) continue; // no path configured for this CLI
    const value = await get(path);
    if (value) {
      env[target] = value;
      resolved.push(target);
    }
  }
  return resolved;
};
