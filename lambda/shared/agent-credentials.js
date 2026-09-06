import {
  DeleteParameterCommand,
  GetParameterCommand,
  GetParametersCommand,
  PutParameterCommand,
} from '@aws-sdk/client-ssm';

export const AGENT_CREDENTIAL_PROVIDERS = ['bedrock', 'kiro'];
export const AGENT_CREDENTIAL_SOURCES = ['user', 'space', 'platform'];
export const AGENT_CREDENTIAL_METADATA_ACTIONS = Object.freeze({
  READ_SCOPE_STATUS: 'read-agent-credential-scope-status',
  RESOLVE_EFFECTIVE_BINDINGS: 'resolve-effective-agent-credential-bindings',
});

export const AGENT_CLI_PROVIDER = {
  kiro: 'kiro',
  claude: 'bedrock',
  opencode: 'bedrock',
  codex: 'bedrock',
};

const PROVIDER_CONFIG = {
  bedrock: {
    parameterName: 'bedrock-bearer-token',
    inputField: 'bedrockBearerToken',
    setField: 'bedrockBearerTokenSet',
    envName: 'AWS_BEARER_TOKEN_BEDROCK',
  },
  kiro: {
    parameterName: 'kiro-api-key',
    inputField: 'kiroApiKey',
    setField: 'kiroApiKeySet',
    envName: 'KIRO_API_KEY',
  },
};

// The temporary-credential variables a Bedrock IAM-role binding resolves to.
// They are NOT a provider's own env name: the binding lives in the same bedrock
// parameter, and which shape it holds is a property of the stored value
// (specs/bedrock-iam-role-credential-mode: req-single-parameter-encoding).
export const AWS_TEMPORARY_CREDENTIAL_ENV_NAMES = Object.freeze([
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
]);

// Every name an invocation may have written for a credential. cleanBaseEnv
// scrubs all of them from the base environment on every invocation, so one
// caller's credentials can never leak into the next one's — which is why the
// three AWS names belong here and not only on the write side.
export const AGENT_CREDENTIAL_ENV_NAMES = Object.freeze([
  ...AGENT_CREDENTIAL_PROVIDERS.map((provider) => PROVIDER_CONFIG[provider].envName),
  ...AWS_TEMPORARY_CREDENTIAL_ENV_NAMES,
]);

const normalizeBase = (base) => String(base || '').replace(/\/+$/, '');

const assertIdentifier = (value, label) => {
  const normalized = String(value || '');
  if (!normalized || !/^[A-Za-z0-9._-]+$/.test(normalized)) {
    throw new Error(`${label} is invalid`);
  }
  return normalized;
};

const assertProvider = (provider) => {
  if (!AGENT_CREDENTIAL_PROVIDERS.includes(provider)) {
    throw new Error(`Unsupported agent credential provider: ${provider}`);
  }
  return provider;
};

const assertSource = (source) => {
  if (!AGENT_CREDENTIAL_SOURCES.includes(source)) {
    throw new Error(`Unsupported agent credential source: ${source}`);
  }
  return source;
};

export const credentialProviderForCli = (cli) => AGENT_CLI_PROVIDER[cli] ?? null;

export const credentialEnvName = (provider) => PROVIDER_CONFIG[assertProvider(provider)].envName;

export const isConfiguredCredentialValue = (value) => {
  const normalized = typeof value === 'string' ? value.trim() : '';
  return normalized !== '' && normalized !== 'placeholder';
};

// ── Bedrock binding value: bearer token or IAM role ──
//
// The bedrock parameter holds EITHER today's plain bearer string OR a JSON
// object naming an IAM role to assume. Every pre-existing value is a plain
// string and therefore still a bearer token, so this is backwards compatible by
// construction (specs/bedrock-iam-role-credential-mode: dec-value-encoding).
//
// Discrimination is positional, never a guess: a trimmed value starting with `{`
// MUST parse as an object carrying a valid roleArn, else it is rejected. Any
// other non-empty value is a bearer token and is never parsed. Rejection happens
// on the settings write path so a malformed value can never reach a stage.
export const CREDENTIAL_VALUE_KINDS = Object.freeze({ BEARER: 'bearer', ROLE: 'role' });

// The spec's `^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+`, narrowed to reject
// trailing whitespace and embedded junk. An IAM role path and name contain no
// whitespace, so `\S+$` excludes nothing a real ARN can carry.
const ROLE_ARN_PATTERN = /^arn:aws[a-z-]*:iam::[0-9]{12}:role\/\S+$/;
const ROLE_ARN_MAX_LENGTH = 2048;
// The STS ExternalId charset and length bounds.
const EXTERNAL_ID_PATTERN = /^[\w+=,.@:/-]+$/;
const EXTERNAL_ID_MIN_LENGTH = 2;
const EXTERNAL_ID_MAX_LENGTH = 1224;

export const BEDROCK_ROLE_BINDING_INVALID = 'BEDROCK_ROLE_BINDING_INVALID';

const invalidRoleBinding = (message) =>
  Object.assign(new Error(message), { code: BEDROCK_ROLE_BINDING_INVALID });

// True when the value is SHAPED like a role object. Says nothing about validity —
// a true here means the value must parse, or the write is rejected.
export const looksLikeRoleBindingValue = (value) =>
  typeof value === 'string' && value.trim().startsWith('{');

// Parse a role binding value. Throws BEDROCK_ROLE_BINDING_INVALID with a reason
// that names the offending field and never echoes the value.
export const parseRoleBindingValue = (value) => {
  if (!looksLikeRoleBindingValue(value)) {
    throw invalidRoleBinding('Credential value is not a role binding object');
  }
  let parsed;
  try {
    parsed = JSON.parse(value.trim());
  } catch {
    throw invalidRoleBinding('Role binding must be valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw invalidRoleBinding('Role binding must be a JSON object');
  }
  const roleArn = typeof parsed.roleArn === 'string' ? parsed.roleArn.trim() : '';
  if (!roleArn) throw invalidRoleBinding('Role binding requires roleArn');
  if (roleArn.length > ROLE_ARN_MAX_LENGTH) {
    throw invalidRoleBinding(`roleArn must be at most ${ROLE_ARN_MAX_LENGTH} characters`);
  }
  if (!ROLE_ARN_PATTERN.test(roleArn)) {
    throw invalidRoleBinding('roleArn must be a valid IAM role ARN');
  }
  let externalId = null;
  if (parsed.externalId !== undefined && parsed.externalId !== null && parsed.externalId !== '') {
    if (typeof parsed.externalId !== 'string') {
      throw invalidRoleBinding('externalId must be a string');
    }
    externalId = parsed.externalId.trim();
    if (
      externalId.length < EXTERNAL_ID_MIN_LENGTH ||
      externalId.length > EXTERNAL_ID_MAX_LENGTH ||
      !EXTERNAL_ID_PATTERN.test(externalId)
    ) {
      throw invalidRoleBinding(
        `externalId must be ${EXTERNAL_ID_MIN_LENGTH} to ${EXTERNAL_ID_MAX_LENGTH} characters in the STS external-id charset`,
      );
    }
  }
  return { roleArn, externalId };
};

// The kind of a configured binding value: 'role' for a valid role object,
// 'bearer' for any other configured value, null when nothing is configured.
// Throws for a role-shaped value that does not parse — a malformed binding is an
// error, never silently a bearer token.
export const credentialValueKind = (value) => {
  if (!isConfiguredCredentialValue(value)) return null;
  if (!looksLikeRoleBindingValue(value)) return CREDENTIAL_VALUE_KINDS.BEARER;
  parseRoleBindingValue(value);
  return CREDENTIAL_VALUE_KINDS.ROLE;
};

// Non-throwing variant for read paths that must not fail on a value someone
// wrote before validation existed: a malformed role-shaped value is reported as
// a role so it is never mistaken for a usable bearer token.
export const credentialValueKindSafe = (value) => {
  if (!isConfiguredCredentialValue(value)) return null;
  return looksLikeRoleBindingValue(value)
    ? CREDENTIAL_VALUE_KINDS.ROLE
    : CREDENTIAL_VALUE_KINDS.BEARER;
};

// Validate a credential-scope write BEFORE it reaches SSM.
//
// specs/bedrock-iam-role-credential-mode: req-single-parameter-encoding puts
// validation on the settings write path so a malformed value can never reach a
// stage, and req-role-credential-mode keeps role bindings out of user scope
// (dec-user-scope-role-deferred).
//
// Returns null when the update is acceptable, else { error, issues } for a 400.
// Throws nothing: every caller is an HTTP handler.
export const validateCredentialScopeUpdate = ({ source, update = {} }) => {
  const value = update?.bedrockBearerToken;
  // Only a role-SHAPED value is inspected. Any other non-empty value is a bearer
  // token and is deliberately never parsed, which is what keeps every
  // pre-existing deployment working untouched.
  if (typeof value !== 'string' || !looksLikeRoleBindingValue(value)) return null;
  if (source === 'user') {
    // PUT /users/me/agent-credentials is gated only on authentication, so any
    // member could otherwise name a role ARN. Permitting this scope later is
    // backwards compatible; forbidding it later would be breaking.
    return {
      error: 'A Bedrock IAM role cannot be configured at user scope',
      code: 'BEDROCK_ROLE_SCOPE_UNSUPPORTED',
      issues: [
        'Role bindings are supported at space and platform scope only. Personal credentials must be a Bedrock API key.',
      ],
    };
  }
  try {
    parseRoleBindingValue(value);
    return null;
  } catch (error) {
    // The message names the offending field and never echoes the value.
    return {
      error: 'Invalid Bedrock role binding',
      code: error.code || BEDROCK_ROLE_BINDING_INVALID,
      issues: [error.message],
    };
  }
};

export const agentCredentialPath = ({
  base,
  source,
  provider,
  projectId = null,
  userId = null,
}) => {
  const prefix = normalizeBase(base);
  if (!prefix) throw new Error('Agent credential store is not configured');
  const config = PROVIDER_CONFIG[assertProvider(provider)];
  switch (assertSource(source)) {
    case 'platform':
      return `${prefix}/${config.parameterName}`;
    case 'space':
      return `${prefix}/projects/${assertIdentifier(projectId, 'projectId')}/agent-credentials/${
        config.parameterName
      }`;
    case 'user':
      return `${prefix}/users/${assertIdentifier(userId, 'userId')}/agent-credentials/${
        config.parameterName
      }`;
    default:
      throw new Error(`Unsupported agent credential source: ${source}`);
  }
};

export const normalizeCredentialBinding = (binding) => {
  if (!binding || typeof binding !== 'object' || Array.isArray(binding)) return null;
  const provider = assertProvider(binding.provider);
  const source = assertSource(binding.source);
  return {
    provider,
    source,
    ...(source === 'user' ? { userId: assertIdentifier(binding.userId, 'userId') } : {}),
  };
};

const scopePaths = ({ base, source, projectId, userId }) =>
  Object.fromEntries(
    AGENT_CREDENTIAL_PROVIDERS.map((provider) => [
      provider,
      agentCredentialPath({ base, source, provider, projectId, userId }),
    ]),
  );

const deleteParameterIfPresent = async (ssm, path) => {
  try {
    await ssm.send(new DeleteParameterCommand({ Name: path }));
    return true;
  } catch (error) {
    if (error?.name === 'ParameterNotFound') return false;
    throw error;
  }
};

// Broker-only read path. API Lambdas call the metadata broker and deliberately
// have no ssm:GetParameter(s) permission on agent credential paths.
const fetchValues = async (ssm, paths) => {
  const names = [...new Set(Object.values(paths))];
  if (names.length === 0) return {};
  const result = await ssm.send(
    new GetParametersCommand({
      Names: names,
      WithDecryption: true,
    }),
  );
  return Object.fromEntries(
    (result.Parameters || []).map((parameter) => [parameter.Name, parameter.Value || '']),
  );
};

// Per-provider set-state for one scope.
//
// specs/bedrock-iam-role-credential-mode: req-configured-semantics.
// `bedrockBearerTokenSet` keeps its EXACT original meaning — a bearer token is
// configured — which now requires excluding a role object. Without this the
// legacy boolean would read true for a role binding (isConfiguredCredentialValue
// only checks non-empty and not the placeholder), telling both credential cards
// that a bearer secret is set when none is.
//
// It deliberately does NOT become "this scope is configured". That question is
// answered by the mode fields added in Phase 2; widening this boolean's meaning
// would silently change what two existing UI cards assert.
export const readCredentialScopeStatus = async (
  ssm,
  { base, source, projectId = null, userId = null },
) => {
  const paths = scopePaths({ base, source, projectId, userId });
  const values = await fetchValues(ssm, paths);
  return Object.fromEntries(
    AGENT_CREDENTIAL_PROVIDERS.map((provider) => {
      const value = values[paths[provider]];
      const set =
        provider === 'bedrock'
          ? credentialValueKindSafe(value) === CREDENTIAL_VALUE_KINDS.BEARER
          : isConfiguredCredentialValue(value);
      return [PROVIDER_CONFIG[provider].setField, set];
    }),
  );
};

export const writeCredentialScope = async (
  ssm,
  { base, source, projectId = null, userId = null, update = {} },
) => {
  assertSource(source);
  const written = [];
  const cleared = [];
  for (const provider of AGENT_CREDENTIAL_PROVIDERS) {
    const field = PROVIDER_CONFIG[provider].inputField;
    if (typeof update[field] !== 'string') continue;
    const path = agentCredentialPath({ base, source, provider, projectId, userId });
    const value = update[field].trim();
    if (value) {
      await ssm.send(
        new PutParameterCommand({
          Name: path,
          Value: value,
          Type: 'SecureString',
          Overwrite: true,
        }),
      );
      written.push(provider);
      continue;
    }
    if (source === 'platform') {
      await ssm.send(
        new PutParameterCommand({
          Name: path,
          Value: 'placeholder',
          Type: 'SecureString',
          Overwrite: true,
        }),
      );
    } else {
      await deleteParameterIfPresent(ssm, path);
    }
    cleared.push(provider);
  }
  return { saved: true, written, cleared };
};

export const deleteCredentialScope = async (
  ssm,
  { base, source, projectId = null, userId = null },
) => {
  const normalizedSource = assertSource(source);
  if (normalizedSource === 'platform') {
    throw new Error('Platform agent credentials cannot be deleted as a scope');
  }
  const deleted = [];
  const missing = [];
  for (const provider of AGENT_CREDENTIAL_PROVIDERS) {
    const path = agentCredentialPath({
      base,
      source: normalizedSource,
      provider,
      projectId,
      userId,
    });
    if (await deleteParameterIfPresent(ssm, path)) deleted.push(provider);
    else missing.push(provider);
  }
  return { deleted, missing };
};

export const resolveEffectiveCredentialBindings = async (ssm, { base, projectId, userId }) => {
  const sources = {
    user: scopePaths({ base, source: 'user', userId }),
    space: scopePaths({ base, source: 'space', projectId }),
    platform: scopePaths({ base, source: 'platform' }),
  };
  const bindings = {};
  const unresolved = new Set(AGENT_CREDENTIAL_PROVIDERS);
  for (const source of AGENT_CREDENTIAL_SOURCES) {
    const paths = Object.fromEntries(
      [...unresolved].map((provider) => [provider, sources[source][provider]]),
    );
    const values = await fetchValues(ssm, paths);
    for (const provider of unresolved) {
      const path = sources[source][provider];
      if (!isConfiguredCredentialValue(values[path])) continue;
      bindings[provider] = {
        provider,
        source,
        ...(source === 'user' ? { userId: assertIdentifier(userId, 'userId') } : {}),
      };
      unresolved.delete(provider);
    }
    if (unresolved.size === 0) break;
  }
  for (const provider of unresolved) bindings[provider] = null;
  return bindings;
};

export const readCredentialBindingValue = async (ssm, { base, binding, projectId = null }) => {
  const normalized = normalizeCredentialBinding(binding);
  if (!normalized) return '';
  const path = agentCredentialPath({
    base,
    source: normalized.source,
    provider: normalized.provider,
    projectId,
    userId: normalized.userId,
  });
  try {
    const result = await ssm.send(
      new GetParameterCommand({
        Name: path,
        WithDecryption: true,
      }),
    );
    const value = result.Parameter?.Value || '';
    return isConfiguredCredentialValue(value) ? value : '';
  } catch (error) {
    if (error?.name === 'ParameterNotFound') return '';
    throw error;
  }
};

export const credentialSourcesFromBindings = (bindings = {}) => ({
  bedrock: bindings.bedrock?.source ?? null,
  kiro: bindings.kiro?.source ?? null,
});

export const availableClisForBindings = ({ installed = [], bindings = {} } = {}) =>
  installed.filter((cli) => {
    const provider = credentialProviderForCli(cli);
    return provider && bindings[provider];
  });

export default {
  agentCredentialPath,
  availableClisForBindings,
  credentialEnvName,
  credentialProviderForCli,
  credentialSourcesFromBindings,
  credentialValueKind,
  credentialValueKindSafe,
  deleteCredentialScope,
  isConfiguredCredentialValue,
  looksLikeRoleBindingValue,
  normalizeCredentialBinding,
  parseRoleBindingValue,
  readCredentialBindingValue,
  readCredentialScopeStatus,
  resolveEffectiveCredentialBindings,
  validateCredentialScopeUpdate,
  writeCredentialScope,
};
