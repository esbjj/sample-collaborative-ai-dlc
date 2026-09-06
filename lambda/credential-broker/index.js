import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { SSMClient } from '@aws-sdk/client-ssm';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { executionMetaKey } from '../shared/v2-process-keys.js';
import {
  ACTIVE,
  canonicalRepo,
  getBinding,
  invalidationReasonForError,
  loggableErrorCode,
  markBindingInvalid,
} from '../shared/source-control-bindings.js';
import { resolveBindingCredential } from '../shared/source-control-credentials.js';
import { repoUrl, repoProvider } from '../shared/repo-provider.js';
import {
  BEDROCK_ROLE_BINDING_INVALID,
  CREDENTIAL_VALUE_KINDS,
  looksLikeRoleBindingValue,
  parseRoleBindingValue,
  readCredentialBindingValue,
} from '../shared/agent-credentials.js';
import { verifyIssuedAgentCredentialGrant } from '../shared/agent-credential-grants.js';
import { AGENT_AUTH_MODES } from '../shared/agent-command-registry.js';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const ssm = new SSMClient({});
const sts = new STSClient({});
const secrets = new SecretsManagerClient({});

const CREDENTIAL_ACTIVE_EXECUTION_STATUSES = new Set(['CREATED', 'RUNNING']);
const RESOLVE_AGENT_CREDENTIALS = 'resolve-agent-credentials';

// ── Bedrock IAM-role resolution ──
// specs/bedrock-iam-role-credential-mode: req-broker-side-assume,
// req-broker-credential-resolution, req-session-name-attribution.
//
// The broker is already the sole IAM principal permitted to read credential
// material and already validates a signed grant, so it is already the trusted
// resolver — which is why the AssumeRole happens HERE and never in a container.
// The container never names a role: the ARN is read from SSM at resolution time,
// keyed off the binding the verified grant authorizes.

// con-role-chaining-3600: the broker itself runs under an assumed role, so this
// AssumeRole is role chaining and STS caps it at exactly 3600s. This is a
// ceiling, not a tuning knob, and is deliberately not configurable.
const ROLE_SESSION_DURATION_SECONDS = 3600;
// req-session-name-trust-condition: customers authorize on this format with an
// sts:RoleSessionName trust-policy condition, so changing it is a BREAKING change
// requiring a migration note. Composed in exactly one place, on the server.
const ROLE_SESSION_NAME_PREFIX = 'aidlc-';
const ROLE_SESSION_NAME_PATTERN = /^[\w+=,.@-]{2,64}$/;

export const BEDROCK_ROLE_ERROR_CODES = Object.freeze({
  BINDING_INVALID: BEDROCK_ROLE_BINDING_INVALID,
  ASSUME_DENIED: 'BEDROCK_ROLE_ASSUME_DENIED',
  ASSUME_THROTTLED: 'BEDROCK_ROLE_ASSUME_THROTTLED',
  RESOLUTION_FAILED: 'BEDROCK_ROLE_RESOLUTION_FAILED',
});

// Never carries provider text: an STS message can name the caller session and
// the target role, and the allowlisted code is the only thing that may be logged
// or returned.
const roleError = (code, message) => Object.assign(new Error(message), { code });

const DENIED_STS_ERRORS = new Set([
  'AccessDenied',
  'AccessDeniedException',
  'InvalidClientTokenId',
  'UnrecognizedClientException',
  'ExpiredToken',
  'ExpiredTokenException',
]);
const THROTTLED_STS_ERRORS = new Set([
  'Throttling',
  'ThrottlingException',
  'TooManyRequestsException',
  'RequestLimitExceeded',
  'SlowDown',
]);

// Map an STS failure onto one allowlisted code, discarding the original message.
const classifyAssumeFailure = (error) => {
  const name = error?.name || error?.Code || '';
  if (DENIED_STS_ERRORS.has(name)) {
    return roleError(BEDROCK_ROLE_ERROR_CODES.ASSUME_DENIED, 'Role assumption was denied');
  }
  if (THROTTLED_STS_ERRORS.has(name)) {
    return roleError(BEDROCK_ROLE_ERROR_CODES.ASSUME_THROTTLED, 'Role assumption was throttled');
  }
  return roleError(BEDROCK_ROLE_ERROR_CODES.RESOLUTION_FAILED, 'Role assumption failed');
};

const composeRoleSessionName = (projectId) => {
  const sessionName = `${ROLE_SESSION_NAME_PREFIX}${String(projectId || '')}`;
  if (!projectId || !ROLE_SESSION_NAME_PATTERN.test(sessionName)) {
    // Without a usable projectId there is no attribution, and attribution is the
    // premise the whole showback model rests on — so fail rather than invent one.
    throw roleError(
      BEDROCK_ROLE_ERROR_CODES.RESOLUTION_FAILED,
      'Role session name could not be composed for this request',
    );
  }
  return sessionName;
};

const assumeBedrockRole = async ({ roleArn, externalId, projectId }, stsClient) => {
  const RoleSessionName = composeRoleSessionName(projectId);
  let result;
  try {
    result = await stsClient.send(
      new AssumeRoleCommand({
        RoleArn: roleArn,
        RoleSessionName,
        DurationSeconds: ROLE_SESSION_DURATION_SECONDS,
        // con-tagsession-required: session tags need sts:TagSession in the
        // customer's trust policy, so passing any would fail closed on every
        // role that omits it. Attribution is RoleSessionName only.
        ...(externalId ? { ExternalId: externalId } : {}),
      }),
    );
  } catch (error) {
    throw classifyAssumeFailure(error);
  }
  const credentials = result?.Credentials;
  if (!credentials?.AccessKeyId || !credentials?.SecretAccessKey || !credentials?.SessionToken) {
    throw roleError(
      BEDROCK_ROLE_ERROR_CODES.RESOLUTION_FAILED,
      'Role assumption returned no credentials',
    );
  }
  return {
    AccessKeyId: credentials.AccessKeyId,
    SecretAccessKey: credentials.SecretAccessKey,
    SessionToken: credentials.SessionToken,
    Expiration:
      credentials.Expiration instanceof Date
        ? credentials.Expiration.toISOString()
        : (credentials.Expiration ?? null),
  };
};

const loggableAgentCredentialErrorCode = (error) => {
  switch (error?.code) {
    case 'AGENT_CREDENTIAL_GRANT_EXPIRED':
      return 'AGENT_CREDENTIAL_GRANT_EXPIRED';
    case 'AGENT_CREDENTIAL_GRANT_INVALID':
      return 'AGENT_CREDENTIAL_GRANT_INVALID';
    case 'AGENT_CREDENTIAL_GRANT_NOT_CONFIGURED':
      return 'AGENT_CREDENTIAL_GRANT_NOT_CONFIGURED';
    case BEDROCK_ROLE_ERROR_CODES.BINDING_INVALID:
    case BEDROCK_ROLE_ERROR_CODES.ASSUME_DENIED:
    case BEDROCK_ROLE_ERROR_CODES.ASSUME_THROTTLED:
    case BEDROCK_ROLE_ERROR_CODES.RESOLUTION_FAILED:
      return error.code;
    default:
      return 'AGENT_CREDENTIAL_BROKER_FAILED';
  }
};

const executionIncludesRepository = (meta, provider, repository) => {
  if (!meta || !provider || !repository) return false;
  let requested;
  try {
    requested = canonicalRepo(provider, repository);
  } catch {
    return false;
  }
  return (meta.repos ?? []).some((repo) => {
    const expectedProvider = repoProvider(repo, meta?.gitProvider, meta?.repoProviders);
    if (expectedProvider !== provider) return false;
    try {
      return canonicalRepo(provider, repoUrl(repo)) === requested;
    } catch {
      return false;
    }
  });
};

const authorizeCredentialRequest = async (
  { executionId, projectId, provider, repository, requiredAccess = 'write' },
  { ddbClient = ddb, ssmClient = ssm, secretsClient = secrets } = {},
) => {
  if (!executionId || !projectId || !provider || !repository) {
    throw Object.assign(
      new Error('executionId, projectId, provider, and repository are required'),
      {
        code: 'INVALID_REQUEST',
      },
    );
  }
  if (!['identity', 'read', 'write'].includes(requiredAccess)) {
    throw Object.assign(new Error('requiredAccess must be identity, read, or write'), {
      code: 'INVALID_REQUEST',
    });
  }
  const { Item: execution } = await ddbClient.send(
    new GetCommand({
      TableName: process.env.V2_PROCESS_TABLE,
      Key: executionMetaKey(executionId),
      ConsistentRead: true,
    }),
  );
  if (!execution || execution.projectId !== projectId) {
    throw Object.assign(new Error('Execution was not found for this project'), {
      code: 'EXECUTION_NOT_FOUND',
    });
  }
  if (!CREDENTIAL_ACTIVE_EXECUTION_STATUSES.has(execution.status)) {
    throw Object.assign(new Error('Execution is not active'), {
      code: 'EXECUTION_NOT_ACTIVE',
    });
  }
  if (!executionIncludesRepository(execution, provider, repository)) {
    throw Object.assign(new Error('Repository is not part of this execution'), {
      code: 'REPOSITORY_NOT_ON_EXECUTION',
    });
  }
  const binding = await getBinding(ddbClient, projectId, provider, repository);
  if (!binding || binding.status !== ACTIVE) {
    throw Object.assign(new Error('Project source-control binding is not active'), {
      code: 'SOURCE_CONTROL_NOT_READY',
    });
  }
  if (requiredAccess === 'write' && !binding.capabilities?.repositoryWrite) {
    throw Object.assign(new Error('Project source-control binding is not writable'), {
      code: 'WRITE_ACCESS_REQUIRED',
    });
  }
  if (requiredAccess === 'identity') {
    return {
      committer:
        binding.actorName && binding.actorEmail
          ? { name: binding.actorName, email: binding.actorEmail }
          : null,
    };
  }
  try {
    return await resolveBindingCredential({
      ddb: ddbClient,
      ssm: ssmClient,
      secrets: secretsClient,
      binding,
      requiredAccess,
    });
  } catch (error) {
    const invalidReason = invalidationReasonForError(error);
    if (invalidReason) {
      await markBindingInvalid(ddbClient, binding, invalidReason).catch(() => {});
    }
    throw error;
  }
};

// Resolve ONE authorized binding into a kind-discriminated credential entry.
//
// dec-explicit-discriminator: the resolver treats an entry carrying no `value` as
// a MISSING provider (con-missing-value-is-missing), so a role result cannot
// reuse the bearer shape. `kind` is always present and is the only thing the
// caller may branch on — never field presence.
const resolveAgentCredentialEntry = async (
  binding,
  { ssmClient, stsClient, env, projectId, purpose },
) => {
  const value = await readCredentialBindingValue(ssmClient, {
    base: env.AGENT_SETTINGS_SSM_PREFIX || '',
    binding,
    projectId,
  });
  if (!value) return { binding, kind: null, value: null };
  if (!looksLikeRoleBindingValue(value)) {
    return { binding, kind: CREDENTIAL_VALUE_KINDS.BEARER, value };
  }
  // Throws BEDROCK_ROLE_BINDING_INVALID. Validation also lives on the settings
  // write path (req-single-parameter-encoding); this is the fail-closed backstop
  // for a value written before that existed.
  const { roleArn, externalId } = parseRoleBindingValue(value);
  // req-capabilities-authed: a capabilities request answers "is this binding
  // usable", which the binding itself already answers. Minting here would mean
  // one AssumeRole per settings render, which AWS warns can exceed the STS
  // request-rate quota — so this path deliberately performs NO AssumeRole.
  if (purpose === AGENT_AUTH_MODES.CAPABILITIES) {
    return { binding, kind: CREDENTIAL_VALUE_KINDS.ROLE, usable: true };
  }
  return {
    binding,
    kind: CREDENTIAL_VALUE_KINDS.ROLE,
    credentials: await assumeBedrockRole({ roleArn, externalId, projectId }, stsClient),
  };
};

const authorizeAgentCredentialRequest = async (
  { grant },
  { ssmClient = ssm, stsClient = sts, secret = null, env = process.env, now = undefined } = {},
) => {
  if (!grant) {
    throw Object.assign(new Error('Agent credential grant is required'), {
      code: 'AGENT_CREDENTIAL_GRANT_INVALID',
    });
  }
  const claims = await verifyIssuedAgentCredentialGrant(ssmClient, grant, {
    env,
    secret,
    ...(now ? { now } : {}),
  });
  const credentials = await Promise.all(
    claims.bindings.map((binding) =>
      resolveAgentCredentialEntry(binding, {
        ssmClient,
        stsClient,
        env,
        projectId: claims.projectId,
        purpose: claims.purpose,
      }),
    ),
  );
  return {
    purpose: claims.purpose,
    projectId: claims.projectId,
    executionId: claims.executionId,
    credentials,
  };
};

export const handler = async (event) => {
  const action = event?.action || 'source-control';
  try {
    if (action === RESOLVE_AGENT_CREDENTIALS) {
      return {
        ok: true,
        ...(await authorizeAgentCredentialRequest(event || {})),
      };
    }
    const credential = await authorizeCredentialRequest(event || {});
    if (event?.requiredAccess === 'identity') {
      return { ok: true, committer: credential.committer };
    }
    return {
      ok: true,
      username: credential.username,
      password: credential.token,
      committer: credential.committer,
    };
  } catch (error) {
    // Both code helpers return only allowlisted constants — never provider-
    // derived error text, which can carry credential material.
    const code =
      action === RESOLVE_AGENT_CREDENTIALS
        ? loggableAgentCredentialErrorCode(error)
        : loggableErrorCode(error, 'CREDENTIAL_BROKER_FAILED');
    console.error('[credential-broker] request denied', {
      code,
      action,
      executionId: event?.executionId || null,
      projectId: event?.projectId || null,
      provider: event?.provider || null,
      repository: event?.repository || null,
    });
    return { ok: false, code };
  }
};

export {
  RESOLVE_AGENT_CREDENTIALS,
  CREDENTIAL_ACTIVE_EXECUTION_STATUSES,
  ROLE_SESSION_DURATION_SECONDS,
  authorizeAgentCredentialRequest,
  executionIncludesRepository,
  loggableAgentCredentialErrorCode,
  authorizeCredentialRequest,
};
