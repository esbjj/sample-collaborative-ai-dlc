import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import { parseLambdaPayload } from './lambda-payload.js';
import {
  AGENT_CREDENTIAL_METADATA_ACTIONS,
  AGENT_CREDENTIAL_PROVIDERS,
  normalizeCredentialBinding,
} from './agent-credentials.js';

const lambda = new LambdaClient({});
const invalidMetadata = (message) =>
  Object.assign(new Error(message), {
    code: 'AGENT_CREDENTIAL_METADATA_FAILED',
  });

const invokeMetadataBroker = async (
  payload,
  {
    lambdaClient = lambda,
    functionName = process.env.AGENT_CREDENTIAL_METADATA_FUNCTION || '',
  } = {},
) => {
  if (!functionName) {
    throw Object.assign(new Error('Agent credential metadata broker is not configured'), {
      code: 'AGENT_CREDENTIAL_METADATA_NOT_CONFIGURED',
    });
  }
  const response = await lambdaClient.send(
    new InvokeCommand({
      FunctionName: functionName,
      InvocationType: 'RequestResponse',
      Payload: Buffer.from(JSON.stringify(payload)),
    }),
  );
  if (response.FunctionError) {
    throw Object.assign(new Error('Agent credential metadata broker invocation failed'), {
      code: 'AGENT_CREDENTIAL_METADATA_FAILED',
    });
  }
  const result = parseLambdaPayload(response.Payload);
  if (!result?.ok) {
    throw Object.assign(new Error('Agent credential metadata broker denied the request'), {
      code: result?.code || 'AGENT_CREDENTIAL_METADATA_FAILED',
    });
  }
  return result;
};

export const readCredentialScopeStatusViaBroker = async (request, deps) => {
  // `includeBindingDetail` defaults to FALSE so the fail-safe direction is the
  // default: a caller must opt in to receiving tenant-identifying binding detail.
  // Only a path gated to a principal that may modify the binding may opt in
  // (specs/bedrock-iam-role-credential-mode: req-same-and-cross-account).
  const { includeBindingDetail = false, ...brokerRequest } = request ?? {};
  const result = await invokeMetadataBroker(
    {
      action: AGENT_CREDENTIAL_METADATA_ACTIONS.READ_SCOPE_STATUS,
      ...brokerRequest,
    },
    deps,
  );
  if (!result.status || typeof result.status !== 'object' || Array.isArray(result.status)) {
    throw invalidMetadata('Agent credential metadata broker returned an invalid status');
  }
  // This is a trust boundary, so every field is coerced rather than spread:
  // the broker's response shape is validated here, not assumed. Phase 2 adds the
  // three mode-aware fields (req-configured-semantics); an unrecognised mode
  // becomes null so a newer broker meeting an older reader degrades to "not
  // configured" rather than rendering a mode the UI cannot interpret.
  const mode = result.status.bedrockMode;
  const status = {
    bedrockBearerTokenSet: result.status.bedrockBearerTokenSet === true,
    kiroApiKeySet: result.status.kiroApiKeySet === true,
    bedrockMode: mode === 'bearer' || mode === 'role' ? mode : null,
    bedrockExternalIdSet: result.status.bedrockExternalIdSet === true,
  };
  // The role ARN is not a secret, but it is tenant-identifying and no
  // lower-privilege surface needs it — GET /agents/settings is reachable by any
  // authenticated user, so it must not carry which role a deployment assumes.
  if (includeBindingDetail) {
    status.bedrockRoleArn =
      typeof result.status.bedrockRoleArn === 'string' && result.status.bedrockRoleArn
        ? result.status.bedrockRoleArn
        : null;
  }
  return status;
};

export const resolveEffectiveCredentialBindingsViaBroker = async (request, deps) => {
  const result = await invokeMetadataBroker(
    {
      action: AGENT_CREDENTIAL_METADATA_ACTIONS.RESOLVE_EFFECTIVE_BINDINGS,
      ...request,
    },
    deps,
  );
  if (!result.bindings || typeof result.bindings !== 'object' || Array.isArray(result.bindings)) {
    throw invalidMetadata('Agent credential metadata broker returned invalid bindings');
  }
  try {
    return Object.fromEntries(
      AGENT_CREDENTIAL_PROVIDERS.map((provider) => [
        provider,
        result.bindings[provider] ? normalizeCredentialBinding(result.bindings[provider]) : null,
      ]),
    );
  } catch {
    throw invalidMetadata('Agent credential metadata broker returned invalid bindings');
  }
};

export { invokeMetadataBroker };

export default {
  invokeMetadataBroker,
  readCredentialScopeStatusViaBroker,
  resolveEffectiveCredentialBindingsViaBroker,
};
