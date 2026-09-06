import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import {
  DeleteParameterCommand,
  SSMClient,
  GetParametersCommand,
  PutParameterCommand,
} from '@aws-sdk/client-ssm';
import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';

const ssmMock = mockClient(SSMClient);
const lambdaMock = mockClient(LambdaClient);
let credentialMetadataHandler;
let handler;

const event = (method, body, groups = null) => ({
  httpMethod: method,
  path: '/agents/settings',
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  requestContext: {
    authorizer: {
      claims: {
        sub: 'user-1',
        ...(groups ? { 'cognito:groups': groups } : {}),
      },
    },
  },
});

beforeAll(async () => {
  process.env.AGENT_SETTINGS_SSM_PREFIX = '/collab/dev';
  process.env.AGENT_CREDENTIAL_METADATA_FUNCTION = 'credential-metadata-test';
  ({ handler } = await import('../index.js'));
});

beforeEach(() => {
  ssmMock.reset();
  lambdaMock.reset();
  credentialMetadataHandler = () => ({
    ok: true,
    status: { bedrockBearerTokenSet: false, kiroApiKeySet: false },
  });
  lambdaMock.on(InvokeCommand).callsFake((input) => {
    const request = JSON.parse(Buffer.from(input.Payload).toString());
    return {
      Payload: Buffer.from(JSON.stringify(credentialMetadataHandler(request))),
    };
  });
});

describe('platform PR strategy settings', () => {
  it('reads pr-per-unit and fails safely to intent-pr for an unknown value', async () => {
    ssmMock.on(GetParametersCommand).resolves({
      Parameters: [{ Name: '/collab/dev/pr-strategy', Value: 'pr-per-unit' }],
    });
    const configured = await handler(event('GET'));
    expect(configured.statusCode).toBe(200);
    expect(JSON.parse(configured.body).prStrategy).toBe('pr-per-unit');
    expect(
      ssmMock
        .commandCalls(GetParametersCommand)
        .flatMap((call) => call.args[0].input.Names ?? [])
        .filter((name) => name.endsWith('/bedrock-bearer-token') || name.endsWith('/kiro-api-key')),
    ).toEqual([]);

    ssmMock.on(GetParametersCommand).resolves({
      Parameters: [{ Name: '/collab/dev/pr-strategy', Value: 'stacked' }],
    });
    const fallback = await handler(event('GET'));
    expect(JSON.parse(fallback.body).prStrategy).toBe('intent-pr');
  });

  it('allows only platform admins to update the strategy', async () => {
    const denied = await handler(event('PUT', { prStrategy: 'pr-per-unit' }));
    expect(denied.statusCode).toBe(403);
    expect(ssmMock.commandCalls(PutParameterCommand)).toHaveLength(0);

    ssmMock.on(PutParameterCommand).resolves({});
    const allowed = await handler(event('PUT', { prStrategy: 'pr-per-unit' }, 'platform-admin'));
    expect(allowed.statusCode).toBe(200);
    expect(ssmMock.commandCalls(PutParameterCommand)[0].args[0].input).toMatchObject({
      Name: '/collab/dev/pr-strategy',
      Value: 'pr-per-unit',
      Type: 'String',
      Overwrite: true,
    });
  });

  it('rejects removed and unknown strategies without writing SSM', async () => {
    const response = await handler(event('PUT', { prStrategy: 'stacked' }, 'platform-admin'));
    expect(response.statusCode).toBe(400);
    expect(ssmMock.commandCalls(PutParameterCommand)).toHaveLength(0);
  });
});

describe('personal agent credentials', () => {
  const personalEvent = (method, body) => ({
    ...event(method, body),
    path: '/users/me/agent-credentials',
  });

  it('returns set-state only for the authenticated user', async () => {
    credentialMetadataHandler = (request) => ({
      ok: true,
      status: {
        bedrockBearerTokenSet: request.source === 'user',
        kiroApiKeySet: false,
      },
    });
    const response = await handler(personalEvent('GET'));
    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual({
      bedrockBearerTokenSet: true,
      kiroApiKeySet: false,
    });
    expect(ssmMock.commandCalls(GetParametersCommand)).toHaveLength(0);
  });

  it('writes and clears only the caller-scoped parameters', async () => {
    ssmMock.on(PutParameterCommand).resolves({});
    ssmMock.on(DeleteParameterCommand).resolves({});
    const response = await handler(
      personalEvent('PUT', {
        bedrockBearerToken: 'new-token',
        kiroApiKey: '',
      }),
    );
    expect(response.statusCode).toBe(200);
    expect(ssmMock.commandCalls(PutParameterCommand)[0].args[0].input).toMatchObject({
      Name: '/collab/dev/users/user-1/agent-credentials/bedrock-bearer-token',
      Value: 'new-token',
      Type: 'SecureString',
    });
    expect(ssmMock.commandCalls(DeleteParameterCommand)[0].args[0].input).toEqual({
      Name: '/collab/dev/users/user-1/agent-credentials/kiro-api-key',
    });
  });

  // specs/bedrock-iam-role-credential-mode — req-role-credential-mode,
  // dec-user-scope-role-deferred. This endpoint is gated only on authentication,
  // so any member could otherwise name a role ARN for the platform to assume.
  it('rejects a role binding at user scope without writing SSM', async () => {
    ssmMock.on(PutParameterCommand).resolves({});
    const response = await handler(
      personalEvent('PUT', {
        bedrockBearerToken: JSON.stringify({
          roleArn: 'arn:aws:iam::111122223333:role/aidlc-bedrock-inference',
        }),
      }),
    );
    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.code).toBe('BEDROCK_ROLE_SCOPE_UNSUPPORTED');
    expect(body.error).toContain('user scope');
    expect(ssmMock.commandCalls(PutParameterCommand)).toHaveLength(0);
  });

  it('still accepts a bearer token at user scope', async () => {
    ssmMock.on(PutParameterCommand).resolves({});
    const response = await handler(
      personalEvent('PUT', { bedrockBearerToken: 'ABSKQmVkcm9jaw==' }),
    );
    expect(response.statusCode).toBe(200);
    expect(ssmMock.commandCalls(PutParameterCommand)[0].args[0].input.Value).toBe(
      'ABSKQmVkcm9jaw==',
    );
  });
});

// specs/bedrock-iam-role-credential-mode — req-single-parameter-encoding.
// Validation lives on the write path so a malformed value can never reach a stage.
describe('platform bedrock role binding', () => {
  const ROLE_VALUE = JSON.stringify({
    roleArn: 'arn:aws:iam::111122223333:role/aidlc-bedrock-inference',
  });

  it('stores a valid role binding in the existing bedrock parameter', async () => {
    ssmMock.on(PutParameterCommand).resolves({});
    const response = await handler(
      event('PUT', { bedrockBearerToken: ROLE_VALUE }, 'platform-admin'),
    );
    expect(response.statusCode).toBe(200);
    // No new SSM path and no new IAM pattern: the same parameter, a different value.
    expect(ssmMock.commandCalls(PutParameterCommand)[0].args[0].input).toMatchObject({
      Name: '/collab/dev/bedrock-bearer-token',
      Value: ROLE_VALUE,
      Type: 'SecureString',
      Overwrite: true,
    });
  });

  it.each([
    ['a non-IAM ARN', JSON.stringify({ roleArn: 'arn:aws:sts::111122223333:role/x' })],
    ['a short account id', JSON.stringify({ roleArn: 'arn:aws:iam::123:role/x' })],
    ['unparseable JSON', '{ "roleArn": '],
    [
      'an external id outside the STS charset',
      JSON.stringify({
        roleArn: 'arn:aws:iam::111122223333:role/aidlc-bedrock-inference',
        externalId: 'has space',
      }),
    ],
  ])('rejects %s with a 400 and writes nothing', async (_label, value) => {
    ssmMock.on(PutParameterCommand).resolves({});
    const response = await handler(event('PUT', { bedrockBearerToken: value }, 'platform-admin'));
    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body).code).toBe('BEDROCK_ROLE_BINDING_INVALID');
    expect(ssmMock.commandCalls(PutParameterCommand)).toHaveLength(0);
  });

  it('leaves the bearer path unchanged, including the placeholder clear', async () => {
    ssmMock.on(PutParameterCommand).resolves({});
    await handler(event('PUT', { bedrockBearerToken: 'ABSKQmVkcm9jaw==' }, 'platform-admin'));
    await handler(event('PUT', { bedrockBearerToken: '' }, 'platform-admin'));
    expect(
      ssmMock.commandCalls(PutParameterCommand).map((call) => call.args[0].input.Value),
    ).toEqual(['ABSKQmVkcm9jaw==', 'placeholder']);
  });
});
