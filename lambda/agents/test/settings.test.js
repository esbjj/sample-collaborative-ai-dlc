import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import { SSMClient, GetParametersCommand, PutParameterCommand } from '@aws-sdk/client-ssm';

const ssmMock = mockClient(SSMClient);
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
  ({ handler } = await import('../index.js'));
});

beforeEach(() => {
  ssmMock.reset();
});

describe('platform PR strategy settings', () => {
  it('reads pr-per-unit and fails safely to intent-pr for an unknown value', async () => {
    ssmMock.on(GetParametersCommand).resolves({
      Parameters: [{ Name: '/collab/dev/pr-strategy', Value: 'pr-per-unit' }],
    });
    const configured = await handler(event('GET'));
    expect(configured.statusCode).toBe(200);
    expect(JSON.parse(configured.body).prStrategy).toBe('pr-per-unit');

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

describe('bedrock auth method settings', () => {
  it('reads role and fails safe to api-key for absent/unknown values', async () => {
    // Explicit 'role' is returned verbatim.
    ssmMock.on(GetParametersCommand).resolves({
      Parameters: [{ Name: '/collab/dev/bedrock-auth-method', Value: 'role' }],
    });
    const roleRes = await handler(event('GET'));
    expect(roleRes.statusCode).toBe(200);
    expect(JSON.parse(roleRes.body).bedrockAuthMethod).toBe('role');

    // Unknown value → fail-safe to api-key (BR-1.2).
    ssmMock.on(GetParametersCommand).resolves({
      Parameters: [{ Name: '/collab/dev/bedrock-auth-method', Value: 'sigv4' }],
    });
    const unknownRes = await handler(event('GET'));
    expect(JSON.parse(unknownRes.body).bedrockAuthMethod).toBe('api-key');

    // Absent parameter → api-key default (zero regression).
    ssmMock.on(GetParametersCommand).resolves({ Parameters: [] });
    const absentRes = await handler(event('GET'));
    expect(JSON.parse(absentRes.body).bedrockAuthMethod).toBe('api-key');
  });

  it('allows only platform admins to write the auth method as a non-secret String', async () => {
    const denied = await handler(event('PUT', { bedrockAuthMethod: 'role' }));
    expect(denied.statusCode).toBe(403);
    expect(ssmMock.commandCalls(PutParameterCommand)).toHaveLength(0);

    ssmMock.on(PutParameterCommand).resolves({});
    const allowed = await handler(event('PUT', { bedrockAuthMethod: 'role' }, 'platform-admin'));
    expect(allowed.statusCode).toBe(200);
    expect(ssmMock.commandCalls(PutParameterCommand)[0].args[0].input).toMatchObject({
      Name: '/collab/dev/bedrock-auth-method',
      Value: 'role',
      Type: 'String',
      Overwrite: true,
    });
  });

  it('rejects invalid auth-method values with 400 before any SSM write', async () => {
    const response = await handler(event('PUT', { bedrockAuthMethod: 'sigv4' }, 'platform-admin'));
    expect(response.statusCode).toBe(400);
    expect(ssmMock.commandCalls(PutParameterCommand)).toHaveLength(0);
  });

  it('does not touch the auth method when the field is omitted (partial update)', async () => {
    ssmMock.on(PutParameterCommand).resolves({});
    const response = await handler(event('PUT', { prStrategy: 'intent-pr' }, 'platform-admin'));
    expect(response.statusCode).toBe(200);
    const authWrites = ssmMock
      .commandCalls(PutParameterCommand)
      .filter((c) => c.args[0].input.Name === '/collab/dev/bedrock-auth-method');
    expect(authWrites).toHaveLength(0);
  });
});
