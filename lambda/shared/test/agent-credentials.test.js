import { beforeEach, describe, expect, it } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import {
  DeleteParameterCommand,
  GetParameterCommand,
  GetParametersCommand,
  PutParameterCommand,
  SSMClient,
} from '@aws-sdk/client-ssm';
import {
  AGENT_CREDENTIAL_ENV_NAMES,
  AWS_TEMPORARY_CREDENTIAL_ENV_NAMES,
  agentCredentialPath,
  availableClisForBindings,
  credentialSourcesFromBindings,
  credentialValueKind,
  credentialValueKindSafe,
  deleteCredentialScope,
  isConfiguredCredentialValue,
  looksLikeRoleBindingValue,
  parseRoleBindingValue,
  readCredentialBindingValue,
  readCredentialScopeStatus,
  resolveEffectiveCredentialBindings,
  validateCredentialScopeUpdate,
  writeCredentialScope,
} from '../agent-credentials.js';

// specs/bedrock-iam-role-credential-mode — req-single-parameter-encoding,
// req-credential-delivery-env. The bedrock parameter holds either a plain bearer
// string or a JSON role object; discrimination is positional and a malformed
// role-shaped value is an error, never silently a bearer token.
describe('bedrock binding value discrimination', () => {
  const ROLE_ARN = 'arn:aws:iam::111122223333:role/aidlc-bedrock-inference';

  it('scrubs the three AWS temporary-credential names alongside every provider name', () => {
    expect(AWS_TEMPORARY_CREDENTIAL_ENV_NAMES).toEqual([
      'AWS_ACCESS_KEY_ID',
      'AWS_SECRET_ACCESS_KEY',
      'AWS_SESSION_TOKEN',
    ]);
    expect(AGENT_CREDENTIAL_ENV_NAMES).toEqual([
      'AWS_BEARER_TOKEN_BEDROCK',
      'KIRO_API_KEY',
      'AWS_ACCESS_KEY_ID',
      'AWS_SECRET_ACCESS_KEY',
      'AWS_SESSION_TOKEN',
    ]);
  });

  it('parses a role object with and without an external id', () => {
    expect(parseRoleBindingValue(JSON.stringify({ roleArn: ROLE_ARN }))).toEqual({
      roleArn: ROLE_ARN,
      externalId: null,
    });
    expect(
      parseRoleBindingValue(`  ${JSON.stringify({ roleArn: ROLE_ARN, externalId: 'abc-123' })}  `),
    ).toEqual({ roleArn: ROLE_ARN, externalId: 'abc-123' });
    expect(credentialValueKind(JSON.stringify({ roleArn: ROLE_ARN }))).toBe('role');
  });

  it('accepts every aws partition in the role ARN and enforces the 2048 ceiling', () => {
    for (const arn of [
      'arn:aws-cn:iam::111122223333:role/aidlc-bedrock-inference',
      'arn:aws-us-gov:iam::111122223333:role/path/to/aidlc-bedrock-inference',
    ]) {
      expect(parseRoleBindingValue(JSON.stringify({ roleArn: arn })).roleArn).toBe(arn);
    }
    const tooLong = `arn:aws:iam::111122223333:role/${'a'.repeat(2048)}`;
    expect(() => parseRoleBindingValue(JSON.stringify({ roleArn: tooLong }))).toThrow(
      /at most 2048 characters/,
    );
  });

  it.each([
    ['not JSON at all', '{ nope'],
    ['an empty object', '{}'],
    ['a null roleArn', '{"roleArn":null}'],
    ['an object with no roleArn', JSON.stringify({ externalId: 'abc-123' })],
    ['a non-IAM ARN', JSON.stringify({ roleArn: 'arn:aws:sts::111122223333:role/x' })],
    ['a malformed account id', JSON.stringify({ roleArn: 'arn:aws:iam::123:role/x' })],
    ['an ARN with no role name', JSON.stringify({ roleArn: 'arn:aws:iam::111122223333:role/' })],
    ['a one-character external id', JSON.stringify({ roleArn: ROLE_ARN, externalId: 'a' })],
    [
      'an external id outside the STS charset',
      JSON.stringify({ roleArn: ROLE_ARN, externalId: 'has space' }),
    ],
    [
      'an over-long external id',
      JSON.stringify({ roleArn: ROLE_ARN, externalId: 'a'.repeat(1225) }),
    ],
    ['a non-string external id', JSON.stringify({ roleArn: ROLE_ARN, externalId: 42 })],
  ])('rejects %s with a typed error that never echoes the value', (_label, value) => {
    let thrown;
    try {
      credentialValueKind(value);
    } catch (error) {
      thrown = error;
    }
    expect(thrown?.code).toBe('BEDROCK_ROLE_BINDING_INVALID');
    expect(thrown.message).not.toContain(value);
  });

  it('treats any other non-empty value as a bearer token and never parses it', () => {
    // A JSON-looking value that does NOT start with a brace stays a bearer token.
    for (const value of ['ABSKQmVkcm9jaw==', 'arn:aws:iam::111122223333:role/x', '[1,2]', 'null']) {
      expect(looksLikeRoleBindingValue(value)).toBe(false);
      expect(credentialValueKind(value)).toBe('bearer');
    }
  });

  it('leaves isConfiguredCredentialValue semantics unchanged', () => {
    expect(isConfiguredCredentialValue('placeholder')).toBe(false);
    expect(isConfiguredCredentialValue('   ')).toBe(false);
    expect(isConfiguredCredentialValue('')).toBe(false);
    expect(isConfiguredCredentialValue(JSON.stringify({ roleArn: ROLE_ARN }))).toBe(true);
    expect(credentialValueKind('placeholder')).toBeNull();
    expect(credentialValueKind('')).toBeNull();
  });

  it('never reports a malformed role-shaped value as a usable bearer token on a read path', () => {
    expect(credentialValueKindSafe('{ nope')).toBe('role');
    expect(credentialValueKindSafe('placeholder')).toBeNull();
    expect(credentialValueKindSafe('token')).toBe('bearer');
  });
});

// specs/bedrock-iam-role-credential-mode — req-single-parameter-encoding,
// req-role-credential-mode, req-configured-semantics.
describe('credential scope write validation', () => {
  const ROLE_ARN = 'arn:aws:iam::111122223333:role/aidlc-bedrock-inference';
  const roleValue = JSON.stringify({ roleArn: ROLE_ARN });

  it.each(['platform', 'space'])('accepts a valid role binding at %s scope', (source) => {
    expect(
      validateCredentialScopeUpdate({ source, update: { bedrockBearerToken: roleValue } }),
    ).toBeNull();
  });

  it('rejects a role binding at user scope, naming the unsupported scope', () => {
    const invalid = validateCredentialScopeUpdate({
      source: 'user',
      update: { bedrockBearerToken: roleValue },
    });
    expect(invalid).toMatchObject({ code: 'BEDROCK_ROLE_SCOPE_UNSUPPORTED' });
    expect(invalid.error).toContain('user scope');
    expect(invalid.issues[0]).toContain('space and platform scope only');
  });

  it('rejects a malformed role binding with a typed code and no value echo', () => {
    const invalid = validateCredentialScopeUpdate({
      source: 'platform',
      update: { bedrockBearerToken: '{"roleArn":"nope"}' },
    });
    expect(invalid).toMatchObject({ code: 'BEDROCK_ROLE_BINDING_INVALID' });
    expect(JSON.stringify(invalid)).not.toContain('nope');
  });

  it.each([
    ['a bearer token at user scope', 'user', 'ABSKQmVkcm9jaw=='],
    ['a bearer token at platform scope', 'platform', 'ABSKQmVkcm9jaw=='],
    ['an empty clear at user scope', 'user', ''],
    ['a bearer-shaped ARN string', 'user', ROLE_ARN],
  ])('leaves %s untouched', (_label, source, bedrockBearerToken) => {
    expect(validateCredentialScopeUpdate({ source, update: { bedrockBearerToken } })).toBeNull();
  });

  it('ignores an update that does not touch the bedrock field', () => {
    expect(
      validateCredentialScopeUpdate({ source: 'user', update: { kiroApiKey: 'k' } }),
    ).toBeNull();
    expect(validateCredentialScopeUpdate({ source: 'user' })).toBeNull();
  });
});

describe('agent credentials', () => {
  const ssm = mockClient(SSMClient);
  const values = new Map();

  beforeEach(() => {
    ssm.reset();
    values.clear();
    ssm.on(GetParametersCommand).callsFake((input) => ({
      Parameters: input.Names.filter((name) => values.has(name)).map((name) => ({
        Name: name,
        Value: values.get(name),
      })),
    }));
    ssm.on(GetParameterCommand).callsFake((input) => {
      if (values.has(input.Name)) {
        return { Parameter: { Name: input.Name, Value: values.get(input.Name) } };
      }
      const error = new Error('missing');
      error.name = 'ParameterNotFound';
      throw error;
    });
    ssm.on(PutParameterCommand).callsFake((input) => {
      values.set(input.Name, input.Value);
      return {};
    });
    ssm.on(DeleteParameterCommand).callsFake((input) => {
      if (!values.has(input.Name)) {
        const error = new Error('missing');
        error.name = 'ParameterNotFound';
        throw error;
      }
      values.delete(input.Name);
      return {};
    });
  });

  it('builds platform, space, and user paths', () => {
    expect(agentCredentialPath({ base: '/app/dev', source: 'platform', provider: 'bedrock' })).toBe(
      '/app/dev/bedrock-bearer-token',
    );
    expect(
      agentCredentialPath({
        base: '/app/dev',
        source: 'space',
        provider: 'kiro',
        projectId: 'p-1',
      }),
    ).toBe('/app/dev/projects/p-1/agent-credentials/kiro-api-key');
    expect(
      agentCredentialPath({
        base: '/app/dev',
        source: 'user',
        provider: 'bedrock',
        userId: 'u-1',
      }),
    ).toBe('/app/dev/users/u-1/agent-credentials/bedrock-bearer-token');
  });

  it('resolves each provider independently with user over space over platform', async () => {
    values.set('/app/dev/bedrock-bearer-token', 'platform-bedrock');
    values.set('/app/dev/kiro-api-key', 'platform-kiro');
    values.set('/app/dev/projects/p-1/agent-credentials/bedrock-bearer-token', 'space-bedrock');
    values.set('/app/dev/users/u-1/agent-credentials/kiro-api-key', 'user-kiro');

    const bindings = await resolveEffectiveCredentialBindings(ssm, {
      base: '/app/dev',
      projectId: 'p-1',
      userId: 'u-1',
    });

    expect(bindings).toEqual({
      bedrock: { provider: 'bedrock', source: 'space' },
      kiro: { provider: 'kiro', source: 'user', userId: 'u-1' },
    });
    expect(credentialSourcesFromBindings(bindings)).toEqual({
      bedrock: 'space',
      kiro: 'user',
    });
    expect(
      availableClisForBindings({
        installed: ['kiro', 'claude', 'opencode', 'codex'],
        bindings,
      }),
    ).toEqual(['kiro', 'claude', 'opencode', 'codex']);
    const reads = ssm.commandCalls(GetParametersCommand).map((call) => call.args[0].input.Names);
    expect(reads).toEqual([
      [
        '/app/dev/users/u-1/agent-credentials/bedrock-bearer-token',
        '/app/dev/users/u-1/agent-credentials/kiro-api-key',
      ],
      ['/app/dev/projects/p-1/agent-credentials/bedrock-bearer-token'],
    ]);
  });

  it('treats placeholder and missing parameters as unset', async () => {
    values.set('/app/dev/bedrock-bearer-token', 'placeholder');
    const status = await readCredentialScopeStatus(ssm, {
      base: '/app/dev',
      source: 'platform',
    });
    expect(status).toEqual({
      bedrockBearerTokenSet: false,
      kiroApiKeySet: false,
    });
  });

  // specs/bedrock-iam-role-credential-mode — req-configured-semantics. The legacy
  // boolean means "a BEARER token is set" and must keep that exact meaning, so a
  // role binding reads false. isConfiguredCredentialValue alone would report true,
  // telling both credential cards a secret exists when none does.
  it('reports bedrockBearerTokenSet false for a role binding while kiro is unaffected', async () => {
    values.set(
      '/app/dev/bedrock-bearer-token',
      JSON.stringify({ roleArn: 'arn:aws:iam::111122223333:role/aidlc-bedrock-inference' }),
    );
    values.set('/app/dev/kiro-api-key', 'kiro-value');

    expect(await readCredentialScopeStatus(ssm, { base: '/app/dev', source: 'platform' })).toEqual({
      bedrockBearerTokenSet: false,
      kiroApiKeySet: true,
    });
  });

  it('still resolves a role binding as a configured effective binding', async () => {
    // The binding EXISTS and is usable even though no bearer secret is set — the
    // two questions are distinct, which is the whole point of the recomputation.
    values.set(
      '/app/dev/bedrock-bearer-token',
      JSON.stringify({ roleArn: 'arn:aws:iam::111122223333:role/aidlc-bedrock-inference' }),
    );

    const bindings = await resolveEffectiveCredentialBindings(ssm, {
      base: '/app/dev',
      projectId: 'p-1',
      userId: 'u-1',
    });

    expect(bindings.bedrock).toEqual({ provider: 'bedrock', source: 'platform' });
    expect(
      availableClisForBindings({ installed: ['claude', 'opencode', 'codex', 'kiro'], bindings }),
    ).toEqual(['claude', 'opencode', 'codex']);
  });

  it('writes, rotates, and clears user credentials without returning values', async () => {
    await writeCredentialScope(ssm, {
      base: '/app/dev',
      source: 'user',
      userId: 'u-1',
      update: { bedrockBearerToken: 'secret-value', kiroApiKey: 'kiro-value' },
    });
    expect(
      await readCredentialScopeStatus(ssm, {
        base: '/app/dev',
        source: 'user',
        userId: 'u-1',
      }),
    ).toEqual({ bedrockBearerTokenSet: true, kiroApiKeySet: true });

    await writeCredentialScope(ssm, {
      base: '/app/dev',
      source: 'user',
      userId: 'u-1',
      update: { bedrockBearerToken: '' },
    });
    expect(
      await readCredentialBindingValue(ssm, {
        base: '/app/dev',
        projectId: 'p-1',
        binding: { provider: 'bedrock', source: 'user', userId: 'u-1' },
      }),
    ).toBe('');
  });

  it('keeps the platform parameter and resets it to placeholder on clear', async () => {
    await writeCredentialScope(ssm, {
      base: '/app/dev',
      source: 'platform',
      update: { kiroApiKey: '' },
    });
    expect(values.get('/app/dev/kiro-api-key')).toBe('placeholder');
  });

  it('deletes a non-platform scope idempotently', async () => {
    const bedrockPath = '/app/dev/projects/p-1/agent-credentials/bedrock-bearer-token';
    const kiroPath = '/app/dev/projects/p-1/agent-credentials/kiro-api-key';
    values.set(bedrockPath, 'space-bedrock');
    values.set(kiroPath, 'space-kiro');

    await expect(
      deleteCredentialScope(ssm, {
        base: '/app/dev',
        source: 'space',
        projectId: 'p-1',
      }),
    ).resolves.toEqual({ deleted: ['bedrock', 'kiro'], missing: [] });
    expect(values.has(bedrockPath)).toBe(false);
    expect(values.has(kiroPath)).toBe(false);

    await expect(
      deleteCredentialScope(ssm, {
        base: '/app/dev',
        source: 'space',
        projectId: 'p-1',
      }),
    ).resolves.toEqual({ deleted: [], missing: ['bedrock', 'kiro'] });
  });
});
