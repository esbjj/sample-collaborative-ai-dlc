import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// specs/bedrock-iam-role-credential-mode — req-least-privilege-assume,
// req-model-grant-families, req-broker-side-assume.
//
// The broker is the ONE principal allowed to assume a customer's Bedrock role.
// These assertions pin the two things that are easy to loosen by accident: the
// resource scope of that permission, and which model families the grant covers.

const read = (relative) => readFileSync(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');

const brokerTerraform = read('../../../terraform/modules/api/lambda/main.tf');
const brokerVariables = read('../../../terraform/modules/api/lambda/variables.tf');
const grantTerraform = read('../../../terraform/bedrock-role-grant.tf');

const terraformBlock = (source, header) => {
  const start = source.indexOf(header);
  if (start < 0) throw new Error(`terraform block not found: ${header}`);
  let depth = 0;
  for (let i = source.indexOf('{', start); i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  throw new Error(`unbalanced terraform block: ${header}`);
};

describe('credential broker sts:AssumeRole scope', () => {
  const policy = terraformBlock(
    brokerTerraform,
    'resource "aws_iam_role_policy" "credential_broker"',
  );

  it('extracts a plausible policy block (guards the extractor itself)', () => {
    expect(policy.length).toBeGreaterThan(500);
    expect(policy).toContain('aws_iam_role.credential_broker.id');
  });

  it('grants sts:AssumeRole only on the configured role set, never a literal wildcard', () => {
    expect(policy).toContain('"sts:AssumeRole"');
    const assumeStatement = policy.slice(policy.indexOf('"sts:AssumeRole"'));
    const resourceLine = assumeStatement.match(/Resource\s*=\s*(.+)/)[1].trim();
    expect(resourceLine).toBe('var.bedrock_assumable_role_arns');
    // A hardcoded "*" here would make the target trust policy the only control.
    expect(resourceLine).not.toBe('"*"');
  });

  it('defaults the assumable set to the documented path-scoped pattern', () => {
    const variable = terraformBlock(brokerVariables, 'variable "bedrock_assumable_role_arns"');
    expect(variable).toContain('default     = ["arn:aws:iam::*:role/aidlc-bedrock-*"]');
    // The bare wildcard remains available, but only as an explicit, documented
    // opt-out an operator has to type (dec-assumable-role-default). The
    // description string escapes its quotes, hence the HCL-escaped form here.
    expect(variable).toContain('[\\"*\\"] to opt out');
    expect(variable).toContain('type        = list(string)');
  });

  it("grants sts:AssumeRole in exactly one permission policy, the broker's", () => {
    // The module's shared `lambda_assume_role_policy` also names sts:AssumeRole,
    // but that is a TRUST policy — it says who may assume the Lambda roles and
    // grants their holders nothing. Only permission policies are counted here.
    const permissionPolicies = [
      ...brokerTerraform.matchAll(/resource "aws_iam_role_policy" "([a-z0-9_]+)"/g),
    ].map((match) => ({
      name: match[1],
      body: terraformBlock(brokerTerraform, match[0]),
    }));
    expect(permissionPolicies.length).toBeGreaterThan(1);
    const granting = permissionPolicies
      .filter((entry) => entry.body.includes('"sts:AssumeRole"'))
      .map((entry) => entry.name);
    expect(granting).toEqual(['credential_broker']);
  });
});

describe('bedrock role grant families', () => {
  // Comments in this file legitimately DISCUSS the patterns that must be absent
  // (con-gpt-global-cris-only explains why there is no eu.openai pattern), so
  // absence must be asserted against the code, not the prose.
  const grantCode = grantTerraform
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('#'))
    .join('\n');

  it.each([
    'inference-profile/eu.anthropic.claude-*',
    'inference-profile/global.anthropic.claude-*',
    'inference-profile/global.openai.gpt-*',
  ])('grants the %s family pattern', (pattern) => {
    // Patterns, not enumerations: con-claude-model-fanout shows a run pinned to
    // one model also invokes others in the same family.
    expect(grantCode).toContain(pattern);
  });

  it('grants no eu.openai pattern, because no such inference profile exists', () => {
    // con-gpt-global-cris-only. Including one would imply a capability that is not
    // there; eu.openai.gpt-5.6-sol returns ValidationException.
    expect(grantCode).not.toContain('eu.openai');
    // Guard the comment-stripping itself: the prose DOES mention it, so a broken
    // filter would make the assertion above pass for the wrong reason.
    expect(grantTerraform).toContain('eu.openai');
  });

  it('region-wildcards foundation models and fences them to an inference profile', () => {
    expect(grantCode).toContain('bedrock:*::foundation-model/anthropic.claude-*');
    expect(grantCode).toContain('bedrock:*::foundation-model/openai.gpt-*');
    // con-fm-fence-works: without the condition a bare foundation-model id would
    // resolve to direct invocation and bypass the inference-profile requirement.
    expect(grantCode).toContain('"bedrock:InferenceProfileArn"');
    expect(grantCode).toContain('StringLike');
  });

  it('includes the Codex mantle statement scoped to project/*', () => {
    // con-codex-mantle: Codex needs bedrock-mantle:CreateInference, which
    // bedrock:InvokeModel does not authorize. Present so Codex works the moment
    // its own defects are fixed — no acceptance criterion depends on it
    // succeeding (req-codex-scope, con-codex-model-missing).
    expect(grantCode).toContain('"bedrock-mantle:CreateInference"');
    expect(grantCode).toContain('bedrock-mantle:*:${local.bedrock_role_account}:project/*');
  });

  it('scopes every account-bearing ARN to the role-owning account, not the platform account', () => {
    // req-model-grant-families: under a central-Bedrock-account topology the role
    // lives in a different account, so a hardcoded caller-identity reference in
    // these ARNs would silently grant nothing.
    const accountBearing = [...grantCode.matchAll(/arn:\$\{[^}]+\}:bedrock[^"]*/g)].map(
      (match) => match[0],
    );
    expect(accountBearing.length).toBeGreaterThan(0);
    for (const arn of accountBearing) {
      // Either account-less (foundation-model) or the role account — never the
      // deployment's own caller identity.
      expect(arn).not.toContain('data.aws_caller_identity');
    }
  });

  it('grants invoke actions only — no management, no logging, no credential creation', () => {
    // Only ACTION positions count. `bedrock:InferenceProfileArn` is a condition
    // key, not an action, so it is excluded by requiring the `Action = [...]`
    // context rather than matching any service-prefixed quoted string.
    const actionLists = [...grantCode.matchAll(/Action\s*=\s*\[([^\]]*)\]/g)].map(
      (match) => match[1],
    );
    const actions = new Set(
      actionLists.flatMap((list) =>
        [...list.matchAll(/"([a-z0-9-]+:[A-Za-z*]+)"/g)].map((m) => m[1]),
      ),
    );
    expect([...actions].toSorted()).toEqual([
      'bedrock-mantle:CreateInference',
      'bedrock:InvokeModel',
      'bedrock:InvokeModelWithResponseStream',
    ]);
    // req-credential-safety: no role in this design may create a long-lived credential.
    expect(grantCode).not.toContain('iam:CreateAccessKey');
    expect(grantCode).not.toContain('iam:CreateServiceSpecificCredential');
  });
});
