// Credential-resolution spike — in-scope CLI matrix + shared constants.
//
// THROWAWAY HARNESS (unit-credential-resolution-spike). This module is disposable
// spike code, not a shipped runtime component (business-rules BR-1.2). It exists
// only to answer risk R-01: do Claude Code, OpenCode, and Codex resolve short-lived
// role/SigV4 credentials from the standard AWS chain when AWS_BEARER_TOKEN_BEDROCK
// is absent? See ./README.md.
//
// Kiro is deliberately EXCLUDED (domain-entities `TargetCli`, business-rules BR-4.3):
// Kiro authenticates via KIRO_API_KEY, not the Bedrock role/SigV4 path, so it has no
// place in this record.

// The one env var whose ABSENCE this whole spike hinges on. The role path is
// exercised by omitting it so each CLI must fall through to the standard AWS
// credential chain / SigV4 (business-rules BR-2.1, security-design SEC-01).
export const BEARER_ENV_VAR = 'AWS_BEARER_TOKEN_BEDROCK';

// The exact set of CLIs the spike probes — mirrors the production driver set
// (cli/drivers.js SUPPORTED_CLIS) minus Kiro. Frozen: the matrix is a constant.
export const IN_SCOPE_CLIS = Object.freeze(['claude', 'opencode', 'codex']);

// True when `cli` is one of the three Bedrock role-path CLIs this spike covers.
export const isInScopeCli = (cli) => IN_SCOPE_CLIS.includes(cli);

// Resolve the AWS region the same way the drivers' envForAuth does
// (BEDROCK_REGION → AWS_REGION → us-east-1). Kept here so the harness never
// hand-rolls region precedence that could drift from production.
export const resolveRegion = (env = {}) => env.BEDROCK_REGION || env.AWS_REGION || 'us-east-1';
