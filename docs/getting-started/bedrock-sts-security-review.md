# Bedrock STS Integration — Security Review

This page is a **security-review deliverable** for the short-lived, role-based
Bedrock authentication path (AWS Well-Architected Security Pillar
[SEC02-BP02](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_unique.html),
_rely on a centralized identity provider_ → prefer temporary credentials over
long-lived secrets).

It is written so a security or compliance reviewer can sign off on the delivered
posture **from this document alone**, without reading source. Every factual claim
below was reconciled against the shipped implementation before publication; a
claim that could not be verified against code was withheld rather than guessed
(fail-closed accuracy). The code locations each claim is derived from are cited
inline so a reviewer who _wants_ to spot-check can, but is not required to.

!!! info "What this feature changes"

    Before this feature, the AgentCore runtime could invoke Amazon Bedrock only
    with a long-lived Bedrock API key (`AWS_BEARER_TOKEN_BEDROCK`) stored as an
    SSM `SecureString`; the execution role held no `bedrock:InvokeModel`
    permission. This feature adds an **opt-in, additive** short-lived role /
    STS path alongside that key. It does **not** replace the key path, and it
    changes nothing for end users invoking models.

The feature is delivered by four units of work. This document synthesizes the
settled, code-present facts from three of them — `unit-bedrock-iam-grant`,
`unit-credential-resolution-adapter`, and `unit-admin-auth-path-selection` — plus
the status of the conditional `unit-apikey-fallback`. It is _descriptive only_:
it is not a second source of truth, and where it quotes a value the source of
truth is the cited code.

## Is the Bedrock grant least-privilege?

**Yes.** The role path is authorized by a single, scoped, invoke-only IAM
statement appended additively to the **existing** AgentCore execution role.

- **Granted actions are exactly two:** `bedrock:InvokeModel` and
  `bedrock:InvokeModelWithResponseStream`. The streaming action is included
  because the agent CLIs stream token output. No other Bedrock action is
  granted.
- **`Resource` is an enumerated model set, never a model wildcard.** The grant is
  two statements. The first lists the exact _cross-region inference profiles_ the
  runtime may address — the deployment's own geography (`us.` / `eu.` / `apac.`,
  derived from the deploy Region) plus the `global.` profiles the model picker
  offers — account- and Region-scoped. The second lists the _underlying
  foundation models_ by exact id. There is **no `bedrock:*`** and **no
  `Resource = "*"`**.
- **The foundation-model ARNs wildcard only the Region segment, and only because
  IAM requires it.** A cross-region inference profile routes a request to any
  Region in its geography, and the invoke is authorized against the foundation
  model _in the destination Region_ — AWS states that a policy naming an
  inference profile "must also specify the foundation model in each Region
  associated with it". Pinning that segment to the deploy Region makes every
  invoke fail with `AccessDenied` on a destination-Region model ARN. The model id
  itself remains fully enumerated.
- **That second statement is fenced by a condition.** The foundation-model ARNs
  authorize an invoke only when `bedrock:InferenceProfileArn` matches one of the
  enumerated profiles, so they grant nothing on their own. A direct on-demand
  invoke of a bare foundation-model id carries no such key and is denied.
- **A model not on the list is denied, not silently allowed.** Because the
  resource set is enumerated, invoking an un-listed model fails closed with a
  diagnosable IAM `AccessDenied`. Widening the scope requires adding the model ARN
  and re-applying Terraform — it cannot happen implicitly.
- **Model ids are reconciled against live Bedrock.** An id that does not exist
  grants nothing, and its failure at invoke time is indistinguishable from a
  deliberate denial, so the catalogue is checked against
  `bedrock:ListInferenceProfiles` / `bedrock:ListFoundationModels` in the deploy
  Region rather than assumed.
- **The grant is additive.** The statements are appended to the execution role's
  existing inline policy; no pre-existing permission is modified, reordered, or
  removed.

_Verified against_ the Terraform grant delivered by `unit-bedrock-iam-grant` in
`terraform/modules/compute/agentcore/main.tf` (the appended
`bedrock:InvokeModel` / `bedrock:InvokeModelWithResponseStream` statement scoped
to the `local.bedrock_model_arns` enumerated list). See the
[[security-design-unit-bedrock-iam-grant]] and [[business-rules-unit-bedrock-iam-grant]]
for the full rule set.

## Are long-lived secrets eliminated on the role path?

**Yes, on the role path there is no stored Bedrock secret.** When the role path
is selected, the runtime simply **does not populate** `AWS_BEARER_TOKEN_BEDROCK`.
Each CLI then resolves **short-lived SigV4 credentials from the AgentCore task
execution role** via the standard AWS credential chain, and those credentials
auto-expire and auto-refresh — nothing long-lived is stored for the model-access
path.

The mechanism is **AWS-native IAM + STS only**: no third-party vault, no
credential broker, no distributed static secret. Because invocations on the role
path are SigV4-signed by the execution role, Bedrock invokes carry
per-principal CloudTrail attribution rather than being obscured behind a shared
bearer token.

The auth-path _selector_ itself is stored as a **non-secret** SSM `String`
parameter (`/{project}/{environment}/bedrock-auth-method`, domain
`{ api-key, role }`, default `api-key`, `lifecycle.ignore_changes = [value]`) —
it holds a mode name, never credential material.

_Verified against_ `lambda/agentcore/auth-resolver.js` (`resolveAgentAuth` skips
`AWS_BEARER_TOKEN_BEDROCK` when the method is `role`) and the non-secret `String`
SSM parameter in `terraform/modules/compute/agentcore/main.tf`. See
[[security-design-unit-credential-resolution-adapter]].

## What happens when both credentials are configured?

**The role path wins, and this is an informational (non-error) state.** When an
admin has selected the `role` path but a Bedrock API key is still stored:

- The resolver omits `AWS_BEARER_TOKEN_BEDROCK`, so the CLI uses the role's
  SigV4 credentials — the **role path takes precedence**.
- The stored key is **left in place, never deleted or rewritten**. Selecting the
  role path is non-destructive; precedence is enforced at _runtime resolution_,
  not by mutating stored state.
- The Admin UI surfaces this as an **informational note** that the role path is
  in effect and the stored key is unused, with an _optional_, admin-initiated
  "clear the unused key" action. It is never rendered as an error.

The selector read is **fail-safe**: only an explicit, trimmed, lower-cased
`role` selects the role path. An unset path, a missing parameter, an SSM error,
or any unrecognized value all resolve to `api-key`, so a misconfiguration
degrades _toward_ the known-good bearer path and never away from it.

_Verified against_ `resolveAuthMethod` / `resolveAgentAuth` in
`lambda/agentcore/auth-resolver.js` (explicit-`role`-wins, fail-safe default) and
the enum-validated, admin-only write path in `lambda/agents/index.js`. See
[[business-rules-unit-credential-resolution-adapter]] and
[[business-rules-unit-admin-auth-path-selection]].

## Can this break existing deployments?

**No — it is zero-regression and opt-in.** The auth-path selector **defaults to
`api-key`**, and on the `api-key` path Bedrock invocation is **byte-for-byte
identical** to the pre-feature bearer-token behavior: the resolver still fetches
and forwards `AWS_BEARER_TOKEN_BEDROCK`, and the model-invocation call path is
unchanged. The new scoped grant sits **unused** until an admin explicitly selects
the role path.

- Existing API-key deployments require **no action** and observe **no change**.
- The Terraform SSM parameter is created with `ignore_changes = [value]`, so an
  admin's runtime selection is **not reset** by subsequent `terraform apply`
  runs.
- Switching to the role path is reversible with a single settings write and does
  not destroy the stored key, so rollback is trivial and non-destructive.

_Verified against_ the `api-key` default in `terraform/modules/compute/agentcore/main.tf`
(SSM parameter `value = "api-key"`, `ignore_changes = [value]`) and the unchanged
bearer-forwarding path in `lambda/agentcore/auth-resolver.js` and
`lambda/agentcore/cli/drivers.js` (`envForAuth` forwards
`AWS_BEARER_TOKEN_BEDROCK` only when present). See
[[reliability-requirements-unit-admin-auth-path-selection]].

## Access control on the selection

Changing the auth-path selection is an **admin-only** operation: the settings
write handler is guarded by `requirePlatformAdmin` and returns `403` to
non-administrators before any field is processed. The value is enum-validated
against `{ api-key, role }` **before any SSM write**, and an invalid value
returns `400` with an allow-listed message and issues no AWS call. The settings
API never echoes secret values — secrets are represented as write-only "set"
boolean flags.

_Verified against_ the `requirePlatformAdmin` guard and the pre-write enum
validation in `lambda/agents/index.js`. See
[[security-requirements-unit-admin-auth-path-selection]].

## Conditional API-key fallback — status

The design allowed for a conditional, per-CLI, short-lived (~12h) Bedrock
API-key **fallback** (`unit-apikey-fallback`), to be built **only if** the
risk-first credential-resolution spike showed that a CLI could not resolve
role/SigV4 credentials from the standard AWS chain (decision
`dec-spike-first-fallback-deferred`).

**This fallback was not built.** No mint code ships in the runtime: there is no
`acquireShortLivedBedrockKey` seam and no ephemeral-token minting path in the
codebase. The role path relies purely on the execution role's temporary SigV4
credentials, so there is **no additional credential-minting surface** to review.
(The spike harness itself lives under
`lambda/agentcore/spike/credential-resolution/` and produces only a
secret-free verdict; it ships no production credential code.)

_Verified against_ the absence of any mint/fallback implementation in
`lambda/` and the deferral decision `dec-spike-first-fallback-deferred`.

## Reviewer sign-off summary

| Reviewer question (SEC02-BP02)                      | Answer                                                                                                                                                                                     |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Is the Bedrock grant least-privilege?               | **Yes** — invoke-only (`bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`) over an enumerated model-ARN list, no wildcard, appended additively to the existing execution role. |
| Are long-lived secrets eliminated on the role path? | **Yes** — the role path stores no Bedrock secret; short-lived SigV4 via the execution role, AWS-native IAM + STS only.                                                                     |
| Both credentials configured?                        | **Role wins**, informational (non-error); the stored key is left unused, never deleted.                                                                                                    |
| Can existing deployments break?                     | **No** — default `api-key`, byte-for-byte unchanged, opt-in, reversible.                                                                                                                   |
| Who can change the selection?                       | **Platform admins only** (`requirePlatformAdmin`), enum-validated before any write.                                                                                                        |
| Conditional API-key fallback shipped?               | **No** — deferred and not built; no minting surface.                                                                                                                                       |

This document contains no secret material. Credentials and environment variables
(for example `AWS_BEARER_TOKEN_BEDROCK`) are referenced by **name only**, never by
value, and the deliverable is covered by the repository's `secretlint` gate.
