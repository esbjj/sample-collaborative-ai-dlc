# Bedrock role mode: operator runbook

Day-two operation of the [IAM-role credential mode](design.md). Setting a binding up is
[operator-trust-policies.md](operator-trust-policies.md); this is what to watch, what to
believe, and what each signal means once it is running.

Every command below is written against a deployment named `collaborative-ai-dlc` in
environment `dev`. Substitute your own project name and environment.

## Watch the credential-expiry counter

This is the single most important number in this document, because a design decision rests
on it. v1 ships **no credential refresh** (`dec-v1-no-refresh`), justified by measurement:
stage durations are p50 5 min, p90 10 min, p99 20 min against a credential that lives
3600 s. That 3600 s is a hard STS ceiling for role chaining, not a tuning knob — the broker
itself runs under an assumed role.

The measurement was taken over a 27-day sample and rested on a single outlier, so
`req-expiry-tripwire` requires the assumption be **watched rather than trusted**. A stage
that outlives its credential fails with the structured reason `credential_expired`, which is
persisted on the execution row and visible in the UI, so counting it needs no log query and
no new telemetry:

```bash
aws dynamodb scan \
  --table-name collaborative-ai-dlc-v2-executions-dev \
  --filter-expression "contains(failureReason, :reason)" \
  --expression-attribute-values '{":reason":{"S":"credential_expired"}}' \
  --select COUNT
```

Verified against a real deployment: it returns `"Count": 0` today, and the same command with
`git_commit_failed` returns `4`, so a zero is a genuine zero rather than a query that matches
nothing. Narrow it to a window by adding a condition on `updatedAt`, or scope it to one
project by scanning that project's partition instead of the table.

> **A non-zero count is the trigger to reopen `dec-v1-no-refresh`.** That is the whole point
> of the counter. Phase 4 of the implementation plan — a loopback container-credentials
> endpoint plus a bounded refresh grant — is entered **only** if this number stops being
> zero. Until then, building refresh would be speculation.

Two things to know before reacting to a count of one or two:

- **A retry re-runs the whole stage attempt**, so work done before the expiry is lost. The
  retry itself is automatic and resolves a fresh credential through the normal invocation
  path; once the retry budget is exhausted the stage ends `FAILED` carrying the same reason.
- **A long stage is not itself evidence of a fault.** `STAGE_CALLBACK_TIMEOUT` permits a
  single attempt to run for 8 hours, so a stage legitimately exceeding one hour is possible
  and is exactly the case `credential_expired` exists to report legibly.

### How the reason is decided, and which way it errs

Two independent signals, either of which files the failure as `credential_expired`:

1. **The credential's own deadline.** The broker returns an expiry with every minted
   credential, so a non-zero CLI exit that happens after that instant is attributed to expiry
   by arithmetic.
2. **The CLI's stderr**, matched against known expiry wordings (`ExpiredToken`, "the security
   token included in the request is expired", and similar).

The deadline check exists because the second signal depends on wording the platform does not
control: a CLI that reports expiry as a bare `403`, or phrases it differently after an
upgrade, would otherwise be filed as `credential_invalid` or `cli_nonzero_exit` — and the
counter would under-report the very thing it exists to measure.

**The counter therefore errs toward over-attribution.** A stage that failed for an unrelated
reason after its credential had expired is counted. That direction is deliberate: a false
positive costs a look at a decision that should be revisited on evidence anyway, while a false
negative leaves the no-refresh decision resting on an assumption nobody rechecked. When
investigating a non-zero count, check the stage's own stderr before concluding the credential
was the cause.

## Reading a resolution failure

The broker returns an allowlisted code and never provider text, because an STS or SSM message
can name the caller session, the target role or the parameter path. Every code below reaches
the stage as `credential_resolution_failed`; the code is what tells you what to do.

| Code                                 | Meaning                                             | Action                                                                              |
| ------------------------------------ | --------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `BEDROCK_ROLE_ASSUME_DENIED`         | The trust policy rejected this deployment           | Check the principal, the session-name condition and the external ID — see below     |
| `BEDROCK_ROLE_ASSUME_THROTTLED`      | STS throttled the `AssumeRole`                      | Transient; the stage retry clears it. Repeated occurrences mean STS request-rate    |
| `BEDROCK_ROLE_BINDING_INVALID`       | The stored value is not a valid role binding        | Re-save the binding; the write path validates it, so this implies a hand-edited SSM |
| `AGENT_CREDENTIAL_STORE_THROTTLED`   | SSM throttled the parameter read                    | Transient; the retry clears it                                                      |
| `AGENT_CREDENTIAL_STORE_UNAVAILABLE` | The parameter could not be read at all              | A permission or KMS fault, not a rate problem — check the broker role and the key   |
| `BEDROCK_ROLE_RESOLUTION_FAILED`     | Anything else, including a session name that failed | Rare; check the broker log for the code and the project id                          |

A **cleared** binding is not a failure: a deleted parameter reports the provider as _missing_,
and the stage fails closed with no credential rather than reporting a store outage.

### Timing and propagation

- **A binding change takes effect on the next resolution, not immediately.** Nothing is
  cached by the platform, but SSM itself is eventually consistent, so a save is _usually_
  visible within seconds and is not promised to be.
- **A role deleted or a trust policy narrowed mid-intent surfaces at the next stage**, not the
  current one. Credentials are minted per invocation, which is what makes a revocation visible
  at all.
- **An already-minted credential outlives a revoked binding by up to 3600 s.** This is an
  accepted risk: there is no in-flight revocation in v1. If you need a hard cut, delete or
  narrow the role's trust policy in the Bedrock account — that stops the next mint immediately
  and does not depend on the platform.

## Attributing Bedrock spend

Attribution is `RoleSessionName` only, composed server-side as `aidlc-<projectId>`. No cost
allocation tag is activated, no CUR export is created and no budget is created by this
platform — those are yours to set up, and this section is how to use them once you have.

**What is verified:** a chained `AssumeRole` followed by `InvokeModel` is attributed in
CloudTrail to the final chained session, with the session name carrying the identity. Probed
live in `eu-central-1`.

**What is assumed:** that _billing_ aggregates by the same identity CloudTrail reports. It is
the natural reading of the caller-identity dimension, but it is inference rather than
something this project measured, so verify it against your own bill before relying on
showback numbers.

With CUR 2.0 enabled and queryable (Athena or Redshift), Bedrock line items carry the
invoking identity, so spend per space is a group-by on the session name:

```sql
SELECT
  regexp_extract(line_item_resource_id, 'aidlc-[0-9a-f-]{36}') AS space,
  SUM(line_item_unblended_cost)                                AS cost
FROM   cur2
WHERE  line_item_product_code = 'AmazonBedrock'
  AND  billing_period = '2026-09'
GROUP BY 1
ORDER BY cost DESC
```

The exact column carrying the identity differs between CUR schema versions and between the
Bedrock line-item types (on-demand invocation versus provisioned throughput), so treat the
`regexp_extract` above as the shape of the query rather than a drop-in. Find the identity
column in your own export first, then group by it.

Two limits worth stating plainly:

- **Concurrent stages in one space are indistinguishable.** The session name identifies the
  _space_, not the stage, deliberately (`req-session-name-attribution`). You cannot attribute
  spend to a stage, only to a space.
- **The session name is identical for a space-scope and a platform-scope binding**, because it
  identifies the space either way. So CloudTrail cannot tell you _which scope's_ binding was
  used for an invocation. If you need that distinction, bind different roles.

### Model invocation logging is not enabled

The platform does not enable Bedrock model invocation logging, and this is deliberate
(`con-invocation-logging-off`). It is an account-wide setting that captures every user's
prompts and completions, so turning it on is an operator decision with a data-handling
consequence, not a platform default.

The practical effect: **you cannot see which model ids a CLI actually reached** without it.
Claude Code fans out to several models within one stage, so a grant scoped to a single model
id would fail in ways the platform cannot show you — which is why the grant is written as
provider-family patterns (`req-model-grant-families`) rather than an enumerated list. If you
need direct model-level evidence, enable invocation logging knowingly and for a bounded
window.

## The bearer token is deprecated

An Amazon Bedrock API key remains fully supported and existing deployments are untouched. It
is nonetheless **deprecated in favour of role mode**, for one reason: it is a long-lived
secret that must be stored, rotated and protected, where an IAM role needs no stored secret at
all and mints short-lived credentials per invocation.

Both cards label it as such. There is no removal date and no forced migration; a scope holding
a bearer token keeps working exactly as before. To migrate, save a role binding in the same
scope — one parameter holds the Bedrock value, so saving the role **replaces** the token, and
both cards warn about that before you do it.

The distinction lives entirely inside the stored value, never in the provider name, so a future
non-AWS provider (LiteLLM, with an API key and base URL) arrives as a new provider beside
`kiro` rather than as a third Bedrock mode.

## Codex on Bedrock is not verified end to end

Codex's **credential path works** — role-mode credentials are delivered to it exactly as to
Claude Code and OpenCode, and its grant includes the `bedrock-mantle:CreateInference` statement
it needs, so nothing here blocks it once the defects below are fixed. But **no acceptance
criterion in this spec depends on a successful Codex invocation**, and you should not expect a
Codex stage to complete today.

Two separate, reproduced defects:

1. **Codex calls the wrong endpoint.** Codex 0.145.0 with `model_provider = amazon-bedrock`
   targets `https://bedrock-mantle.<region>.api.aws/openai/v1/responses`. AWS documents the
   OpenAI-compatible endpoint as `https://bedrock-runtime.<region>.amazonaws.com/openai/v1`.
   The host it uses serves neither the bare model id nor a CRIS profile id, so a real stage
   fails with `404 The model '<id>' does not exist` for both. Reproduced twice on live stages,
   with the stage reason `cli_nonzero_exit` and never a `credential_*` reason — so this is
   Codex's endpoint, not authorization.
2. **GPT-5.6 on Bedrock is reachable only through a cross-Region inference profile.** The bare
   `openai.gpt-5.6-sol` form does not resolve; `global.openai.gpt-5.6-sol` is the servable
   form. The platform's model validator accepts the CRIS forms, so configuration is not the
   blocker.

A third item is a design question rather than a defect: the OpenAI-compatible path
authenticates with a Bedrock API key, and role mode deliberately sets no bearer token. AWS
publishes `aws-bedrock-token-generator`, which derives a short-term key from AWS credentials,
and that is the likely bridge — but it means role mode would need to mint a derived key for
Codex specifically. Until Codex reaches the documented endpoint, that work would be premature.
