# Credential-Resolution Spike (`unit-credential-resolution-spike`)

> **⚠️ THROWAWAY / DISPOSABLE HARNESS.** This directory is spike code, not a shipped
> runtime component (`business-rules-credential-resolution-spike` BR-1.2). Its only
> durable output is a **verdict** — a decision, not code. Delete this directory once
> the verdict has gated the build.

## What this answers (risk R-01)

Story `story-cred-resolution-spike`, requirement `fr-sts-validation-spike`.

For each in-scope CLI — **Claude Code, OpenCode, Codex** (Kiro is out of scope: it uses
`KIRO_API_KEY`, not the Bedrock role path) — does the CLI resolve short-lived **role/SigV4**
credentials from the standard AWS credential chain and reach `bedrock:InvokeModel` **without**
`AWS_BEARER_TOKEN_BEDROCK` present?

The verdict resolves **OQ-02** and gates the build under `dec-spike-first-fallback-deferred`:
whether `unit-apikey-fallback` (`fr-sts-apikey-fallback`) is built at all, and for which CLI(s).

## How it works

For each CLI, serially (`performance-design` / `scalability-design`):

1. Strip `AWS_BEARER_TOKEN_BEDROCK` from a role-only base env.
2. Build the per-CLI auth env through the CLI's **own** `driver.envForAuth` — consuming, never
   modifying, `cli/drivers.js` (`security-design` SEC-05, BR-2.2).
3. Assert the no-bearer precondition on the constructed env. A bearer-present env is a **harness
   defect** — discarded and re-run, never recorded (SEC-01 / BR-2.3).
4. Run a minimal headless invocation via `captureChild` (`cli/spawn.js`) wrapped in a
   per-invocation timeout (default 120 s, `SPIKE_CLI_TIMEOUT_MS`; `performance-design` REQ-PERF-01).
5. Classify the outcome (`classify.js`, `business-logic-model` decision tree):
   - **2xx via SigV4** → `role-native` (fallback not required).
   - **AccessDenied/403 that reached Bedrock as a signed caller** → `role-native (blocked-on-grant)`.
     Credential resolution **succeeded**; the gap is an IAM-scope concern owned by
     `unit-bedrock-iam-grant`. **Never** a reason to widen scope (SEC-03 / BR-3.2).
   - **CLI demands the bearer / reports no credentials** → `fallback-required` (BR-3.3).
   - **Timeout / ambiguous / environmental** → _inconclusive_: re-run, never recorded (BR-3.4).

The aggregate `VerdictRecord` is **fail-closed**: the build gate is satisfied only when every
in-scope CLI has one decisive terminal verdict.

## Secret hygiene (SEC-04)

The verdict record is built from an **allow-list**: CLI name, verdict, bounded error class,
`reachedBedrockAsSigV4`, exit code, a derived summary. Raw stdout/stderr/env are **never**
stored. `secretlint` over this directory and its output is a hard release gate.

## Files

| File           | Purpose                                                                                |
| -------------- | -------------------------------------------------------------------------------------- |
| `cli-scope.js` | In-scope CLI matrix, `BEARER_ENV_VAR`, region resolution.                              |
| `classify.js`  | Pure decision-tree classifier + bounded, secret-free error categorization.             |
| `evidence.js`  | Secret-free, allow-listed evidence builder.                                            |
| `verdict.js`   | `buildEntry` (domain invariants) + fail-closed `aggregateVerdict`.                     |
| `probe-cli.js` | Per-CLI probe: strip bearer → `envForAuth` → precondition → `captureChild` → classify. |
| `run-spike.js` | Serial runner, secret-free serializer, operator `main()` entry point.                  |

## Running it

Unit tests (pure logic + probe/runner with the child mocked) run in CI:

```bash
npx vitest run --project=agentcore -t spike
```

A **decisive `role-native` PASS requires a live credentialed run** and cannot run in CI
(`cicd-pipeline`). An operator runs it inside AgentCore, under the AgentCore execution role,
after the scoped `bedrock:InvokeModel` grant (`unit-bedrock-iam-grant`) is in place:

```bash
node lambda/agentcore/spike/credential-resolution/run-spike.js
# exit 0 = build gate satisfied (all in-scope CLIs decisive); 1 = closed, re-run.
```

The command prints the secret-free verdict JSON to stdout.
