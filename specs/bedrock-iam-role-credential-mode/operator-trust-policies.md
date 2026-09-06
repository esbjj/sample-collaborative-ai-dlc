# Bedrock role trust policies

Operator reference for the Bedrock IAM-role credential mode. The design and its rationale live in [design.md](design.md) beside this file and in [ADR-0001](../../adr/0001-bedrock-iam-role-credential-mode.md).

This file sits with its spec rather than under `docs/`: `zensical.toml` declares an explicit nav, so a file under `docs/` is either published to the public site or orphaned (`dec-spec-location`).

## What you are configuring

Instead of storing a long-lived Bedrock API key, the platform stores a **role ARN**. The credential broker assumes that role for each agent invocation and hands the resulting one-hour credentials to the CLI. You create the role; the platform never does, and cannot — the role may live in a different AWS account, and its trust policy is your authoritative control over who may assume it.

Two documents are needed on the role:

| Document                                     | Where it comes from                                    |
| -------------------------------------------- | ------------------------------------------------------ |
| Permission policy (what the role may invoke) | `terraform output -raw bedrock_role_grant_policy_json` |
| Trust policy (who may assume the role)       | The templates below                                    |

The one value both need is the broker's role ARN:

```bash
terraform -chdir=terraform output -raw credential_broker_role_arn
# arn:aws:iam::<platform-account>:role/collaborative-ai-dlc-credential-broker-dev
```

That is the **only** principal a trust policy has to name. The AgentCore execution role deliberately holds no Bedrock, `bedrock-mantle` or `sts` permission, and a test asserts it stays that way.

## Bootstrap order

Follow this order. Saving the binding before the trust policy exists produces an `AssumeRole` failure, which the bind-time preflight reports at save time instead of mid-stage.

1. Read the broker role ARN and the permission policy from the Terraform outputs above. The Admin → Agents and space Agent cards also show the principal to trust, so you can copy it from the UI.
2. Create the role in the Bedrock-owning account with that permission policy and one of the trust policies below.
3. **Same account as the deployment:** save the binding. That is the whole flow — no external ID exists or is needed.
4. **A different account:** save the binding once. The save is **rejected** because the trust policy cannot yet name an external ID nobody has seen, and the rejection **returns the external ID** the platform generated for this binding. Add it to the trust policy as an `sts:ExternalId` condition, then save again.
5. Confirm a stage runs. CloudTrail in the Bedrock account shows `aidlc-<projectId>` in `userIdentity.arn` within a few minutes.

The external ID is **stable across those retries**: it is generated once into its own per-scope parameter and copied into the binding when a save succeeds. So the trust policy you wrote against the first, rejected attempt stays valid, and you can read the value back at any time from the card or the settings response rather than rotating to rediscover it.

The binding value is stored in the existing `bedrock` SSM parameter, with the external ID attached **by the server** — never send one, and a client-supplied `externalId` is rejected outright. AWS requires the assuming party to control the value:

```json
{ "roleArn": "arn:aws:iam::111122223333:role/aidlc-bedrock-inference" }
```

Role bindings are accepted at **space and platform scope only**. A role object written to a user-scope binding is rejected at write time: that endpoint is gated only on authentication, so any member could otherwise name a role ARN for the platform to assume.

## Recommended: one role scoped to one space

This is the recommended template because the `sts:RoleSessionName` condition is the **only** control that makes a shared Bedrock role space-aware, and it needs no platform code.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<platform-account>:role/collaborative-ai-dlc-credential-broker-<env>"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:RoleSessionName": "aidlc-<projectId>"
        }
      }
    }
  ]
}
```

Substitute the broker role ARN from the Terraform output, and `<projectId>` with the space's id (visible in the space URL).

### One role shared by a documented set of spaces

`StringLike` accepts a pattern, which is the better form when several spaces share one role and enumerating them in `StringEquals` would be unwieldy. `StringEquals` also accepts an array, which is preferable when the set is small and closed.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<platform-account>:role/collaborative-ai-dlc-credential-broker-<env>"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:RoleSessionName": "aidlc-*"
        }
      }
    }
  ]
}
```

> **`aidlc-*` permits every space.** A pattern that broad is equivalent to omitting the condition. Narrow it to the ids you intend, or use an explicit `StringEquals` array.

### Cross-account: add the external ID

When the role lives in an account other than the platform account, an external ID is **required**, per AWS's [confused deputy](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html) guidance. The platform generates it (Phase 2) and will not accept one you supply — AWS requires the value to be controlled by the assuming party, "generated by Example Corp and **not** their customers", so that no two customers can share one.

It is **not a secret**. AWS is explicit: "AWS does not treat the external ID as a secret … The external ID for a role can be seen by anyone with permission to view the role." The protection comes from the platform controlling which value it sends, not from hiding it — and this role's trust policy names the broker as its only principal, so the ARN and external ID together are useless to anyone else. The platform therefore lets you re-read the value whenever you can edit the binding, so recovering a mislaid one is a plain read rather than a rotation. It is still tenant-identifying, so it never appears on the general settings read, in a log line, or in an error message.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<platform-account>:role/collaborative-ai-dlc-credential-broker-<env>"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:RoleSessionName": "aidlc-<projectId>",
          "sts:ExternalId": "<platform-generated-value>"
        }
      }
    }
  ]
}
```

Same-account bindings may omit `sts:ExternalId`: the trust policy already names exactly one principal, and the confused-deputy problem is a third-party one.

## The session-name format is a stability contract

`RoleSessionName` is `aidlc-<projectId>`, composed in exactly one place on the server (the credential broker) and never accepted from a container.

**Treat this format as stable.** Once a customer writes an `sts:RoleSessionName` condition, the format is load-bearing in their account: changing it would break every trust policy carrying the condition. Any change is therefore a **breaking change requiring a migration note**, not an internal refactor.

Two consequences worth recording:

- **Omitting the condition is permitted and sometimes necessary**, but it means _any space that knows the role ARN can use the role_. The platform cannot enforce that constraint from its side, and the ARN is not treated as a secret.
- **A future single-gateway migration would break these policies.** Collapsing to one platform-wide Bedrock role (for example behind a LiteLLM-style gateway) removes the per-space session name that these conditions match. That has to be planned for rather than discovered.

## Attribution and its limits

Attribution is `RoleSessionName` only — no session tags. Session tags would require `sts:TagSession` in your trust policy, so any role omitting it would fail closed.

- CloudTrail in the Bedrock account records `userIdentity.arn` as `…assumed-role/<role>/aidlc-<projectId>`, with `principalId` `AROA…:aidlc-<projectId>`.
- The session name identifies the **space, not the stage**. Two stages running concurrently in one space are indistinguishable in CloudTrail. This is accepted, not an oversight.
- Model invocation logging is not enabled by the platform. It is account-wide per region and captures every user's prompts and completions, so enabling it is an operator decision.

## Diagnosing an `AssumeRole` failure

The broker returns only an allowlisted code — never STS text, which can name the caller session and the target role.

**A role outside the assumable set is reported exactly**, because the platform decides that itself without calling STS. Everything else arrives as one category, `trust-policy-rejected`, and that is a property of STS rather than a shortcut: a wrong external ID, an omitted external ID, a session-name condition mismatch, an untrusted principal and a role that does not exist all return a **byte-identical `AccessDenied`**, differing only in the resource ARN. Measured against a throwaway role on 2026-09-06, including positive controls that succeeded once each condition was satisfied. Guessing a cause from message text would therefore be invention, so the preflight names every candidate instead and tells you the exact value to check each against.

Check them in this order:

| Likely cause                                    | What to check                                                                                                  |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Trust policy does not name the broker principal | Compare against `terraform output -raw credential_broker_role_arn` exactly, including the environment suffix   |
| Session-name condition names a different space  | The condition value must match the session name the preflight reports for the space actually running the stage |
| External ID missing or mismatched               | Required for cross-account; read the current value from the card and compare, do not rotate to find out        |
| Role ARN outside the assumable set              | `terraform output bedrock_assumable_role_arns` — the default requires the role be named `aidlc-bedrock-*`      |
| Role or policy recently changed                 | IAM is eventually consistent; a fresh change can take a short time to take effect                              |

Two properties of the preflight worth knowing before you rely on it:

- **It is an input check, not a security control.** A trust policy can change the instant after it passes, which is why resolution re-checks on every stage. A binding that passed the preflight is not thereby guaranteed to work.
- **It fails open when it cannot run.** If the broker is unreachable, the save proceeds rather than being refused, because a checker being down is a worse reason to block a legitimate binding than persisting one whose failure is already legible as `credential_resolution_failed`.

A **platform-scope** binding is probed with the session name `aidlc-preflight` rather than a space's name, because it serves every space. A trust policy carrying `StringEquals` for one space therefore fails its preflight — correctly, since such a role cannot serve as a platform binding. Use `StringLike`, or bind the role at space scope.

### The role naming convention

The broker's `sts:AssumeRole` permission is scoped by `bedrock_assumable_role_arns`, defaulting to:

```hcl
bedrock_assumable_role_arns = ["arn:aws:iam::*:role/aidlc-bedrock-*"]
```

This imposes a naming convention on whoever owns the Bedrock account. It is defence in depth, not the primary control — the trust policy is authoritative — but a wildcard default would leave the trust policy as the _only_ control.

If the role cannot be renamed, opt out explicitly:

```hcl
bedrock_assumable_role_arns = ["*"]
```

Setting it makes the looser posture a deliberate, visible choice. Narrowing `iam::*` to real account ids is recommended for a known topology.

## Rotating the external ID

Rotation is a coordinated two-party change with a failure window, so plan it rather than performing it ad hoc.

1. Generate a new external ID in the platform (re-saving the binding does this).
2. Update `sts:ExternalId` in the role's trust policy in the Bedrock account.
3. Save the binding.
4. Confirm with the preflight.

**Between steps 1 and 2 every `AssumeRole` for that binding fails.** Stages started in that window fail with `credential_resolution_failed` and consume retry budget. Rotate when no stage is running, or accept the retries.
Rotation is for when the value should genuinely change — a suspected leak into a place it should not be, or a policy requiring periodic change. It is **not** the way to recover a value you have mislaid: the platform will show you the current external ID again whenever you can edit the binding, so read it rather than rotating and paying the failure window above for nothing.

### Same-account bindings

No external ID is generated for a binding whose role lives in the platform account, and none is needed: the trust policy already names exactly one principal and the confused-deputy problem is a third-party one. If you later move that role to another account, save the binding again — that generates the external ID, which you then add to the trust policy.

### One role shared by several spaces

Each binding carries its own external ID, so if several spaces each bind the same role, the role's trust policy has to accept every one of their values. That grows with the number of spaces, and the `sts:RoleSessionName` condition already gives you per-space scoping. Prefer a single platform-scope binding for a shared role, and reserve space-scope bindings for spaces that genuinely need a different role. AWS's own recommendation is one external ID per AWS account, which is what a single platform-scope binding gives you.

## What happens when a credential expires

v1 ships **no refresh mechanism**, by measurement rather than omission: stage durations are p50 5 min, p90 10 min, p99 20 min against a credential that lives 3600 s. That 3600 s is a hard STS ceiling for role chaining, not a configurable value — the broker itself runs under an assumed role.

A stage that outlives its credential fails with reason `credential_expired`, and the existing stage retry resolves a fresh credential through the normal invocation path.

- **A retry re-runs the whole stage attempt**, so work done before the expiry is lost.
- Once the retry budget is exhausted the stage ends `FAILED` carrying the same reason.
- `credential_expired` is a persisted, UI-visible failure reason. **A non-zero count is the trigger to revisit the no-refresh decision** — that is the evidence the decision rests on, so it is worth watching rather than assuming.

One accepted risk to be aware of: a credential already minted stays valid for up to 3600 s after the binding is revoked or changed. There is no in-flight revocation in v1.
