# =============================================================================
# Bedrock IAM-role credential mode — the customer-side role grant
#
# specs/bedrock-iam-role-credential-mode: req-model-grant-families,
# req-least-privilege-assume, req-same-and-cross-account.
#
# The role that the credential broker assumes is NOT created here. It belongs to
# whoever owns the Bedrock account, which under a central-Bedrock-account topology
# is a different account from this deployment. Terraform cannot create a role in
# an account it does not manage, and it must not: the trust policy is the
# customer's authoritative control over who may assume it.
#
# What this file does is render, from one place, the exact two documents an
# operator has to paste into that account — the permission policy below and the
# trust policy in specs/bedrock-iam-role-credential-mode/operator-trust-policies.md. Rendering them from
# Terraform expressions rather than a copyable code block in prose means the
# account id, region wildcards and condition keys are derived, not retyped.
#
# `terraform output -raw bedrock_role_grant_policy_json`
# `terraform output -raw credential_broker_role_arn`
# =============================================================================

# Needed to default the Bedrock role account to this deployment's own account.
data "aws_caller_identity" "current" {}

# The account that OWNS the Bedrock role. Defaults to this deployment's account,
# which is the same-account case. For a central Bedrock account, set this to that
# account id: every ARN in the grant must name the account owning the role, not
# the platform account (req-model-grant-families).
variable "bedrock_role_account_id" {
  description = "AWS account id owning the Bedrock role the broker assumes. Defaults to this deployment's account (the same-account case)."
  type        = string
  default     = ""

  validation {
    condition     = var.bedrock_role_account_id == "" || can(regex("^[0-9]{12}$", var.bedrock_role_account_id))
    error_message = "bedrock_role_account_id must be a 12-digit AWS account id, or empty to use this deployment's account."
  }
}

# See modules/api/lambda/variables.tf for the full rationale. Declared here too so
# an operator can set it in their .tfvars without reaching into a module.
variable "bedrock_assumable_role_arns" {
  description = "IAM role ARNs the credential broker may assume for Bedrock access. Path-scoped by default; set [\"*\"] to opt out of the naming convention."
  type        = list(string)
  default     = ["arn:aws:iam::*:role/aidlc-bedrock-*"]

  validation {
    condition     = length(var.bedrock_assumable_role_arns) > 0
    error_message = "bedrock_assumable_role_arns must not be empty; the broker would be unable to resolve any role binding."
  }
}

locals {
  bedrock_role_account = coalesce(
    var.bedrock_role_account_id != "" ? var.bedrock_role_account_id : null,
    data.aws_caller_identity.current.account_id,
  )

  # Inference-profile patterns, never enumerations.
  #
  # con-claude-model-fanout: Claude Code invokes models beyond the configured one
  # (a run pinned to sonnet-5 also called opus-5 and haiku-4-5), so any allowlist
  # narrower than the provider family breaks real runs.
  #
  # con-gpt-global-cris-only: GPT is reachable ONLY through global CRIS. There is
  # deliberately no `eu.openai.*` pattern because no such profile exists — adding
  # one would imply a capability that does not.
  bedrock_grant_inference_profile_arns = [
    "arn:${data.aws_partition.current.partition}:bedrock:*:${local.bedrock_role_account}:inference-profile/eu.anthropic.claude-*",
    "arn:${data.aws_partition.current.partition}:bedrock:*:${local.bedrock_role_account}:inference-profile/global.anthropic.claude-*",
    "arn:${data.aws_partition.current.partition}:bedrock:*:${local.bedrock_role_account}:inference-profile/global.openai.gpt-*",
  ]

  # Foundation-model ARNs are account-less and region-wildcarded, then FENCED by a
  # StringLike condition on bedrock:InferenceProfileArn. con-fm-fence-works: a bare
  # foundation-model id resolves to direct invocation and is denied by the
  # condition, which forces every call through an inference profile by design.
  bedrock_grant_foundation_model_arns = [
    "arn:${data.aws_partition.current.partition}:bedrock:*::foundation-model/anthropic.claude-*",
    "arn:${data.aws_partition.current.partition}:bedrock:*::foundation-model/openai.gpt-*",
  ]

  bedrock_role_grant_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InvokeThroughInferenceProfiles"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = local.bedrock_grant_inference_profile_arns
      },
      {
        Sid      = "InvokeFoundationModelsOnlyViaInferenceProfile"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = local.bedrock_grant_foundation_model_arns
        Condition = {
          StringLike = {
            "bedrock:InferenceProfileArn" = "arn:${data.aws_partition.current.partition}:bedrock:*:${local.bedrock_role_account}:inference-profile/*"
          }
        }
      },
      {
        # Codex only. con-codex-mantle: Codex 0.145.0 calls
        # bedrock-mantle.<region>.api.aws/openai/v1/responses and needs
        # bedrock-mantle:CreateInference; bedrock:InvokeModel does not authorize it.
        #
        # Included so Codex works the moment its own defects are fixed. Codex is
        # NOT verified end to end in v1 (con-codex-model-missing: mantle in
        # eu-central-1 serves none of the model ids it needs), and no acceptance
        # criterion depends on a successful Codex invocation (req-codex-scope).
        Sid      = "CodexMantleInference"
        Effect   = "Allow"
        Action   = ["bedrock-mantle:CreateInference"]
        Resource = ["arn:${data.aws_partition.current.partition}:bedrock-mantle:*:${local.bedrock_role_account}:project/*"]
      },
    ]
  }
}
