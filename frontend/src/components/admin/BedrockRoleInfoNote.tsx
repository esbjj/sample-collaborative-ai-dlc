// Presentational note shown when the Bedrock auth path is "Short-lived role
// (STS)". It has no I/O and no internal state. Part of
// unit-admin-auth-path-selection (frontend-components); realizes the display
// side of fr-sts-precedence-rule and the fr-sts-documentation role-scope
// reference (BR-4, BR-5.4).
//
// Three content states:
//   1. role selected, no stored key      → "no secret needed" info line
//   2. both configured (role + stored key) → informational precedence note
//      (role wins, stored key unused) with an OPTIONAL "Clear the unused key"
//      affordance. Never an error, never blocking (BR-4.1, dec-precedence-role-
//      wins-informational).
//   3. "View role scope" disclosure       → always available on the role path;
//      read-only least-privilege reference for the security-reviewer persona.

import { ShieldCheck } from 'lucide-react';

interface Props {
  /** True when the role path is selected AND a bearer token is still stored. */
  bothConfigured: boolean;
  /** Optional admin-initiated cleanup of the now-unused stored bearer token.
   *  When provided (and bothConfigured), renders a "Clear the unused key"
   *  action. Never invoked automatically (BR-4.3). */
  onClearKey?: () => void;
}

export function BedrockRoleInfoNote({ bothConfigured, onClearKey }: Props) {
  return (
    <div className="space-y-2" data-testid="bedrock-role-info-note">
      {/* Neutral/muted styling — never destructive. Meaning conveyed in text,
          not colour alone (accessibility-checklist). */}
      <div
        className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-xs text-muted-foreground"
        role="status"
        aria-live="polite"
      >
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-foreground" aria-hidden="true" />
        {bothConfigured ? (
          <div className="space-y-1">
            <p className="text-foreground">
              The short-lived role (STS) path takes precedence. The stored Bedrock bearer token is{' '}
              <strong>unused</strong> while this path is selected.
            </p>
            <p>
              No secret is required — the AgentCore runtime obtains short-lived, auto-expiring
              credentials from its execution role.
            </p>
            {onClearKey && (
              <button
                type="button"
                onClick={onClearKey}
                className="mt-1 inline-flex items-center text-[11px] font-medium text-foreground underline underline-offset-2 hover:text-destructive"
                data-testid="bedrock-role-info-note-clear-key"
              >
                Clear the unused key
              </button>
            )}
          </div>
        ) : (
          <p>
            No secret is required. The AgentCore runtime obtains short-lived, auto-expiring
            credentials from its execution role via AWS STS.
          </p>
        )}
      </div>

      {/* Read-only least-privilege scope reference (fr-sts-documentation /
          FR-STS-05). Exact model ARNs and regions are authored in the IaC unit
          (unit-bedrock-iam-grant); this is a descriptive reference for the
          security reviewer. Native <details> is keyboard-operable by default. */}
      <details
        className="text-[11px] text-muted-foreground"
        data-testid="bedrock-role-scope-disclosure"
      >
        <summary className="cursor-pointer select-none font-medium text-foreground">
          View role scope
        </summary>
        <div className="mt-1.5 space-y-1 border-l-2 border-border pl-3">
          <p>
            The AgentCore execution role is granted a scoped, least-privilege
            <code className="mx-1 rounded bg-muted px-1 text-[10px]">bedrock:InvokeModel</code>
            (and
            <code className="mx-1 rounded bg-muted px-1 text-[10px]">
              bedrock:InvokeModelWithResponseStream
            </code>
            ) permission, bounded to the specific model ARNs the platform uses — never a wildcard.
          </p>
          <p>
            No long-lived Bedrock secret is stored on this path, advancing AWS Well-Architected best
            practice SEC02-BP02 (prefer temporary credentials).
          </p>
        </div>
      </details>
    </div>
  );
}
