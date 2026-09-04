// Credential-resolution spike — pure classifier (decision tree).
//
// THROWAWAY HARNESS (unit-credential-resolution-spike). Pure, deterministic, no I/O
// — the load-bearing correctness core of the spike, unit-testable in isolation
// (reliability-design). It maps a raw invocation outcome to exactly one verdict per
// the business-logic-model classification table and business-rules BR-3.
//
// The whole point of the spike lives in the distinction between:
//   • fallback-required — the CLI could NOT resolve role credentials without a bearer
//     token (business-rules BR-3.3), and
//   • role-native (blocked-on-grant) — the CLI DID resolve role credentials and reached
//     Bedrock as an authenticated SigV4 caller, but the IAM grant is insufficient
//     (business-rules BR-3.2). This is NOT a failure and NEVER a reason to widen IAM
//     scope (security-design SEC-03).

// Terminal verdicts recordable for a CLI (domain-entities CliVerdict).
export const VERDICTS = Object.freeze({
  ROLE_NATIVE: 'role-native',
  FALLBACK_REQUIRED: 'fallback-required',
  // Not a terminal verdict: the probe must be re-run (business-rules BR-3.4).
  // Present in the enum so callers name it explicitly rather than with a bare string.
  INCONCLUSIVE: 'inconclusive',
});

// Bounded, secret-free error families. Raw CLI error text is reduced to one of these
// coarse classes for classification and evidence (security-design SEC-04); the verbatim
// text is never persisted.
export const ERROR_CLASS = Object.freeze({
  NONE: 'none', // invocation succeeded
  ACCESS_DENIED: 'access-denied', // 403 / AccessDenied — reached Bedrock, grant gap
  CREDENTIALS_REQUIRED: 'credentials-required', // CLI demands bearer / no creds resolved
  TIMEOUT: 'timeout', // per-invocation watchdog fired (performance-design)
  ENVIRONMENTAL: 'environmental', // network / model-not-enabled / cold-start flake
  UNKNOWN: 'unknown', // unrecognised signal — treated as inconclusive
});

// Note attached to a role-native verdict whose invocation was blocked by IAM scope,
// referencing unit-bedrock-iam-grant as the owner of the grant gap (business-rules BR-3.2).
export const BLOCKED_ON_GRANT_NOTE = 'blocked-on-grant';

// Ordered, case-insensitive signature table mapping raw CLI error text → a bounded
// ERROR_CLASS. First match wins, so more-specific credential signatures precede the
// broad access-denied family. Kept deliberately small and auditable.
const ERROR_SIGNATURES = [
  // The CLI hard-requires the bearer token / cannot sign with SigV4 / found no creds.
  {
    class: ERROR_CLASS.CREDENTIALS_REQUIRED,
    patterns: [
      'aws_bearer_token_bedrock',
      'bearer token',
      'unable to locate credentials',
      'could not load credentials',
      'no credentials',
      'credentialsproviderror',
      'missing credentials',
    ],
  },
  // Reached Bedrock as an authenticated caller but the grant is insufficient.
  {
    class: ERROR_CLASS.ACCESS_DENIED,
    patterns: [
      'accessdenied',
      'access denied',
      'not authorized to perform',
      'bedrock:invokemodel',
      '403',
    ],
  },
  // Ambiguous / environmental — never a verdict, always a re-run (business-rules BR-3.4).
  {
    class: ERROR_CLASS.ENVIRONMENTAL,
    patterns: [
      'could not connect',
      'network',
      'timeout', // network-level timeout text (distinct from the watchdog TIMEOUT signal)
      'etimedout',
      'econnreset',
      'enotfound',
      'model not enabled',
      'is not enabled',
      'throttl',
      'service unavailable',
      'model.*not.*found',
      'validationexception',
    ],
  },
];

// Reduce raw stderr/stdout text to a bounded, secret-free ERROR_CLASS. Never returns
// or retains the raw text. An empty/whitespace input with no other signal is UNKNOWN.
export const categorizeError = (rawText = '') => {
  const text = String(rawText).toLowerCase();
  if (!text.trim()) return ERROR_CLASS.UNKNOWN;
  for (const { class: cls, patterns } of ERROR_SIGNATURES) {
    for (const p of patterns) {
      // Patterns are simple substrings unless they contain regex metachars.
      if (/[.*]/.test(p) ? new RegExp(p).test(text) : text.includes(p)) return cls;
    }
  }
  return ERROR_CLASS.UNKNOWN;
};

// classify — the decision tree from business-logic-model "Outcome Classification".
//
// Inputs (already reduced to a bounded, secret-free shape by the probe):
//   invocationSucceeded — true when InvokeModel returned 2xx via SigV4 (BR-3.1).
//   reachedBedrockAsSigV4 — true when the request was an authenticated SigV4 call that
//     reached Bedrock (distinguishes a grant gap from a resolution failure, BR-3.2).
//   errorClass — one of ERROR_CLASS.
//   timedOut — the per-invocation watchdog fired (performance-design → inconclusive).
//
// Returns { verdict, fallbackRequired, errorClass, note } — verdict is one of VERDICTS.
// INCONCLUSIVE carries fallbackRequired:null (undecided) and is never recorded (BR-3.4).
export const classify = ({
  invocationSucceeded = false,
  reachedBedrockAsSigV4 = false,
  errorClass = ERROR_CLASS.UNKNOWN,
  timedOut = false,
} = {}) => {
  // Watchdog breach is a correctness event → inconclusive, re-run (performance-design).
  if (timedOut) {
    return {
      verdict: VERDICTS.INCONCLUSIVE,
      fallbackRequired: null,
      errorClass: ERROR_CLASS.TIMEOUT,
      note: null,
    };
  }

  // Row 1 — 2xx via SigV4 with no bearer token: role-native (BR-3.1).
  if (invocationSucceeded) {
    return {
      verdict: VERDICTS.ROLE_NATIVE,
      fallbackRequired: false,
      errorClass: ERROR_CLASS.NONE,
      note: null,
    };
  }

  // Row 2 — AccessDenied/403 that still reached Bedrock as a signed SigV4 caller:
  // credential resolution SUCCEEDED; the failure is an IAM grant gap owned by
  // unit-bedrock-iam-grant. role-native (blocked-on-grant), never a pass justification
  // to widen scope (BR-3.2, security-design SEC-03).
  if (errorClass === ERROR_CLASS.ACCESS_DENIED && reachedBedrockAsSigV4) {
    return {
      verdict: VERDICTS.ROLE_NATIVE,
      fallbackRequired: false,
      errorClass: ERROR_CLASS.ACCESS_DENIED,
      note: BLOCKED_ON_GRANT_NOTE,
    };
  }

  // Row 3 — the CLI cannot resolve role credentials without shimming (demands the
  // bearer token / refuses SigV4 / reports no credentials): fallback-required (BR-3.3).
  if (errorClass === ERROR_CLASS.CREDENTIALS_REQUIRED) {
    return {
      verdict: VERDICTS.FALLBACK_REQUIRED,
      fallbackRequired: true,
      errorClass: ERROR_CLASS.CREDENTIALS_REQUIRED,
      note: null,
    };
  }

  // A bare AccessDenied that did NOT demonstrably reach Bedrock as a signed caller is
  // ambiguous (we cannot prove resolution succeeded) → inconclusive, re-run (BR-3.4).
  // Row 4 — everything else (environmental / unknown) is inconclusive, re-run.
  return { verdict: VERDICTS.INCONCLUSIVE, fallbackRequired: null, errorClass, note: null };
};
