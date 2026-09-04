// Credential-resolution spike — secret-free evidence builder.
//
// THROWAWAY HARNESS (unit-credential-resolution-spike). Builds the frozen,
// allow-listed InvocationEvidence (domain-entities ProbeOutcome → evidence summary)
// from a raw probe result. This is the SEC-04 boundary: raw stdout/stderr/env are
// NEVER copied into evidence; only a bounded set of non-sensitive audit facts survives
// (security-design Control 4). secretlint is the deterministic backstop over the output.

import { categorizeError, ERROR_CLASS } from './classify.js';

// Hard cap on the human-readable summary so a chatty child can never balloon the
// evidence (performance-design bounded buffer) and no long verbatim line survives.
const MAX_SUMMARY_LEN = 200;

// Fixed, human-readable one-liner per error class — derived, never the raw text.
// This is what appears in the verdict record's evidence, so it is intentionally
// generic and secret-free.
const ERROR_SUMMARY = Object.freeze({
  [ERROR_CLASS.NONE]: 'InvokeModel succeeded via SigV4 (no bearer token present)',
  [ERROR_CLASS.ACCESS_DENIED]:
    'AccessDenied/403 from an authenticated SigV4 caller (credential resolution succeeded; IAM grant insufficient)',
  [ERROR_CLASS.CREDENTIALS_REQUIRED]:
    'CLI could not resolve role credentials from the standard chain (demanded a bearer token or reported no credentials)',
  [ERROR_CLASS.TIMEOUT]: 'per-invocation timeout watchdog fired',
  [ERROR_CLASS.ENVIRONMENTAL]:
    'ambiguous/environmental failure (network, model-not-enabled, or cold-start)',
  [ERROR_CLASS.UNKNOWN]: 'unrecognised invocation signal',
});

// buildEvidence — reduce a raw probe result to a frozen, secret-free evidence object.
//
// Inputs:
//   exitCode — the CLI process exit status (or null on spawn failure / timeout).
//   errorClass — a pre-categorized ERROR_CLASS (from the probe), OR omitted to let
//     this builder categorize `rawErrorText` itself. `rawErrorText` is used ONLY to
//     derive the class and is then discarded — it is never stored.
//   reachedBedrockAsSigV4 — whether the request was an authenticated SigV4 call.
//   timedOut — the watchdog fired.
//
// Returns a frozen { exitCode, errorClass, reachedBedrockAsSigV4, timedOut, summary }.
export const buildEvidence = ({
  exitCode = null,
  errorClass = null,
  rawErrorText = '',
  reachedBedrockAsSigV4 = false,
  timedOut = false,
} = {}) => {
  const cls = timedOut ? ERROR_CLASS.TIMEOUT : (errorClass ?? categorizeError(rawErrorText));
  const summary = (ERROR_SUMMARY[cls] ?? ERROR_SUMMARY[ERROR_CLASS.UNKNOWN]).slice(
    0,
    MAX_SUMMARY_LEN,
  );
  return Object.freeze({
    exitCode: exitCode === null ? null : Number(exitCode),
    errorClass: cls,
    reachedBedrockAsSigV4: Boolean(reachedBedrockAsSigV4),
    timedOut: Boolean(timedOut),
    summary,
  });
};
