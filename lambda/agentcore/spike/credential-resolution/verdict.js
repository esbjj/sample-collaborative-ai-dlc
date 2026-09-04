// Credential-resolution spike — verdict entry construction + record aggregation.
//
// THROWAWAY HARNESS (unit-credential-resolution-spike). Pure, immutable value objects
// (reliability-design): a CliVerdict entry per CLI (domain-entities CliVerdict) and the
// VerdictRecord aggregate root (domain-entities VerdictRecord) that resolves OQ-02 and
// gates the build (business-rules BR-1, BR-4, BR-5).

import { IN_SCOPE_CLIS, isInScopeCli } from './cli-scope.js';
import { VERDICTS } from './classify.js';

// buildEntry — construct one frozen, recorded CliVerdict row (business-rules BR-4.1).
//
// Enforces the domain invariants:
//   • the CLI must be in scope (domain-entities TargetCli; Kiro excluded, BR-4.3);
//   • only a terminal verdict (role-native | fallback-required) may be recorded — an
//     inconclusive result is not a verdict and must be re-run, never recorded (BR-3.4,
//     domain-entities CliVerdict "only a recorded verdict may enter the VerdictRecord").
//
// Throws on violation so a harness bug fails loud rather than recording a bad row.
export const buildEntry = ({ cli, verdict, fallbackRequired, evidence, note = null } = {}) => {
  if (!isInScopeCli(cli)) {
    throw new Error(
      `buildEntry: "${cli}" is not an in-scope CLI (have: ${IN_SCOPE_CLIS.join(', ')})`,
    );
  }
  if (verdict !== VERDICTS.ROLE_NATIVE && verdict !== VERDICTS.FALLBACK_REQUIRED) {
    throw new Error(
      `buildEntry: verdict "${verdict}" is not terminal — inconclusive results are re-run, never recorded (BR-3.4)`,
    );
  }
  // fallbackRequired is redundantly explicit per fr-sts-validation-spike AC / BR-4.2,
  // and must agree with the verdict.
  const expected = verdict === VERDICTS.FALLBACK_REQUIRED;
  if (Boolean(fallbackRequired) !== expected) {
    throw new Error(
      `buildEntry: fallbackRequired (${fallbackRequired}) contradicts verdict "${verdict}"`,
    );
  }
  return Object.freeze({
    cli,
    verdict,
    fallbackRequired: expected,
    note: note ?? null,
    evidence: evidence ?? null,
  });
};

// aggregateVerdict — derive the VerdictRecord aggregate from the recorded entries
// (domain-entities VerdictRecord, business-rules BR-4/BR-5).
//
// Invariants enforced here:
//   • the record is COMPLETE only when every in-scope CLI has exactly one recorded entry
//     (no pending/inconclusive) — otherwise the build gate stays CLOSED (fail-closed,
//     reliability-design; business-rules BR-1.1);
//   • oq02Conclusion / fallbackRequired are PURE functions of the entries, never entered
//     by hand (domain-entities VerdictRecord invariant);
//   • fallbackRequiredFor lists ONLY the CLIs that need a fallback (BR-5.2) — a role-native
//     CLI never appears.
//
// Returns a frozen VerdictRecord.
export const aggregateVerdict = (entries = [], { producedAt = null } = {}) => {
  const list = Array.isArray(entries) ? entries : [];

  // One-and-only-one recorded entry per in-scope CLI ⇒ complete (business-rules BR-1.1).
  const byCli = new Map(list.map((e) => [e?.cli, e]));
  const complete =
    IN_SCOPE_CLIS.every((cli) => byCli.has(cli)) && byCli.size === IN_SCOPE_CLIS.length;

  const fallbackRequiredFor = IN_SCOPE_CLIS.filter(
    (cli) => byCli.get(cli)?.verdict === VERDICTS.FALLBACK_REQUIRED,
  );
  const fallbackRequired = fallbackRequiredFor.length > 0;

  // OQ-02 conclusion (business-logic-model decision tree, BR-5).
  const oq02Conclusion = !complete
    ? 'incomplete'
    : fallbackRequired
      ? `fallback-needed-for: ${fallbackRequiredFor.join(', ')}`
      : 'fallback-not-needed';

  // Fail-closed build gate: downstream (unit-credential-resolution-adapter) may proceed
  // ONLY when the record is complete with a decisive verdict for every in-scope CLI
  // (business-rules BR-1.1 / BR-5). An incomplete record leaves the gate closed.
  const buildGateSatisfied = complete;

  return Object.freeze({
    // Ordered rows, one per in-scope CLI (stable order = IN_SCOPE_CLIS).
    cliVerdicts: Object.freeze(IN_SCOPE_CLIS.map((cli) => byCli.get(cli)).filter(Boolean)),
    complete,
    fallbackRequired,
    fallbackRequiredFor: Object.freeze(fallbackRequiredFor),
    oq02Conclusion,
    buildGateSatisfied,
    producedAt: producedAt ?? new Date().toISOString(),
  });
};
