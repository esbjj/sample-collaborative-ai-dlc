// Credential-resolution spike — serial runner + verdict serializer + CLI entry point.
//
// THROWAWAY HARNESS (unit-credential-resolution-spike). Drives the three in-scope CLIs
// SERIALLY (performance-design / scalability-design: one child at a time for unambiguous
// per-CLI failure attribution), records only terminal verdicts, aggregates the fail-closed
// VerdictRecord, and serialises it as a secret-free JSON document — the spike's SOLE durable
// output (business-rules BR-1.2, domain-entities VerdictRecord).
//
// `main()` is an OPERATOR-DRIVEN entry point: a genuine role-native PASS needs a live
// bedrock:InvokeModel under the scoped grant (unit-bedrock-iam-grant), which cannot run in
// automated CI (cicd-pipeline). Unit tests exercise every path with the invocation mocked.

import { IN_SCOPE_CLIS } from './cli-scope.js';
import { VERDICTS } from './classify.js';
import { probeCli, PreconditionError } from './probe-cli.js';
import { buildEntry, aggregateVerdict } from './verdict.js';

// runSpike — probe each in-scope CLI serially and aggregate the VerdictRecord.
//
// • Terminal verdicts (role-native | fallback-required) are recorded as entries.
// • Inconclusive results and precondition failures record NO entry, leaving the
//   fail-closed build gate CLOSED (aggregateVerdict marks the record incomplete) —
//   the operator must fix the environment/harness and re-run (business-rules BR-3.4).
// `probe` is injectable for tests; production uses the real probeCli.
export const runSpike = async ({
  baseEnv = {},
  clis = IN_SCOPE_CLIS,
  probe = probeCli,
  producedAt = null,
} = {}) => {
  const entries = [];
  const skipped = []; // { cli, reason } — inconclusive / precondition defects (secret-free)

  // SERIAL: one CLI at a time (no Promise.all) — correctness, not a bottleneck.
  for (const cli of clis) {
    try {
      const { classification, evidence } = await probe({ cli, baseEnv });
      if (
        classification.verdict === VERDICTS.ROLE_NATIVE ||
        classification.verdict === VERDICTS.FALLBACK_REQUIRED
      ) {
        entries.push(
          buildEntry({
            cli,
            verdict: classification.verdict,
            fallbackRequired: classification.fallbackRequired,
            note: classification.note,
            evidence,
          }),
        );
      } else {
        // Inconclusive — re-run, never recorded (BR-3.4). Gate stays closed.
        skipped.push({ cli, reason: `inconclusive (${evidence.errorClass})` });
      }
    } catch (err) {
      if (err instanceof PreconditionError) {
        // Harness defect (BR-2.3 / SEC-01) — discard, re-run. Gate stays closed.
        skipped.push({ cli, reason: 'precondition-failed (bearer present in cliEnv)' });
      } else {
        throw err; // unexpected — fail loud
      }
    }
  }

  const record = aggregateVerdict(entries, { producedAt });
  return Object.freeze({ ...record, skipped: Object.freeze(skipped) });
};

// serializeVerdict — the secret-free JSON document written as the spike's durable output.
// Only allow-listed audit facts are emitted (security-design SEC-04); it is built from the
// aggregated record whose entries already contain only bounded evidence.
export const serializeVerdict = (record) =>
  JSON.stringify(
    {
      unit: 'unit-credential-resolution-spike',
      story: 'story-cred-resolution-spike',
      requirement: 'fr-sts-validation-spike',
      producedAt: record.producedAt,
      buildGateSatisfied: record.buildGateSatisfied,
      oq02Conclusion: record.oq02Conclusion,
      fallbackRequired: record.fallbackRequired,
      fallbackRequiredFor: record.fallbackRequiredFor,
      cliVerdicts: record.cliVerdicts.map((e) => ({
        cli: e.cli,
        verdict: e.verdict,
        fallbackRequired: e.fallbackRequired,
        note: e.note,
        evidence: e.evidence,
      })),
      skipped: record.skipped ?? [],
    },
    null,
    2,
  );

// main — operator entry point. Runs the serial spike against the ambient container env
// and prints the verdict JSON to stdout. Exit code MIRRORS the fail-closed build gate
// (0 = gate satisfied, 1 = closed) so a CI/operator wrapper can branch on it.
export const main = async ({
  env = process.env,
  log = console.log,
  errorLog = console.error,
} = {}) => {
  const record = await runSpike({ baseEnv: env });
  log(serializeVerdict(record));
  if (!record.buildGateSatisfied) {
    errorLog(
      '[spike] build gate CLOSED — record incomplete; fix environment/harness and re-run (BR-3.4).',
    );
    return 1;
  }
  return 0;
};

// Run only when invoked directly (node run-spike.js), never on import.
if (import.meta.url === `file://${process.argv[1]}`) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error('[spike] unexpected failure:', err?.message ?? err);
      process.exit(2);
    });
}
