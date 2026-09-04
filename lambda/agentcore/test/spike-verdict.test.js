import { describe, it, expect } from 'vitest';
import { buildEntry, aggregateVerdict } from '../spike/credential-resolution/verdict.js';
import { VERDICTS, BLOCKED_ON_GRANT_NOTE } from '../spike/credential-resolution/classify.js';

const roleNative = (cli, note = null) =>
  buildEntry({ cli, verdict: VERDICTS.ROLE_NATIVE, fallbackRequired: false, note, evidence: null });
const fallback = (cli) =>
  buildEntry({ cli, verdict: VERDICTS.FALLBACK_REQUIRED, fallbackRequired: true, evidence: null });

describe('buildEntry (domain invariants)', () => {
  it('records a valid terminal verdict as a frozen row', () => {
    const e = roleNative('claude', BLOCKED_ON_GRANT_NOTE);
    expect(Object.isFrozen(e)).toBe(true);
    expect(e).toMatchObject({
      cli: 'claude',
      verdict: VERDICTS.ROLE_NATIVE,
      fallbackRequired: false,
      note: BLOCKED_ON_GRANT_NOTE,
    });
  });

  it('BR-4.3: rejects an out-of-scope CLI (e.g. kiro)', () => {
    expect(() => roleNative('kiro')).toThrow(/not an in-scope CLI/);
  });

  it('BR-3.4: rejects a non-terminal (inconclusive) verdict', () => {
    expect(() =>
      buildEntry({
        cli: 'codex',
        verdict: VERDICTS.INCONCLUSIVE,
        fallbackRequired: null,
        evidence: null,
      }),
    ).toThrow(/not terminal/);
  });

  it('rejects fallbackRequired that contradicts the verdict', () => {
    expect(() =>
      buildEntry({
        cli: 'codex',
        verdict: VERDICTS.ROLE_NATIVE,
        fallbackRequired: true,
        evidence: null,
      }),
    ).toThrow(/contradicts verdict/);
  });
});

describe('aggregateVerdict (fail-closed build gate, OQ-02 resolution)', () => {
  const at = '2026-09-04T00:00:00.000Z';

  it('BR-5.1: all three role-native → gate satisfied, fallback dropped', () => {
    const r = aggregateVerdict(
      [roleNative('claude'), roleNative('opencode'), roleNative('codex')],
      { producedAt: at },
    );
    expect(r.complete).toBe(true);
    expect(r.buildGateSatisfied).toBe(true);
    expect(r.fallbackRequired).toBe(false);
    expect(r.fallbackRequiredFor).toEqual([]);
    expect(r.oq02Conclusion).toBe('fallback-not-needed');
  });

  it('BR-5.2: one fallback-required → gate satisfied (decisive), fallback scoped to that CLI only', () => {
    const r = aggregateVerdict([roleNative('claude'), fallback('opencode'), roleNative('codex')], {
      producedAt: at,
    });
    expect(r.complete).toBe(true);
    expect(r.buildGateSatisfied).toBe(true);
    expect(r.fallbackRequired).toBe(true);
    expect(r.fallbackRequiredFor).toEqual(['opencode']); // role-native CLIs never appear
    expect(r.oq02Conclusion).toBe('fallback-needed-for: opencode');
  });

  it('fail-closed: a missing in-scope CLI leaves the record incomplete and the gate CLOSED', () => {
    const r = aggregateVerdict([roleNative('claude'), roleNative('opencode')], { producedAt: at });
    expect(r.complete).toBe(false);
    expect(r.buildGateSatisfied).toBe(false);
    expect(r.oq02Conclusion).toBe('incomplete');
  });

  it('emits rows in stable IN_SCOPE_CLIS order regardless of input order', () => {
    const r = aggregateVerdict([fallback('codex'), roleNative('claude'), roleNative('opencode')], {
      producedAt: at,
    });
    expect(r.cliVerdicts.map((e) => e.cli)).toEqual(['claude', 'opencode', 'codex']);
  });

  it('returns a frozen record with a frozen cliVerdicts list', () => {
    const r = aggregateVerdict([roleNative('claude'), roleNative('opencode'), roleNative('codex')]);
    expect(Object.isFrozen(r)).toBe(true);
    expect(Object.isFrozen(r.cliVerdicts)).toBe(true);
  });
});
