import { describe, it, expect } from 'vitest';
import { buildEvidence } from '../spike/credential-resolution/evidence.js';
import { ERROR_CLASS } from '../spike/credential-resolution/classify.js';

// Evidence builder — the SEC-04 secret-free boundary.
describe('buildEvidence (secret-free, allow-listed)', () => {
  it('produces a frozen object with only allow-listed audit fields', () => {
    const ev = buildEvidence({
      exitCode: 0,
      errorClass: ERROR_CLASS.NONE,
      reachedBedrockAsSigV4: true,
    });
    expect(Object.isFrozen(ev)).toBe(true);
    expect(Object.keys(ev).toSorted()).toEqual(
      ['errorClass', 'exitCode', 'reachedBedrockAsSigV4', 'summary', 'timedOut'].toSorted(),
    );
  });

  it('SEC-04: never stores raw error text — a planted fake secret does not leak into evidence', () => {
    const plantedSecret = 'AKIAFAKE1234567890XX bearer=super-secret-token';
    const ev = buildEvidence({
      exitCode: 1,
      rawErrorText: `AccessDeniedException ${plantedSecret}`,
      reachedBedrockAsSigV4: true,
    });
    const serialized = JSON.stringify(ev);
    expect(serialized).not.toContain('AKIAFAKE');
    expect(serialized).not.toContain('super-secret-token');
    // The raw text is used only to derive the class, then discarded.
    expect(ev.errorClass).toBe(ERROR_CLASS.ACCESS_DENIED);
  });

  it('a timeout forces the TIMEOUT class regardless of supplied errorClass', () => {
    const ev = buildEvidence({ exitCode: null, errorClass: ERROR_CLASS.NONE, timedOut: true });
    expect(ev.errorClass).toBe(ERROR_CLASS.TIMEOUT);
    expect(ev.timedOut).toBe(true);
    expect(ev.exitCode).toBeNull();
  });

  it('carries a bounded, human-readable derived summary per class', () => {
    const ev = buildEvidence({ exitCode: 1, errorClass: ERROR_CLASS.CREDENTIALS_REQUIRED });
    expect(ev.summary).toContain('could not resolve role credentials');
    expect(ev.summary.length).toBeLessThanOrEqual(200);
  });
});
