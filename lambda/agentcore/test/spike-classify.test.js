import { describe, it, expect } from 'vitest';
import {
  classify,
  categorizeError,
  VERDICTS,
  ERROR_CLASS,
  BLOCKED_ON_GRANT_NOTE,
} from '../spike/credential-resolution/classify.js';

// Pure classifier — the load-bearing decision tree from the business-logic-model.
describe('classify (credential-resolution spike decision tree)', () => {
  it('BR-3.1: 2xx via SigV4 with no bearer → role-native, fallback not required', () => {
    const r = classify({ invocationSucceeded: true });
    expect(r.verdict).toBe(VERDICTS.ROLE_NATIVE);
    expect(r.fallbackRequired).toBe(false);
    expect(r.note).toBeNull();
    expect(r.errorClass).toBe(ERROR_CLASS.NONE);
  });

  it('BR-3.2: AccessDenied that reached Bedrock as a signed caller → role-native (blocked-on-grant)', () => {
    const r = classify({
      invocationSucceeded: false,
      reachedBedrockAsSigV4: true,
      errorClass: ERROR_CLASS.ACCESS_DENIED,
    });
    expect(r.verdict).toBe(VERDICTS.ROLE_NATIVE);
    expect(r.fallbackRequired).toBe(false);
    expect(r.note).toBe(BLOCKED_ON_GRANT_NOTE);
  });

  it('BR-3.2 guard: AccessDenied that did NOT reach Bedrock as SigV4 → inconclusive, never a pass', () => {
    // We cannot prove resolution succeeded → must re-run, never justify widening scope (SEC-03).
    const r = classify({
      invocationSucceeded: false,
      reachedBedrockAsSigV4: false,
      errorClass: ERROR_CLASS.ACCESS_DENIED,
    });
    expect(r.verdict).toBe(VERDICTS.INCONCLUSIVE);
    expect(r.fallbackRequired).toBeNull();
  });

  it('BR-3.3: CLI demands the bearer / no credentials → fallback-required', () => {
    const r = classify({
      invocationSucceeded: false,
      errorClass: ERROR_CLASS.CREDENTIALS_REQUIRED,
    });
    expect(r.verdict).toBe(VERDICTS.FALLBACK_REQUIRED);
    expect(r.fallbackRequired).toBe(true);
  });

  it('performance-design: a timeout is inconclusive (TIMEOUT), never a terminal verdict', () => {
    const r = classify({ timedOut: true, invocationSucceeded: false });
    expect(r.verdict).toBe(VERDICTS.INCONCLUSIVE);
    expect(r.errorClass).toBe(ERROR_CLASS.TIMEOUT);
    expect(r.fallbackRequired).toBeNull();
  });

  it('BR-3.4: environmental failure → inconclusive, re-run', () => {
    const r = classify({
      invocationSucceeded: false,
      errorClass: ERROR_CLASS.ENVIRONMENTAL,
    });
    expect(r.verdict).toBe(VERDICTS.INCONCLUSIVE);
    expect(r.fallbackRequired).toBeNull();
  });

  it('unknown signal defaults to inconclusive', () => {
    expect(classify({}).verdict).toBe(VERDICTS.INCONCLUSIVE);
  });
});

describe('categorizeError (bounded, secret-free error families)', () => {
  it('maps a bearer-token demand to CREDENTIALS_REQUIRED', () => {
    expect(categorizeError('Error: AWS_BEARER_TOKEN_BEDROCK is required')).toBe(
      ERROR_CLASS.CREDENTIALS_REQUIRED,
    );
    expect(categorizeError('Unable to locate credentials')).toBe(ERROR_CLASS.CREDENTIALS_REQUIRED);
  });

  it('maps an IAM denial to ACCESS_DENIED', () => {
    expect(
      categorizeError('AccessDeniedException: not authorized to perform bedrock:InvokeModel'),
    ).toBe(ERROR_CLASS.ACCESS_DENIED);
  });

  it('maps network / model-not-enabled to ENVIRONMENTAL', () => {
    expect(categorizeError('could not connect to endpoint')).toBe(ERROR_CLASS.ENVIRONMENTAL);
    expect(categorizeError('The provided model identifier is not enabled')).toBe(
      ERROR_CLASS.ENVIRONMENTAL,
    );
  });

  it('empty / unrecognised text → UNKNOWN', () => {
    expect(categorizeError('')).toBe(ERROR_CLASS.UNKNOWN);
    expect(categorizeError('   ')).toBe(ERROR_CLASS.UNKNOWN);
    expect(categorizeError('some totally opaque line')).toBe(ERROR_CLASS.UNKNOWN);
  });

  it('credential signature wins over a co-occurring access-denied token (order matters)', () => {
    expect(categorizeError('no credentials; got 403 later')).toBe(ERROR_CLASS.CREDENTIALS_REQUIRED);
  });
});
