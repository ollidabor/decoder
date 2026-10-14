import { DecoderError } from './errors.ts';

/** Hard limits keep memory and regex work bounded regardless of input. */
export const LIMITS = Object.freeze({
  maxDocumentChars: 1_000_000,
  maxKeywordInputChars: 20_000,
  maxKeywords: 500,
  maxKeywordChars: 200,
  minKeyChars: 12,
  maxKeyChars: 1_024,
});

/**
 * Characters that are never legitimate in a plain-text document:
 * - C0/C1 control chars except tab, LF, CR (blocks ANSI/terminal escape injection)
 * - Bidi overrides/isolates (blocks "Trojan Source" style visual spoofing)
 * - Zero-width / invisible chars (blocks keyword evasion such as "Bo​ston")
 * - Unpaired surrogates (invalid Unicode)
 */
const FORBIDDEN =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F؜​-‏‪-‮⁠-⁤⁦-⁩﻿]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export function assertString(value: unknown, field: string): asserts value is string {
  if (typeof value !== 'string') {
    throw new DecoderError('INVALID_TYPE', `${field} must be a string.`);
  }
}

export function assertSafeText(value: string, field: string, maxChars: number): void {
  if (value.length === 0) {
    throw new DecoderError('EMPTY_INPUT', `${field} must not be empty.`);
  }
  if (value.length > maxChars) {
    throw new DecoderError('INPUT_TOO_LARGE', `${field} exceeds the maximum of ${maxChars} characters.`);
  }
  if (FORBIDDEN.test(value)) {
    throw new DecoderError(
      'FORBIDDEN_CHARACTERS',
      `${field} contains control, invisible or bidirectional-override characters.`,
    );
  }
}

/** Validates and canonicalises (NFC) a document before redaction. */
export function validateDocument(value: unknown, field = 'Document'): string {
  assertString(value, field);
  const normalized = value.normalize('NFC');
  assertSafeText(normalized, field, LIMITS.maxDocumentChars);
  return normalized;
}

export function validateKey(value: unknown): string {
  assertString(value, 'Key');
  if (value.length < LIMITS.minKeyChars) {
    throw new DecoderError('WEAK_KEY', `Key must be at least ${LIMITS.minKeyChars} characters.`);
  }
  assertSafeText(value, 'Key', LIMITS.maxKeyChars);
  return value.normalize('NFC');
}
