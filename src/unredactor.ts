import { DecoderError } from './errors.ts';
import { open, seal, generateKey } from './envelope.ts';
import { MASK, redactDetailed } from './redactor.ts';
import { assertSafeText, assertString, LIMITS, validateKey } from './validation.ts';

export interface SealedRedaction {
  /** Redacted text followed by an encrypted envelope holding the removed content. */
  readonly document: string;
  /** Key required to unredact. Generated when none was supplied. */
  readonly key: string;
  readonly keyWasGenerated: boolean;
  readonly count: number;
}

/**
 * Assignment Part 2 (sealing side): redacts like Part 1 and appends an
 * AES-256-GCM encrypted envelope so the document can later be restored with `key`.
 */
export async function redactWithKey(
  keywords: unknown,
  document: unknown,
  key?: unknown,
): Promise<SealedRedaction> {
  const keyWasGenerated = key === undefined || key === '';
  const secret = keyWasGenerated ? generateKey() : validateKey(key);
  const { text, redactions } = redactDetailed(keywords, document);
  return {
    document: await seal(text, redactions, secret),
    key: secret,
    keyWasGenerated,
    count: redactions.length,
  };
}

/** Assignment Part 2: restores the original document text using the key. */
export async function unredact(key: unknown, document: unknown): Promise<string> {
  const secret = validateKey(key);
  assertString(document, 'Document');
  // Envelope + payload can be larger than the original document.
  assertSafeText(document, 'Document', LIMITS.maxDocumentChars * 3);

  const { body, redactions } = await open(document, secret);

  let out = '';
  let cursor = 0;
  for (const { offset, original } of redactions) {
    if (offset < cursor || body.slice(offset, offset + MASK.length) !== MASK) {
      throw new DecoderError('MALFORMED_ENVELOPE', 'Envelope does not match the redacted text.');
    }
    out += body.slice(cursor, offset) + original;
    cursor = offset + MASK.length;
  }
  return out + body.slice(cursor);
}
