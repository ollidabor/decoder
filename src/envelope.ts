import { createCipheriv, createDecipheriv, randomBytes, scrypt as scryptCb } from 'node:crypto';
import { promisify } from 'node:util';
import { DecoderError } from './errors.ts';
import type { Redaction } from './redactor.ts';

const scrypt = promisify(scryptCb) as (
  password: string,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

export const ENVELOPE_MARKER = '-----BEGIN DECODER ENVELOPE';
const BEGIN = `${ENVELOPE_MARKER} v1-----`;
const END = '-----END DECODER ENVELOPE v1-----';

const VERSION = 1;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const HEADER_LEN = 1 + SALT_LEN + IV_LEN + TAG_LEN;
const PAD_BLOCK = 256;
// scrypt cost: ~32 MiB / ~100 ms per attempt makes brute-forcing a key expensive.
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 } as const;

/** Random 192-bit key, URL-safe so it is easy to copy into a file. */
export function generateKey(): string {
  return randomBytes(24).toString('base64url');
}

const deriveKey = (key: string, salt: Buffer): Promise<Buffer> => scrypt(key, salt, 32, SCRYPT);

/**
 * The AAD binds the ciphertext to the exact redacted text, so any edit to the
 * visible document (moving or deleting an XXXX) makes decryption fail loudly
 * instead of silently restoring text in the wrong place.
 */
const aad = (header: Buffer, body: string): Buffer => Buffer.concat([header, Buffer.from(body, 'utf8')]);

export async function seal(body: string, redactions: readonly Redaction[], key: string): Promise<string> {
  const json = JSON.stringify({ r: redactions.map((r) => [r.offset, r.original]) });
  // Pad with whitespace (valid trailing JSON) so ciphertext size only reveals a coarse bucket.
  const padded = json.padEnd(Math.ceil((json.length + 1) / PAD_BLOCK) * PAD_BLOCK, ' ');

  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const dk = await deriveKey(key, salt);
  const prefix = Buffer.concat([Buffer.from([VERSION]), salt, iv]);

  const cipher = createCipheriv('aes-256-gcm', dk, iv);
  cipher.setAAD(aad(prefix, body));
  const ciphertext = Buffer.concat([cipher.update(padded, 'utf8'), cipher.final()]);
  const blob = Buffer.concat([prefix, cipher.getAuthTag(), ciphertext]).toString('base64');

  const lines = blob.match(/.{1,76}/g) ?? [];
  return `${body}\n${BEGIN}\n${lines.join('\n')}\n${END}\n`;
}

export interface OpenedEnvelope {
  readonly body: string;
  readonly redactions: readonly Redaction[];
}

export function splitEnvelope(document: string): { body: string; blob: Buffer } {
  const start = document.lastIndexOf(`\n${BEGIN}\n`);
  if (start === -1) {
    throw new DecoderError('MISSING_ENVELOPE', 'Document has no decoder envelope; it cannot be unredacted.');
  }
  const body = document.slice(0, start);
  if (body.includes(ENVELOPE_MARKER)) {
    throw new DecoderError('MALFORMED_ENVELOPE', 'Document contains more than one envelope.');
  }
  const rest = document.slice(start + BEGIN.length + 2).trimEnd();
  if (!rest.endsWith(END)) {
    throw new DecoderError('MALFORMED_ENVELOPE', 'Envelope end marker is missing.');
  }
  const b64 = rest.slice(0, -END.length).replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64) || b64.length % 4 !== 0) {
    throw new DecoderError('MALFORMED_ENVELOPE', 'Envelope is not valid base64.');
  }
  const blob = Buffer.from(b64, 'base64');
  if (blob.length <= HEADER_LEN || blob[0] !== VERSION) {
    throw new DecoderError('MALFORMED_ENVELOPE', 'Envelope header is invalid or unsupported.');
  }
  return { body, blob };
}

export async function open(document: string, key: string): Promise<OpenedEnvelope> {
  const { body, blob } = splitEnvelope(document);
  const prefix = blob.subarray(0, 1 + SALT_LEN + IV_LEN);
  const salt = blob.subarray(1, 1 + SALT_LEN);
  const iv = blob.subarray(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
  const tag = blob.subarray(1 + SALT_LEN + IV_LEN, HEADER_LEN);
  const ciphertext = blob.subarray(HEADER_LEN);

  let plaintext: string;
  try {
    const decipher = createDecipheriv('aes-256-gcm', await deriveKey(key, salt), iv);
    decipher.setAAD(aad(prefix, body));
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    throw new DecoderError('DECRYPTION_FAILED', 'Wrong key, or the document was modified after redaction.');
  }

  return { body, redactions: parsePayload(plaintext) };
}

/** Defence in depth: even authenticated payloads are shape-checked before use. */
function parsePayload(plaintext: string): Redaction[] {
  let data: unknown;
  try {
    data = JSON.parse(plaintext);
  } catch {
    throw new DecoderError('MALFORMED_ENVELOPE', 'Envelope payload is not valid.');
  }
  const entries = (data as { r?: unknown } | null)?.r;
  if (!Array.isArray(entries)) {
    throw new DecoderError('MALFORMED_ENVELOPE', 'Envelope payload is not valid.');
  }
  return entries.map((entry: unknown) => {
    if (
      !Array.isArray(entry) ||
      entry.length !== 2 ||
      !Number.isSafeInteger(entry[0]) ||
      (entry[0] as number) < 0 ||
      typeof entry[1] !== 'string'
    ) {
      throw new DecoderError('MALFORMED_ENVELOPE', 'Envelope payload is not valid.');
    }
    return { offset: entry[0] as number, original: entry[1] as string };
  });
}
