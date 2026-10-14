import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DecoderError, redactWithKey, unredact } from '../src/index.ts';

const code = (c: string) => (e: unknown) => e instanceof DecoderError && e.code === c;
const KEYWORDS = `Hello world "Boston Red Sox", 'Pepperoni Pizza', 'Cheese Pizza', beer`;
const DOC = 'Hello world!\nThe Boston\nRed Sox fan ate Cheese Pizza with a BEER.\nLiteral XXXX stays XXXX.\n';
const KEY = 'correct horse battery staple';

test('round-trips with a user-supplied key', async () => {
  const sealed = await redactWithKey(KEYWORDS, DOC, KEY);
  assert.equal(sealed.count, 5);
  assert.equal(sealed.keyWasGenerated, false);
  assert.ok(sealed.document.startsWith('XXXX XXXX!\nThe XXXX fan ate XXXX with a XXXX.\nLiteral XXXX stays XXXX.\n'));
  assert.equal(await unredact(KEY, sealed.document), DOC);
});

test('generates a strong key when none is given', async () => {
  const sealed = await redactWithKey(KEYWORDS, DOC);
  assert.equal(sealed.keyWasGenerated, true);
  assert.ok(sealed.key.length >= 32);
  assert.equal(await unredact(sealed.key, sealed.document), DOC);
});

test('does not leak redacted content in the sealed document', async () => {
  const sealed = await redactWithKey(KEYWORDS, DOC, KEY);
  for (const secret of ['Boston', 'Pizza', 'BEER', 'Hello']) assert.ok(!sealed.document.includes(secret));
});

test('tolerates trailing whitespace after the envelope', async () => {
  const sealed = await redactWithKey(KEYWORDS, DOC, KEY);
  assert.equal(await unredact(KEY, `${sealed.document}\n\n  `), DOC);
});

test('rejects a wrong key', async () => {
  const sealed = await redactWithKey(KEYWORDS, DOC, KEY);
  await assert.rejects(unredact('wrong key but long enough', sealed.document), code('DECRYPTION_FAILED'));
});

test('detects tampering of the visible text', async () => {
  const sealed = await redactWithKey(KEYWORDS, DOC, KEY);
  await assert.rejects(unredact(KEY, sealed.document.replace('ate', 'ATE')), code('DECRYPTION_FAILED'));
});

test('detects tampering of the envelope', async () => {
  const sealed = await redactWithKey(KEYWORDS, DOC, KEY);
  const lines = sealed.document.split('\n');
  const idx = lines.findIndex((l) => l.startsWith('-----BEGIN')) + 2; // ciphertext, past the header
  const l = lines[idx]!;
  lines[idx] = (l[0] === 'A' ? 'B' : 'A') + l.slice(1);
  await assert.rejects(unredact(KEY, lines.join('\n')), code('DECRYPTION_FAILED'));
});

test('rejects documents without a valid envelope', async () => {
  await assert.rejects(unredact(KEY, 'XXXX plain text'), code('MISSING_ENVELOPE'));
  await assert.rejects(
    unredact(KEY, 'x\n-----BEGIN DECODER ENVELOPE v1-----\n!!!\n-----END DECODER ENVELOPE v1-----\n'),
    code('MALFORMED_ENVELOPE'),
  );
});

test('refuses to redact a document that already holds an envelope', async () => {
  const sealed = await redactWithKey(KEYWORDS, DOC, KEY);
  await assert.rejects(redactWithKey('beer', sealed.document, KEY), code('RESERVED_MARKER'));
});

test('validates keys', async () => {
  await assert.rejects(redactWithKey(KEYWORDS, DOC, 'short'), code('WEAK_KEY'));
  await assert.rejects(unredact(123, 'doc'), code('INVALID_TYPE'));
  await assert.rejects(unredact('key with \u001b escape!!', 'doc'), code('FORBIDDEN_CHARACTERS'));
});
