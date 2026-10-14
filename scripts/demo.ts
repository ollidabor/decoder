/**
 * End-to-end demo of Part 1 and Part 2 using fictional sample data.
 * Nothing is written to disk; the generated key only lives in memory.
 */
import { readFileSync } from 'node:fs';
import { DecoderError, redact, redactWithKey, unredact } from '../src/index.ts';

const read = (name: string): string => readFileSync(new URL(`../samples/${name}`, import.meta.url), 'utf8');
const keywords = read('keywords.txt').trim();
const original = read('document.txt');
const line = (title: string): void => console.log(`\n=== ${title} ${'='.repeat(Math.max(0, 60 - title.length))}`);

line('Keywords');
console.log(keywords);

line('Original document');
console.log(original);

line('Part 1 - redact (irreversible)');
console.log(redact(keywords, original));

line('Part 2 - redact with key');
const sealed = await redactWithKey(keywords, original);
console.log(sealed.document);
console.log(`(${sealed.count} occurrences, generated key: ${sealed.key})`);

line('Part 2 - unredact with the right key');
const restored = await unredact(sealed.key, sealed.document);
console.log(restored);
console.log(`Round trip identical: ${restored === original}`);

line('Security checks');
const attempt = async (label: string, fn: () => unknown): Promise<void> => {
  try {
    await fn();
    console.log(`  ${label}: unexpectedly succeeded`);
  } catch (error) {
    console.log(`  ${label}: rejected -> ${error instanceof DecoderError ? error.code : 'error'}`);
  }
};
await attempt('Wrong key', () => unredact('this-is-not-the-key', sealed.document));
await attempt('Tampered document', () => unredact(sealed.key, sealed.document.replace('XXXX', 'YYYY')));
await attempt('Terminal escape injection', () => redact('beer', 'beer \u001b[31mred\u001b[0m'));
await attempt('Zero-width keyword evasion', () => redact('beer', 'b​eer'));
await attempt('Bidi override (Trojan Source)', () => redact('beer', 'beer ‮evil'));
await attempt('Unterminated phrase', () => redact('"Boston Red Sox', original));
await attempt('Weak user key', () => redactWithKey(keywords, original, 'short'));
console.log('  Regex metacharacters are literal:', JSON.stringify(redact('a.*b (x|y)', 'a.*b (x|y) vs aXXb x')));
console.log('  HTML is plain text:', JSON.stringify(redact('secret', '<script>alert("secret")</script>')));
