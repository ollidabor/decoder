import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DecoderError, redact } from '../src/index.ts';

const code = (c: string) => (e: unknown) => e instanceof DecoderError && e.code === c;
const KEYWORDS = `Hello world "Boston Red Sox", 'Pepperoni Pizza', 'Cheese Pizza', beer`;

test('redacts keywords and phrases with XXXX', () => {
  assert.equal(
    redact(KEYWORDS, 'Hello! I love the Boston Red Sox, Pepperoni Pizza and beer.'),
    'XXXX! I love the XXXX, XXXX and XXXX.',
  );
});

test('is case-insensitive and whole-word only', () => {
  assert.equal(redact('beer', 'BEER, Beer, beers, root-beer, beerhouse'), 'XXXX, XXXX, beers, root-XXXX, beerhouse');
});

test('matches phrases across line breaks and repeated whitespace', () => {
  assert.equal(redact('"Boston Red Sox"', 'the Boston\n  Red\tSox won'), 'the XXXX won');
});

test('prefers the longest overlapping term', () => {
  assert.equal(redact('Boston "Boston Red Sox"', 'Boston Red Sox in Boston'), 'XXXX in XXXX');
});

test('treats regex metacharacters literally (no regex injection)', () => {
  assert.equal(redact('".*" a+b (x|y) C++', '.* a+b aab (x|y) x C++ code'), 'XXXX XXXX aab XXXX x XXXX code');
});

test('handles Unicode words', () => {
  assert.equal(redact('café Ñandú', 'Un CAFÉ con el ñandú, cafés.'), 'Un XXXX con el XXXX, cafés.');
});

test('treats HTML/script as plain text', () => {
  assert.equal(redact('alert', '<script>alert(1)</script>'), '<script>XXXX(1)</script>');
});

test('leaves text unchanged when nothing matches', () => {
  assert.equal(redact('beer', 'water only'), 'water only');
});

test('rejects unsafe documents', () => {
  assert.throws(() => redact('beer', 'beer \u001b[2J'), code('FORBIDDEN_CHARACTERS'));
  assert.throws(() => redact('beer', 'b​eer'), code('FORBIDDEN_CHARACTERS'));
  assert.throws(() => redact('beer', 'x ‮ y'), code('FORBIDDEN_CHARACTERS'));
  assert.throws(() => redact('beer', 'bad \uD800 surrogate'), code('FORBIDDEN_CHARACTERS'));
  assert.throws(() => redact('beer', ''), code('EMPTY_INPUT'));
  assert.throws(() => redact('beer', 'x'.repeat(1_000_001)), code('INPUT_TOO_LARGE'));
  assert.throws(() => redact('beer', { toString: () => 'beer' }), code('INVALID_TYPE'));
});

test('stays fast on adversarial input (no catastrophic backtracking)', () => {
  const terms = Array.from({ length: 500 }, (_, i) => `"a a a a ${i}"`).join(' ');
  const start = performance.now();
  redact(terms, 'a '.repeat(200_000));
  assert.ok(performance.now() - start < 1_500);
});
