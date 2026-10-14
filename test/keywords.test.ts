import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DecoderError, parseKeywords } from '../src/index.ts';

const code = (c: string) => (e: unknown) => e instanceof DecoderError && e.code === c;

test('parses the assignment example', () => {
  assert.deepEqual(parseKeywords(`Hello world "Boston Red Sox", 'Pepperoni Pizza', 'Cheese Pizza', beer`), [
    'Hello',
    'world',
    'Boston Red Sox',
    'Pepperoni Pizza',
    'Cheese Pizza',
    'beer',
  ]);
});

test('accepts smart quotes, collapses inner whitespace, keeps apostrophes inside words', () => {
  assert.deepEqual(parseKeywords('“New   York”, ‘Area 51’ don\'t'), ['New York', 'Area 51', "don't"]);
});

test('removes duplicates case-insensitively and ignores empty phrases', () => {
  assert.deepEqual(parseKeywords('beer BEER "" , , Beer'), ['beer']);
});

test('rejects invalid keyword input', () => {
  assert.throws(() => parseKeywords('"Boston Red Sox'), code('UNTERMINATED_QUOTE'));
  assert.throws(() => parseKeywords(' , , '), code('INVALID_KEYWORDS'));
  assert.throws(() => parseKeywords(''), code('EMPTY_INPUT'));
  assert.throws(() => parseKeywords(42), code('INVALID_TYPE'));
  assert.throws(() => parseKeywords('a'.repeat(201)), code('KEYWORD_TOO_LONG'));
  assert.throws(() => parseKeywords(Array.from({ length: 501 }, (_, i) => `k${i}`).join(' ')), code('TOO_MANY_KEYWORDS'));
  assert.throws(() => parseKeywords('beer\u0000'), code('FORBIDDEN_CHARACTERS'));
});
