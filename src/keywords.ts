import { DecoderError } from './errors.ts';
import { assertSafeText, assertString, LIMITS } from './validation.ts';

/** Opening quote -> matching closing quote. Smart quotes are accepted too. */
const QUOTES: ReadonlyMap<string, string> = new Map([
  ['"', '"'],
  ["'", "'"],
  ['“', '”'], // “ ”
  ['‘', '’'], // ‘ ’
]);

const isSeparator = (ch: string): boolean => ch === ',' || /\s/u.test(ch);

/**
 * Parses a censor list such as:
 *   Hello world "Boston Red Sox", 'Pepperoni Pizza', 'Cheese Pizza', beer
 * into ["Hello", "world", "Boston Red Sox", "Pepperoni Pizza", "Cheese Pizza", "beer"].
 *
 * Rules: terms are separated by whitespace and/or commas; phrases are wrapped in
 * single or double quotes. A quote only opens a phrase at the start of a term, so
 * apostrophes inside words (e.g. don't) are kept literally. Duplicates are removed
 * case-insensitively.
 */
export function parseKeywords(input: unknown): string[] {
  assertString(input, 'Keywords');
  const text = input.normalize('NFC');
  assertSafeText(text, 'Keywords', LIMITS.maxKeywordInputChars);

  const terms: string[] = [];
  let i = 0;

  while (i < text.length) {
    const ch = text[i]!;
    if (isSeparator(ch)) {
      i++;
      continue;
    }

    const closer = QUOTES.get(ch);
    if (closer !== undefined) {
      const end = text.indexOf(closer, i + 1);
      if (end === -1) {
        throw new DecoderError('UNTERMINATED_QUOTE', 'Keywords contain an unterminated quoted phrase.');
      }
      terms.push(text.slice(i + 1, end));
      i = end + 1;
      continue;
    }

    let end = i;
    while (end < text.length && !isSeparator(text[end]!)) end++;
    terms.push(text.slice(i, end));
    i = end;
  }

  const seen = new Set<string>();
  const result: string[] = [];
  for (const raw of terms) {
    const term = raw.trim().replace(/\s+/gu, ' ');
    if (term.length === 0) continue;
    if (term.length > LIMITS.maxKeywordChars) {
      throw new DecoderError('KEYWORD_TOO_LONG', `Each keyword must be at most ${LIMITS.maxKeywordChars} characters.`);
    }
    const folded = term.toLocaleLowerCase('und');
    if (seen.has(folded)) continue;
    seen.add(folded);
    result.push(term);
  }

  if (result.length === 0) {
    throw new DecoderError('INVALID_KEYWORDS', 'No keywords or phrases were provided.');
  }
  if (result.length > LIMITS.maxKeywords) {
    throw new DecoderError('TOO_MANY_KEYWORDS', `At most ${LIMITS.maxKeywords} keywords are allowed.`);
  }
  return result;
}
