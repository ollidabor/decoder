import { DecoderError } from './errors.ts';
import { parseKeywords } from './keywords.ts';
import { validateDocument } from './validation.ts';
import { ENVELOPE_MARKER } from './envelope.ts';

/** Fixed-width mask: the original length of a redacted term is not revealed. */
export const MASK = 'XXXX';

export interface Redaction {
  /** Index of the mask inside the redacted text (UTF-16 code units). */
  readonly offset: number;
  /** The original text that was removed. */
  readonly original: string;
}

export interface RedactionResult {
  readonly text: string;
  readonly redactions: readonly Redaction[];
}

const WORD_CHAR = /[\p{L}\p{N}_]/u;
const NOT_WORD_BEFORE = '(?<![\\p{L}\\p{N}_])';
const NOT_WORD_AFTER = '(?![\\p{L}\\p{N}_])';

// Every user-supplied character is escaped, so keywords are matched literally and
// can never inject regex syntax.
const escapeRegExp = (s: string): string => s.replace(/[\\^$.*+?()[\]{}|/]/g, '\\$&');

interface TrieNode {
  readonly children: Map<string, { char: string; node: TrieNode }>;
  terminal: boolean;
}

const newNode = (): TrieNode => ({ children: new Map(), terminal: false });

/**
 * Compiles the terms into a prefix trie and then into one regex. Shared prefixes
 * are tested once, so matching cost grows with term length, not with the number of
 * terms. Quantifiers are only `\s+` between phrase words, never nested, so the
 * pattern cannot backtrack catastrophically (ReDoS-safe).
 */
function trieToPattern(node: TrieNode, lastChar: string): string {
  const branches: string[] = [];
  for (const { char, node: child } of node.children.values()) {
    branches.push((char === ' ' ? '\\s+' : escapeRegExp(char)) + trieToPattern(child, char));
  }
  // Ending here is tried last so that longer terms win ("Boston Red Sox" over "Boston").
  // Whole-word rule: a term ending in a word character must not be followed by one.
  if (node.terminal) branches.push(WORD_CHAR.test(lastChar) ? NOT_WORD_AFTER : '');
  if (branches.length === 1) return branches[0]!;
  return `(?:${branches.join('|')})`;
}

export function buildMatcher(terms: readonly string[]): RegExp {
  const root = newNode();
  for (const term of terms) {
    let node = root;
    for (const char of term) {
      const key = char.toLowerCase();
      let edge = node.children.get(key);
      if (!edge) {
        edge = { char, node: newNode() };
        node.children.set(key, edge);
      }
      node = edge.node;
    }
    node.terminal = true;
  }

  // Whole-word rule at the start: a term starting with a word character must not be
  // preceded by one ("beer" does not match inside "rootbeer").
  const starts = [...root.children.values()].map(({ char, node }) => {
    const guard = WORD_CHAR.test(char) ? NOT_WORD_BEFORE : '';
    return guard + escapeRegExp(char) + trieToPattern(node, char);
  });
  return new RegExp(starts.join('|'), 'giu');
}

/**
 * Core redaction: case-insensitive, whole-word, whitespace-tolerant inside phrases
 * ("Boston\n  Red Sox" still matches "Boston Red Sox").
 */
export function redactDetailed(keywords: unknown, document: unknown): RedactionResult {
  const terms = parseKeywords(keywords);
  const text = validateDocument(document);
  if (text.includes(ENVELOPE_MARKER)) {
    throw new DecoderError('RESERVED_MARKER', 'Document already contains a decoder envelope; unredact it first.');
  }

  const matcher = buildMatcher(terms);
  const redactions: Redaction[] = [];
  let out = '';
  let cursor = 0;

  for (const match of text.matchAll(matcher)) {
    const index = match.index;
    out += text.slice(cursor, index);
    redactions.push({ offset: out.length, original: match[0] });
    out += MASK;
    cursor = index + match[0].length;
  }
  out += text.slice(cursor);

  return { text: out, redactions };
}

/** Assignment Part 1: returns the document with every keyword/phrase replaced by XXXX. */
export function redact(keywords: unknown, document: unknown): string {
  return redactDetailed(keywords, document).text;
}
