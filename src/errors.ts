/**
 * Error codes exposed to callers. Messages are fixed strings and never echo
 * user input, so error output can't leak document content or keys.
 */
export type DecoderErrorCode =
  | 'INVALID_TYPE'
  | 'EMPTY_INPUT'
  | 'INPUT_TOO_LARGE'
  | 'FORBIDDEN_CHARACTERS'
  | 'INVALID_KEYWORDS'
  | 'TOO_MANY_KEYWORDS'
  | 'KEYWORD_TOO_LONG'
  | 'UNTERMINATED_QUOTE'
  | 'RESERVED_MARKER'
  | 'WEAK_KEY'
  | 'MISSING_ENVELOPE'
  | 'MALFORMED_ENVELOPE'
  | 'DECRYPTION_FAILED';

export class DecoderError extends Error {
  readonly code: DecoderErrorCode;

  constructor(code: DecoderErrorCode, message: string) {
    super(message);
    this.name = 'DecoderError';
    this.code = code;
  }
}
