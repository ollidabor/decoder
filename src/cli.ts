#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { DecoderError } from './errors.ts';
import { readStdin, readTextFile, writePrivateFile } from './io.ts';
import { redact } from './redactor.ts';
import { redactWithKey, unredact } from './unredactor.ts';

const USAGE = `decoder - redact and unredact text documents

Usage:
  decoder redact   (--keywords <list> | --keywords-file <path>) [--in <path>] [--out <path>]
                   [--key-file <path> | --key-out <path>] [--irreversible] [--force]
  decoder unredact  --key-file <path> [--in <path>] [--out <path>] [--force]

Input defaults to stdin and output to stdout.

Keys are never accepted as command-line arguments (they would end up in shell history
and the process list). Provide them through --key-file or the DECODER_KEY env variable.

  redact        Part 1 + 2. Replaces keywords with XXXX and appends an encrypted
                envelope. Without a key, a strong key is generated and written to
                --key-out (0600) or printed to stderr.
  --irreversible  Part 1 only: plain redaction, no envelope, nothing can be restored.
  unredact      Part 2. Restores the original text using the key.
`;

const options = {
  keywords: { type: 'string' },
  'keywords-file': { type: 'string' },
  in: { type: 'string' },
  out: { type: 'string' },
  'key-file': { type: 'string' },
  'key-out': { type: 'string' },
  irreversible: { type: 'boolean', default: false },
  force: { type: 'boolean', default: false },
  help: { type: 'boolean', short: 'h', default: false },
} as const;

type Values = ReturnType<typeof parseArgs<{ options: typeof options; allowPositionals: true }>>['values'];

class UsageError extends Error {}

const readInput = (path: string | undefined): Promise<string> => (path ? readTextFile(path) : readStdin());

async function emit(path: string | undefined, content: string, force: boolean): Promise<void> {
  if (path) await writePrivateFile(path, content, force);
  else process.stdout.write(content);
}

async function readKey(values: Values, required: boolean): Promise<string | undefined> {
  if (values['key-file']) return (await readTextFile(values['key-file'])).trim();
  const fromEnv = process.env['DECODER_KEY'];
  if (fromEnv) return fromEnv;
  if (required) throw new UsageError('A key is required: use --key-file <path> or DECODER_KEY.');
  return undefined;
}

async function runRedact(values: Values): Promise<void> {
  if (values.keywords !== undefined && values['keywords-file'] !== undefined) {
    throw new UsageError('Use either --keywords or --keywords-file, not both.');
  }
  const keywords = values['keywords-file'] ? await readTextFile(values['keywords-file']) : values.keywords;
  if (keywords === undefined) throw new UsageError('Missing --keywords or --keywords-file.');
  const document = await readInput(values.in);

  if (values.irreversible) {
    await emit(values.out, redact(keywords, document), values.force);
    return;
  }

  const result = await redactWithKey(keywords, document, await readKey(values, false));
  await emit(values.out, result.document, values.force);
  process.stderr.write(`Redacted ${result.count} occurrence(s).\n`);

  if (result.keyWasGenerated) {
    if (values['key-out']) {
      await writePrivateFile(values['key-out'], `${result.key}\n`, values.force);
      process.stderr.write(`Key written to ${values['key-out']} (permissions 0600). Store it securely.\n`);
    } else {
      process.stderr.write(`Generated key (store it securely, it is not saved anywhere):\n${result.key}\n`);
    }
  }
}

async function runUnredact(values: Values): Promise<void> {
  const key = await readKey(values, true);
  const document = await readInput(values.in);
  await emit(values.out, await unredact(key, document), values.force);
}

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({ args: argv, options, allowPositionals: true, strict: true });
  const [command, ...extra] = positionals;

  if (values.help || command === undefined) {
    process.stdout.write(USAGE);
    return command === undefined && !values.help ? 1 : 0;
  }
  if (extra.length > 0) throw new UsageError('Unexpected extra arguments.');

  switch (command) {
    case 'redact':
      await runRedact(values);
      return 0;
    case 'unredact':
      await runUnredact(values);
      return 0;
    default:
      throw new UsageError('Unknown command. Use "redact" or "unredact".');
  }
}

/** Only fixed, known messages are printed; raw errors could include file contents or paths. */
function describe(error: unknown): string {
  if (error instanceof DecoderError) return `${error.code}: ${error.message}`;
  if (error instanceof UsageError) return `USAGE: ${error.message}\nRun with --help for usage.`;
  const code = (error as { code?: unknown } | null)?.code;
  switch (code) {
    case 'ENOENT':
      return 'IO: File not found.';
    case 'EEXIST':
      return 'IO: Output file already exists (use --force to overwrite).';
    case 'EACCES':
    case 'EPERM':
      return 'IO: Permission denied.';
    case 'EISDIR':
      return 'IO: Path is a directory.';
    case 'ERR_PARSE_ARGS_UNKNOWN_OPTION':
    case 'ERR_PARSE_ARGS_INVALID_OPTION_VALUE':
    case 'ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL':
      return 'USAGE: Invalid option.\nRun with --help for usage.';
    default:
      return 'ERROR: Unexpected failure.';
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`${describe(error)}\n`);
    process.exitCode = 1;
  },
);
