# decoder

A lightweight, zero-runtime-dependency tool to redact keywords and phrases from text
documents and restore them later with a key.

- **Redact (Part 1):** replaces every keyword/phrase with `XXXX`.
- **Unredact (Part 2):** restores the original text using a key.

## Requirements

- Node.js 22.18+ (Node 24 recommended; TypeScript runs natively, no build step)

## Setup

```bash
npm ci        # dev tooling only: typescript + @types/node
npm run check # typecheck + tests
```

## Usage

```bash
# Guided demo with fictional sample data
npm run demo

# CLI
node src/cli.ts redact --keywords-file samples/keywords.txt --in samples/document.txt \
  --out out/doc.redacted.txt --key-out out/doc.key
node src/cli.ts unredact --key-file out/doc.key --in out/doc.redacted.txt

# Part 1 only (irreversible)
node src/cli.ts redact --irreversible --keywords 'beer "Boston Red Sox"' < samples/document.txt

# Local web demo (binds to 127.0.0.1 only)
npm run web
```

Run `node src/cli.ts --help` for all options.

## Keyword format

Terms separated by spaces and/or commas; phrases wrapped in single or double quotes:

```
Hello world "Boston Red Sox", 'Pepperoni Pizza', 'Cheese Pizza', beer
```

Matching is case-insensitive, whole-word, and tolerant of line breaks inside phrases.

## Security notes

- Keys are never accepted as command-line arguments; use `--key-file` or `DECODER_KEY`.
- Output files are created with `0600` permissions and are never overwritten without `--force`.
- Never commit real documents or keys. `.gitignore` excludes `out/`, `*.key`, `*.redacted.txt` and `.env*`.
