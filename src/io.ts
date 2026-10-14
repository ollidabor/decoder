import { open as openFile } from 'node:fs/promises';
import { DecoderError } from './errors.ts';

const MAX_FILE_BYTES = 12 * 1024 * 1024;
const utf8 = new TextDecoder('utf-8', { fatal: true });

/** Rejects binary / invalid UTF-8 instead of silently mangling it. Strips a leading BOM. */
function decode(bytes: Uint8Array): string {
  try {
    return utf8.decode(bytes);
  } catch {
    throw new DecoderError('FORBIDDEN_CHARACTERS', 'Input is not valid UTF-8 text.');
  }
}

/** Reads a regular file only (no devices/FIFOs), with a hard size cap. */
export async function readTextFile(path: string): Promise<string> {
  const handle = await openFile(path, 'r');
  try {
    const info = await handle.stat();
    if (!info.isFile()) {
      throw new DecoderError('INVALID_TYPE', 'Input path must be a regular file.');
    }
    if (info.size > MAX_FILE_BYTES) {
      throw new DecoderError('INPUT_TOO_LARGE', 'Input file is too large.');
    }
    return decode(await handle.readFile());
  } finally {
    await handle.close();
  }
}

export async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > MAX_FILE_BYTES) {
      throw new DecoderError('INPUT_TOO_LARGE', 'Standard input is too large.');
    }
    chunks.push(buf);
  }
  return decode(Buffer.concat(chunks));
}

/**
 * Writes owner-only (0600) since outputs may hold classified text or keys.
 * Refuses to overwrite an existing file unless `force` is set.
 */
export async function writePrivateFile(path: string, content: string, force: boolean): Promise<void> {
  const handle = await openFile(path, force ? 'w' : 'wx', 0o600);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(content, 'utf8');
  } finally {
    await handle.close();
  }
}
