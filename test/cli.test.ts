import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CLI = new URL('../src/cli.ts', import.meta.url).pathname;
const run = (args: string[], input?: string | Buffer, env: NodeJS.ProcessEnv = {}) =>
  spawnSync(process.execPath, [CLI, ...args], {
    input,
    encoding: 'utf8',
    env: { PATH: process.env['PATH'], ...env },
  });

test('CLI: full redact -> unredact round trip through files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'decoder-'));
  try {
    const doc = 'Agent met at the Boston Red Sox game with a beer.\n';
    writeFileSync(join(dir, 'in.txt'), doc);
    const r = run([
      'redact', '--keywords', `"Boston Red Sox" beer`, '--in', join(dir, 'in.txt'),
      '--out', join(dir, 'out.txt'), '--key-out', join(dir, 'k.key'),
    ]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(statSync(join(dir, 'k.key')).mode & 0o777, 0o600);
    assert.equal(statSync(join(dir, 'out.txt')).mode & 0o777, 0o600);
    assert.ok(!r.stderr.includes(readFileSync(join(dir, 'k.key'), 'utf8').trim()), 'key must not be echoed');

    const u = run(['unredact', '--key-file', join(dir, 'k.key'), '--in', join(dir, 'out.txt')]);
    assert.equal(u.status, 0, u.stderr);
    assert.equal(u.stdout, doc);

    const again = run(['redact', '--keywords', 'beer', '--in', join(dir, 'in.txt'), '--out', join(dir, 'out.txt')]);
    assert.equal(again.status, 1);
    assert.match(again.stderr, /already exists/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI: Part 1 irreversible via stdin, key from env', () => {
  const r = run(['redact', '--irreversible', '--keywords', 'beer'], 'cold beer\n');
  assert.equal(r.status, 0);
  assert.equal(r.stdout, 'cold XXXX\n');

  const sealed = run(['redact', '--keywords', 'beer'], 'cold beer\n', { DECODER_KEY: 'env-provided-key-123' });
  const back = run(['unredact'], sealed.stdout, { DECODER_KEY: 'env-provided-key-123' });
  assert.equal(back.stdout, 'cold beer\n');
});

test('CLI: errors never echo input content', () => {
  const r = run(['redact', '--keywords', '"TOP-SECRET-PHRASE'], 'TOP-SECRET-PHRASE doc');
  assert.equal(r.status, 1);
  assert.ok(!r.stderr.includes('TOP-SECRET'));
  assert.match(r.stderr, /UNTERMINATED_QUOTE/);

  const bad = run(['unredact', '--key', 'leaky'], 'x');
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /Invalid option/);

  const bin = run(['redact', '--keywords', 'x'], Buffer.from([0xff, 0xfe, 0x20, 0x78]));
  assert.equal(bin.status, 1);
  assert.match(bin.stderr, /not valid UTF-8/);
});
