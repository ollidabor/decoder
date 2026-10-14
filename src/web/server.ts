import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { DecoderError } from '../errors.ts';
import { redact } from '../redactor.ts';
import { redactWithKey, unredact } from '../unredactor.ts';

const HOST = '127.0.0.1'; // Never exposed to the network.
const PORT = parsePort(process.env['PORT']);
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const MAX_IN_FLIGHT = 4;
const ALLOWED_HOSTS = new Set([`127.0.0.1:${PORT}`, `localhost:${PORT}`]);
const ALLOWED_ORIGINS = new Set([...ALLOWED_HOSTS].map((h) => `http://${h}`));

function parsePort(raw: string | undefined): number {
  if (raw === undefined) return 8787;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error('PORT must be an integer between 1024 and 65535.');
  }
  return port;
}

// Static assets are loaded once from fixed paths: no filesystem lookups per request,
// so path traversal is impossible.
const asset = (name: string): Buffer => readFileSync(new URL(`./public/${name}`, import.meta.url));
const STATIC: ReadonlyMap<string, { body: Buffer; type: string }> = new Map([
  ['/', { body: asset('index.html'), type: 'text/html; charset=utf-8' }],
  ['/app.js', { body: asset('app.js'), type: 'text/javascript; charset=utf-8' }],
  ['/styles.css', { body: asset('styles.css'), type: 'text/css; charset=utf-8' }],
]);

const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
    "form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
};

class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function send(res: ServerResponse, status: number, body: Buffer | string, type: string): void {
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': type, 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

const sendJson = (res: ServerResponse, status: number, data: unknown): void =>
  send(res, status, JSON.stringify(data), 'application/json; charset=utf-8');

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const type = req.headers['content-type'] ?? '';
  if (!/^application\/json(;|$)/i.test(type)) throw new HttpError(415, 'Content-Type must be application/json.');
  const declared = Number(req.headers['content-length'] ?? 0);
  if (declared > MAX_BODY_BYTES) throw new HttpError(413, 'Request body is too large.');

  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).length;
    if (total > MAX_BODY_BYTES) throw new HttpError(413, 'Request body is too large.');
    chunks.push(chunk as Buffer);
  }

  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  } catch {
    throw new HttpError(400, 'Request body must be valid UTF-8 JSON.');
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new HttpError(400, 'Request body must be a JSON object.');
  }
  return data as Record<string, unknown>;
}

/** Only own, string-typed fields are read; anything else in the payload is ignored. */
function field(body: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(body, name) ? body[name] : undefined;
}

async function handleApi(path: string, body: Record<string, unknown>): Promise<unknown> {
  switch (path) {
    case '/api/redact': {
      const keywords = field(body, 'keywords');
      const document = field(body, 'document');
      if (field(body, 'irreversible') === true) {
        return { document: redact(keywords, document) };
      }
      const key = field(body, 'key');
      const result = await redactWithKey(keywords, document, key === '' ? undefined : key);
      return {
        document: result.document,
        count: result.count,
        // The generated key is returned once so the user can store it; it is never logged or persisted.
        ...(result.keyWasGenerated ? { generatedKey: result.key } : {}),
      };
    }
    case '/api/unredact':
      return { document: await unredact(field(body, 'key'), field(body, 'document')) };
    default:
      throw new HttpError(404, 'Not found.');
  }
}

let inFlight = 0;

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  // DNS-rebinding protection: only answer requests addressed to this exact local host.
  if (!ALLOWED_HOSTS.has(req.headers.host ?? '')) throw new HttpError(421, 'Misdirected request.');

  const path = new URL(req.url ?? '/', `http://${HOST}`).pathname;

  if (req.method === 'GET') {
    const file = STATIC.get(path);
    if (!file) throw new HttpError(404, 'Not found.');
    send(res, 200, file.body, file.type);
    return;
  }

  if (req.method !== 'POST' || !path.startsWith('/api/')) throw new HttpError(405, 'Method not allowed.');

  // CSRF protection: browsers always send Origin on cross-site POSTs.
  if (!ALLOWED_ORIGINS.has(req.headers.origin ?? '')) throw new HttpError(403, 'Forbidden origin.');

  if (inFlight >= MAX_IN_FLIGHT) throw new HttpError(503, 'Server busy, try again.');
  inFlight++;
  try {
    sendJson(res, 200, await handleApi(path, await readJson(req)));
  } finally {
    inFlight--;
  }
}

const server = createServer((req, res) => {
  handle(req, res).catch((error: unknown) => {
    // Never log request bodies, keys or documents; only fixed, known messages go back to the client.
    if (error instanceof DecoderError) {
      sendJson(res, 422, { error: error.code, message: error.message });
    } else if (error instanceof HttpError) {
      sendJson(res, error.status, { error: 'HTTP', message: error.message });
    } else {
      sendJson(res, 500, { error: 'INTERNAL', message: 'Unexpected failure.' });
    }
  });
});

server.requestTimeout = 30_000;
server.headersTimeout = 10_000;
server.maxHeadersCount = 50;

server.listen(PORT, HOST, () => {
  process.stdout.write(`Decoder demo running at http://localhost:${PORT} (local only). Ctrl+C to stop.\n`);
});
