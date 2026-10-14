// All output is written via .value / .textContent - never innerHTML - so document
// content can never be interpreted as markup or script (no XSS). CSP enforces the same.
'use strict';

const $ = (id) => document.getElementById(id);
const status = $('status');

function setStatus(message, isError) {
  status.textContent = message;
  status.className = isError ? 'error' : 'ok';
}

async function post(path, payload) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    credentials: 'omit',
    cache: 'no-store',
  });
  const data = await res.json().catch(() => ({ message: 'Invalid server response.' }));
  if (!res.ok) throw new Error(data.message || 'Request failed.');
  return data;
}

$('redact-btn').addEventListener('click', async () => {
  setStatus('Redacting...', false);
  try {
    const data = await post('/api/redact', {
      keywords: $('keywords').value,
      document: $('source').value,
      key: $('redact-key').value,
      irreversible: $('irreversible').checked,
    });
    $('redacted').value = data.document;
    $('restored').value = '';
    if (data.generatedKey) {
      $('unredact-key').value = data.generatedKey;
      setStatus(`Redacted ${data.count} occurrence(s). A key was generated and placed in the Unredact panel - store it securely.`, false);
    } else if (typeof data.count === 'number') {
      $('unredact-key').value = '';
      setStatus(`Redacted ${data.count} occurrence(s). Enter your key to unredact.`, false);
    } else {
      setStatus('Irreversible redaction done. This document cannot be restored.', false);
    }
  } catch (err) {
    setStatus(err.message, true);
  }
});

$('unredact-btn').addEventListener('click', async () => {
  setStatus('Unredacting...', false);
  try {
    const data = await post('/api/unredact', { key: $('unredact-key').value, document: $('redacted').value });
    $('restored').value = data.document;
    setStatus('Document restored.', false);
  } catch (err) {
    $('restored').value = '';
    setStatus(err.message, true);
  }
});

$('toggle-key').addEventListener('click', (event) => {
  const input = $('unredact-key');
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  event.currentTarget.textContent = show ? 'Hide' : 'Show';
  event.currentTarget.setAttribute('aria-pressed', String(show));
});
