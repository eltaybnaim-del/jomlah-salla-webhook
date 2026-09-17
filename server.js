const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 10000);
const WEBHOOK_SECRET = process.env.SALLA_WEBHOOK_SECRET || '';

function send(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store'
  });
  res.end(payload);
}

function safeEqualHex(a, b) {
  const left = Buffer.from(String(a || '').replace(/^sha256=/i, '').trim(), 'hex');
  const right = Buffer.from(String(b || '').replace(/^sha256=/i, '').trim(), 'hex');
  if (!left.length || left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function verifySignature(rawBody, providedSignature) {
  if (!WEBHOOK_SECRET || !providedSignature) return false;
  const expected = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');
  return safeEqualHex(expected, providedSignature);
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url === '/health')) {
    return send(res, 200, {
      ok: true,
      service: 'jomlah-salla-webhook',
      webhookConfigured: Boolean(WEBHOOK_SECRET)
    });
  }

  if (req.method !== 'POST' || req.url !== '/webhook') {
    return send(res, 404, { ok: false, error: 'Not found' });
  }

  const chunks = [];
  let size = 0;

  req.on('data', (chunk) => {
    size += chunk.length;
    if (size > 1024 * 1024) {
      res.destroy();
      return;
    }
    chunks.push(chunk);
  });

  req.on('end', () => {
    const rawBody = Buffer.concat(chunks);
    const signature = req.headers['x-salla-signature'];
    const strategy = String(req.headers['x-salla-security-strategy'] || '').toLowerCase();

    if (strategy && strategy !== 'signature') {
      return send(res, 401, { ok: false, error: 'Unsupported security strategy' });
    }

    if (!verifySignature(rawBody, signature)) {
      return send(res, 401, { ok: false, error: 'Invalid webhook signature' });
    }

    let payload;
    try {
      payload = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return send(res, 400, { ok: false, error: 'Invalid JSON' });
    }

    const event = payload?.event || 'unknown';
    const merchant = payload?.merchant || null;

    // Never log access_token / refresh_token or customer/order payloads.
    console.log(JSON.stringify({
      received: true,
      event,
      merchant,
      created_at: payload?.created_at || null
    }));

    // The authorization payload is intentionally not persisted yet.
    // Persistence will be added only after a secure encrypted store is connected.
    if (event === 'app.store.authorize') {
      return send(res, 202, {
        ok: true,
        event,
        note: 'Authorization received securely; encrypted token storage is not enabled yet.'
      });
    }

    return send(res, 200, { ok: true, event });
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`jomlah-salla-webhook listening on ${PORT}`);
});
