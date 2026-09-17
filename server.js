const http = require('http');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = Number(process.env.PORT || 10000);
const WEBHOOK_SECRET = process.env.SALLA_WEBHOOK_SECRET || '';
const DATABASE_URL = process.env.DATABASE_URL || '';
const DATABASE_SSL = String(process.env.DATABASE_SSL || 'false').toLowerCase() === 'true';
const TOKEN_ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY || '';

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: DATABASE_SSL ? { rejectUnauthorized: false } : false,
      max: 5,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000
    })
  : null;

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
  const cleanA = String(a || '').replace(/^sha256=/i, '').trim();
  const cleanB = String(b || '').replace(/^sha256=/i, '').trim();
  if (!/^[a-f0-9]{64}$/i.test(cleanA) || !/^[a-f0-9]{64}$/i.test(cleanB)) return false;
  const left = Buffer.from(cleanA, 'hex');
  const right = Buffer.from(cleanB, 'hex');
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

function getEncryptionKey() {
  if (!TOKEN_ENCRYPTION_KEY) throw new Error('TOKEN_ENCRYPTION_KEY is not configured');
  const key = Buffer.from(TOKEN_ENCRYPTION_KEY, 'base64');
  if (key.length !== 32) throw new Error('TOKEN_ENCRYPTION_KEY must decode to exactly 32 bytes');
  return key;
}

function encryptSecret(value) {
  if (!value) return null;
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

async function ensureSchema() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS salla_tokens (
      merchant_id BIGINT PRIMARY KEY,
      access_token_enc TEXT NOT NULL,
      refresh_token_enc TEXT,
      expires_at TIMESTAMPTZ,
      scope TEXT,
      token_type TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function storeAuthorization(payload) {
  if (!pool) throw new Error('DATABASE_URL is not configured');
  const merchant = payload?.merchant;
  const data = payload?.data || {};
  if (!merchant || !data.access_token) throw new Error('Authorization payload is missing merchant or access_token');

  const accessTokenEnc = encryptSecret(data.access_token);
  const refreshTokenEnc = data.refresh_token ? encryptSecret(data.refresh_token) : null;
  const expiresAt = data.expires ? new Date(Number(data.expires) * 1000) : null;

  await pool.query(
    `INSERT INTO salla_tokens
      (merchant_id, access_token_enc, refresh_token_enc, expires_at, scope, token_type, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW())
     ON CONFLICT (merchant_id) DO UPDATE SET
       access_token_enc = EXCLUDED.access_token_enc,
       refresh_token_enc = EXCLUDED.refresh_token_enc,
       expires_at = EXCLUDED.expires_at,
       scope = EXCLUDED.scope,
       token_type = EXCLUDED.token_type,
       updated_at = NOW()`,
    [
      String(merchant),
      accessTokenEnc,
      refreshTokenEnc,
      expiresAt,
      data.scope || null,
      data.token_type || null
    ]
  );
}

async function deleteAuthorization(merchant) {
  if (!pool || !merchant) return;
  await pool.query('DELETE FROM salla_tokens WHERE merchant_id = $1', [String(merchant)]);
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url === '/health')) {
    return send(res, 200, {
      ok: true,
      service: 'jomlah-salla-webhook',
      webhookConfigured: Boolean(WEBHOOK_SECRET),
      databaseConfigured: Boolean(DATABASE_URL),
      encryptionConfigured: Boolean(TOKEN_ENCRYPTION_KEY)
    });
  }

  if (req.method !== 'POST' || req.url !== '/webhook') {
    return send(res, 404, { ok: false, error: 'Not found' });
  }

  const chunks = [];
  let size = 0;
  let aborted = false;

  req.on('data', (chunk) => {
    if (aborted) return;
    size += chunk.length;
    if (size > 1024 * 1024) {
      aborted = true;
      return send(res, 413, { ok: false, error: 'Payload too large' });
    }
    chunks.push(chunk);
  });

  req.on('end', async () => {
    if (aborted) return;

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

    // Never log access_token, refresh_token, customer, or order payload contents.
    console.log(JSON.stringify({
      received: true,
      event,
      merchant,
      created_at: payload?.created_at || null
    }));

    try {
      if (event === 'app.store.authorize') {
        await storeAuthorization(payload);
        return send(res, 200, { ok: true, event, stored: true });
      }

      if (event === 'app.uninstalled') {
        await deleteAuthorization(merchant);
        return send(res, 200, { ok: true, event, tokenRemoved: true });
      }

      return send(res, 200, { ok: true, event });
    } catch (error) {
      console.error(JSON.stringify({
        event,
        merchant,
        error: error.message
      }));
      return send(res, 503, { ok: false, error: 'Temporary storage failure' });
    }
  });
});

async function start() {
  try {
    await ensureSchema();
  } catch (error) {
    console.error(`Database initialization warning: ${error.message}`);
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`jomlah-salla-webhook listening on ${PORT}`);
  });
}

start();
