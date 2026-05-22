const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// --- Configuration ---
// JWT_SECRET hardening: refuse to start without one, and refuse to start
// with the historical placeholder (which leaked into a few earlier
// builds). A short secret in dev is fine; production gets a length
// warning but is allowed to proceed if NODE_ENV is unset.
const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = process.env.NODE_ENV || 'development';

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is required. Generate one with: openssl rand -hex 32');
  process.exit(1);
}
if (JWT_SECRET === 'change-me-in-production') {
  console.error('FATAL: JWT_SECRET is the placeholder value. Replace with a real secret.');
  process.exit(1);
}
if (NODE_ENV === 'production' && JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET must be at least 32 characters in production.');
  process.exit(1);
}
if (JWT_SECRET.length < 32) {
  console.warn('WARN: JWT_SECRET is shorter than 32 chars — fine for dev, not for production.');
}

const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const PORT = process.env.PORT || 3000;

// Railway terminates TLS at a proxy, so trust the first proxy hop to get
// the real client IP for rate-limit keying.
app.set('trust proxy', 1);

// --- Middleware ---
app.use(helmet());

// CORS: comma-separated allowlist via CORS_ALLOWED_ORIGINS. Mobile apps
// don't send an Origin header, so they're always allowed through; this
// only gates the Flutter web flavors. In production the allowlist is
// REQUIRED — refusing to start avoids the "accidentally permissive"
// failure mode. In development we fall back to permissive with a warning.
//
// Loopback origins (http://localhost:<port>, http://127.0.0.1:<port>,
// http://[::1]:<port>) are always accepted in addition to the allowlist
// so Flutter Web's random dev port doesn't require an env-var update
// every `flutter run`. A remote attacker cannot forge a loopback Origin
// header — browsers only set Origin=http://localhost:... when the page
// is actually served from localhost on the user's own machine, so this
// doesn't widen the public attack surface. DNS rebinding can still
// resolve a public hostname to 127.0.0.1, but rebinding doesn't change
// the Origin header the browser sends, so it doesn't bypass this gate.
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
function isLoopbackOrigin(origin) {
  try {
    const url = new URL(origin);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
    return LOOPBACK_HOSTS.has(url.hostname);
  } catch {
    return false;
  }
}

// Normalize origins for comparison: lowercase scheme+host, strip trailing
// slash. The browser sends `https://nexbus.example` with no slash, but
// operators routinely paste `https://nexbus.example/` into the env var and
// then spend an hour wondering why the allowlist isn't matching.
function normalizeOrigin(o) {
  return o.trim().replace(/\/+$/, '').toLowerCase();
}

const RAW_CORS_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || '').trim();
let corsOptions;
if (RAW_CORS_ORIGINS) {
  const allowed = new Set(
    RAW_CORS_ORIGINS.split(',').map(normalizeOrigin).filter(Boolean)
  );
  corsOptions = {
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);  // mobile / curl
      if (isLoopbackOrigin(origin)) return cb(null, true);
      if (allowed.has(normalizeOrigin(origin))) return cb(null, true);
      // Silent rejection is the default `cors` behavior: the request still
      // reaches the handler, but the response omits Access-Control-Allow-
      // Origin and the browser kills it before JS sees anything (Dio
      // surfaces this as "XMLHttpRequest onError callback was called"
      // with null status/body). Logging the rejected origin here turns an
      // invisible failure into one operators can resolve from the Render
      // logs — read the origin, append it to CORS_ALLOWED_ORIGINS, restart.
      console.warn(
        `CORS rejected origin "${origin}". Add it to CORS_ALLOWED_ORIGINS ` +
        `(current allowlist: ${[...allowed].join(', ') || '(empty)'} ` +
        `plus loopback) and restart.`
      );
      cb(null, false);
    },
  };
} else if (NODE_ENV === 'production') {
  console.error('FATAL: CORS_ALLOWED_ORIGINS must be set in production. Comma-separated list of allowed web origins.');
  process.exit(1);
} else {
  console.warn('WARN: CORS allowlist not configured — allowing all origins (NODE_ENV != production).');
  corsOptions = undefined;
}
app.use(cors(corsOptions));

app.use(express.json({ limit: '1mb' }));

// --- Rate limiting ---
const globalLimiter = rateLimit({
  windowMs: 60_000,
  limit: Number(process.env.RATE_LIMIT_GLOBAL) || 600,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests, slow down' },
  skip: (req) => req.path === '/health',
});
const authLimiter = rateLimit({
  windowMs: 60_000,
  limit: Number(process.env.RATE_LIMIT_AUTH) || 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { success: false, message: 'Too many auth attempts, try again in a minute' },
});
app.use(globalLimiter);
app.use('/auth', authLimiter);

// --- Database Pool ---
// Connection-string precedence: APP_DATABASE_URL (the nexbus_app role, RLS
// applies) wins; falls back to DATABASE_URL (the migration owner role, RLS
// bypassed) for local dev / pre-activation. Migration scripts (migrate.js,
// migrate-up.js) read DATABASE_URL directly — they always run as owner.
//
// Session timezone is set via the Postgres startup option `-c timezone=...`
// so it's applied before the client is handed out — avoids the race the
// pool's async 'connect' handler would introduce (triggered pg's
// deprecation warning about querying a client that's still executing a
// query).
const RUNTIME_DATABASE_URL = process.env.APP_DATABASE_URL || process.env.DATABASE_URL;

// Replica is optional. When APP_DATABASE_REPLICA_URL isn't set we just
// reuse the primary URL — every request behaves as if there's no replica
// and the regulator surface lands on the same node as everything else.
// This keeps dev simple and lets prod toggle the replica on by setting
// the env var (no code change required).
const RUNTIME_REPLICA_URL = process.env.APP_DATABASE_REPLICA_URL || RUNTIME_DATABASE_URL;
const REPLICA_CONFIGURED  = !!process.env.APP_DATABASE_REPLICA_URL;

const pool = new Pool({
  connectionString: RUNTIME_DATABASE_URL,
  ssl: RUNTIME_DATABASE_URL ? { rejectUnauthorized: false } : false,
  max: Number(process.env.PG_POOL_MAX) || 50,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  options: '-c timezone=Africa/Douala',
});

pool.on('error', (err) => {
  console.error('Unexpected pool error:', err.message);
});

// Read replica pool. Smaller default max — replica usage is bursty
// (regulator dashboards, PDF generation) and we don't want a runaway
// query saturating connections.
const replicaPool = new Pool({
  connectionString: RUNTIME_REPLICA_URL,
  ssl: RUNTIME_REPLICA_URL ? { rejectUnauthorized: false } : false,
  max: Number(process.env.PG_REPLICA_POOL_MAX) || 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  options: '-c timezone=Africa/Douala -c statement_timeout=30000',
});

replicaPool.on('error', (err) => {
  console.error('Unexpected replicaPool error:', err.message);
});

// Return timestamps as plain local time strings (Africa/Douala = UTC+1).
// Strips the timezone suffix so Flutter receives a bare datetime string
// (e.g. "2026-03-21T23:20:00" instead of "2026-03-21T23:20:00+01"),
// preventing double-conversion since the app treats bare strings as local.
const pg = require('pg');
const TIMESTAMPTZ_OID = 1184;
const TIMESTAMP_OID = 1114;

function stripTz(val) {
  if (!val) return val;
  return val.replace(' ', 'T').replace(/[+-]\d{2}(:\d{2})?$/, '');
}

pg.types.setTypeParser(TIMESTAMPTZ_OID, stripTz);
pg.types.setTypeParser(TIMESTAMP_OID, (val) => val ? val.replace(' ', 'T') : val);

// --- SQL Field Maps (snake_case → camelCase for Flutter) ---
const FIELDS = {
  agency: `id, name, logo_url AS "logoUrl", park_name AS "parkName", contact_phone AS "contactPhone", is_active AS "isActive", created_at AS "createdAt", updated_at AS "updatedAt"`,
  staff: `id, agency_id AS "agencyId", phone, name, role, is_active AS "isActive", last_login AS "lastLogin", created_at AS "createdAt", updated_at AS "updatedAt"`,
  route: `id, agency_id AS "agencyId", origin, destination, bus_capacity AS "busCapacity", category, departure_times AS "departureTimes", is_active AS "isActive", created_at AS "createdAt", updated_at AS "updatedAt"`,
  // updatedByName: subquery resolves staff_users.name for the seller who
  // last touched the row. Same-agency RLS (migration 013) means every
  // role that can read the departure can also resolve the name. The
  // SELECT projection of staff_users never includes pin_hash, so this
  // doesn't widen the credential surface.
  departure: `id, route_id AS "routeId", agency_id AS "agencyId", seats_sold AS "seatsSold", seats_reserved AS "seatsReserved", total_seats AS "totalSeats", category, status, scheduled_time AS "scheduledTime", departed_at AS "departedAt", updated_by AS "updatedBy", (SELECT name FROM staff_users WHERE id = departures.updated_by) AS "updatedByName", created_at AS "createdAt", updated_at AS "updatedAt", bus_number AS "busNumber", remarks`,
};

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

// Best-effort JWT decoding. Runs globally so req.staff is populated
// before withRequestDb sets the per-request RLS context. Invalid or
// missing tokens leave req.staff undefined — `authenticate` then
// rejects, but anonymous routes (passenger reads, /events) proceed
// normally.
function decodeJwt(req, _res, next) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    try {
      req.staff = jwt.verify(header.slice(7), JWT_SECRET);
    } catch {
      // Leave req.staff undefined; authenticate() will 401 if the route
      // requires a valid token.
    }
  }
  next();
}

// Per-request DB client factory. Opens a transaction, sets the RLS
// identity GUCs from req.staff (or NULLs for anonymous), exposes req.db
// for handlers to query against, and finalizes (COMMIT on 2xx, ROLLBACK
// otherwise) when the response ends.
//
// Variants:
//   makeRequestDb(pool)                                            // primary, read+write
//   makeRequestDb(replicaPool, { readOnly: true,                   // replica, read-only,
//                                fallbackPool: pool,               //   fall back to primary
//                                skipPaths: [...] })               //   when replica errors
//
// Bootstrap paths skip this:
//   /health      — pings pool directly, no identity needed
//   /health/*    — including replica-lag, no transaction wrapper
//   /auth/login  — runs before identity is established; uses
//                  fn_authenticate_staff via the shared pool
//   /internal/*  — admin endpoints (e.g. MV refresh) bypass the
//                  per-request transaction because some operations
//                  (REFRESH MATERIALIZED VIEW CONCURRENTLY) cannot
//                  run inside a tx block.
//
// All app handlers (this file + routers under ./routes/) use req.db.
// RLS only starts gating access once the runtime pool's connection
// string switches from the migration owner to the nexbus_app role per
// migration 010's activation checklist. Until then this middleware
// runs every request through a transaction against the owner role
// (which bypasses RLS) — correct behaviour, just no enforcement yet.
function makeRequestDb(targetPool, opts = {}) {
  const {
    readOnly = false,
    fallbackPool = null,
    skipPaths = [],
    label = 'primary',
  } = opts;

  return function requestDb(req, res, next) {
    if (req.path === '/health' || req.path.startsWith('/health/')) return next();
    if (req.path === '/auth/login') return next();
    if (req.path.startsWith('/internal/')) return next();
    if (skipPaths.some((p) => req.path === p || req.path.startsWith(p))) {
      return next();
    }

    targetPool.connect().then(async (client) => {
      let finalized = false;

      const finalize = async () => {
        if (finalized) return;
        finalized = true;
        try {
          if (readOnly) {
            // Replica transactions are read-only; rollback is the
            // canonical close (commit on read-only is harmless but
            // logged as a no-op).
            await client.query('ROLLBACK').catch(() => {});
          } else if (res.statusCode >= 400) {
            await client.query('ROLLBACK').catch(() => {});
          } else {
            await client.query('COMMIT').catch(() => {});
          }
        } finally {
          client.release();
        }
      };

      try {
        await client.query(readOnly ? 'BEGIN READ ONLY' : 'BEGIN');
        await client.query(
          'SELECT fn_set_request_context($1, $2, $3)',
          [
            req.staff?.role     || null,
            req.staff?.agencyId || null,
            req.staff?.id       || null,
          ]
        );
        req.db = client;
        req.dbSource = label;
        res.on('finish', finalize);
        res.on('close',  finalize);
        next();
      } catch (e) {
        finalized = true;
        try { await client.query('ROLLBACK'); } catch { /* ignore */ }
        client.release();
        if (fallbackPool && fallbackPool !== targetPool) {
          console.warn(`requestDb[${label}] failed (${e.message}); falling back to primary`);
          return makeRequestDb(fallbackPool, { readOnly, label: 'primary-fallback' })(req, res, next);
        }
        next(e);
      }
    }).catch((e) => {
      if (fallbackPool && fallbackPool !== targetPool) {
        console.warn(`requestDb[${label}] connect failed (${e.message}); falling back to primary`);
        return makeRequestDb(fallbackPool, { readOnly, label: 'primary-fallback' })(req, res, next);
      }
      next(e);
    });
  };
}

// Back-compat alias: existing tests / docs reference withRequestDb by
// name. New code should use makeRequestDb directly.
const withRequestDb = makeRequestDb(pool, {
  skipPaths: ['/regulator'],   // regulator router brings its own replica-bound middleware
  label: 'primary',
});

function authenticate(req, res, next) {
  // decodeJwt already ran; req.staff is populated iff the bearer token
  // was present and valid. Reject anything else.
  if (!req.staff) {
    return res.status(401).json({ success: false, message: 'Missing or invalid authorization header' });
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.staff || !roles.includes(req.staff.role)) {
      return res.status(403).json({ success: false, message: 'Insufficient permissions' });
    }
    next();
  };
}

// ============================================================
// RESPONSE & VALIDATION HELPERS
// ============================================================

function ok(res, data, status = 200) {
  res.status(status).json({ success: true, data });
}

function fail(res, message, status = 400) {
  res.status(status).json({ success: false, message });
}

function serverError(res, err) {
  console.error('Server error:', err.message);
  // Only echo the underlying message in non-production. In production
  // it can leak schema/internal-state hints, so callers see a generic
  // message and operators read the real cause from the logs above.
  const expose = NODE_ENV !== 'production';
  res.status(500).json({
    success: false,
    message: expose ? (err.message || 'Internal server error') : 'Internal server error',
  });
}

// SQLSTATE class P0 is PL/pgSQL — every code in that class either comes
// from a hand-written RAISE EXCEPTION in our stored functions (P0001,
// P0007/8, P0099, …) or from the auto-raised NO_DATA_FOUND / TOO_MANY_ROWS
// conditions (P0002/3). Messages are always user-facing and safe to echo.
// Everything outside class P0 (23xxx constraint violations, 42xxx syntax,
// connection drops, …) may leak schema/internal-state hints and is routed
// through serverError instead.
function isUserFacingDbError(err) {
  return typeof err?.code === 'string' && err.code.startsWith('P0');
}

function requireFields(body, fields) {
  const missing = fields.filter((f) => body[f] === undefined || body[f] === null || body[f] === '');
  return missing.length > 0 ? `Missing required fields: ${missing.join(', ')}` : null;
}

// Wire request-context middleware now that the helpers and pool are
// defined. Order: decodeJwt populates req.staff, withRequestDb opens
// the per-request transaction and sets the RLS GUCs from req.staff.
app.use(decodeJwt);
app.use(withRequestDb);

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ status: 'unhealthy', error: err.message });
  }
});

// ============================================================
// 1. AUTH
// ============================================================

// Bootstrap path: runs on the shared pool (not req.db) because identity
// isn't established yet. fn_authenticate_staff is SECURITY DEFINER, so
// it can read staff_users + UPDATE last_login even after the runtime
// pool moves to the nexbus_app role under RLS.
app.post('/auth/login', async (req, res) => {
  const { phone, pin } = req.body;
  const err = requireFields(req.body, ['phone', 'pin']);
  if (err) return fail(res, err);

  try {
    const result = await pool.query(
      'SELECT * FROM fn_authenticate_staff($1, $2)',
      [phone, pin]
    );

    if (result.rows.length === 0) {
      pool.query(
        `INSERT INTO audit_log (action, entity_type, entity_id, new_values)
         VALUES ('login_failed', 'staff_user', gen_random_uuid(), $1)`,
        [JSON.stringify({ phone })]
      ).catch(() => {});
      return fail(res, 'Invalid phone or PIN', 401);
    }

    // fn_authenticate_staff returns columns already aliased to camelCase.
    const staff = result.rows[0];

    pool.query(
      `INSERT INTO audit_log (action, entity_type, entity_id, performed_by)
       VALUES ('login_success', 'staff_user', $1, $1)`,
      [staff.id]
    ).catch(() => {});

    const token = jwt.sign(
      { id: staff.id, agencyId: staff.agencyId, role: staff.role, name: staff.name },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    ok(res, { staff, token });
  } catch (err) {
    serverError(res, err);
  }
});

// ============================================================
// 2. AGENCIES (public read, admin write)
// ============================================================

app.get('/agencies', async (req, res) => {
  try {
    const includeInactive = req.query.includeInactive === 'true';
    const query = includeInactive
      ? `SELECT ${FIELDS.agency} FROM agencies ORDER BY name ASC`
      : `SELECT ${FIELDS.agency} FROM agencies WHERE is_active = true ORDER BY name ASC`;
    const result = await req.db.query(query);
    ok(res, result.rows);
  } catch (err) {
    serverError(res, err);
  }
});

app.get('/agencies/:id', async (req, res) => {
  try {
    const result = await req.db.query(
      `SELECT ${FIELDS.agency} FROM agencies WHERE id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0) return fail(res, 'Agency not found', 404);
    ok(res, result.rows[0]);
  } catch (err) {
    serverError(res, err);
  }
});

app.post('/agencies', authenticate, requireRole('super_admin'), async (req, res) => {
  const { name, logoUrl, parkName, contactPhone } = req.body;
  const err = requireFields(req.body, ['name', 'parkName', 'contactPhone']);
  if (err) return fail(res, err);

  try {
    const result = await req.db.query(
      `INSERT INTO agencies (name, logo_url, park_name, contact_phone)
       VALUES ($1, $2, $3, $4) RETURNING ${FIELDS.agency}`,
      [name, logoUrl || null, parkName, contactPhone]
    );
    ok(res, result.rows[0], 201);
  } catch (err) {
    if (err.code === '23505') return fail(res, 'Agency name already exists', 409);
    serverError(res, err);
  }
});

app.put('/agencies/:id', authenticate, requireRole('super_admin', 'admin'), async (req, res) => {
  const { name, logoUrl, parkName, contactPhone, isActive } = req.body;
  try {
    const result = await req.db.query(
      `UPDATE agencies SET
         name = COALESCE($1, name),
         logo_url = COALESCE($2, logo_url),
         park_name = COALESCE($3, park_name),
         contact_phone = COALESCE($4, contact_phone),
         is_active = COALESCE($5, is_active)
       WHERE id = $6 RETURNING ${FIELDS.agency}`,
      [name, logoUrl, parkName, contactPhone, isActive, req.params.id]
    );
    if (result.rows.length === 0) return fail(res, 'Agency not found', 404);
    ok(res, result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return fail(res, 'Agency name already exists', 409);
    serverError(res, err);
  }
});

app.delete('/agencies/:id', authenticate, requireRole('super_admin'), async (req, res) => {
  try {
    const result = await req.db.query(
      `UPDATE agencies SET is_active = false WHERE id = $1 RETURNING ${FIELDS.agency}`,
      [req.params.id]
    );
    if (result.rows.length === 0) return fail(res, 'Agency not found', 404);
    ok(res, result.rows[0]);
  } catch (err) {
    serverError(res, err);
  }
});

// Hard delete agency and all related data (staff, routes, departures)
app.delete('/agencies/:id/permanent', authenticate, requireRole('super_admin'), async (req, res) => {
  try {
    const result = await req.db.query(
      `DELETE FROM agencies WHERE id = $1 RETURNING id, name`,
      [req.params.id]
    );
    if (result.rows.length === 0) return fail(res, 'Agency not found', 404);
    ok(res, result.rows[0]);
  } catch (err) {
    serverError(res, err);
  }
});

// Hard delete all staff for an agency (except super_admin)
app.delete('/agencies/:id/staff', authenticate, requireRole('super_admin'), async (req, res) => {
  try {
    const result = await req.db.query(
      `DELETE FROM staff_users WHERE agency_id = $1 AND role <> 'super_admin' RETURNING id`,
      [req.params.id]
    );
    ok(res, { deleted: result.rowCount });
  } catch (err) {
    serverError(res, err);
  }
});

// Hard delete all routes and departures for an agency
app.delete('/agencies/:id/routes', authenticate, requireRole('super_admin'), async (req, res) => {
  try {
    const result = await req.db.query(
      `DELETE FROM routes WHERE agency_id = $1 RETURNING id`,
      [req.params.id]
    );
    ok(res, { deleted: result.rowCount });
  } catch (err) {
    serverError(res, err);
  }
});

// Hard delete a single staff member
app.delete('/staff/:id/permanent', authenticate, requireRole('super_admin'), async (req, res) => {
  try {
    const result = await req.db.query(
      `DELETE FROM staff_users WHERE id = $1 AND role <> 'super_admin' RETURNING id, name`,
      [req.params.id]
    );
    if (result.rows.length === 0) return fail(res, 'Staff not found or is super_admin', 404);
    ok(res, result.rows[0]);
  } catch (err) {
    serverError(res, err);
  }
});

// ============================================================
// 3. STAFF (admin-only)
// ============================================================

app.get('/staff', authenticate, requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    let result;
    if (req.staff.role === 'super_admin') {
      result = await req.db.query(`SELECT ${FIELDS.staff} FROM staff_users ORDER BY name ASC`);
    } else {
      result = await req.db.query(
        `SELECT ${FIELDS.staff} FROM staff_users WHERE agency_id = $1 ORDER BY name ASC`,
        [req.staff.agencyId]
      );
    }
    ok(res, result.rows);
  } catch (err) {
    serverError(res, err);
  }
});

app.post('/staff', authenticate, requireRole('super_admin', 'admin'), async (req, res) => {
  const { agencyId, phone, pin, name, role } = req.body;
  const err = requireFields(req.body, ['phone', 'pin', 'name', 'role']);
  if (err) return fail(res, err);

  // Defense in depth: fn_create_staff is SECURITY DEFINER (bypasses RLS),
  // so we have to enforce admin scoping here. RLS would catch this on
  // direct INSERTs, but the function path is wide open without these
  // checks. super_admin can do anything.
  if (req.staff.role === 'admin') {
    if (!agencyId || agencyId !== req.staff.agencyId) {
      return fail(res, 'Cannot create staff for another agency', 403);
    }
    if (!['admin', 'ticket_seller'].includes(role)) {
      return fail(res, 'Cannot create staff with this role', 403);
    }
  }

  try {
    const result = await req.db.query(
      `SELECT fn_create_staff($1::uuid, $2::text, $3::text, $4::text, $5::staff_role) AS id`,
      [agencyId || null, phone, pin, name, role]
    );
    const newStaff = await req.db.query(
      `SELECT ${FIELDS.staff} FROM staff_users WHERE id = $1`,
      [result.rows[0].id]
    );
    ok(res, newStaff.rows[0], 201);
  } catch (err) {
    if (err.code === '23505') return fail(res, 'Phone number already registered', 409);
    if (err.message.includes('P0007')) return fail(res, 'PIN must be 4-6 digits');
    if (err.message.includes('P0008')) return fail(res, err.message);
    serverError(res, err);
  }
});

app.put('/staff/:id', authenticate, requireRole('super_admin', 'admin'), async (req, res) => {
  const { name, phone, pin, role, agencyId, isActive } = req.body;

  // Pre-flight admin scope check. Pre-RLS-activation the runtime pool
  // bypasses RLS entirely, so without this an admin could PUT
  // /staff/:other-agency-staff. Post-activation the RLS USING clause
  // would also block it; this stays as belt-and-braces.
  if (req.staff.role === 'admin') {
    const existing = await req.db.query(
      'SELECT agency_id, role FROM staff_users WHERE id = $1',
      [req.params.id]
    );
    if (existing.rows.length === 0) return fail(res, 'Staff not found', 404);
    if (existing.rows[0].agency_id !== req.staff.agencyId) {
      return fail(res, 'Cannot edit staff from another agency', 403);
    }
    // Forbid agency reassignment by admin (super_admin still can).
    if (agencyId && agencyId !== req.staff.agencyId) {
      return fail(res, 'Cannot move staff to another agency', 403);
    }
    // Forbid role escalation to super_admin / regulator.
    if (role && !['admin', 'ticket_seller'].includes(role)) {
      return fail(res, 'Cannot assign this role', 403);
    }
  }

  try {
    let result;
    if (pin) {
      // Validate PIN format
      if (!/^\d{4,6}$/.test(pin)) return fail(res, 'PIN must be 4-6 digits');
      // Update including PIN hash
      result = await req.db.query(
        `UPDATE staff_users SET
           name = COALESCE($1, name),
           phone = COALESCE($2, phone),
           pin_hash = crypt($3, gen_salt('bf', 10)),
           role = COALESCE($4, role),
           agency_id = COALESCE($5, agency_id),
           is_active = COALESCE($6, is_active)
         WHERE id = $7 RETURNING ${FIELDS.staff}`,
        [name, phone, pin, role, agencyId, isActive, req.params.id]
      );
    } else {
      // Update without changing PIN
      result = await req.db.query(
        `UPDATE staff_users SET
           name = COALESCE($1, name),
           phone = COALESCE($2, phone),
           role = COALESCE($3, role),
           agency_id = COALESCE($4, agency_id),
           is_active = COALESCE($5, is_active)
         WHERE id = $6 RETURNING ${FIELDS.staff}`,
        [name, phone, role, agencyId, isActive, req.params.id]
      );
    }
    if (result.rows.length === 0) return fail(res, 'Staff not found', 404);
    ok(res, result.rows[0]);
  } catch (err) {
    serverError(res, err);
  }
});

app.delete('/staff/:id', authenticate, requireRole('super_admin', 'admin'), async (req, res) => {
  // Same scope check as PUT — admins can only deactivate their own
  // agency's staff. (Hard-delete /staff/:id/permanent stays super_admin-only.)
  if (req.staff.role === 'admin') {
    const existing = await req.db.query(
      'SELECT agency_id FROM staff_users WHERE id = $1',
      [req.params.id]
    );
    if (existing.rows.length === 0) return fail(res, 'Staff not found', 404);
    if (existing.rows[0].agency_id !== req.staff.agencyId) {
      return fail(res, 'Cannot deactivate staff from another agency', 403);
    }
  }

  try {
    const result = await req.db.query(
      `UPDATE staff_users SET is_active = false WHERE id = $1 RETURNING ${FIELDS.staff}`,
      [req.params.id]
    );
    if (result.rows.length === 0) return fail(res, 'Staff not found', 404);

    // Same transaction as the deactivation above; let an audit failure
    // bubble up so the deactivation rolls back atomically rather than
    // committing without an audit trail.
    await req.db.query(
      `INSERT INTO audit_log (action, entity_type, entity_id, performed_by)
       VALUES ('staff_deactivated', 'staff_user', $1, $2)`,
      [req.params.id, req.staff.id]
    );

    ok(res, result.rows[0]);
  } catch (err) {
    serverError(res, err);
  }
});

// Materialize today's (or any date's) departures from each active
// route's departure_times template. Admin-triggered to eliminate the
// per-departure-per-day manual creation labor. Idempotent — calling
// twice on the same date is a safe no-op for already-existing rows.
app.post('/agencies/:agencyId/materialize-departures',
  authenticate,
  requireRole('super_admin', 'admin'),
  async (req, res) => {
    const { agencyId } = req.params;
    const { date } = req.body || {};

    // Admin can only materialize their own agency. super_admin: any.
    if (req.staff.role === 'admin' && req.staff.agencyId !== agencyId) {
      return fail(res, 'Forbidden', 403);
    }

    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return fail(res, 'date (YYYY-MM-DD) is required');
    }

    try {
      const result = await req.db.query(
        'SELECT * FROM fn_materialize_route_departures($1::uuid, $2::date, $3::uuid)',
        [agencyId, date, req.staff.id]
      );
      ok(res, result.rows[0]);
    } catch (err) {
      if (err.code === 'P0003') return fail(res, err.message, 403);
      serverError(res, err);
    }
  });

// End-of-shift reconciliation: per-staff seat activity + commissions
// for one calendar day in Africa/Douala. Self-only unless super_admin.
// Both stored functions are SECURITY DEFINER and revalidate caller
// identity from the request-context GUC, so the route's authz check
// is the outer layer of defense in depth.
app.get('/staff/:id/reconciliation', authenticate, async (req, res) => {
  const targetStaffId = req.params.id;
  if (req.staff.id !== targetStaffId && req.staff.role !== 'super_admin') {
    return fail(res, 'Forbidden', 403);
  }

  // Default to today in Africa/Douala. Caller may pass ?date=YYYY-MM-DD.
  let date = req.query.date;
  if (date) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return fail(res, 'Invalid date; expected YYYY-MM-DD');
    }
  } else {
    // Build today's WAT date as a string. WAT = UTC+1, no DST, so a
    // simple +1h shift on the UTC clock and reading the date parts is
    // exact (the project pins this assumption — see schema_acid.sql).
    const wat = new Date(Date.now() + 60 * 60 * 1000);
    const y = wat.getUTCFullYear();
    const m = String(wat.getUTCMonth() + 1).padStart(2, '0');
    const d = String(wat.getUTCDate()).padStart(2, '0');
    date = `${y}-${m}-${d}`;
  }

  try {
    const [seats, bookings] = await Promise.all([
      req.db.query(
        'SELECT * FROM fn_staff_reconciliation_seats($1::uuid, $2::date)',
        [targetStaffId, date]
      ),
      req.db.query(
        'SELECT * FROM fn_staff_reconciliation_bookings($1::uuid, $2::date)',
        [targetStaffId, date]
      ),
    ]);

    // Roll-up totals computed in JS — keeps the SQL functions simple
    // and the per-row data intact for the breakdown lists.
    const seatsSold     = seats.rows.reduce((s, r) => s + r.seatsSold,     0);
    const seatsRefunded = seats.rows.reduce((s, r) => s + r.seatsRefunded, 0);
    // Seats that flowed through QR confirmations. Distinct stream from
    // 'seats_updated' (see migration 011 header), so safe to add to the
    // seller's "seats I touched" headline without double-counting.
    const seatsFromBookings = bookings.rows.reduce((s, b) => s + b.seatCount, 0);
    const totalCommission = bookings.rows.reduce(
      (s, b) => s + Number(b.commissionAmount), 0
    );
    const currency = bookings.rows[0]?.currency || 'XAF';

    ok(res, {
      staffId: targetStaffId,
      date,
      summary: {
        seatsSold,
        seatsRefunded,
        netSeats: seatsSold - seatsRefunded,
        departuresWorked: seats.rows.length,
        bookingsConfirmed: bookings.rows.length,
        seatsFromBookings,
        totalCommission,
        currency,
      },
      byDeparture: seats.rows,
      byBooking: bookings.rows,
    });
  } catch (err) {
    if (err.code === 'P0003') return fail(res, err.message, 403);
    serverError(res, err);
  }
});

// ============================================================
// 4. ROUTES (public read, admin write)
// ============================================================

app.get('/routes', async (req, res) => {
  try {
    const result = await req.db.query(
      `SELECT ${FIELDS.route} FROM routes WHERE is_active = true ORDER BY origin, destination ASC`
    );
    ok(res, result.rows);
  } catch (err) {
    serverError(res, err);
  }
});

app.get('/agencies/:agencyId/routes', async (req, res) => {
  try {
    const result = await req.db.query(
      `SELECT ${FIELDS.route} FROM routes WHERE agency_id = $1 AND is_active = true ORDER BY origin, destination ASC`,
      [req.params.agencyId]
    );
    ok(res, result.rows);
  } catch (err) {
    serverError(res, err);
  }
});

app.post('/routes', authenticate, requireRole('super_admin', 'admin'), async (req, res) => {
  const { id, agencyId, origin, destination, busCapacity, category, departureTimes } = req.body;
  const err = requireFields(req.body, ['agencyId', 'origin', 'destination', 'busCapacity']);
  if (err) return fail(res, err);

  try {
    const cat = category || 'classic';
    const times = departureTimes || [];

    // Find existing route (including inactive) with same agency, origin, destination, category
    const existing = await req.db.query(
      `SELECT ${FIELDS.route} FROM routes
       WHERE agency_id = $1 AND LOWER(origin) = LOWER($2) AND LOWER(destination) = LOWER($3) AND category = $4`,
      [agencyId, origin, destination, cat]
    );

    if (existing.rows.length > 0) {
      // Route exists — reactivate if needed, update capacity/times, and return it
      const result = await req.db.query(
        `UPDATE routes SET bus_capacity = $1, departure_times = $2, is_active = true
         WHERE id = $3 RETURNING ${FIELDS.route}`,
        [busCapacity, times, existing.rows[0].id]
      );
      return ok(res, result.rows[0]);
    }

    // Create new route
    const values = [agencyId, origin, destination, busCapacity, cat, times];
    let query;
    if (id) {
      query = `INSERT INTO routes (id, agency_id, origin, destination, bus_capacity, category, departure_times)
               VALUES ($7, $1, $2, $3, $4, $5, $6) RETURNING ${FIELDS.route}`;
      values.push(id);
    } else {
      query = `INSERT INTO routes (agency_id, origin, destination, bus_capacity, category, departure_times)
               VALUES ($1, $2, $3, $4, $5, $6) RETURNING ${FIELDS.route}`;
    }
    const result = await req.db.query(query, values);
    ok(res, result.rows[0], 201);
  } catch (err) {
    if (err.code === '23505') return fail(res, 'Duplicate route for this agency', 409);
    if (err.code === '23514') return fail(res, 'Invalid route data (check capacity and origin/destination)');
    serverError(res, err);
  }
});

app.put('/routes/:id', authenticate, requireRole('super_admin', 'admin'), async (req, res) => {
  const { origin, destination, busCapacity, category, departureTimes, isActive } = req.body;
  try {
    const result = await req.db.query(
      `UPDATE routes SET
         origin = COALESCE($1, origin),
         destination = COALESCE($2, destination),
         bus_capacity = COALESCE($3, bus_capacity),
         category = COALESCE($4, category),
         departure_times = COALESCE($5, departure_times),
         is_active = COALESCE($6, is_active)
       WHERE id = $7 RETURNING ${FIELDS.route}`,
      [origin, destination, busCapacity, category, departureTimes, isActive, req.params.id]
    );
    if (result.rows.length === 0) return fail(res, 'Route not found', 404);
    ok(res, result.rows[0]);
  } catch (err) {
    serverError(res, err);
  }
});

// Bulk-shift today's (or any date's) non-departed departures on one
// route by ±N minutes. Bounded server-side to ±360 minutes; returns
// {shifted, skippedDeparted}. P0099 from the function = unique-time
// collision → 409.
app.post('/routes/:routeId/departures/bulk-shift',
  authenticate,
  requireRole('super_admin', 'admin'),
  async (req, res) => {
    const { routeId } = req.params;
    const { minutes, date } = req.body || {};

    if (typeof minutes !== 'number' || !Number.isInteger(minutes)) {
      return fail(res, 'minutes (integer) is required');
    }
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return fail(res, 'date (YYYY-MM-DD) is required');
    }

    try {
      const result = await req.db.query(
        'SELECT * FROM fn_bulk_shift_route_departures($1::uuid, $2::date, $3::int, $4::uuid)',
        [routeId, date, minutes, req.staff.id]
      );
      ok(res, result.rows[0]);
    } catch (err) {
      if (err.code === 'P0001') return fail(res, err.message, 400);
      if (err.code === 'P0002') return fail(res, err.message, 404);
      if (err.code === 'P0003') return fail(res, err.message, 403);
      if (err.code === 'P0099') return fail(res, err.message, 409);
      serverError(res, err);
    }
  });

app.delete('/routes/:id', authenticate, requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const result = await req.db.query(
      `UPDATE routes SET is_active = false WHERE id = $1 RETURNING ${FIELDS.route}`,
      [req.params.id]
    );
    if (result.rows.length === 0) return fail(res, 'Route not found', 404);
    ok(res, result.rows[0]);
  } catch (err) {
    serverError(res, err);
  }
});

// ============================================================
// 5. DEPARTURES (public read, staff write)
// ============================================================

// Bounded list: defaults to a rolling window around "now" so unbounded history
// never gets serialized. Callers can override with ?from, ?to (ISO8601),
// ?limit (max 1000), ?offset. Intended: a departure board shows today +
// tomorrow by default; pass an explicit range for reporting needs.
const DEFAULT_WINDOW_BEFORE_MS = 12 * 60 * 60 * 1000;   // 12h ago
const DEFAULT_WINDOW_AFTER_MS = 48 * 60 * 60 * 1000;    // 48h ahead
const MAX_LIMIT = 1000;
const DEFAULT_LIMIT = 500;

function parseDepartureWindow(q) {
  const now = Date.now();
  const from = q.from ? new Date(q.from) : new Date(now - DEFAULT_WINDOW_BEFORE_MS);
  const to = q.to ? new Date(q.to) : new Date(now + DEFAULT_WINDOW_AFTER_MS);
  if (isNaN(from.getTime()) || isNaN(to.getTime())) return null;
  const limit = Math.min(MAX_LIMIT, Math.max(1, Number(q.limit) || DEFAULT_LIMIT));
  const offset = Math.max(0, Number(q.offset) || 0);
  return { from: from.toISOString(), to: to.toISOString(), limit, offset };
}

app.get('/departures', async (req, res) => {
  const w = parseDepartureWindow(req.query);
  if (!w) return fail(res, 'Invalid from/to query parameter');
  try {
    const result = await req.db.query(
      `SELECT ${FIELDS.departure} FROM departures
       WHERE scheduled_time >= $1 AND scheduled_time < $2
       ORDER BY scheduled_time ASC
       LIMIT $3 OFFSET $4`,
      [w.from, w.to, w.limit, w.offset]
    );
    ok(res, result.rows);
  } catch (err) {
    serverError(res, err);
  }
});

app.get('/agencies/:agencyId/departures', async (req, res) => {
  const w = parseDepartureWindow(req.query);
  if (!w) return fail(res, 'Invalid from/to query parameter');
  try {
    const result = await req.db.query(
      `SELECT ${FIELDS.departure} FROM departures
       WHERE agency_id = $1 AND scheduled_time >= $2 AND scheduled_time < $3
       ORDER BY scheduled_time ASC
       LIMIT $4 OFFSET $5`,
      [req.params.agencyId, w.from, w.to, w.limit, w.offset]
    );
    ok(res, result.rows);
  } catch (err) {
    serverError(res, err);
  }
});

app.get('/routes/:routeId/departures', async (req, res) => {
  const limit = Math.min(MAX_LIMIT, Math.max(1, Number(req.query.limit) || DEFAULT_LIMIT));
  const offset = Math.max(0, Number(req.query.offset) || 0);
  try {
    const result = await req.db.query(
      `SELECT ${FIELDS.departure} FROM departures
       WHERE route_id = $1
       ORDER BY scheduled_time ASC
       LIMIT $2 OFFSET $3`,
      [req.params.routeId, limit, offset]
    );
    ok(res, result.rows);
  } catch (err) {
    serverError(res, err);
  }
});

app.post('/departures', authenticate, async (req, res) => {
  const { id, routeId, agencyId, scheduledTime, seatsSold, totalSeats, category, status, busNumber, remarks } = req.body;
  const err = requireFields(req.body, ['routeId', 'agencyId', 'totalSeats']);
  if (err) return fail(res, err);

  try {
    const base = [routeId, agencyId, scheduledTime || new Date().toISOString(), seatsSold || 0, totalSeats, category || 'classic', status || 'not_boarding', busNumber || null, remarks || null];
    let query;
    if (id) {
      query = `INSERT INTO departures (id, route_id, agency_id, scheduled_time, seats_sold, total_seats, category, status, bus_number, remarks)
               VALUES ($10, $1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING ${FIELDS.departure}`;
      base.push(id);
    } else {
      query = `INSERT INTO departures (route_id, agency_id, scheduled_time, seats_sold, total_seats, category, status, bus_number, remarks)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING ${FIELDS.departure}`;
    }
    const result = await req.db.query(query, base);
    ok(res, result.rows[0], 201);
  } catch (err) {
    if (err.code === '23505') return fail(res, 'Duplicate departure for this route/time', 409);
    if (err.code === '23514') return fail(res, 'Invalid departure data (check seat counts and status)');
    serverError(res, err);
  }
});

app.put('/departures/:id', authenticate, async (req, res) => {
  const { seatsSold, totalSeats, status, busNumber, remarks, departedAt } = req.body;
  try {
    const result = await req.db.query(
      `UPDATE departures SET
         seats_sold = COALESCE($1, seats_sold),
         total_seats = COALESCE($2, total_seats),
         status = COALESCE($3, status),
         bus_number = COALESCE($4, bus_number),
         remarks = COALESCE($5, remarks),
         departed_at = COALESCE($6, departed_at),
         updated_by = $7
       WHERE id = $8 RETURNING ${FIELDS.departure}`,
      [seatsSold, totalSeats, status, busNumber, remarks, departedAt, req.staff.id, req.params.id]
    );
    if (result.rows.length === 0) return fail(res, 'Departure not found', 404);
    ok(res, result.rows[0]);
  } catch (err) {
    if (err.code === '23514') return fail(res, 'Invalid update (check seat counts and status constraints)');
    serverError(res, err);
  }
});

app.delete('/departures/:id', authenticate, async (req, res) => {
  try {
    const result = await req.db.query(
      `DELETE FROM departures WHERE id = $1 RETURNING id`,
      [req.params.id]
    );
    if (result.rows.length === 0) return fail(res, 'Departure not found', 404);
    ok(res, { id: req.params.id });
  } catch (err) {
    serverError(res, err);
  }
});

// ACID-Safe Seat Selling (via stored function with row-level locking)
app.post('/departures/:id/sell-seats', authenticate, async (req, res) => {
  const { delta, staffId } = req.body;
  const err = requireFields(req.body, ['delta', 'staffId']);
  if (err) return fail(res, err);

  try {
    const result = await req.db.query(
      `SELECT departure_id AS id, seats_sold AS "seatsSold", total_seats AS "totalSeats",
              available_seats AS "availableSeats", fill_percentage AS "fillPercentage", status,
              auto_confirmed_codes AS "autoConfirmedCodes"
       FROM fn_sell_seats($1::uuid, $2::int, $3::uuid)`,
      [req.params.id, delta, staffId]
    );
    ok(res, result.rows[0]);
  } catch (err) {
    if (isUserFacingDbError(err)) return fail(res, err.message);
    serverError(res, err);
  }
});

// ACID-Safe Status Update (via stored function with state machine enforcement)
app.post('/departures/:id/update-status', authenticate, async (req, res) => {
  const { status, staffId } = req.body;
  const err = requireFields(req.body, ['status', 'staffId']);
  if (err) return fail(res, err);

  try {
    const result = await req.db.query(
      `SELECT departure_id AS id, old_status AS "oldStatus", new_status AS "newStatus",
              departed_at AS "departedAt", updated_at AS "updatedAt"
       FROM fn_update_departure_status($1::uuid, $2::departure_status, $3::uuid)`,
      [req.params.id, status, staffId]
    );
    ok(res, result.rows[0]);
  } catch (err) {
    if (isUserFacingDbError(err)) return fail(res, err.message);
    serverError(res, err);
  }
});

// ============================================================
// 6. TOWNS
// ============================================================

app.get('/towns', async (req, res) => {
  try {
    const result = await req.db.query('SELECT name FROM towns ORDER BY name ASC');
    ok(res, result.rows);
  } catch (err) {
    serverError(res, err);
  }
});

app.post('/towns', authenticate, requireRole('super_admin'), async (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return fail(res, 'Town name is required');

  try {
    const result = await req.db.query(
      'INSERT INTO towns (name) VALUES ($1) ON CONFLICT (name) DO NOTHING RETURNING name',
      [name.trim()]
    );
    if (result.rows.length === 0) return fail(res, 'Town already exists', 409);
    ok(res, result.rows[0], 201);
  } catch (err) {
    serverError(res, err);
  }
});

app.delete('/towns/:name', authenticate, requireRole('super_admin'), async (req, res) => {
  try {
    const result = await req.db.query(
      'DELETE FROM towns WHERE name = $1 RETURNING name',
      [decodeURIComponent(req.params.name)]
    );
    if (result.rows.length === 0) return fail(res, 'Town not found', 404);
    ok(res, result.rows[0]);
  } catch (err) {
    serverError(res, err);
  }
});

// ============================================================
// 7. SYNC (Offline Queue Processing)
// ============================================================

app.post('/sync', authenticate, async (req, res) => {
  const { entityType, entityId, action, payload } = req.body;
  const err = requireFields(req.body, ['entityType', 'entityId', 'action', 'payload']);
  if (err) return fail(res, err);

  // withRequestDb already opened the transaction and set the RLS context.
  // Aliasing keeps the handler closures below unchanged.
  const client = req.db;
  try {
    const handlers = {
      departure: {
        create: async () => {
          // Verify routeId exists; if not, try to find a matching route for this agency
          let routeId = payload.routeId;
          const routeCheck = await client.query('SELECT id FROM routes WHERE id = $1', [routeId]);
          if (routeCheck.rows.length === 0) {
            // Route UUID doesn't exist — find a route matching agency + category
            const cat = payload.category || 'classic';
            const fallback = await client.query(
              `SELECT id FROM routes WHERE agency_id = $1 AND category = $2 AND is_active = true LIMIT 1`,
              [payload.agencyId, cat]
            );
            if (fallback.rows.length > 0) {
              routeId = fallback.rows[0].id;
            }
            // If still no route found, the INSERT will fail with FK violation — that's correct
          }
          return client.query(
            `INSERT INTO departures (id, route_id, agency_id, scheduled_time, seats_sold, total_seats, category, status, bus_number, remarks)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (id) DO UPDATE SET
               seats_sold = EXCLUDED.seats_sold, status = EXCLUDED.status,
               bus_number = EXCLUDED.bus_number, remarks = EXCLUDED.remarks
             RETURNING ${FIELDS.departure}`,
            [entityId, routeId, payload.agencyId, payload.scheduledTime || new Date().toISOString(),
             payload.seatsSold || 0, payload.totalSeats, payload.category || 'classic',
             payload.status || 'not_boarding', payload.busNumber || null, payload.remarks || null]
          );
        },
        update: () => client.query(
          `UPDATE departures SET
             seats_sold = COALESCE($1, seats_sold), total_seats = COALESCE($2, total_seats),
             status = COALESCE($3, status), bus_number = COALESCE($4, bus_number),
             remarks = COALESCE($5, remarks), updated_by = $6
           WHERE id = $7 RETURNING ${FIELDS.departure}`,
          [payload.seatsSold, payload.totalSeats, payload.status,
           payload.busNumber, payload.remarks, req.staff.id, entityId]
        ),
        delete: () => client.query('DELETE FROM departures WHERE id = $1', [entityId]),
      },
      route: {
        create: async () => {
          const cat = payload.category || 'classic';
          const times = payload.departureTimes || [];
          // Find existing route (including inactive) with same agency, origin, destination, category
          const existing = await client.query(
            `SELECT ${FIELDS.route} FROM routes
             WHERE agency_id = $1 AND LOWER(origin) = LOWER($2) AND LOWER(destination) = LOWER($3) AND category = $4`,
            [payload.agencyId, payload.origin, payload.destination, cat]
          );
          if (existing.rows.length > 0) {
            return client.query(
              `UPDATE routes SET bus_capacity = $1, departure_times = $2, is_active = true
               WHERE id = $3 RETURNING ${FIELDS.route}`,
              [payload.busCapacity, times, existing.rows[0].id]
            );
          }
          return client.query(
            `INSERT INTO routes (id, agency_id, origin, destination, bus_capacity, category, departure_times)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (id) DO UPDATE SET
               origin = EXCLUDED.origin, destination = EXCLUDED.destination,
               bus_capacity = EXCLUDED.bus_capacity
             RETURNING ${FIELDS.route}`,
            [entityId, payload.agencyId, payload.origin, payload.destination,
             payload.busCapacity, cat, times]
          );
        },
        update: () => client.query(
          `UPDATE routes SET
             origin = COALESCE($1, origin), destination = COALESCE($2, destination),
             bus_capacity = COALESCE($3, bus_capacity), category = COALESCE($4, category),
             departure_times = COALESCE($5, departure_times)
           WHERE id = $6 RETURNING ${FIELDS.route}`,
          [payload.origin, payload.destination, payload.busCapacity,
           payload.category, payload.departureTimes, entityId]
        ),
        delete: () => client.query('UPDATE routes SET is_active = false WHERE id = $1', [entityId]),
      },
      agency: {
        create: () => client.query(
          `INSERT INTO agencies (id, name, logo_url, park_name, contact_phone, is_active)
           VALUES ($1, $2, $3, $4, $5, COALESCE($6, true))
           ON CONFLICT (id) DO UPDATE SET
             name = EXCLUDED.name, logo_url = EXCLUDED.logo_url,
             park_name = EXCLUDED.park_name, contact_phone = EXCLUDED.contact_phone,
             is_active = EXCLUDED.is_active
           RETURNING ${FIELDS.agency}`,
          [entityId, payload.name, payload.logoUrl || null, payload.parkName,
           payload.contactPhone, payload.isActive]
        ),
        update: () => client.query(
          `UPDATE agencies SET
             name = COALESCE($1, name), logo_url = COALESCE($2, logo_url),
             park_name = COALESCE($3, park_name), contact_phone = COALESCE($4, contact_phone),
             is_active = COALESCE($5, is_active)
           WHERE id = $6 RETURNING ${FIELDS.agency}`,
          [payload.name, payload.logoUrl, payload.parkName,
           payload.contactPhone, payload.isActive, entityId]
        ),
        delete: () => client.query(
          'UPDATE agencies SET is_active = false WHERE id = $1 RETURNING id', [entityId]
        ),
      },
      staff: {
        create: async () => {
          const pin = payload.pin;
          if (pin && /^\d{4,6}$/.test(pin)) {
            const result = await client.query(
              `SELECT fn_create_staff($1::uuid, $2::text, $3::text, $4::text, $5::staff_role) AS id`,
              [payload.agencyId || null, payload.phone, pin, payload.name, payload.role || 'ticket_seller']
            );
            return client.query(
              `SELECT ${FIELDS.staff} FROM staff_users WHERE id = $1`,
              [result.rows[0].id]
            );
          }
          // Fallback: insert directly without PIN (shouldn't normally happen)
          return client.query(
            `INSERT INTO staff_users (id, agency_id, phone, pin_hash, name, role, is_active)
             VALUES ($1, $2, $3, crypt('0000', gen_salt('bf', 10)), $4, $5, COALESCE($6, true))
             ON CONFLICT (id) DO UPDATE SET
               name = EXCLUDED.name, phone = EXCLUDED.phone,
               role = EXCLUDED.role, is_active = EXCLUDED.is_active
             RETURNING ${FIELDS.staff}`,
            [entityId, payload.agencyId || null, payload.phone,
             payload.name, payload.role || 'ticket_seller', payload.isActive]
          );
        },
        update: async () => {
          const pin = payload.pin;
          if (pin && /^\d{4,6}$/.test(pin)) {
            return client.query(
              `UPDATE staff_users SET
                 name = COALESCE($1, name), phone = COALESCE($2, phone),
                 role = COALESCE($3, role), agency_id = COALESCE($4, agency_id),
                 is_active = COALESCE($5, is_active),
                 pin_hash = crypt($6, gen_salt('bf', 10))
               WHERE id = $7 RETURNING ${FIELDS.staff}`,
              [payload.name, payload.phone, payload.role,
               payload.agencyId, payload.isActive, pin, entityId]
            );
          }
          return client.query(
            `UPDATE staff_users SET
               name = COALESCE($1, name), phone = COALESCE($2, phone),
               role = COALESCE($3, role), agency_id = COALESCE($4, agency_id),
               is_active = COALESCE($5, is_active)
             WHERE id = $6 RETURNING ${FIELDS.staff}`,
            [payload.name, payload.phone, payload.role,
             payload.agencyId, payload.isActive, entityId]
          );
        },
        delete: () => client.query(
          'UPDATE staff_users SET is_active = false WHERE id = $1 RETURNING id', [entityId]
        ),
      },
    };

    const handler = handlers[entityType]?.[action];
    if (!handler) {
      // fail() sets a 4xx; withRequestDb's finalize() will ROLLBACK.
      return fail(res, `Unsupported sync operation: ${entityType}.${action}`);
    }

    const result = await handler();
    ok(res, result.rows?.[0] || { id: entityId });
  } catch (err) {
    if (isUserFacingDbError(err)) return fail(res, err.message);
    serverError(res, err);
  }
});

// ============================================================
// REGULATOR SURFACE (read-only, scope-gated)
// ============================================================

const createRegulatorRouter = require('./routes/regulator');
app.use('/regulator', createRegulatorRouter({
  pool, authenticate, requireRole, ok, fail, serverError,
}));

const createAdminRouter = require('./routes/admin');
app.use('/admin', createAdminRouter({
  pool, authenticate, requireRole, ok, fail, serverError,
}));

// Bookings + commissions (mounted at root because routes are mixed:
// /bookings/* are passenger-facing, /agencies/:id/* are agency dashboards).
const createBookingRouter = require('./routes/bookings');
app.use('/', createBookingRouter({
  pool, authenticate, requireRole, ok, fail, serverError,
}));

// Passenger event telemetry — anonymous batch ingest, has its own
// per-IP rate limit defined in the route module.
const createPassengerEventsRouter = require('./routes/passenger_events');
app.use('/', createPassengerEventsRouter({ pool, ok, fail }));

// ============================================================
// ERROR HANDLERS
// ============================================================

app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// ============================================================
// START
// ============================================================

// Bind explicitly to 0.0.0.0 — Render's proxy sits in a different network
// namespace, so a default-localhost bind would be unreachable. Logging
// the host alongside the port makes mismatches between the platform's
// $PORT and our actual listener visible in the logs at a glance.
const HOST = '0.0.0.0';
app.listen(PORT, HOST, () => {
  console.log(`Server listening on ${HOST}:${PORT}`);
});
