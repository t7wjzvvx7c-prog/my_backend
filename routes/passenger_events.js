// Passenger event telemetry endpoint.
//
// Anonymous, batch-only ingest for the passenger app's funnel events.
// Distinct from /audit (operational evidence) — this stream is best-effort,
// no PII, and may be aggressively rate-limited.
//
//   POST /passenger-events:batch    (anonymous)  — ingest up to 50 events
//
// Per-event accept/reject: malformed events don't fail the whole batch.
// Returns 207-style { results: [{ id, status, error? }, ...] }.
//
// Idempotency: events have client-generated UUIDs; ON CONFLICT (id) DO NOTHING
// so retries of the same batch are safe.

const KIND_SET = new Set([
  'search_performed',
  'search_no_results',
  'departure_viewed',
  'departure_tapped',
  'booking_started',
  'booking_submitted',
  'booking_abandoned',
  'attestation_traveled',
  'attestation_no_show',
  'attestation_skipped',
]);

const CATEGORY_SET = new Set(['classic', 'vip', 'business']);
const PLATFORM_SET = new Set(['android', 'ios', 'web', 'desktop']);

const MAX_BATCH_SIZE = 50;
const MAX_EVENT_AGE_MS = 30 * 24 * 60 * 60 * 1000;  // 30 days
const MAX_FUTURE_SKEW_MS = 60 * 60 * 1000;          // 1 hour clock-skew tolerance

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isUuid(v) {
  return typeof v === 'string' && UUID_RE.test(v);
}

function asNullableInt(v, { min, max } = {}) {
  if (v === null || v === undefined) return null;
  if (typeof v !== 'number' || !Number.isInteger(v)) {
    throw new Error('not an integer');
  }
  if (min !== undefined && v < min) throw new Error(`< ${min}`);
  if (max !== undefined && v > max) throw new Error(`> ${max}`);
  return v;
}

function asNullableString(v, maxLen) {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v !== 'string') throw new Error('not a string');
  if (maxLen && v.length > maxLen) throw new Error(`> ${maxLen} chars`);
  return v;
}

function asNullableEnum(v, allowed) {
  if (v === null || v === undefined || v === '') return null;
  if (!allowed.has(v)) throw new Error('not in allowed set');
  return v;
}

function asNullableUuid(v) {
  if (v === null || v === undefined || v === '') return null;
  if (!isUuid(v)) throw new Error('not a UUID');
  return v;
}

/**
 * Validate one event. Returns the normalized row tuple ready for INSERT,
 * or throws with a human-readable reason.
 */
function normalizeEvent(e, now) {
  if (!e || typeof e !== 'object') throw new Error('event must be an object');

  if (!isUuid(e.id))                     throw new Error('id must be a UUID');
  if (!KIND_SET.has(e.kind))             throw new Error('unknown kind');
  if (!isUuid(e.sessionId))              throw new Error('sessionId must be a UUID');
  if (typeof e.occurredAt !== 'string')  throw new Error('occurredAt required');

  const occurred = new Date(e.occurredAt);
  if (isNaN(occurred.getTime()))         throw new Error('occurredAt unparseable');

  const ageMs = now - occurred.getTime();
  if (ageMs > MAX_EVENT_AGE_MS)          throw new Error('occurredAt too old');
  if (ageMs < -MAX_FUTURE_SKEW_MS)       throw new Error('occurredAt too far in future');

  // Optional fields, validated permissively.
  const origin       = asNullableString(e.origin, 100);
  const destination  = asNullableString(e.destination, 100);
  const category     = asNullableEnum(e.category, CATEGORY_SET);
  const timeFromMin  = asNullableInt(e.timeFromMin, { min: 0, max: 1439 });
  const timeToMin    = asNullableInt(e.timeToMin,   { min: 0, max: 1439 });
  const resultCount  = asNullableInt(e.resultCount, { min: 0 });
  const departureId  = asNullableUuid(e.departureId);
  const agencyId     = asNullableUuid(e.agencyId);
  const bookingId    = asNullableUuid(e.bookingId);
  const appVersion   = asNullableString(e.appVersion, 20);
  const platform     = asNullableEnum(e.platform, PLATFORM_SET);
  const isOffline    = e.isOfflineCapture === true;

  return [
    e.id, e.kind, e.sessionId, occurred.toISOString(),
    origin, destination, category, timeFromMin, timeToMin, resultCount,
    departureId, agencyId, bookingId,
    appVersion, platform, isOffline,
  ];
}

// pool is no longer used directly — the per-request RLS-aware client lives
// on req.db (set by withRequestDb in server.js). Kept in the destructure
// for backward compatibility with the constructor call in server.js.
module.exports = function createPassengerEventsRouter({ ok, fail }) {
  const express = require('express');
  const rateLimit = require('express-rate-limit');
  const router = express.Router();

  // Tighter than the global limiter — anonymous endpoint with no auth means
  // we want a hard ceiling per IP. A real device sending one batch every
  // 30s comfortably fits under 60/min; abusers are stopped early.
  const eventsLimiter = rateLimit({
    windowMs: 60_000,
    limit: Number(process.env.RATE_LIMIT_PASSENGER_EVENTS) || 60,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { success: false, message: 'Too many event batches, slow down' },
  });

  router.post('/passenger-events:batch', eventsLimiter, async (req, res) => {
    const events = Array.isArray(req.body?.events) ? req.body.events : null;
    if (!events) return fail(res, 'events: array required');
    if (events.length === 0) return ok(res, { results: [] });
    if (events.length > MAX_BATCH_SIZE) {
      return fail(res, `batch too large (max ${MAX_BATCH_SIZE})`);
    }

    const now = Date.now();
    const results = [];
    const acceptedRows = [];

    // Pre-validate everything; collect per-event verdicts so the response
    // mirrors the batch shape. Validation failures don't touch the DB.
    for (const e of events) {
      try {
        const row = normalizeEvent(e, now);
        acceptedRows.push(row);
        results.push({ id: e?.id ?? null, status: 'accepted' });
      } catch (err) {
        results.push({
          id: e?.id ?? null,
          status: 'rejected',
          error: err.message,
        });
      }
    }

    if (acceptedRows.length === 0) {
      return ok(res, { results });
    }

    // One multi-row INSERT for all accepted events. Generated columns
    // (occurred_date, occurred_hour) are derived by Postgres.
    const cols = [
      'id', 'kind', 'session_id', 'occurred_at',
      'origin', 'destination', 'category', 'time_from_min', 'time_to_min', 'result_count',
      'departure_id', 'agency_id', 'booking_id',
      'app_version', 'platform', 'is_offline_capture',
    ];
    const colsSql = cols.join(', ');

    const placeholders = acceptedRows
      .map((_, i) => {
        const base = i * cols.length;
        const params = cols.map((__, j) => `$${base + j + 1}`).join(', ');
        return `(${params})`;
      })
      .join(', ');

    const flatParams = acceptedRows.flat();

    try {
      // ON CONFLICT DO NOTHING: client retries are safe; same event id never
      // double-counts. Returning the inserted ids would be nice for the
      // client to know exactly what landed, but isn't necessary for the
      // outbox flusher (which trusts 'accepted' to mean "delete locally").
      await req.db.query(
        `INSERT INTO passenger_events (${colsSql})
         VALUES ${placeholders}
         ON CONFLICT (id) DO NOTHING`,
        flatParams
      );
      ok(res, { results });
    } catch (e) {
      // If the bulk insert fails, mark all *accepted* events as deferred so
      // the client retries them rather than dropping. Validation rejects
      // stay rejected — those won't ever succeed.
      console.error('passenger_events insert failed:', e.message);
      const recovered = results.map((r) =>
        r.status === 'accepted' ? { ...r, status: 'deferred' } : r
      );
      res.status(503).json({ success: false, results: recovered, message: 'temporary failure, retry' });
    }
  });

  return router;
};
