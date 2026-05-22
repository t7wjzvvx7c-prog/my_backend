// Booking + commission endpoints.
// Passenger flow:
//   POST   /bookings                       (anonymous)  — create reservation
//   GET    /bookings/:code                 (anonymous)  — look up by code
//   GET    /bookings?phone=...             (anonymous)  — passenger's bookings
//   POST   /bookings/:code/cancel          (anonymous)  — passenger cancels (only while pending)
//
// Staff flow:
//   POST   /bookings/:code/confirm         (auth)       — atomic confirm + commission
//   GET    /agencies/:id/bookings          (auth)       — agency dashboard
//   POST   /bookings/expire-sweep          (auth)       — manual sweep trigger
//
// Commission management:
//   GET    /agencies/:id/commissions                (auth)
//   GET    /agencies/:id/commissions/settings       (auth)
//   PUT    /agencies/:id/commissions/settings       (super_admin)
//   POST   /agencies/:id/commissions/settle         (super_admin) — mark a period paid

// All queries run on req.db (the per-request RLS-aware client created by
// withRequestDb in server.js). pool is kept in the destructure as a
// no-op for backward compat with the constructor call site.
module.exports = function createBookingRouter({ authenticate, requireRole, ok, fail, serverError }) {
  const express = require('express');
  const router = express.Router();

  // Field lists as arrays of [column, alias?] pairs so we can apply a table
  // prefix when joining. `bookingFields('b')` yields a properly prefixed
  // SELECT clause for the bookings table.
  const BOOKING_COLS = [
    ['id'], ['code'],
    ['departure_id', 'departureId'],
    ['agency_id', 'agencyId'],
    ['passenger_name', 'passengerName'],
    ['passenger_phone', 'passengerPhone'],
    ['seat_count', 'seatCount'],
    ['status'],
    ['expires_at', 'expiresAt'],
    ['confirmed_by', 'confirmedBy'],
    ['confirmed_at', 'confirmedAt'],
    ['cancelled_at', 'cancelledAt'],
    ['notes'],
    ['created_at', 'createdAt'],
    ['updated_at', 'updatedAt'],
  ];
  const COMMISSION_COLS = [
    ['id'],
    ['booking_id', 'bookingId'],
    ['agency_id', 'agencyId'],
    ['seat_count', 'seatCount'],
    ['fare_per_seat', 'farePerSeat'],
    ['fare_total', 'fareTotal'],
    ['commission_rate', 'commissionRate'],
    ['flat_fee', 'flatFee'],
    ['commission_amount', 'commissionAmount'],
    ['currency'],
    ['period'],
    ['status'],
    ['settled_at', 'settledAt'],
    ['created_at', 'createdAt'],
  ];
  const SETTINGS_COLS = [
    ['agency_id', 'agencyId'],
    ['commission_rate', 'commissionRate'],
    ['flat_fee', 'flatFee'],
    ['currency'],
    ['created_at', 'createdAt'],
    ['updated_at', 'updatedAt'],
  ];

  function selectFields(cols, prefix = '') {
    const p = prefix ? `${prefix}.` : '';
    return cols
      .map(([col, alias]) => alias ? `${p}${col} AS "${alias}"` : `${p}${col}`)
      .join(', ');
  }

  const bookingFields    = (p = '')  => selectFields(BOOKING_COLS, p);
  const commissionFields = (p = '')  => selectFields(COMMISSION_COLS, p);
  const settingsFields   = (p = '')  => selectFields(SETTINGS_COLS, p);

  function requireFields(body, fields) {
    const missing = fields.filter((f) => body[f] === undefined || body[f] === null || body[f] === '');
    return missing.length > 0 ? `Missing required fields: ${missing.join(', ')}` : null;
  }

  // Map known stored-function error codes to client-friendly statuses.
  function mapPgError(err) {
    const code = err.code || '';
    const msg = err.message || 'Operation failed';
    if (code === 'P0001') return { status: 409, msg };       // business rule violation
    if (code === 'P0002') return { status: 404, msg };       // not found
    if (code === 'P0003') return { status: 403, msg };       // not authorized
    if (code === 'P0004') return { status: 409, msg };       // capacity
    return { status: 400, msg };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Passenger: create booking (anonymous)
  // ──────────────────────────────────────────────────────────────────────────
  router.post('/bookings', async (req, res) => {
    const { departureId, passengerName, passengerPhone, seatCount, ttlMinutes } = req.body;
    const err = requireFields(req.body, ['departureId', 'passengerName', 'passengerPhone']);
    if (err) return fail(res, err);

    const seats = Number(seatCount) || 1;
    const ttl = Math.min(Math.max(Number(ttlMinutes) || 60, 5), 1440);

    try {
      const result = await req.db.query(
        // Explicit casts: pg sends params as type 'unknown', which Postgres
        // auto-coerces to text/varchar but NOT to uuid or int. Without casts,
        // function resolution fails with "fn_create_booking(unknown, unknown,
        // ...) does not exist".
        `SELECT id, code, departure_id AS "departureId", agency_id AS "agencyId",
                passenger_name AS "passengerName", passenger_phone AS "passengerPhone",
                seat_count AS "seatCount", status, expires_at AS "expiresAt", created_at AS "createdAt"
         FROM fn_create_booking($1::uuid, $2::text, $3::text, $4::int, $5::int)`,
        [departureId, passengerName, passengerPhone, seats, ttl]
      );
      ok(res, result.rows[0], 201);
    } catch (e) {
      const m = mapPgError(e);
      return fail(res, m.msg, m.status);
    }
  });

  // Look up by code. Authenticated. When the caller's agency doesn't match
  // the booking's agency (and they aren't super_admin), the response is
  // redacted to the minimum the client needs to render a "wrong agency"
  // notice — passenger name, phone, route, scheduled time, and park details
  // are stripped server-side. The booking still resolves (so the client
  // knows it exists and whose agency it belongs to), but no PII leaks
  // across agencies.
  //
  // The booking code remains "secret" enough to act as a soft passkey on
  // the unauthenticated /attest and /cancel endpoints below — those use
  // code + phone as a pair, never code alone.
  router.get('/bookings/code/:code', authenticate, async (req, res) => {
    try {
      const result = await req.db.query(
        `SELECT ${bookingFields('b')},
                a.name AS "agencyName", a.contact_phone AS "agencyContactPhone", a.park_name AS "agencyParkName",
                d.scheduled_time AS "scheduledTime",
                r.origin, r.destination
           FROM bookings b
           JOIN agencies a ON a.id = b.agency_id
           JOIN departures d ON d.id = b.departure_id
           JOIN routes r ON r.id = d.route_id
          WHERE b.code = upper($1)`,
        [req.params.code]
      );
      if (result.rows.length === 0) return fail(res, 'Booking not found', 404);

      const row = result.rows[0];
      const isCrossAgency =
          req.staff.role !== 'super_admin' &&
          req.staff.agencyId !== row.agencyId;

      if (isCrossAgency) {
        // Redacted projection. expiresAt stays so the client can compute
        // isExpired; agencyId + agencyName let the client render
        // "This booking belongs to {X}".
        return ok(res, {
          id: row.id,
          code: row.code,
          status: row.status,
          agencyId: row.agencyId,
          agencyName: row.agencyName,
          expiresAt: row.expiresAt,
        });
      }

      ok(res, row);
    } catch (e) { serverError(res, e); }
  });

  // Passenger's bookings by phone (anonymous, but phone-scoped).
  router.get('/bookings', async (req, res) => {
    const phone = req.query.phone;
    if (!phone) return fail(res, 'phone is required');
    try {
      const result = await req.db.query(
        `SELECT ${bookingFields('b')},
                a.name AS "agencyName", a.park_name AS "agencyParkName",
                d.scheduled_time AS "scheduledTime",
                r.origin, r.destination
           FROM bookings b
           JOIN agencies a ON a.id = b.agency_id
           JOIN departures d ON d.id = b.departure_id
           JOIN routes r ON r.id = d.route_id
          WHERE b.passenger_phone = $1
          ORDER BY b.created_at DESC
          LIMIT 100`,
        [phone]
      );
      ok(res, result.rows);
    } catch (e) { serverError(res, e); }
  });

  // Passenger post-trip attestation: "did you travel?". Anonymous endpoint,
  // gated by code + phone match server-side. Window: 15min–24h after the
  // scheduled departure.
  router.post('/bookings/code/:code/attest', async (req, res) => {
    const { phone, traveled } = req.body || {};
    if (typeof traveled !== 'boolean' || !phone) {
      return fail(res, 'phone (string) and traveled (boolean) are required');
    }
    try {
      const result = await req.db.query(
        `SELECT booking_id AS "bookingId",
                new_status AS "newStatus",
                commission_amount AS "commissionAmount",
                agency_id AS "agencyId",
                departure_id AS "departureId"
           FROM fn_passenger_attest_travel($1::text, $2::text, $3::boolean)`,
        [req.params.code, phone, traveled]
      );
      ok(res, result.rows[0]);
    } catch (e) {
      const m = mapPgError(e);
      return fail(res, m.msg, m.status);
    }
  });

  // Passenger cancels (only while pending; the SQL function enforces it).
  router.post('/bookings/code/:code/cancel', async (req, res) => {
    const { reason } = req.body || {};
    try {
      const result = await req.db.query(
        `SELECT booking_id AS id, status
           FROM fn_cancel_booking($1::text, $2::text, NULL::uuid)`,
        [req.params.code, reason || 'cancelled by passenger']
      );
      ok(res, result.rows[0]);
    } catch (e) {
      const m = mapPgError(e);
      return fail(res, m.msg, m.status);
    }
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Staff: confirm booking
  // ──────────────────────────────────────────────────────────────────────────
  router.post('/bookings/code/:code/confirm', authenticate, async (req, res) => {
    const { farePerSeat } = req.body || {};
    try {
      const result = await req.db.query(
        `SELECT booking_id AS "bookingId", departure_id AS "departureId",
                seat_count AS "seatCount", new_seats_sold AS "newSeatsSold",
                commission_amount AS "commissionAmount", departure_status AS "departureStatus"
           FROM fn_confirm_booking($1::text, $2::uuid, $3::numeric)`,
        [req.params.code, req.staff.id, farePerSeat ?? null]
      );
      ok(res, result.rows[0]);
    } catch (e) {
      const m = mapPgError(e);
      return fail(res, m.msg, m.status);
    }
  });

  // Revert an auto-attribution: "this walk-in wasn't my app passenger".
  // 10-minute window after confirmation; outside that window the SQL function
  // raises P0001.
  router.post('/bookings/code/:code/revert-auto-confirm', authenticate, async (req, res) => {
    try {
      const result = await req.db.query(
        `SELECT booking_id AS "bookingId",
                departure_id AS "departureId",
                new_status AS "newStatus"
           FROM fn_revert_auto_attribution($1::text, $2::uuid)`,
        [req.params.code, req.staff.id]
      );
      ok(res, result.rows[0]);
    } catch (e) {
      const m = mapPgError(e);
      return fail(res, m.msg, m.status);
    }
  });

  // Staff cancels a pending booking (e.g. passenger no-show before TTL).
  router.post('/bookings/code/:code/staff-cancel', authenticate, async (req, res) => {
    const { reason } = req.body || {};
    try {
      const result = await req.db.query(
        `SELECT booking_id AS id, status
           FROM fn_cancel_booking($1::text, $2::text, $3::uuid)`,
        [req.params.code, reason || 'cancelled by staff', req.staff.id]
      );
      ok(res, result.rows[0]);
    } catch (e) {
      const m = mapPgError(e);
      return fail(res, m.msg, m.status);
    }
  });

  // Refund a confirmed booking. Reverses the seat sale and voids the
  // commission ledger entry. Cash refund happens off-app between the
  // agency and the passenger. Rejected if the commission has already
  // settled (status='paid'); those go through the platform admin.
  router.post('/bookings/code/:code/refund', authenticate, async (req, res) => {
    const { reason } = req.body || {};
    try {
      const result = await req.db.query(
        `SELECT booking_id        AS "bookingId",
                departure_id      AS "departureId",
                seats_sold        AS "seatsSold",
                commission_amount AS "commissionAmount",
                status            AS "status"
           FROM fn_refund_booking($1::text, $2::uuid, $3::text)`,
        [req.params.code, req.staff.id, reason || null]
      );
      ok(res, result.rows[0]);
    } catch (e) {
      const m = mapPgError(e);
      return fail(res, m.msg, m.status);
    }
  });

  // Agency-scoped booking list
  router.get('/agencies/:agencyId/bookings', authenticate, async (req, res) => {
    // Authz: super_admin/regulator can see any; agency staff only their own.
    if (req.staff.role !== 'super_admin' && req.staff.role !== 'regulator' && req.staff.agencyId !== req.params.agencyId) {
      return fail(res, 'Forbidden', 403);
    }
    const { status, from, to } = req.query;
    const params = [req.params.agencyId];
    let where = `b.agency_id = $1`;
    if (status) { params.push(status); where += ` AND b.status = $${params.length}`; }
    if (from)   { params.push(from);   where += ` AND b.created_at >= $${params.length}`; }
    if (to)     { params.push(to);     where += ` AND b.created_at <= $${params.length}`; }

    try {
      const result = await req.db.query(
        `SELECT ${bookingFields('b')},
                d.scheduled_time AS "scheduledTime",
                r.origin, r.destination
           FROM bookings b
           JOIN departures d ON d.id = b.departure_id
           JOIN routes r     ON r.id = d.route_id
          WHERE ${where}
          ORDER BY b.created_at DESC
          LIMIT 500`,
        params
      );
      ok(res, result.rows);
    } catch (e) { serverError(res, e); }
  });

  // Manual sweep — clears expired holds. Useful as an admin button.
  router.post('/bookings/expire-sweep', authenticate, async (req, res) => {
    try {
      const result = await req.db.query(`SELECT fn_expire_pending_bookings() AS expired`);
      ok(res, { expired: result.rows[0].expired });
    } catch (e) { serverError(res, e); }
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Commissions
  // ──────────────────────────────────────────────────────────────────────────
  router.get('/agencies/:agencyId/commissions', authenticate, async (req, res) => {
    if (req.staff.role !== 'super_admin' && req.staff.role !== 'regulator' && req.staff.agencyId !== req.params.agencyId) {
      return fail(res, 'Forbidden', 403);
    }
    try {
      // Aggregated summary
      const summary = await req.db.query(
        `SELECT period, currency,
                SUM(commission_amount) AS total,
                SUM(commission_amount) FILTER (WHERE status='accrued')  AS accrued,
                SUM(commission_amount) FILTER (WHERE status='invoiced') AS invoiced,
                SUM(commission_amount) FILTER (WHERE status='paid')     AS paid,
                COUNT(*) AS bookings,
                SUM(seat_count) AS seats
           FROM commission_ledger
          WHERE agency_id = $1
          GROUP BY period, currency
          ORDER BY period DESC
          LIMIT 60`,
        [req.params.agencyId]
      );
      // Recent entries
      const recent = await req.db.query(
        `SELECT ${commissionFields('cl')},
                b.code AS "bookingCode", b.passenger_name AS "passengerName"
           FROM commission_ledger cl
           JOIN bookings b ON b.id = cl.booking_id
          WHERE cl.agency_id = $1
          ORDER BY cl.created_at DESC
          LIMIT 100`,
        [req.params.agencyId]
      );
      ok(res, { summary: summary.rows, recent: recent.rows });
    } catch (e) { serverError(res, e); }
  });

  router.get('/agencies/:agencyId/commissions/settings', authenticate, async (req, res) => {
    if (req.staff.role !== 'super_admin' && req.staff.agencyId !== req.params.agencyId) {
      return fail(res, 'Forbidden', 403);
    }
    try {
      const r = await req.db.query(
        `SELECT ${settingsFields()} FROM commission_settings WHERE agency_id = $1`,
        [req.params.agencyId]
      );
      if (r.rows.length === 0) {
        // Auto-create a default row so the agency dashboard is never empty.
        await req.db.query(
          `INSERT INTO commission_settings (agency_id) VALUES ($1) ON CONFLICT DO NOTHING`,
          [req.params.agencyId]
        );
        const r2 = await req.db.query(
          `SELECT ${settingsFields()} FROM commission_settings WHERE agency_id = $1`,
          [req.params.agencyId]
        );
        return ok(res, r2.rows[0]);
      }
      ok(res, r.rows[0]);
    } catch (e) { serverError(res, e); }
  });

  router.put('/agencies/:agencyId/commissions/settings', authenticate, requireRole('super_admin'), async (req, res) => {
    const { commissionRate, flatFee, currency } = req.body || {};
    try {
      const result = await req.db.query(
        `INSERT INTO commission_settings (agency_id, commission_rate, flat_fee, currency)
         VALUES ($1, COALESCE($2, 0.05), COALESCE($3, 0), COALESCE($4, 'XAF'))
         ON CONFLICT (agency_id) DO UPDATE SET
           commission_rate = COALESCE($2, commission_settings.commission_rate),
           flat_fee        = COALESCE($3, commission_settings.flat_fee),
           currency        = COALESCE($4, commission_settings.currency)
         RETURNING ${settingsFields()}`,
        [req.params.agencyId, commissionRate, flatFee, currency]
      );
      ok(res, result.rows[0]);
    } catch (e) { serverError(res, e); }
  });

  // Mark a period paid (or invoiced). super_admin only.
  router.post('/agencies/:agencyId/commissions/settle', authenticate, requireRole('super_admin'), async (req, res) => {
    const { period, status } = req.body || {};
    if (!period || !['invoiced', 'paid', 'voided', 'accrued'].includes(status)) {
      return fail(res, 'period and valid status required');
    }
    try {
      const result = await req.db.query(
        `UPDATE commission_ledger
            SET status = $3,
                settled_at = CASE WHEN $3 IN ('paid', 'voided') THEN now() ELSE settled_at END
          WHERE agency_id = $1 AND period = $2
          RETURNING id`,
        [req.params.agencyId, period, status]
      );
      ok(res, { updated: result.rowCount });
    } catch (e) { serverError(res, e); }
  });

  return router;
};
