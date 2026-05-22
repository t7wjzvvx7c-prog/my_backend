const express = require('express');
const fs = require('fs');
const path = require('path');
const { resolvePeriod, fetchAgencyDossierData } = require('../services/regulator_data');
const { generateAgencyDossierPdf } = require('../services/report_generator');

// Reports are stored on disk. REPORTS_DIR can point at a Railway Volume
// mount for durability across deploys; without one the directory is
// ephemeral, which is acceptable for demo / pilot scale.
const REPORTS_DIR = process.env.REPORTS_DIR || path.join(__dirname, '..', 'reports');
try { fs.mkdirSync(REPORTS_DIR, { recursive: true }); } catch (_) {}

// Regulator surface — read-only endpoints for transport authorities,
// municipal regulators, and syndicat officers. Mounted under /regulator
// in server.js. All endpoints require role='regulator' and a non-empty
// regulator_scope row. Default-deny: a regulator with no scope rows
// gets 403, never accidental access.
//
// Exported as a factory so the dependencies (auth helpers + response
// helpers) come from server.js without re-export plumbing. All queries
// run on req.db (the per-request RLS-aware client created by
// withRequestDb in server.js); the service modules in
// services/regulator_data.js and services/report_generator.js accept
// any object exposing .query(sql, params), so we hand them req.db.
module.exports = function createRegulatorRouter({
  authenticate,
  requireRole,
  ok,
  fail,
  serverError,
}) {
  const router = express.Router();

  // --------------------------------------------------------------
  // Field maps — kept distinct from server.js FIELDS so changes here
  // never affect the shape returned to the agency app.
  // --------------------------------------------------------------
  const REG_FIELDS = {
    park: `id, name, city, region, lat, lng, is_active AS "isActive"`,
    agencySummary: `
      a.id,
      a.name,
      a.contact_phone AS "contactPhone",
      a.is_active     AS "isActive"
    `,
  };

  // --------------------------------------------------------------
  // requireScope: loads the caller's regulator_scope rows and
  // resolves them to concrete agency_ids and park_ids attached to
  // req.scope. Empty scope → 403.
  //
  // Scope shape:
  //   { national: true,  agencyIds: null, parkIds: null }   (unrestricted)
  //   { national: false, agencyIds: [...], parkIds: [...] } (restricted)
  // --------------------------------------------------------------
  async function requireScope(req, res, next) {
    try {
      const scopeRows = await req.db.query(
        `SELECT scope_type, scope_value FROM regulator_scope WHERE staff_user_id = $1`,
        [req.staff.id]
      );

      if (scopeRows.rows.length === 0) {
        return fail(res, 'No regulator scope assigned', 403);
      }

      const isNational = scopeRows.rows.some((r) => r.scope_type === 'national');
      if (isNational) {
        req.scope = { national: true, agencyIds: null, parkIds: null };
        return next();
      }

      const cities  = scopeRows.rows.filter((r) => r.scope_type === 'city').map((r) => r.scope_value);
      const parkIds = scopeRows.rows.filter((r) => r.scope_type === 'park').map((r) => r.scope_value);
      // syndicat scope is reserved; not yet resolvable until a syndicats table exists

      const parks = await req.db.query(
        `SELECT id FROM parks
          WHERE is_active = true
            AND (id = ANY($1::uuid[]) OR city = ANY($2::text[]))`,
        [parkIds, cities]
      );
      const resolvedParkIds = parks.rows.map((r) => r.id);

      if (resolvedParkIds.length === 0) {
        return fail(res, 'No accessible parks within scope', 403);
      }

      const agencies = await req.db.query(
        `SELECT DISTINCT agency_id FROM agency_parks WHERE park_id = ANY($1::uuid[])`,
        [resolvedParkIds]
      );

      req.scope = {
        national: false,
        agencyIds: agencies.rows.map((r) => r.agency_id),
        parkIds: resolvedParkIds,
      };
      next();
    } catch (err) {
      serverError(res, err);
    }
  }

  // Every regulator route runs through these three layers in order.
  router.use(authenticate);
  router.use(requireRole('regulator'));
  router.use(requireScope);

  // --------------------------------------------------------------
  // GET /regulator/overview
  //
  // KPI strip for the live operations tab. Returns counts and
  // averages over today's departures within scope, where "today"
  // is interpreted in Africa/Douala (the pool already sets session
  // timezone, so date math works without extra casts).
  //
  // Logs a 'report_viewed' audit row so regulator access is itself
  // auditable — donors and procurement reviewers care about this.
  // --------------------------------------------------------------
  router.get('/overview', async (req, res) => {
    const scopedAgency = req.scope.national
      ? { clause: '', params: [] }
      : { clause: 'AND agency_id = ANY($1::uuid[])', params: [req.scope.agencyIds] };

    const scopedAgencyOnAlias = req.scope.national
      ? { clause: '', params: [] }
      : { clause: 'AND a.id = ANY($1::uuid[])', params: [req.scope.agencyIds] };

    const scopedPark = req.scope.national
      ? { clause: '', params: [] }
      : { clause: 'WHERE id = ANY($1::uuid[])', params: [req.scope.parkIds] };

    try {
      const [agencyRow, todayRow, parkRow] = await Promise.all([
        req.db.query(
          `SELECT COUNT(*)::int AS n
             FROM agencies a
            WHERE a.is_active = true ${scopedAgencyOnAlias.clause}`,
          scopedAgencyOnAlias.params
        ),
        req.db.query(
          `SELECT
              COUNT(*)::int AS departures,
              COALESCE(
                AVG(CASE WHEN total_seats > 0
                         THEN seats_sold::numeric / total_seats
                         ELSE 0 END),
                0
              )::numeric(5,3) AS avg_fill
           FROM departures
           WHERE scheduled_time::date = (now() AT TIME ZONE 'Africa/Douala')::date
             ${scopedAgency.clause}`,
          scopedAgency.params
        ),
        req.db.query(
          `SELECT COUNT(*)::int AS n FROM parks ${scopedPark.clause}`,
          scopedPark.params
        ),
      ]);

      // Audit the access. Use the regulator's own staff id as entity
      // since this view is not tied to a specific dossier.
      req.db.query(
        `INSERT INTO audit_log (action, entity_type, entity_id, performed_by, new_values)
         VALUES ('report_viewed', 'regulator_overview', $1, $1, $2)`,
        [req.staff.id, JSON.stringify({ ip: req.ip })]
      ).catch(() => { /* never block the response on audit write */ });

      ok(res, {
        agencies: agencyRow.rows[0].n,
        departuresToday: todayRow.rows[0].departures,
        avgFillRate: parseFloat(todayRow.rows[0].avg_fill),
        parks: parkRow.rows[0].n,
      });
    } catch (err) {
      serverError(res, err);
    }
  });

  // --------------------------------------------------------------
  // GET /regulator/parks
  //
  // Parks in scope plus a count of agencies operating from each.
  // Powers the live map markers and the park dropdown in filters.
  // --------------------------------------------------------------
  router.get('/parks', async (req, res) => {
    const where = req.scope.national ? '' : 'WHERE p.id = ANY($1::uuid[])';
    const params = req.scope.national ? [] : [req.scope.parkIds];

    try {
      const result = await req.db.query(
        `SELECT ${REG_FIELDS.park},
                (SELECT COUNT(*)::int FROM agency_parks ap WHERE ap.park_id = p.id) AS "agencyCount"
           FROM parks p
           ${where}
          ORDER BY p.city ASC, p.name ASC`,
        params
      );
      ok(res, result.rows);
    } catch (err) {
      serverError(res, err);
    }
  });

  // --------------------------------------------------------------
  // GET /regulator/agencies
  //
  // Agencies in scope with a compact reporting summary: today's
  // departure count and most recent update timestamp. The Annuaire
  // tab uses this; drill-down to a full dossier is a later endpoint.
  // --------------------------------------------------------------
  router.get('/agencies', async (req, res) => {
    const where = req.scope.national ? '' : 'WHERE a.id = ANY($1::uuid[])';
    const params = req.scope.national ? [] : [req.scope.agencyIds];

    try {
      const result = await req.db.query(
        `SELECT ${REG_FIELDS.agencySummary},
                (SELECT COUNT(*)::int
                   FROM departures d
                  WHERE d.agency_id = a.id
                    AND d.scheduled_time::date = (now() AT TIME ZONE 'Africa/Douala')::date
                ) AS "departuresToday",
                (SELECT MAX(d.updated_at)
                   FROM departures d
                  WHERE d.agency_id = a.id
                ) AS "lastDepartureUpdate"
           FROM agencies a
           ${where}
          ORDER BY a.name ASC`,
        params
      );
      ok(res, result.rows);
    } catch (err) {
      serverError(res, err);
    }
  });

  // --------------------------------------------------------------
  // GET /regulator/agencies/:id/dossier?from=YYYY-MM-DD&to=YYYY-MM-DD
  //
  // Full drill-down for a single agency. Defaults to last 7 days.
  //
  // Per-entity scope check: the regulator must already have this
  // agency in scope (national OR via agency_parks linkage). A 404
  // is returned for out-of-scope ids — same response as a non-
  // existent agency, to avoid leaking the existence of agencies
  // outside the regulator's scope.
  //
  // Returns:
  //   - agency:    basic identity fields
  //   - period:    { from, to } actually used
  //   - metrics:   totals, status breakdown, on-time rate, avg fill
  //   - topRoutes: 5 highest-volume routes in period
  //   - recentAudit: last 20 audit events touching this agency's
  //                  departures or staff
  //
  // Audit access is itself logged with action='report_viewed' and
  // entity_type='agency_dossier'.
  // --------------------------------------------------------------
  router.get('/agencies/:id/dossier', async (req, res) => {
    const agencyId = req.params.id;

    // Per-entity scope check. National scope skips the list check.
    if (!req.scope.national && !req.scope.agencyIds.includes(agencyId)) {
      return fail(res, 'Agency not found', 404);
    }

    try {
      const period = await resolvePeriod(req.db, req.query.from, req.query.to);
      const data = await fetchAgencyDossierData(req.db, agencyId, period.from, period.to);

      if (data === null) return fail(res, 'Agency not found', 404);

      // Audit the dossier view.
      req.db.query(
        `INSERT INTO audit_log (action, entity_type, entity_id, performed_by, new_values)
         VALUES ('report_viewed', 'agency_dossier', $1, $2, $3)`,
        [agencyId, req.staff.id, JSON.stringify({ ...period, ip: req.ip })]
      ).catch(() => { /* never block on audit write */ });

      ok(res, data);
    } catch (err) {
      if (err.code === 'INVALID_DATE') return fail(res, err.message, 400);
      serverError(res, err);
    }
  });

  // --------------------------------------------------------------
  // GET /regulator/routes
  //
  // Network-wide route performance, grouped by (origin, destination).
  // Multiple agencies competing on the same OD pair are aggregated
  // into one row — this is the regulator's natural unit of analysis,
  // distinct from the per-agency view served by /agencies and the
  // per-agency dossier.
  //
  // Query params (all optional):
  //   from, to  — YYYY-MM-DD inclusive; defaults to last 7 days
  //   sort      — 'volume' (default) | 'fill' | 'ontime'
  //   page      — 1-indexed, default 1
  //   pageSize  — default 50, max 200
  //
  // Returns:
  //   { period, sort, items, page, pageSize, total, hasMore }
  //
  // Each item:
  //   { origin, destination, agenciesOperating, totalDepartures,
  //     avgFillRate, onTimeRate }
  //
  // Scope: aggregates only over departures from agencies in the
  // regulator's scope. A regulator with city='Douala' looking at
  // 'Douala → Yaoundé' will see Douala-based agencies' operations
  // on that corridor but not Yaoundé-based agencies' — correct,
  // since they are not responsible for the latter.
  // --------------------------------------------------------------
  router.get('/routes', async (req, res) => {
    const sortOptions = {
      volume: '"totalDepartures" DESC',
      fill:   '"avgFillRate" DESC',
      ontime: '"onTimeRate" DESC',
    };
    const sort = req.query.sort || 'volume';
    const orderBy = sortOptions[sort];
    if (!orderBy) return fail(res, "Invalid sort; expected 'volume', 'fill', or 'ontime'", 400);

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize, 10) || 50));
    const offset = (page - 1) * pageSize;

    try {
      const period = await resolvePeriod(req.db, req.query.from, req.query.to);

      // Build the agency-scope clause once. National-scope skips it.
      const agencyParams = req.scope.national ? [] : [req.scope.agencyIds];
      const agencyClause = req.scope.national
        ? ''
        : `AND r.agency_id = ANY($${agencyParams.length}::uuid[])`;

      // The aggregation is identical for items and total count, so a
      // common subquery keeps them in sync. Placeholder numbering lines
      // up for both queries: $1=from, $2=to, [$3=agencyIds], $N=limit/offset.
      const baseFromIdx = agencyParams.length + 1;
      const baseToIdx   = agencyParams.length + 2;

      const itemsParams = [...agencyParams, period.from, period.to, pageSize, offset];
      const totalParams = [...agencyParams, period.from, period.to];

      const aggSql = `
        SELECT
          r.origin,
          r.destination,
          COUNT(DISTINCT r.agency_id)::int AS "agenciesOperating",
          COUNT(d.id)::int                  AS "totalDepartures",
          COALESCE(
            AVG(CASE WHEN d.total_seats > 0
                     THEN d.seats_sold::numeric / d.total_seats
                     ELSE 0 END),
            0
          )::numeric(5,3) AS "avgFillRate",
          COALESCE(
            AVG(
              CASE
                WHEN d.status = 'departed' AND d.departed_at IS NOT NULL
                  THEN CASE
                         WHEN d.departed_at <= d.scheduled_time + INTERVAL '30 minutes'
                           THEN 1.0 ELSE 0.0
                       END
                ELSE NULL
              END
            ),
            0
          )::numeric(5,3) AS "onTimeRate"
        FROM routes r
        JOIN departures d ON d.route_id = r.id
        WHERE d.scheduled_time::date BETWEEN $${baseFromIdx}::date AND $${baseToIdx}::date
          ${agencyClause}
        GROUP BY r.origin, r.destination
      `;

      const [items, totalRow] = await Promise.all([
        req.db.query(
          `${aggSql}
           ORDER BY ${orderBy}, r.origin ASC, r.destination ASC
           LIMIT $${itemsParams.length - 1} OFFSET $${itemsParams.length}`,
          itemsParams,
        ),
        req.db.query(
          `SELECT COUNT(*)::int AS total FROM (${aggSql}) agg`,
          totalParams,
        ),
      ]);

      ok(res, {
        period,
        sort,
        items: items.rows.map((r) => ({
          origin: r.origin,
          destination: r.destination,
          agenciesOperating: r.agenciesOperating,
          totalDepartures: r.totalDepartures,
          avgFillRate: parseFloat(r.avgFillRate),
          onTimeRate: parseFloat(r.onTimeRate),
        })),
        page,
        pageSize,
        total: totalRow.rows[0].total,
        hasMore: offset + items.rows.length < totalRow.rows[0].total,
      });
    } catch (err) {
      if (err.code === 'INVALID_DATE') return fail(res, err.message, 400);
      serverError(res, err);
    }
  });

  // --------------------------------------------------------------
  // GET /regulator/routes/breakdown
  //
  // Per-agency split for ONE OD pair. Closes the analytical loop:
  // /routes shows which corridors are underperforming network-wide;
  // this drill-down shows which agencies on that corridor are
  // dragging the corridor's numbers down. Tapping an agency row in
  // the UI then opens that agency's dossier — the same direction
  // every regulator query naturally flows.
  //
  // Query params:
  //   origin       — required (route origin string, exact match)
  //   destination  — required
  //   from, to     — optional YYYY-MM-DD; defaults to last 7 days
  //   sort         — 'volume' (default) | 'fill' | 'ontime' | 'share'
  //
  // Returns:
  //   { origin, destination, period, sort, items, totalDepartures }
  //
  // Each item:
  //   { agencyId, agencyName, departures, avgFillRate, onTimeRate,
  //     marketShare }   // share is in [0..1] across in-scope agencies
  //
  // Scope: aggregates ONLY over in-scope agencies. The market-share
  // denominator is therefore the corridor's volume *as visible to
  // this regulator*, not the absolute corridor volume — the right
  // semantics for accountability ("of the operators I oversee, who
  // is the biggest player on this lane").
  //
  // No pagination: real corridors have ~3–15 agencies.
  // --------------------------------------------------------------
  router.get('/routes/breakdown', async (req, res) => {
    const origin      = req.query.origin;
    const destination = req.query.destination;
    if (!origin || !destination) {
      return fail(res, 'origin and destination are required', 400);
    }

    const sortOptions = {
      volume: 'departures DESC',
      fill:   '"avgFillRate" DESC',
      ontime: '"onTimeRate" DESC',
      share:  'departures DESC', // share is monotonic with departures
    };
    const sort = req.query.sort || 'volume';
    const orderBy = sortOptions[sort];
    if (!orderBy) {
      return fail(res, "Invalid sort; expected 'volume', 'fill', 'ontime', or 'share'", 400);
    }

    try {
      const period = await resolvePeriod(req.db, req.query.from, req.query.to);

      const params = [origin, destination, period.from, period.to];
      const agencyClause = req.scope.national
        ? ''
        : (params.push(req.scope.agencyIds), `AND r.agency_id = ANY($${params.length}::uuid[])`);

      const result = await req.db.query(
        `SELECT
            a.id        AS "agencyId",
            a.name      AS "agencyName",
            COUNT(d.id)::int AS departures,
            COALESCE(
              AVG(CASE WHEN d.total_seats > 0
                       THEN d.seats_sold::numeric / d.total_seats
                       ELSE 0 END),
              0
            )::numeric(5,3) AS "avgFillRate",
            COALESCE(
              AVG(
                CASE
                  WHEN d.status = 'departed' AND d.departed_at IS NOT NULL
                    THEN CASE
                           WHEN d.departed_at <= d.scheduled_time + INTERVAL '30 minutes'
                             THEN 1.0 ELSE 0.0
                         END
                  ELSE NULL
                END
              ),
              0
            )::numeric(5,3) AS "onTimeRate"
           FROM routes r
           JOIN agencies a   ON a.id = r.agency_id
           JOIN departures d ON d.route_id = r.id
          WHERE r.origin = $1
            AND r.destination = $2
            AND d.scheduled_time::date BETWEEN $3::date AND $4::date
            ${agencyClause}
          GROUP BY a.id, a.name
          ORDER BY ${orderBy}, a.name ASC`,
        params,
      );

      // Compute market share in JS — keeps the SQL readable. Total is
      // bounded by the in-scope filter, so it is "the share within
      // the operators this regulator oversees", not absolute.
      const total = result.rows.reduce((s, r) => s + r.departures, 0);
      const items = result.rows.map((r) => ({
        agencyId: r.agencyId,
        agencyName: r.agencyName,
        departures: r.departures,
        avgFillRate: parseFloat(r.avgFillRate),
        onTimeRate: parseFloat(r.onTimeRate),
        marketShare: total === 0 ? 0 : r.departures / total,
      }));

      ok(res, {
        origin,
        destination,
        period,
        sort,
        items,
        totalDepartures: total,
      });
    } catch (err) {
      if (err.code === 'INVALID_DATE') return fail(res, err.message, 400);
      serverError(res, err);
    }
  });

  // --------------------------------------------------------------
  // GET /regulator/audit
  //
  // Paginated, filterable audit log of operational events. Scope is
  // enforced at the SQL level: the result set never includes events
  // for departures or staff outside the regulator's scope. Default
  // view excludes regulator-self events ('regulator_overview',
  // 'agency_dossier', 'report_viewed' on those entities) — those are
  // access logs, not operational audit.
  //
  // Query params (all optional):
  //   agencyId   — uuid; must intersect scope, else 404
  //   action     — audit_action enum value
  //   entityType — 'departure' | 'staff_user'
  //   from, to   — YYYY-MM-DD inclusive; UTC date arithmetic
  //   page       — 1-indexed, default 1
  //   pageSize   — default 50, max 200
  //
  // Returns:
  //   { items, page, pageSize, total, hasMore }
  // --------------------------------------------------------------
  router.get('/audit', async (req, res) => {
    // Resolve effective agency scope: the intersection of the
    // regulator's scope and the optional ?agencyId filter.
    const requestedAgency = req.query.agencyId || null;
    let effectiveAgencyIds; // null = unrestricted (national + no agency filter)

    if (req.scope.national && !requestedAgency) {
      effectiveAgencyIds = null;
    } else if (req.scope.national && requestedAgency) {
      effectiveAgencyIds = [requestedAgency];
    } else if (!req.scope.national && requestedAgency) {
      if (!req.scope.agencyIds.includes(requestedAgency)) {
        return fail(res, 'Agency not found', 404);
      }
      effectiveAgencyIds = [requestedAgency];
    } else {
      effectiveAgencyIds = req.scope.agencyIds;
    }

    const action = req.query.action || null;
    const entityType = req.query.entityType || null;
    if (entityType && !['departure', 'staff_user'].includes(entityType)) {
      return fail(res, 'Invalid entityType', 400);
    }

    const dateRe = /^\d{4}-\d{2}-\d{2}$/;
    const fromIso = req.query.from || null;
    const toIso   = req.query.to   || null;
    if ((fromIso && !dateRe.test(fromIso)) || (toIso && !dateRe.test(toIso))) {
      return fail(res, 'Invalid date format; expected YYYY-MM-DD', 400);
    }

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize, 10) || 50));
    const offset = (page - 1) * pageSize;

    // Build the WHERE clause incrementally. Numbered params keep
    // the query understandable; the alternative (named placeholders
    // through a helper) would be more code than it's worth here.
    const params = [];
    const whereParts = [];

    // Operational scope: only departure/staff events linked to in-scope agencies.
    if (effectiveAgencyIds === null) {
      whereParts.push(`al.entity_type IN ('departure','staff_user')`);
    } else {
      params.push(effectiveAgencyIds);
      const p = `$${params.length}::uuid[]`;
      whereParts.push(`(
        (al.entity_type = 'departure'
          AND al.entity_id IN (SELECT id FROM departures   WHERE agency_id = ANY(${p})))
        OR
        (al.entity_type = 'staff_user'
          AND al.entity_id IN (SELECT id FROM staff_users  WHERE agency_id = ANY(${p})))
      )`);
    }

    if (action) {
      params.push(action);
      whereParts.push(`al.action::text = $${params.length}`);
    }
    if (entityType) {
      params.push(entityType);
      whereParts.push(`al.entity_type = $${params.length}`);
    }
    if (fromIso) {
      params.push(fromIso);
      whereParts.push(`al.created_at >= $${params.length}::date`);
    }
    if (toIso) {
      params.push(toIso);
      whereParts.push(`al.created_at < ($${params.length}::date + INTERVAL '1 day')`);
    }

    const whereClause = `WHERE ${whereParts.join(' AND ')}`;

    try {
      // Items + total in parallel. Total is bounded by the same WHERE.
      const itemsParams = [...params, pageSize, offset];
      const limitClause = `LIMIT $${itemsParams.length - 1} OFFSET $${itemsParams.length}`;

      const [items, totalRow] = await Promise.all([
        req.db.query(
          `SELECT al.id,
                  al.action::text       AS action,
                  al.entity_type        AS "entityType",
                  al.entity_id          AS "entityId",
                  al.performed_by       AS "performedBy",
                  al.new_values         AS "newValues",
                  al.old_values         AS "oldValues",
                  al.created_at         AS "createdAt"
             FROM audit_log al
             ${whereClause}
             ORDER BY al.created_at DESC
             ${limitClause}`,
          itemsParams
        ),
        req.db.query(
          `SELECT COUNT(*)::int AS total FROM audit_log al ${whereClause}`,
          params
        ),
      ]);

      const total = totalRow.rows[0].total;
      ok(res, {
        items: items.rows,
        page,
        pageSize,
        total,
        hasMore: offset + items.rows.length < total,
      });
    } catch (err) {
      serverError(res, err);
    }
  });

  // --------------------------------------------------------------
  // POST /regulator/reports
  //
  // Generate a report. Currently supports template='agency_dossier';
  // params: { agencyId, from?, to? } (defaults: last 7 days).
  //
  // Response:
  //   { id, template, generatedAt, contentHash,
  //     params, downloadUrl }
  //
  // Side effects:
  //   - PDF is written to REPORTS_DIR/{id}.pdf
  //   - Row inserted in generated_reports with content_hash
  //   - audit_log entry with action='report_generated'
  //
  // Per-entity scope check is enforced for templates that target a
  // specific agency. Out-of-scope ids return 404 (no info leak).
  // --------------------------------------------------------------
  router.post('/reports', async (req, res) => {
    const { template, params = {} } = req.body || {};

    if (template !== 'agency_dossier') {
      return fail(res, `Unsupported template '${template}'. Supported: agency_dossier`, 400);
    }
    const agencyId = params.agencyId;
    if (!agencyId) return fail(res, "Missing params.agencyId", 400);

    if (!req.scope.national && !req.scope.agencyIds.includes(agencyId)) {
      return fail(res, 'Agency not found', 404);
    }

    try {
      const period = await resolvePeriod(req.db, params.from, params.to);

      // Pre-allocate the report id so the same uuid lives in the PDF
      // (footer + storage filename) and the database row.
      const idRow = await req.db.query('SELECT gen_random_uuid()::text AS id');
      const reportId = idRow.rows[0].id;

      // Look up regulator's display name for the cover page.
      const me = await req.db.query(
        'SELECT name FROM staff_users WHERE id = $1', [req.staff.id],
      );
      const generatedByName = me.rows[0]?.name || 'Régulateur';
      const generatedAt = new Date();

      const { buffer, contentHash, data } = await generateAgencyDossierPdf({
        // Service expects a "pool" key but really wants any querier — pass
        // the request-scoped client so its reads land in this transaction.
        pool: req.db, agencyId,
        fromIso: period.from, toIso: period.to,
        reportId, generatedAt, generatedByName,
      });

      // Persist file then row, in that order, so a successful row always
      // points at a real file. If the row insert fails the file is
      // orphaned — acceptable, regenerating overwrites cleanly.
      const filePath = path.join(REPORTS_DIR, `${reportId}.pdf`);
      fs.writeFileSync(filePath, buffer);

      const scopeJson = {
        agencyId,
        agencyName: data.agency.name,
        period,
        metrics: data.metrics,
      };

      await req.db.query(
        `INSERT INTO generated_reports
            (id, template, scope_json, generated_by, generated_at, file_path, content_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [reportId, template, scopeJson, req.staff.id, generatedAt, filePath, contentHash],
      );

      // Audit. Best-effort; never block the response.
      req.db.query(
        `INSERT INTO audit_log (action, entity_type, entity_id, performed_by, new_values)
         VALUES ('report_generated', 'generated_report', $1, $2, $3)`,
        [reportId, req.staff.id, JSON.stringify({ template, agencyId, period, contentHash })],
      ).catch(() => {});

      ok(res, {
        id: reportId,
        template,
        generatedAt: generatedAt.toISOString(),
        contentHash,
        params: { agencyId, ...period },
        downloadUrl: `/regulator/reports/${reportId}/download`,
      }, 201);
    } catch (err) {
      if (err.code === 'INVALID_DATE')   return fail(res, err.message, 400);
      if (err.code === 'AGENCY_NOT_FOUND') return fail(res, 'Agency not found', 404);
      serverError(res, err);
    }
  });

  // --------------------------------------------------------------
  // GET /regulator/reports
  //
  // List reports the caller has previously generated. Filters:
  //   template, from, to, page, pageSize.
  // Scoped to the caller's own staff id — a regulator only sees
  // their own generation history. (For a multi-regulator audit
  // view of report generation, query audit_log with
  // action='report_generated'.)
  // --------------------------------------------------------------
  router.get('/reports', async (req, res) => {
    const dateRe = /^\d{4}-\d{2}-\d{2}$/;
    const { template, from, to } = req.query;
    if ((from && !dateRe.test(from)) || (to && !dateRe.test(to))) {
      return fail(res, 'Invalid date format; expected YYYY-MM-DD', 400);
    }
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize, 10) || 50));
    const offset = (page - 1) * pageSize;

    const params = [req.staff.id];
    const where = ['generated_by = $1'];
    if (template) { params.push(template); where.push(`template = $${params.length}`); }
    if (from)     { params.push(from);     where.push(`generated_at >= $${params.length}::date`); }
    if (to)       { params.push(to);       where.push(`generated_at <  ($${params.length}::date + INTERVAL '1 day')`); }

    const whereClause = `WHERE ${where.join(' AND ')}`;

    try {
      const itemsParams = [...params, pageSize, offset];
      const [items, totalRow] = await Promise.all([
        req.db.query(
          `SELECT id, template, scope_json AS "scopeJson",
                  generated_at AS "generatedAt", content_hash AS "contentHash"
             FROM generated_reports
             ${whereClause}
             ORDER BY generated_at DESC
             LIMIT $${itemsParams.length - 1} OFFSET $${itemsParams.length}`,
          itemsParams,
        ),
        req.db.query(
          `SELECT COUNT(*)::int AS total FROM generated_reports ${whereClause}`,
          params,
        ),
      ]);

      ok(res, {
        items: items.rows.map((r) => ({
          ...r,
          downloadUrl: `/regulator/reports/${r.id}/download`,
        })),
        page, pageSize,
        total: totalRow.rows[0].total,
        hasMore: offset + items.rows.length < totalRow.rows[0].total,
      });
    } catch (err) {
      serverError(res, err);
    }
  });

  // --------------------------------------------------------------
  // GET /regulator/reports/:id
  //
  // Metadata for a previously generated report. Scoped: a regulator
  // can only fetch metadata for reports they themselves generated.
  // --------------------------------------------------------------
  router.get('/reports/:id', async (req, res) => {
    try {
      const r = await req.db.query(
        `SELECT id, template, scope_json AS "scopeJson",
                generated_at AS "generatedAt", content_hash AS "contentHash"
           FROM generated_reports
          WHERE id = $1 AND generated_by = $2`,
        [req.params.id, req.staff.id],
      );
      if (r.rows.length === 0) return fail(res, 'Report not found', 404);
      ok(res, {
        ...r.rows[0],
        downloadUrl: `/regulator/reports/${req.params.id}/download`,
      });
    } catch (err) {
      serverError(res, err);
    }
  });

  // --------------------------------------------------------------
  // GET /regulator/reports/:id/download
  //
  // Streams the PDF bytes. Same scope rule as metadata.
  // Logs audit_log action='report_downloaded'.
  // --------------------------------------------------------------
  router.get('/reports/:id/download', async (req, res) => {
    try {
      const r = await req.db.query(
        `SELECT file_path, content_hash, scope_json
           FROM generated_reports
          WHERE id = $1 AND generated_by = $2`,
        [req.params.id, req.staff.id],
      );
      if (r.rows.length === 0) return fail(res, 'Report not found', 404);

      const { file_path: filePath, content_hash: hash } = r.rows[0];
      if (!fs.existsSync(filePath)) {
        return fail(res, 'Report file missing on server', 410);
      }

      req.db.query(
        `INSERT INTO audit_log (action, entity_type, entity_id, performed_by, new_values)
         VALUES ('report_downloaded', 'generated_report', $1, $2, $3)`,
        [req.params.id, req.staff.id, JSON.stringify({ ip: req.ip })],
      ).catch(() => {});

      // Headers: filename includes the short id so saves are easy to
      // distinguish; X-Content-Hash exposes the SHA-256 so the client
      // can display it without a separate metadata request.
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition',
        `attachment; filename="dossier-${req.params.id.slice(0, 8)}.pdf"`);
      res.setHeader('X-Content-Hash', hash);
      fs.createReadStream(filePath).pipe(res);
    } catch (err) {
      serverError(res, err);
    }
  });

  return router;
};
