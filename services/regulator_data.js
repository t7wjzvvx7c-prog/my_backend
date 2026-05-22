// Shared data-fetching for the regulator surface. The HTTP route handler
// and the PDF generator both call into this so the live dossier view and
// the generated PDF report are derived from the exact same query — the
// hash on a generated PDF is therefore meaningful (the underlying numbers
// are reproducible).

/// Returns the period bounds in YYYY-MM-DD strings. If both [from] and
/// [to] are provided, they are validated and used as-is. Otherwise the
/// last 7 days in Africa/Douala are computed in the database.
async function resolvePeriod(pool, from, to) {
  const dateRe = /^\d{4}-\d{2}-\d{2}$/;
  if ((from && !dateRe.test(from)) || (to && !dateRe.test(to))) {
    const e = new Error('Invalid date format; expected YYYY-MM-DD');
    e.code = 'INVALID_DATE';
    throw e;
  }
  if (from && to) return { from, to };

  const period = await pool.query(
    `SELECT
       ((now() AT TIME ZONE 'Africa/Douala')::date - INTERVAL '6 days')::date AS f,
       (now() AT TIME ZONE 'Africa/Douala')::date AS t`
  );
  return {
    from: period.rows[0].f.toISOString().slice(0, 10),
    to:   period.rows[0].t.toISOString().slice(0, 10),
  };
}

/// Fetches every piece of data needed to render an agency dossier (live
/// or PDF). Returns null if the agency does not exist. Does NOT enforce
/// regulator scope — callers must have already checked.
async function fetchAgencyDossierData(pool, agencyId, fromIso, toIso) {
  const [agencyRow, metricsRow, statusRows, topRoutesRows, auditRows] =
    await Promise.all([
      pool.query(
        `SELECT id, name, contact_phone AS "contactPhone",
                park_name AS "parkName", is_active AS "isActive",
                created_at AS "createdAt"
           FROM agencies WHERE id = $1`,
        [agencyId]
      ),
      pool.query(
        `SELECT
           COUNT(*)::int AS departures,
           COUNT(*) FILTER (WHERE status = 'departed')::int AS departed,
           COALESCE(
             AVG(CASE WHEN total_seats > 0
                      THEN seats_sold::numeric / total_seats
                      ELSE 0 END),
             0
           )::numeric(5,3) AS avg_fill,
           COALESCE(
             AVG(
               CASE
                 WHEN status = 'departed' AND departed_at IS NOT NULL
                   THEN CASE
                          WHEN departed_at <= scheduled_time + INTERVAL '30 minutes'
                            THEN 1.0 ELSE 0.0
                        END
                 ELSE NULL
               END
             ),
             0
           )::numeric(5,3) AS on_time_rate
         FROM departures
         WHERE agency_id = $1
           AND scheduled_time::date BETWEEN $2::date AND $3::date`,
        [agencyId, fromIso, toIso]
      ),
      pool.query(
        `SELECT status::text AS status, COUNT(*)::int AS count
           FROM departures
          WHERE agency_id = $1
            AND scheduled_time::date BETWEEN $2::date AND $3::date
          GROUP BY status
          ORDER BY count DESC`,
        [agencyId, fromIso, toIso]
      ),
      pool.query(
        `SELECT r.id, r.origin, r.destination,
                COUNT(d.id)::int AS departures,
                COALESCE(
                  AVG(CASE WHEN d.total_seats > 0
                           THEN d.seats_sold::numeric / d.total_seats
                           ELSE 0 END),
                  0
                )::numeric(5,3) AS avg_fill
           FROM routes r
           JOIN departures d ON d.route_id = r.id
          WHERE r.agency_id = $1
            AND d.scheduled_time::date BETWEEN $2::date AND $3::date
          GROUP BY r.id, r.origin, r.destination
          ORDER BY departures DESC
          LIMIT 5`,
        [agencyId, fromIso, toIso]
      ),
      pool.query(
        `SELECT al.id,
                al.action::text   AS action,
                al.entity_type    AS "entityType",
                al.entity_id      AS "entityId",
                al.performed_by   AS "performedBy",
                al.new_values     AS "newValues",
                al.created_at     AS "createdAt"
           FROM audit_log al
          WHERE (
                  al.entity_type = 'departure'
                  AND al.entity_id IN (SELECT id FROM departures WHERE agency_id = $1)
                )
             OR (
                  al.entity_type = 'staff_user'
                  AND al.entity_id IN (SELECT id FROM staff_users WHERE agency_id = $1)
                )
          ORDER BY al.created_at DESC
          LIMIT 20`,
        [agencyId]
      ),
    ]);

  if (agencyRow.rows.length === 0) return null;

  const m = metricsRow.rows[0];
  return {
    agency: agencyRow.rows[0],
    period: { from: fromIso, to: toIso },
    metrics: {
      departures: m.departures,
      departed: m.departed,
      avgFillRate: parseFloat(m.avg_fill),
      onTimeRate: parseFloat(m.on_time_rate),
    },
    statusBreakdown: statusRows.rows,
    topRoutes: topRoutesRows.rows.map((r) => ({
      id: r.id,
      origin: r.origin,
      destination: r.destination,
      departures: r.departures,
      avgFillRate: parseFloat(r.avg_fill),
    })),
    recentAudit: auditRows.rows,
  };
}

module.exports = { resolvePeriod, fetchAgencyDossierData };
