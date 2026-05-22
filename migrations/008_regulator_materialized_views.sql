-- ============================================================
-- Migration 008: regulator-facing materialized views
-- ============================================================
-- The regulator dossier endpoint runs three aggregate queries per
-- agency per request — bounded by today's data volume (small) but
-- guaranteed to scale linearly with departure history. Once a paid
-- regulator contract goes live with daily PDF generation across all
-- agencies, the same queries become 5-second hits on a multi-million
-- row departures table.
--
-- This migration precomputes the daily-grain rollups so the dossier
-- query becomes a SUM/AVG over <100 rows instead of a GROUP BY across
-- the full table. Refresh is nightly; lag is acceptable for regulator
-- analytics (they don't need real-time).
--
-- The MVs replicate to the read replica via WAL like any other
-- relation. Refresh is a write operation on the primary — the
-- replica picks up the new pages automatically.
--
-- Refresh strategy:
--   * REFRESH MATERIALIZED VIEW CONCURRENTLY requires a unique index
--     and CANNOT be called inside a transaction block.
--   * fn_refresh_regulator_views handles both cases: tries
--     CONCURRENTLY first, falls back to non-concurrent on first
--     refresh (when the MV has no rows yet, CONCURRENTLY refuses).
--   * The function is SECURITY DEFINER so cron / admin endpoint can
--     trigger it without owning the views.
--
-- Idempotent.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 1. Per-agency daily metrics
--    (powers dossier "metrics" block: departures, departed,
--    avg_fill, on_time_rate)
-- ------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS mv_agency_daily_metrics CASCADE;
CREATE MATERIALIZED VIEW mv_agency_daily_metrics AS
SELECT
    agency_id,
    (scheduled_time AT TIME ZONE 'Africa/Douala')::date AS day,
    COUNT(*)::int                                       AS departures,
    COUNT(*) FILTER (WHERE status = 'departed')::int    AS departed,
    SUM(seats_sold)::int                                AS seats_sold_total,
    SUM(total_seats)::int                               AS total_seats,
    -- Sum of per-row fill so the consumer can compute weighted
    -- average across an arbitrary date range:
    --     SUM(seats_sold)::numeric / NULLIF(SUM(total_seats),0)
    -- gives the right answer when summing days.
    COUNT(*) FILTER (
        WHERE status = 'departed'
          AND departed_at IS NOT NULL
          AND departed_at <= scheduled_time + INTERVAL '30 minutes'
    )::int                                              AS departed_on_time
FROM departures
GROUP BY agency_id, (scheduled_time AT TIME ZONE 'Africa/Douala')::date
WITH NO DATA;

CREATE UNIQUE INDEX idx_mv_agency_daily_metrics
    ON mv_agency_daily_metrics (agency_id, day);
CREATE INDEX idx_mv_agency_daily_metrics_day
    ON mv_agency_daily_metrics (day);

COMMENT ON MATERIALIZED VIEW mv_agency_daily_metrics IS
'Daily per-agency rollup. Sum across days for a date-range dossier query.';

-- ------------------------------------------------------------
-- 2. Per-agency / per-route daily metrics
--    (powers dossier "topRoutes" block)
-- ------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS mv_agency_route_daily CASCADE;
CREATE MATERIALIZED VIEW mv_agency_route_daily AS
SELECT
    r.agency_id,
    r.id          AS route_id,
    r.origin,
    r.destination,
    (d.scheduled_time AT TIME ZONE 'Africa/Douala')::date AS day,
    COUNT(*)::int  AS departures,
    SUM(d.seats_sold)::int AS seats_sold_total,
    SUM(d.total_seats)::int AS total_seats
FROM departures d
JOIN routes r ON r.id = d.route_id
GROUP BY r.agency_id, r.id, r.origin, r.destination,
         (d.scheduled_time AT TIME ZONE 'Africa/Douala')::date
WITH NO DATA;

CREATE UNIQUE INDEX idx_mv_agency_route_daily
    ON mv_agency_route_daily (agency_id, route_id, day);
CREATE INDEX idx_mv_agency_route_daily_agency
    ON mv_agency_route_daily (agency_id, day);

COMMENT ON MATERIALIZED VIEW mv_agency_route_daily IS
'Daily per-route rollup keyed by agency. Powers top-routes-in-period.';

-- ------------------------------------------------------------
-- 3. Per-agency daily status counts
--    (powers dossier "statusBreakdown" block)
-- ------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS mv_agency_daily_status CASCADE;
CREATE MATERIALIZED VIEW mv_agency_daily_status AS
SELECT
    agency_id,
    (scheduled_time AT TIME ZONE 'Africa/Douala')::date AS day,
    status,
    COUNT(*)::int AS count
FROM departures
GROUP BY agency_id, (scheduled_time AT TIME ZONE 'Africa/Douala')::date, status
WITH NO DATA;

CREATE UNIQUE INDEX idx_mv_agency_daily_status
    ON mv_agency_daily_status (agency_id, day, status);

COMMENT ON MATERIALIZED VIEW mv_agency_daily_status IS
'Daily status-breakdown rollup. Sum counts across days in a range.';

-- ------------------------------------------------------------
-- 4. Refresh function. SECURITY DEFINER so cron/admin can run it
--    without owning the MVs. Tries CONCURRENTLY first; falls back
--    to non-concurrent on the very first refresh (when MV is empty
--    and CONCURRENTLY refuses).
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_refresh_regulator_views()
RETURNS TABLE (view_name TEXT, refreshed_at TIMESTAMPTZ, duration_ms INT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_views CONSTANT TEXT[] := ARRAY[
        'mv_agency_daily_metrics',
        'mv_agency_route_daily',
        'mv_agency_daily_status'
    ];
    v_name TEXT;
    v_t0   TIMESTAMPTZ;
BEGIN
    FOREACH v_name IN ARRAY v_views LOOP
        v_t0 := clock_timestamp();
        BEGIN
            EXECUTE format('REFRESH MATERIALIZED VIEW CONCURRENTLY %I', v_name);
        EXCEPTION
            -- First refresh after CREATE WITH NO DATA fails CONCURRENTLY
            -- because there's no prior snapshot to diff against. Fall
            -- back to a plain refresh, which seeds the MV.
            WHEN feature_not_supported OR object_not_in_prerequisite_state THEN
                EXECUTE format('REFRESH MATERIALIZED VIEW %I', v_name);
        END;
        view_name    := v_name;
        refreshed_at := now();
        duration_ms  := EXTRACT(MILLISECOND FROM (clock_timestamp() - v_t0))::int +
                        EXTRACT(SECOND FROM (clock_timestamp() - v_t0))::int * 1000;
        RETURN NEXT;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION fn_refresh_regulator_views IS
'Refresh all regulator-facing materialized views. Cron nightly via /internal/refresh-regulator-views. SECURITY DEFINER so the calling role need not own the MVs.';

-- ------------------------------------------------------------
-- 5. Permissions. The runtime role (nexbus_app) needs SELECT on
--    the MVs and EXECUTE on the refresh function. Refresh is
--    triggered by the admin endpoint, which uses the owner role.
-- ------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nexbus_app') THEN
        GRANT SELECT ON mv_agency_daily_metrics TO nexbus_app;
        GRANT SELECT ON mv_agency_route_daily   TO nexbus_app;
        GRANT SELECT ON mv_agency_daily_status  TO nexbus_app;
        GRANT EXECUTE ON FUNCTION fn_refresh_regulator_views() TO nexbus_app;
    END IF;
END $$;

-- ------------------------------------------------------------
-- 6. Seed the views so the dossier endpoint never returns
--    an "unpopulated" error on first deploy.
-- ------------------------------------------------------------
SELECT fn_refresh_regulator_views();

COMMIT;
