-- ============================================================
-- Migration 008: Passenger event analytics views
-- ============================================================
-- Two daily-grain materialized views over passenger_events:
--
--   mv_route_demand_daily  — search volume per (origin, destination, date),
--     including searches_no_results which is the headline regulator metric:
--     "passengers searched this route N times last week and found nothing."
--
--   mv_agency_funnel_daily — view → tap → book → travel funnel per
--     (agency_id, date). The bookings_submitted vs traveled gap is the
--     honesty signal: agencies whose confirmed bookings rarely match a
--     traveled attestation are either dishonoring holds or padding numbers.
--
-- Refresh strategy: CONCURRENTLY (no reader lock) on a 15-minute schedule.
-- The migration does an initial non-concurrent populate so the first
-- scheduled refresh has data to diff against.
--
-- Cost note: full-refresh aggregation. Acceptable while passenger_events
-- is < ~5M rows. Above that, partition the base table by occurred_date
-- and switch to an incremental UPSERT pattern.
--
-- Idempotent.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 1. mv_route_demand_daily
-- ------------------------------------------------------------
-- Only search events carry (origin, destination) — view/tap/booking events
-- carry departure_id/agency_id instead. So this view is purely the search
-- demand signal.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_route_demand_daily AS
SELECT
    origin,
    destination,
    occurred_date,
    COUNT(*) FILTER (WHERE kind = 'search_performed')                          AS searches_with_results,
    COUNT(*) FILTER (WHERE kind = 'search_no_results')                         AS searches_no_results,
    COUNT(*)                                                                   AS searches_total,
    COUNT(DISTINCT session_id)                                                 AS unique_sessions,
    (AVG(result_count) FILTER (WHERE kind = 'search_performed'))::NUMERIC(10,2) AS avg_result_count
FROM passenger_events
WHERE kind IN ('search_performed', 'search_no_results')
  AND origin IS NOT NULL
  AND destination IS NOT NULL
GROUP BY origin, destination, occurred_date
WITH NO DATA;

-- Required for REFRESH MATERIALIZED VIEW CONCURRENTLY.
CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_route_demand_pk
    ON mv_route_demand_daily (origin, destination, occurred_date);
-- Date-first index for "last 7/30 days" range scans.
CREATE INDEX IF NOT EXISTS idx_mv_route_demand_date
    ON mv_route_demand_daily (occurred_date DESC);

COMMENT ON MATERIALIZED VIEW mv_route_demand_daily IS
    'Daily route-level passenger search demand. searches_no_results is the capacity-gap signal regulators care about most.';


-- ------------------------------------------------------------
-- 2. mv_agency_funnel_daily
-- ------------------------------------------------------------
-- View → tap → booking → travel funnel for agency-context events.
-- Search events are excluded (no agency_id); they live in the route view.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_agency_funnel_daily AS
SELECT
    agency_id,
    occurred_date,
    COUNT(*) FILTER (WHERE kind = 'departure_viewed')      AS views,
    COUNT(*) FILTER (WHERE kind = 'departure_tapped')      AS taps,
    COUNT(*) FILTER (WHERE kind = 'booking_started')       AS bookings_started,
    COUNT(*) FILTER (WHERE kind = 'booking_submitted')     AS bookings_submitted,
    COUNT(*) FILTER (WHERE kind = 'booking_abandoned')     AS bookings_abandoned,
    COUNT(*) FILTER (WHERE kind = 'attestation_traveled')  AS traveled,
    COUNT(*) FILTER (WHERE kind = 'attestation_no_show')   AS no_shows,
    COUNT(DISTINCT session_id)                             AS unique_sessions
FROM passenger_events
WHERE agency_id IS NOT NULL
GROUP BY agency_id, occurred_date
WITH NO DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_agency_funnel_pk
    ON mv_agency_funnel_daily (agency_id, occurred_date);
CREATE INDEX IF NOT EXISTS idx_mv_agency_funnel_date
    ON mv_agency_funnel_daily (occurred_date DESC);

COMMENT ON MATERIALIZED VIEW mv_agency_funnel_daily IS
    'Daily agency-level passenger funnel. The (bookings_submitted - traveled) gap is the honesty signal for regulator review.';


-- ------------------------------------------------------------
-- 3. Initial populate (non-concurrent — required first time)
-- ------------------------------------------------------------
-- These are no-ops if the views already had data from a prior run, but
-- safe to repeat.
REFRESH MATERIALIZED VIEW mv_route_demand_daily;
REFRESH MATERIALIZED VIEW mv_agency_funnel_daily;


-- ------------------------------------------------------------
-- 4. Refresh helper
-- ------------------------------------------------------------
-- Call from a scheduler (pg_cron, app-side worker, external cron).
-- Recommended cadence: every 15 minutes during business hours, hourly
-- otherwise. CONCURRENTLY means active regulator dashboard queries
-- don't block during refresh.
CREATE OR REPLACE FUNCTION fn_refresh_passenger_event_views()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_route_demand_daily;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_agency_funnel_daily;
END;
$$;

COMMENT ON FUNCTION fn_refresh_passenger_event_views IS
    'Refresh both passenger-event materialized views without locking readers. Schedule every 15 minutes during peak hours.';


-- ------------------------------------------------------------
-- 5. Convenience views for regulator dashboard queries
-- ------------------------------------------------------------
-- Top routes by unmet demand over the last 30 days.
CREATE OR REPLACE VIEW v_top_unmet_demand_30d AS
SELECT
    origin,
    destination,
    SUM(searches_total)        AS searches_total,
    SUM(searches_no_results)   AS searches_no_results,
    SUM(unique_sessions)       AS unique_sessions,
    ROUND(
        100.0 * SUM(searches_no_results)::NUMERIC
              / NULLIF(SUM(searches_total), 0),
        1
    )                          AS no_results_pct
FROM mv_route_demand_daily
-- CURRENT_DATE reflects the session timezone, which the runtime pool sets
-- to Africa/Douala — so this is "30 days before today, WAT".
WHERE occurred_date >= CURRENT_DATE - 30
GROUP BY origin, destination
HAVING SUM(searches_total) > 0
ORDER BY searches_no_results DESC, searches_total DESC;

COMMENT ON VIEW v_top_unmet_demand_30d IS
    'Routes with the highest no-result search volume over the last 30 days. Headline view for the regulator capacity-gap report.';

-- Agency funnel + honesty score over the last 30 days.
CREATE OR REPLACE VIEW v_agency_funnel_30d AS
SELECT
    agency_id,
    SUM(views)              AS views,
    SUM(taps)               AS taps,
    SUM(bookings_started)   AS bookings_started,
    SUM(bookings_submitted) AS bookings_submitted,
    SUM(bookings_abandoned) AS bookings_abandoned,
    SUM(traveled)           AS traveled,
    SUM(no_shows)           AS no_shows,
    SUM(unique_sessions)    AS unique_sessions,
    -- Conversion ratios: each NULL when its denominator is 0.
    ROUND(100.0 * SUM(taps)::NUMERIC               / NULLIF(SUM(views), 0), 1)              AS view_to_tap_pct,
    ROUND(100.0 * SUM(bookings_submitted)::NUMERIC / NULLIF(SUM(taps), 0), 1)               AS tap_to_book_pct,
    ROUND(100.0 * SUM(traveled)::NUMERIC           / NULLIF(SUM(bookings_submitted), 0), 1) AS book_to_travel_pct
FROM mv_agency_funnel_daily
-- CURRENT_DATE reflects the session timezone, which the runtime pool sets
-- to Africa/Douala — so this is "30 days before today, WAT".
WHERE occurred_date >= CURRENT_DATE - 30
GROUP BY agency_id;

COMMENT ON VIEW v_agency_funnel_30d IS
    'Per-agency funnel over the last 30 days. book_to_travel_pct is the honesty signal — sustained low values warrant regulator review.';

COMMIT;
