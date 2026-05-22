-- ============================================================
-- Migration 007: Passenger event telemetry
-- ============================================================
-- Anonymous funnel telemetry from the passenger app: search,
-- view, tap, booking start/submit/abandon, and post-trip
-- attestation.
--
-- Distinct from audit_log (operational/regulatory evidence) by
-- design — different stream, different retention, different
-- access policy. Mixing them would either weaken audit_log's
-- compliance posture or constrain analytics with audit retention.
--
-- No PII: session_id is a client-generated UUID that lives in
-- the passenger app's Hive box. The only bridge to identifiable
-- data is booking_id, which joins to bookings — regulator
-- queries should never expose passenger name/phone from this
-- stream.
--
-- Idempotent.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 1. Enum: passenger_event_kind
-- ------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'passenger_event_kind') THEN
        CREATE TYPE passenger_event_kind AS ENUM (
            'search_performed',
            'search_no_results',
            'departure_viewed',
            'departure_tapped',
            'booking_started',
            'booking_submitted',
            'booking_abandoned',
            'attestation_traveled',
            'attestation_no_show',
            'attestation_skipped'
        );
    END IF;
END $$;


-- ------------------------------------------------------------
-- 2. Table: passenger_events
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS passenger_events (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind               passenger_event_kind NOT NULL,
    session_id         UUID                 NOT NULL,
    occurred_at        TIMESTAMPTZ          NOT NULL DEFAULT now(),

    -- Search/route context (kind-dependent; nullable)
    origin             VARCHAR(100),
    destination        VARCHAR(100),
    category           bus_category,
    time_from_min      SMALLINT,
    time_to_min        SMALLINT,
    result_count       INT,

    -- Departure / agency context (nullable; ON DELETE SET NULL so analytics
    -- survive operational cleanup without losing the funnel row entirely).
    departure_id       UUID REFERENCES departures(id) ON DELETE SET NULL,
    agency_id          UUID REFERENCES agencies(id)   ON DELETE SET NULL,

    -- Booking context (only for booking_* and attestation_* kinds)
    booking_id         UUID REFERENCES bookings(id)   ON DELETE SET NULL,

    -- Lightweight client context (no PII)
    app_version        VARCHAR(20),
    platform           VARCHAR(20),
    is_offline_capture BOOLEAN              NOT NULL DEFAULT false,

    -- Generated columns for fast bucketing in WAT (Africa/Douala)
    occurred_date      DATE     GENERATED ALWAYS AS
                       ((occurred_at AT TIME ZONE 'Africa/Douala')::date) STORED,
    occurred_hour      SMALLINT GENERATED ALWAYS AS
                       (EXTRACT(hour FROM (occurred_at AT TIME ZONE 'Africa/Douala'))::SMALLINT) STORED,

    CONSTRAINT chk_pe_time_from CHECK (time_from_min IS NULL OR (time_from_min >= 0 AND time_from_min < 1440)),
    CONSTRAINT chk_pe_time_to   CHECK (time_to_min   IS NULL OR (time_to_min   >= 0 AND time_to_min   < 1440)),
    CONSTRAINT chk_pe_result    CHECK (result_count  IS NULL OR result_count   >= 0),
    CONSTRAINT chk_pe_platform  CHECK (platform IS NULL OR platform IN ('android','ios','web','desktop'))
);


-- ------------------------------------------------------------
-- 3. Indexes
-- ------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_pe_kind_time   ON passenger_events (kind, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_pe_route_date  ON passenger_events (origin, destination, occurred_date)
    WHERE origin IS NOT NULL AND destination IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pe_agency_date ON passenger_events (agency_id, occurred_date)
    WHERE agency_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pe_session     ON passenger_events (session_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_pe_booking     ON passenger_events (booking_id)
    WHERE booking_id IS NOT NULL;

COMMENT ON TABLE  passenger_events IS
    'Anonymous passenger funnel telemetry. No PII — session_id is client-generated. Booking_id is the only bridge to identifiable data (in bookings).';
COMMENT ON COLUMN passenger_events.session_id IS
    'Client-generated UUID, persisted in the passenger app Hive box. Stable per device until app data is cleared.';
COMMENT ON COLUMN passenger_events.is_offline_capture IS
    'true if the event was queued offline and posted later. Lets analytics separate real-time from delayed signal.';


-- ------------------------------------------------------------
-- 4. Retention helper
-- ------------------------------------------------------------
-- Not auto-invoked. Call from a scheduled job (cron / pg_cron / app-side
-- worker). Default retention: 13 months — enough for year-over-year
-- comparisons; aggregates kept indefinitely in materialized views.
CREATE OR REPLACE FUNCTION fn_purge_passenger_events_older_than(p_days INTEGER)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_deleted BIGINT;
BEGIN
    IF p_days IS NULL OR p_days < 30 THEN
        RAISE EXCEPTION 'Refusing to purge events newer than 30 days (got %)', p_days
            USING ERRCODE = 'P0001';
    END IF;

    DELETE FROM passenger_events
     WHERE occurred_at < now() - (p_days || ' days')::interval;

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

COMMENT ON FUNCTION fn_purge_passenger_events_older_than IS
    'Delete passenger_events older than p_days. Refuses values < 30 as a safety guard. Recommended retention: 395 (13 months).';

COMMIT;
