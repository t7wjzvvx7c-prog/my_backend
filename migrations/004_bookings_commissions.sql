-- ============================================================
-- Migration 004: Bookings + Commission Ledger
-- ============================================================
-- Additive only. Idempotent.
--
-- Adds the off-app payment booking flow:
--   - bookings: passenger reserves a seat, gets a short code; status starts
--     'pending' and flips to 'confirmed' when staff scan/enter the code at
--     the park. Seats are NOT decremented at reservation; they are reserved
--     softly via the seats_reserved column on departures.
--   - commission_settings: per-agency commission terms.
--   - commission_ledger: one row per confirmed booking, accruing commission
--     owed by the agency to the platform. Periodic settlement is reflected
--     by status transitions (accrued -> invoiced -> paid).
--
-- Why off-app payment: the platform only collects commission, not fares.
-- The act of confirming a booking IS the commission event, which is why
-- fn_confirm_booking is a single atomic stored function.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 0. New audit actions
-- ------------------------------------------------------------
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'booking_created';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'booking_confirmed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'booking_cancelled';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'booking_expired';

-- ------------------------------------------------------------
-- 1. Soft seat reservation column on departures
-- ------------------------------------------------------------
-- Tracks seats held by pending bookings without affecting seats_sold.
-- Available seats = total_seats - seats_sold - seats_reserved.
ALTER TABLE departures
    ADD COLUMN IF NOT EXISTS seats_reserved INTEGER NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_seats_reserved_non_negative'
    ) THEN
        ALTER TABLE departures
            ADD CONSTRAINT chk_seats_reserved_non_negative CHECK (seats_reserved >= 0);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_seats_total_within_capacity'
    ) THEN
        ALTER TABLE departures
            ADD CONSTRAINT chk_seats_total_within_capacity CHECK (seats_sold + seats_reserved <= total_seats);
    END IF;
END $$;

-- ------------------------------------------------------------
-- 2. Booking status enum
-- ------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'booking_status') THEN
        CREATE TYPE booking_status AS ENUM (
            'pending',     -- created by passenger, awaiting confirmation
            'confirmed',   -- staff confirmed at park, seat sold, commission accrued
            'expired',     -- TTL elapsed without confirmation
            'cancelled'    -- passenger or staff cancelled
        );
    END IF;
END $$;

-- ------------------------------------------------------------
-- 3. Bookings
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bookings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code            VARCHAR(12) NOT NULL UNIQUE,
    departure_id    UUID NOT NULL REFERENCES departures(id) ON DELETE CASCADE,
    agency_id       UUID NOT NULL REFERENCES agencies(id)  ON DELETE CASCADE,
    passenger_name  VARCHAR(150) NOT NULL,
    passenger_phone VARCHAR(20)  NOT NULL,
    seat_count      INTEGER      NOT NULL DEFAULT 1,
    status          booking_status NOT NULL DEFAULT 'pending',
    expires_at      TIMESTAMPTZ  NOT NULL,
    confirmed_by    UUID REFERENCES staff_users(id),
    confirmed_at    TIMESTAMPTZ,
    cancelled_at    TIMESTAMPTZ,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_booking_seat_count CHECK (seat_count > 0 AND seat_count <= 20),
    CONSTRAINT chk_booking_phone_format CHECK (passenger_phone ~ '^\+?[0-9]{8,15}$'),
    -- A confirmed booking must record who confirmed it and when. Other
    -- statuses do not require these fields (and may legitimately leave
    -- them NULL).
    CONSTRAINT chk_booking_confirmed_consistency CHECK (
        status <> 'confirmed'
        OR (confirmed_at IS NOT NULL AND confirmed_by IS NOT NULL)
    ),
    CONSTRAINT chk_booking_cancelled_consistency CHECK (
        status <> 'cancelled' OR cancelled_at IS NOT NULL
    )
);

CREATE INDEX IF NOT EXISTS idx_bookings_departure ON bookings (departure_id);
CREATE INDEX IF NOT EXISTS idx_bookings_agency    ON bookings (agency_id);
CREATE INDEX IF NOT EXISTS idx_bookings_status    ON bookings (status, expires_at);
CREATE INDEX IF NOT EXISTS idx_bookings_phone     ON bookings (passenger_phone);
CREATE INDEX IF NOT EXISTS idx_bookings_code      ON bookings (code);

COMMENT ON TABLE  bookings IS 'Passenger seat reservations made via the app; payment happens off-app.';
COMMENT ON COLUMN bookings.code IS 'Short human-readable code shown to passenger and entered/scanned by staff.';
COMMENT ON COLUMN bookings.expires_at IS 'When pending booking auto-expires and frees the soft seat hold.';

-- updated_at trigger
DROP TRIGGER IF EXISTS trg_bookings_updated ON bookings;
CREATE TRIGGER trg_bookings_updated
    BEFORE UPDATE ON bookings
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- ------------------------------------------------------------
-- 4. Commission settings (per agency)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS commission_settings (
    agency_id        UUID PRIMARY KEY REFERENCES agencies(id) ON DELETE CASCADE,
    commission_rate  NUMERIC(5,4) NOT NULL DEFAULT 0.0500,    -- 5% default
    flat_fee         NUMERIC(10,2) NOT NULL DEFAULT 0,         -- optional flat fee per booking
    currency         VARCHAR(3)   NOT NULL DEFAULT 'XAF',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_commission_rate_range CHECK (commission_rate >= 0 AND commission_rate <= 1),
    CONSTRAINT chk_flat_fee_non_negative CHECK (flat_fee >= 0)
);

COMMENT ON TABLE commission_settings IS 'Per-agency commission terms applied at booking confirmation.';
COMMENT ON COLUMN commission_settings.commission_rate IS 'Fraction of fare (0..1). Default 5%.';

DROP TRIGGER IF EXISTS trg_commission_settings_updated ON commission_settings;
CREATE TRIGGER trg_commission_settings_updated
    BEFORE UPDATE ON commission_settings
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- Seed default commission settings for any agency that doesn't have one.
INSERT INTO commission_settings (agency_id)
SELECT a.id FROM agencies a
LEFT JOIN commission_settings cs ON cs.agency_id = a.id
WHERE cs.agency_id IS NULL
ON CONFLICT DO NOTHING;

-- ------------------------------------------------------------
-- 5. Commission ledger
-- ------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'commission_status') THEN
        CREATE TYPE commission_status AS ENUM (
            'accrued',     -- recorded at booking confirmation, owed
            'invoiced',    -- bundled into a settlement invoice
            'paid',        -- agency paid the platform
            'voided'       -- booking refunded/disputed; commission reversed
        );
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS commission_ledger (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    booking_id      UUID NOT NULL UNIQUE REFERENCES bookings(id) ON DELETE CASCADE,
    agency_id       UUID NOT NULL REFERENCES agencies(id) ON DELETE CASCADE,
    seat_count      INTEGER       NOT NULL,
    fare_per_seat   NUMERIC(10,2),
    fare_total      NUMERIC(10,2),
    commission_rate NUMERIC(5,4)  NOT NULL,
    flat_fee        NUMERIC(10,2) NOT NULL DEFAULT 0,
    commission_amount NUMERIC(10,2) NOT NULL,
    currency        VARCHAR(3)    NOT NULL DEFAULT 'XAF',
    period          DATE          NOT NULL,
    status          commission_status NOT NULL DEFAULT 'accrued',
    settled_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_commission_amount_non_negative CHECK (commission_amount >= 0)
);

CREATE INDEX IF NOT EXISTS idx_commission_agency_period ON commission_ledger (agency_id, period);
CREATE INDEX IF NOT EXISTS idx_commission_status        ON commission_ledger (status);

COMMENT ON TABLE commission_ledger IS 'Per-booking commission entries. One row per confirmed booking.';

-- ------------------------------------------------------------
-- 6. fn_create_booking — atomic reservation
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_create_booking(
    p_departure_id    UUID,
    p_passenger_name  VARCHAR,
    p_passenger_phone VARCHAR,
    p_seat_count      INTEGER,
    p_ttl_minutes     INTEGER DEFAULT 60
)
RETURNS TABLE (
    id              UUID,
    code            VARCHAR,
    departure_id    UUID,
    agency_id       UUID,
    passenger_name  VARCHAR,
    passenger_phone VARCHAR,
    seat_count      INTEGER,
    status          booking_status,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_dep        RECORD;
    v_code       VARCHAR(12);
    v_booking_id UUID;
    v_attempts   INTEGER := 0;
BEGIN
    -- Lock the departure row to prevent overbooking races.
    SELECT d.id, d.agency_id, d.status, d.seats_sold, d.total_seats, d.seats_reserved
      INTO v_dep
      FROM departures d
     WHERE d.id = p_departure_id
       FOR UPDATE;

    IF v_dep IS NULL THEN
        RAISE EXCEPTION 'Departure % not found', p_departure_id USING ERRCODE = 'P0002';
    END IF;

    IF v_dep.status IN ('departed', 'full') THEN
        RAISE EXCEPTION 'Cannot book: departure is %', v_dep.status USING ERRCODE = 'P0001';
    END IF;

    IF p_seat_count < 1 OR p_seat_count > 20 THEN
        RAISE EXCEPTION 'Seat count must be between 1 and 20' USING ERRCODE = 'P0001';
    END IF;

    IF (v_dep.seats_sold + v_dep.seats_reserved + p_seat_count) > v_dep.total_seats THEN
        RAISE EXCEPTION 'Not enough seats: % requested, % available',
            p_seat_count,
            (v_dep.total_seats - v_dep.seats_sold - v_dep.seats_reserved)
            USING ERRCODE = 'P0004';
    END IF;

    -- Generate a short collision-safe code from an alphabet that excludes
    -- visually confusable characters (O/0, I/1, L). 7 chars from a 31-char
    -- alphabet ≈ 27 trillion combinations — collision-resistant for any
    -- realistic volume, and unambiguous when read off a phone screen.
    DECLARE
        v_alphabet CONSTANT TEXT := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
        v_alpha_len CONSTANT INTEGER := length(v_alphabet);
        v_i INTEGER;
    BEGIN
        LOOP
            v_attempts := v_attempts + 1;
            v_code := '';
            FOR v_i IN 1..7 LOOP
                v_code := v_code || substr(
                    v_alphabet,
                    1 + (get_byte(gen_random_bytes(1), 0) % v_alpha_len),
                    1
                );
            END LOOP;
            IF NOT EXISTS (SELECT 1 FROM bookings b WHERE b.code = v_code) THEN
                EXIT;
            END IF;
            IF v_attempts > 10 THEN
                RAISE EXCEPTION 'Could not generate unique booking code' USING ERRCODE = 'P0099';
            END IF;
        END LOOP;
    END;

    INSERT INTO bookings (code, departure_id, agency_id, passenger_name, passenger_phone, seat_count, expires_at)
    VALUES (
        v_code, p_departure_id, v_dep.agency_id,
        p_passenger_name, p_passenger_phone, p_seat_count,
        now() + make_interval(mins => p_ttl_minutes)
    )
    RETURNING bookings.id INTO v_booking_id;

    -- Hold the seats softly.
    UPDATE departures
       SET seats_reserved = seats_reserved + p_seat_count
     WHERE id = p_departure_id;

    INSERT INTO audit_log (action, entity_type, entity_id, new_values)
    VALUES (
        'booking_created', 'booking', v_booking_id,
        jsonb_build_object(
            'code', v_code,
            'departureId', p_departure_id,
            'seatCount', p_seat_count,
            'phone', p_passenger_phone
        )
    );

    RETURN QUERY
    SELECT b.id, b.code, b.departure_id, b.agency_id,
           b.passenger_name, b.passenger_phone, b.seat_count,
           b.status, b.expires_at, b.created_at
      FROM bookings b
     WHERE b.id = v_booking_id;
END;
$$;

COMMENT ON FUNCTION fn_create_booking IS
'ATOMIC booking reservation. Locks departure, validates capacity, soft-holds seats, generates short code.';

-- ------------------------------------------------------------
-- 7. fn_confirm_booking — atomic confirmation + commission
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_confirm_booking(
    p_code           VARCHAR,
    p_staff_id       UUID,
    p_fare_per_seat  NUMERIC DEFAULT NULL
)
RETURNS TABLE (
    booking_id        UUID,
    departure_id      UUID,
    seat_count        INTEGER,
    new_seats_sold    INTEGER,
    commission_amount NUMERIC,
    departure_status  departure_status
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_booking   RECORD;
    v_dep       RECORD;
    v_settings  RECORD;
    v_fare      NUMERIC(10,2);
    v_commission NUMERIC(10,2);
    v_new_sold  INTEGER;
BEGIN
    -- Lock the booking
    SELECT b.id, b.departure_id, b.agency_id, b.seat_count, b.status, b.expires_at, b.passenger_name, b.passenger_phone
      INTO v_booking
      FROM bookings b
     WHERE b.code = upper(p_code)
       FOR UPDATE;

    IF v_booking IS NULL THEN
        RAISE EXCEPTION 'Booking code % not found', p_code USING ERRCODE = 'P0002';
    END IF;

    IF v_booking.status <> 'pending' THEN
        RAISE EXCEPTION 'Booking is %, cannot confirm', v_booking.status USING ERRCODE = 'P0001';
    END IF;

    IF v_booking.expires_at < now() THEN
        -- Auto-expire and release the soft hold.
        UPDATE bookings SET status = 'expired' WHERE id = v_booking.id;
        UPDATE departures
           SET seats_reserved = GREATEST(seats_reserved - v_booking.seat_count, 0)
         WHERE id = v_booking.departure_id;
        RAISE EXCEPTION 'Booking has expired' USING ERRCODE = 'P0001';
    END IF;

    -- Authz: staff must belong to this agency (super_admin allowed).
    IF NOT EXISTS (
        SELECT 1 FROM staff_users su
         WHERE su.id = p_staff_id
           AND su.is_active = true
           AND (su.role = 'super_admin' OR su.agency_id = v_booking.agency_id)
    ) THEN
        RAISE EXCEPTION 'Staff % is not authorized for this agency', p_staff_id USING ERRCODE = 'P0003';
    END IF;

    -- Lock the departure for seat update.
    SELECT d.id, d.seats_sold, d.total_seats, d.seats_reserved, d.status
      INTO v_dep
      FROM departures d
     WHERE d.id = v_booking.departure_id
       FOR UPDATE;

    IF v_dep.status = 'departed' THEN
        RAISE EXCEPTION 'Cannot confirm: departure has already departed' USING ERRCODE = 'P0001';
    END IF;

    v_new_sold := v_dep.seats_sold + v_booking.seat_count;
    IF v_new_sold > v_dep.total_seats THEN
        RAISE EXCEPTION 'Confirmation would exceed capacity' USING ERRCODE = 'P0004';
    END IF;

    -- Get commission settings (fallback to defaults).
    SELECT cs.commission_rate, cs.flat_fee, cs.currency
      INTO v_settings
      FROM commission_settings cs
     WHERE cs.agency_id = v_booking.agency_id;

    IF v_settings IS NULL THEN
        v_settings.commission_rate := 0.0500;
        v_settings.flat_fee := 0;
        v_settings.currency := 'XAF';
    END IF;

    -- Compute commission. If no fare provided, commission is the flat fee only.
    v_fare := COALESCE(p_fare_per_seat, 0) * v_booking.seat_count;
    v_commission := ROUND((v_fare * v_settings.commission_rate) + v_settings.flat_fee, 2);

    -- Apply: confirm booking, release reservation, increment seats_sold.
    UPDATE bookings
       SET status = 'confirmed',
           confirmed_by = p_staff_id,
           confirmed_at = now()
     WHERE id = v_booking.id;

    UPDATE departures
       SET seats_sold     = v_new_sold,
           seats_reserved = GREATEST(seats_reserved - v_booking.seat_count, 0),
           updated_by     = p_staff_id
     WHERE id = v_dep.id;

    -- Insert commission ledger entry.
    INSERT INTO commission_ledger (
        booking_id, agency_id, seat_count, fare_per_seat, fare_total,
        commission_rate, flat_fee, commission_amount, currency, period
    ) VALUES (
        v_booking.id, v_booking.agency_id, v_booking.seat_count,
        p_fare_per_seat, v_fare,
        v_settings.commission_rate, v_settings.flat_fee, v_commission,
        v_settings.currency,
        (now() AT TIME ZONE 'Africa/Douala')::date
    );

    -- Audit
    INSERT INTO audit_log (action, entity_type, entity_id, performed_by, new_values)
    VALUES (
        'booking_confirmed', 'booking', v_booking.id, p_staff_id,
        jsonb_build_object(
            'departureId', v_booking.departure_id,
            'seatCount', v_booking.seat_count,
            'commission', v_commission,
            'fare', v_fare
        )
    );

    RETURN QUERY
    SELECT v_booking.id, v_booking.departure_id, v_booking.seat_count,
           v_new_sold, v_commission,
           (SELECT d.status FROM departures d WHERE d.id = v_dep.id);
END;
$$;

COMMENT ON FUNCTION fn_confirm_booking IS
'ATOMIC: confirms a pending booking, increments seats_sold, releases soft hold, writes commission ledger entry.';

-- ------------------------------------------------------------
-- 8. fn_cancel_booking — atomic cancellation, releases hold
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_cancel_booking(
    p_code      VARCHAR,
    p_reason    TEXT DEFAULT NULL,
    p_staff_id  UUID DEFAULT NULL
)
RETURNS TABLE (
    booking_id  UUID,
    status      booking_status
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_booking RECORD;
BEGIN
    SELECT b.id, b.departure_id, b.seat_count, b.status, b.agency_id
      INTO v_booking
      FROM bookings b
     WHERE b.code = upper(p_code)
       FOR UPDATE;

    IF v_booking IS NULL THEN
        RAISE EXCEPTION 'Booking code % not found', p_code USING ERRCODE = 'P0002';
    END IF;

    IF v_booking.status <> 'pending' THEN
        RAISE EXCEPTION 'Booking is %, cannot cancel', v_booking.status USING ERRCODE = 'P0001';
    END IF;

    UPDATE bookings
       SET status = 'cancelled',
           cancelled_at = now(),
           notes = COALESCE(notes, '') || COALESCE(E'\nCancellation: ' || p_reason, '')
     WHERE id = v_booking.id;

    UPDATE departures
       SET seats_reserved = GREATEST(seats_reserved - v_booking.seat_count, 0)
     WHERE id = v_booking.departure_id;

    INSERT INTO audit_log (action, entity_type, entity_id, performed_by, new_values)
    VALUES (
        'booking_cancelled', 'booking', v_booking.id, p_staff_id,
        jsonb_build_object('reason', p_reason, 'seatCount', v_booking.seat_count)
    );

    RETURN QUERY SELECT v_booking.id, 'cancelled'::booking_status;
END;
$$;

COMMENT ON FUNCTION fn_cancel_booking IS
'ATOMIC cancellation. Releases the soft seat hold and audits.';

-- ------------------------------------------------------------
-- 9. fn_expire_pending_bookings — sweep job for expired holds
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_expire_pending_bookings()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER := 0;
    v_b     RECORD;
BEGIN
    FOR v_b IN
        SELECT id, departure_id, seat_count
          FROM bookings
         WHERE status = 'pending' AND expires_at < now()
           FOR UPDATE SKIP LOCKED
    LOOP
        UPDATE bookings SET status = 'expired' WHERE id = v_b.id;
        UPDATE departures
           SET seats_reserved = GREATEST(seats_reserved - v_b.seat_count, 0)
         WHERE id = v_b.departure_id;
        INSERT INTO audit_log (action, entity_type, entity_id, new_values)
        VALUES ('booking_expired', 'booking', v_b.id, jsonb_build_object('seatCount', v_b.seat_count));
        v_count := v_count + 1;
    END LOOP;
    RETURN v_count;
END;
$$;

COMMENT ON FUNCTION fn_expire_pending_bookings IS
'Sweep: marks past-TTL pending bookings expired and releases their soft holds. Run periodically.';

-- ------------------------------------------------------------
-- 10. View: agency commission summary by period
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_agency_commission_summary AS
SELECT
    cl.agency_id,
    a.name                                AS agency_name,
    cl.period,
    cl.currency,
    COUNT(*)                              AS booking_count,
    SUM(cl.seat_count)                    AS seats_sold,
    SUM(cl.fare_total)                    AS gross_fare,
    SUM(cl.commission_amount)             AS commission_total,
    SUM(cl.commission_amount) FILTER (WHERE cl.status = 'accrued')  AS accrued_total,
    SUM(cl.commission_amount) FILTER (WHERE cl.status = 'invoiced') AS invoiced_total,
    SUM(cl.commission_amount) FILTER (WHERE cl.status = 'paid')     AS paid_total
FROM commission_ledger cl
JOIN agencies a ON a.id = cl.agency_id
GROUP BY cl.agency_id, a.name, cl.period, cl.currency;

COMMENT ON VIEW v_agency_commission_summary IS 'Per-agency, per-day commission roll-up for dashboards and invoicing.';

COMMIT;
