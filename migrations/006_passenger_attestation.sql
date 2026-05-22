-- ============================================================
-- Migration 006: Passenger post-trip attestation
-- ============================================================
-- Closes the leak when a seller never touches the dashboard at all.
--
-- Window: starting 15 minutes after the scheduled departure, up to 24
-- hours after, the passenger can attest "I traveled" (or "I didn't").
-- A "yes" auto-confirms the booking and accrues commission, even if the
-- seller never confirmed it. A "no" cancels and releases the soft hold.
--
-- Auth: there's no passenger account. The booking code + phone number
-- pair acts as the secret. We strip non-digits before comparing so
-- formatting differences ("+237 6XX XXX XXX" vs "237600000000") don't
-- block legitimate passengers.
--
-- Idempotent.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 1. New audit action
-- ------------------------------------------------------------
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'booking_passenger_attested';

-- ------------------------------------------------------------
-- 2. confirmation_source column on bookings
-- ------------------------------------------------------------
-- Values: 'staff' (manual fn_confirm_booking), 'auto_walkin' (fn_sell_seats
-- auto-attribution), 'passenger' (this migration). NULL for legacy rows
-- before this column existed.
ALTER TABLE bookings
    ADD COLUMN IF NOT EXISTS confirmation_source VARCHAR(20);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_booking_confirmation_source'
    ) THEN
        ALTER TABLE bookings
            ADD CONSTRAINT chk_booking_confirmation_source
            CHECK (confirmation_source IS NULL
                OR confirmation_source IN ('staff', 'auto_walkin', 'passenger'));
    END IF;
END $$;

-- Backfill: existing confirmed rows came from the staff path.
UPDATE bookings
   SET confirmation_source = 'staff'
 WHERE status = 'confirmed' AND confirmation_source IS NULL;

-- The original constraint required confirmed_by NOT NULL. Passenger
-- attestation has no staff actor, so relax to require only confirmed_at.
ALTER TABLE bookings DROP CONSTRAINT IF EXISTS chk_booking_confirmed_consistency;
ALTER TABLE bookings
    ADD CONSTRAINT chk_booking_confirmed_consistency
    CHECK (status <> 'confirmed' OR confirmed_at IS NOT NULL);

-- ------------------------------------------------------------
-- 3. fn_passenger_attest_travel
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_passenger_attest_travel(
    p_code     VARCHAR,
    p_phone    VARCHAR,
    p_traveled BOOLEAN
)
RETURNS TABLE (
    booking_id        UUID,
    new_status        booking_status,
    commission_amount NUMERIC,
    agency_id         UUID,
    departure_id      UUID
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_b           RECORD;
    v_d           RECORD;
    v_settings    RECORD;
    v_commission  NUMERIC(10,2) := 0;
    v_min_attest  TIMESTAMPTZ;
    v_max_attest  TIMESTAMPTZ;
    v_strip_phone CONSTANT TEXT := '[^0-9]';
BEGIN
    SELECT b.id, b.code, b.departure_id, b.agency_id, b.status,
           b.passenger_phone, b.seat_count, b.confirmed_at
      INTO v_b
      FROM bookings b
     WHERE b.code = upper(p_code)
       FOR UPDATE;

    IF v_b IS NULL THEN
        RAISE EXCEPTION 'Booking % not found', p_code USING ERRCODE = 'P0002';
    END IF;

    -- Weak auth: phone must match (digits-only, so formatting differences ok).
    IF regexp_replace(v_b.passenger_phone, v_strip_phone, '', 'g') <>
       regexp_replace(p_phone,            v_strip_phone, '', 'g') THEN
        RAISE EXCEPTION 'Phone does not match this booking' USING ERRCODE = 'P0003';
    END IF;

    -- Lock the departure to read scheduled_time and adjust seats_reserved.
    SELECT d.id, d.scheduled_time, d.status AS dep_status,
           d.seats_sold, d.seats_reserved, d.total_seats
      INTO v_d
      FROM departures d
     WHERE d.id = v_b.departure_id
       FOR UPDATE;

    v_min_attest := v_d.scheduled_time + INTERVAL '15 minutes';
    v_max_attest := v_d.scheduled_time + INTERVAL '24 hours';

    IF now() < v_min_attest THEN
        RAISE EXCEPTION
            'Too early — attestation opens 15 minutes after scheduled departure'
            USING ERRCODE = 'P0001';
    END IF;
    IF now() > v_max_attest THEN
        RAISE EXCEPTION
            'Attestation window closed (24 hours after scheduled departure)'
            USING ERRCODE = 'P0001';
    END IF;

    -- Idempotent for already-resolved bookings: no double-charge.
    IF v_b.status = 'confirmed' THEN
        RETURN QUERY SELECT v_b.id, v_b.status, 0::NUMERIC, v_b.agency_id, v_b.departure_id;
        RETURN;
    END IF;
    IF v_b.status = 'cancelled' THEN
        RAISE EXCEPTION 'Booking was cancelled and cannot be re-opened'
            USING ERRCODE = 'P0001';
    END IF;
    -- 'expired' is fine to confirm via attestation — the soft hold is moot
    -- by now (bus has departed) and the platform still wants the commission.

    IF p_traveled THEN
        -- Lookup commission terms.
        SELECT cs.commission_rate, cs.flat_fee, cs.currency
          INTO v_settings
          FROM commission_settings cs
         WHERE cs.agency_id = v_b.agency_id;
        IF v_settings IS NULL THEN
            v_settings.commission_rate := 0.0500;
            v_settings.flat_fee        := 0;
            v_settings.currency        := 'XAF';
        END IF;

        -- Passenger doesn't enter fare; flat fee only.
        v_commission := ROUND(v_settings.flat_fee, 2);

        UPDATE bookings
           SET status              = 'confirmed',
               confirmed_at        = now(),
               confirmation_source = 'passenger',
               notes               = COALESCE(notes, '') ||
                                     E'\n[passenger attested travel at ' || now()::text || ']'
         WHERE id = v_b.id;

        -- Release the soft hold if still pending. Skip for already-expired
        -- (the soft hold was already returned by the expire sweep).
        IF v_b.status = 'pending' THEN
            UPDATE departures
               SET seats_reserved = GREATEST(seats_reserved - v_b.seat_count, 0)
             WHERE id = v_d.id;
        END IF;

        INSERT INTO commission_ledger (
            booking_id, agency_id, seat_count, fare_per_seat, fare_total,
            commission_rate, flat_fee, commission_amount, currency, period
        ) VALUES (
            v_b.id, v_b.agency_id, v_b.seat_count, NULL, NULL,
            v_settings.commission_rate, v_settings.flat_fee, v_commission,
            v_settings.currency,
            (now() AT TIME ZONE 'Africa/Douala')::date
        );

        INSERT INTO audit_log (action, entity_type, entity_id, new_values)
        VALUES (
            'booking_passenger_attested', 'booking', v_b.id,
            jsonb_build_object(
                'traveled', true,
                'commission', v_commission,
                'sourceStatus', v_b.status::text
            )
        );

        RETURN QUERY SELECT v_b.id, 'confirmed'::booking_status, v_commission,
                            v_b.agency_id, v_b.departure_id;
    ELSE
        UPDATE bookings
           SET status       = 'cancelled',
               cancelled_at = now(),
               notes        = COALESCE(notes, '') ||
                              E'\n[passenger attested no-travel at ' || now()::text || ']'
         WHERE id = v_b.id;

        IF v_b.status = 'pending' THEN
            UPDATE departures
               SET seats_reserved = GREATEST(seats_reserved - v_b.seat_count, 0)
             WHERE id = v_d.id;
        END IF;

        INSERT INTO audit_log (action, entity_type, entity_id, new_values)
        VALUES (
            'booking_passenger_attested', 'booking', v_b.id,
            jsonb_build_object('traveled', false, 'sourceStatus', v_b.status::text)
        );

        RETURN QUERY SELECT v_b.id, 'cancelled'::booking_status, 0::NUMERIC,
                            v_b.agency_id, v_b.departure_id;
    END IF;
END;
$$;

COMMENT ON FUNCTION fn_passenger_attest_travel IS
'Passenger post-trip attestation. Code + phone act as the secret. Active 15 minutes to 24 hours after scheduled departure. "yes" → confirm + commission, "no" → cancel.';

COMMIT;
