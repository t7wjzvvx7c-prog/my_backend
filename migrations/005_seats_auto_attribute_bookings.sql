-- ============================================================
-- Migration 005: Auto-attribute pending bookings on walk-in seat increments
-- ============================================================
-- Plug the leak where a seller can dodge commission by selling to an
-- app-booked passenger as if they were a walk-in.
--
-- Behaviour:
--   When fn_sell_seats(+N) runs, before incrementing seats_sold it scans
--   pending bookings for that departure (oldest first). Any booking whose
--   seat_count fits in the remaining +N is auto-confirmed: status flipped,
--   commission ledger entry written (flat fee only, since fare is unknown
--   on the walk-in path), seats_reserved decremented. The leftover N is
--   recorded as walk-in seats_sold.
--
--   The seller gets back a list of auto_confirmed_codes so the UI can
--   show "We confirmed code XYZ for you" with an Undo button.
--
--   fn_revert_auto_attribution lets staff undo within a 10-minute window:
--   booking → cancelled, ledger entry → voided, seats_sold unchanged
--   (the walk-in keeps its seat). After 10 minutes the entry locks in.
--
-- Idempotent: CREATE OR REPLACE on functions, ALTER TYPE ... IF NOT EXISTS.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 1. New audit actions
-- ------------------------------------------------------------
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'booking_auto_confirmed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'booking_auto_reverted';

-- ------------------------------------------------------------
-- 2. fn_sell_seats — replace with auto-attribution version
-- ------------------------------------------------------------
DROP FUNCTION IF EXISTS fn_sell_seats(UUID, INTEGER, UUID);

CREATE OR REPLACE FUNCTION fn_sell_seats(
    p_departure_id  UUID,
    p_seats_to_sell INTEGER,
    p_staff_id      UUID
)
RETURNS TABLE (
    departure_id          UUID,
    seats_sold            INTEGER,
    total_seats           INTEGER,
    available_seats       INTEGER,
    fill_percentage       NUMERIC,
    status                departure_status,
    auto_confirmed_codes  TEXT[]
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_current     RECORD;
    v_settings    RECORD;
    v_booking     RECORD;
    v_remaining   INTEGER;
    v_auto_count  INTEGER := 0;
    v_codes       TEXT[]  := ARRAY[]::TEXT[];
    v_ids         UUID[]  := ARRAY[]::UUID[];
    v_new_sold    INTEGER;
    v_new_reserved INTEGER;
    v_commission  NUMERIC(10,2);
BEGIN
    -- ISOLATION: lock the departure row.
    SELECT d.id, d.seats_sold, d.total_seats, d.seats_reserved, d.status, d.agency_id
      INTO v_current
      FROM departures d
     WHERE d.id = p_departure_id
       FOR UPDATE;

    IF v_current IS NULL THEN
        RAISE EXCEPTION 'Departure % not found', p_departure_id USING ERRCODE = 'P0002';
    END IF;
    IF v_current.status = 'departed' THEN
        RAISE EXCEPTION 'Cannot sell seats: departure has already departed' USING ERRCODE = 'P0001';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM staff_users su
         WHERE su.id = p_staff_id AND su.is_active = true
           AND (su.role = 'super_admin' OR su.agency_id = v_current.agency_id)
    ) THEN
        RAISE EXCEPTION 'Staff % is not authorized for this agency', p_staff_id
            USING ERRCODE = 'P0003';
    END IF;

    -- Phase 1 — pick which pending bookings (if any) we'll auto-confirm.
    -- Only relevant when actually selling (positive delta).
    IF p_seats_to_sell > 0 THEN
        v_remaining := p_seats_to_sell;

        FOR v_booking IN
            SELECT b.id, b.code, b.seat_count
              FROM bookings b
             WHERE b.departure_id = p_departure_id
               AND b.status = 'pending'
               AND b.expires_at > now()
             ORDER BY b.created_at ASC
             FOR UPDATE
        LOOP
            EXIT WHEN v_remaining <= 0;
            IF v_booking.seat_count <= v_remaining THEN
                v_ids        := v_ids        || v_booking.id;
                v_codes      := v_codes      || v_booking.code;
                v_auto_count := v_auto_count + v_booking.seat_count;
                v_remaining  := v_remaining  - v_booking.seat_count;
            END IF;
        END LOOP;
    END IF;

    -- Phase 2 — compute new state and validate capacity.
    v_new_sold     := v_current.seats_sold + p_seats_to_sell;
    v_new_reserved := v_current.seats_reserved - v_auto_count;

    IF v_new_sold < 0 THEN
        RAISE EXCEPTION 'Seats sold cannot be negative (current: %, change: %)',
            v_current.seats_sold, p_seats_to_sell USING ERRCODE = 'P0005';
    END IF;
    IF v_new_sold > v_current.total_seats THEN
        RAISE EXCEPTION 'Not enough seats: requested %, available %',
            p_seats_to_sell, (v_current.total_seats - v_current.seats_sold)
            USING ERRCODE = 'P0004';
    END IF;
    -- Walk-in beyond what app bookings can absorb gets blocked by remaining holds.
    IF v_new_sold + v_new_reserved > v_current.total_seats THEN
        RAISE EXCEPTION
            'Not enough seats: % requested, % free (% still held by pending app bookings — wait for them to expire or confirm those passengers first)',
            p_seats_to_sell,
            (v_current.total_seats - v_current.seats_sold - v_current.seats_reserved + v_auto_count),
            v_new_reserved
            USING ERRCODE = 'P0004';
    END IF;

    -- Phase 3 — apply auto-confirmations and commission ledger.
    IF v_auto_count > 0 THEN
        -- Commission settings (fall back to defaults if missing).
        SELECT cs.commission_rate, cs.flat_fee, cs.currency
          INTO v_settings
          FROM commission_settings cs
         WHERE cs.agency_id = v_current.agency_id;
        IF v_settings IS NULL THEN
            v_settings.commission_rate := 0.0500;
            v_settings.flat_fee        := 0;
            v_settings.currency        := 'XAF';
        END IF;

        -- The walk-in path doesn't know the fare. Commission = flat fee only.
        -- If you want rate-based commission to apply here too, expose a fare
        -- input on the seat counter and pass it through.
        v_commission := ROUND(v_settings.flat_fee, 2);

        UPDATE bookings
           SET status       = 'confirmed',
               confirmed_by = p_staff_id,
               confirmed_at = now(),
               notes        = COALESCE(notes, '') ||
                              E'\n[auto-confirmed via walk-in seat increment at ' || now()::text || ']'
         WHERE id = ANY(v_ids);

        INSERT INTO commission_ledger (
            booking_id, agency_id, seat_count, fare_per_seat, fare_total,
            commission_rate, flat_fee, commission_amount, currency, period
        )
        SELECT b.id, b.agency_id, b.seat_count, NULL, NULL,
               v_settings.commission_rate, v_settings.flat_fee, v_commission,
               v_settings.currency,
               (now() AT TIME ZONE 'Africa/Douala')::date
          FROM bookings b
         WHERE b.id = ANY(v_ids);

        INSERT INTO audit_log (action, entity_type, entity_id, performed_by, new_values)
        SELECT 'booking_auto_confirmed', 'booking', b.id, p_staff_id,
               jsonb_build_object(
                   'code', b.code,
                   'seatCount', b.seat_count,
                   'departureId', p_departure_id,
                   'commission', v_commission
               )
          FROM bookings b
         WHERE b.id = ANY(v_ids);
    END IF;

    -- Phase 4 — apply seat counts to the departure.
    UPDATE departures d
       SET seats_sold     = v_new_sold,
           seats_reserved = v_new_reserved,
           updated_by     = p_staff_id
     WHERE d.id = p_departure_id;

    -- Audit the seat update itself.
    INSERT INTO audit_log (action, entity_type, entity_id, performed_by, old_values, new_values)
    VALUES (
        'seats_updated', 'departure', p_departure_id, p_staff_id,
        jsonb_build_object('seats_sold', v_current.seats_sold, 'seats_reserved', v_current.seats_reserved),
        jsonb_build_object('seats_sold', v_new_sold, 'seats_reserved', v_new_reserved,
                           'change', p_seats_to_sell, 'auto_confirmed', v_codes)
    );

    RETURN QUERY
    SELECT
        d.id,
        d.seats_sold,
        d.total_seats,
        (d.total_seats - d.seats_sold),
        ROUND((d.seats_sold::numeric / d.total_seats) * 100, 1),
        d.status,
        v_codes
      FROM departures d
     WHERE d.id = p_departure_id;
END;
$$;

COMMENT ON FUNCTION fn_sell_seats IS
'ATOMIC seat sell with auto-attribution: pending bookings whose seat_count fits in the +delta are auto-confirmed and commission is recorded. Returns auto_confirmed_codes so the seller UI can offer Undo.';

-- ------------------------------------------------------------
-- 3. fn_revert_auto_attribution — staff override
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_revert_auto_attribution(
    p_code     VARCHAR,
    p_staff_id UUID
)
RETURNS TABLE (
    booking_id   UUID,
    departure_id UUID,
    new_status   booking_status
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_booking RECORD;
    v_window CONSTANT INTERVAL := INTERVAL '10 minutes';
BEGIN
    SELECT b.id, b.departure_id, b.agency_id, b.status, b.seat_count, b.confirmed_at, b.notes
      INTO v_booking
      FROM bookings b
     WHERE b.code = upper(p_code)
       FOR UPDATE;

    IF v_booking IS NULL THEN
        RAISE EXCEPTION 'Booking % not found', p_code USING ERRCODE = 'P0002';
    END IF;
    IF v_booking.status <> 'confirmed' THEN
        RAISE EXCEPTION 'Booking is %, cannot revert', v_booking.status USING ERRCODE = 'P0001';
    END IF;
    IF v_booking.confirmed_at IS NULL OR v_booking.confirmed_at < now() - v_window THEN
        RAISE EXCEPTION 'Revert window expired (10 minutes after confirmation)' USING ERRCODE = 'P0001';
    END IF;

    -- Authz: staff must be on this agency (or super_admin).
    IF NOT EXISTS (
        SELECT 1 FROM staff_users su
         WHERE su.id = p_staff_id AND su.is_active = true
           AND (su.role = 'super_admin' OR su.agency_id = v_booking.agency_id)
    ) THEN
        RAISE EXCEPTION 'Staff % is not authorized for this agency', p_staff_id USING ERRCODE = 'P0003';
    END IF;

    -- Booking goes to cancelled (not back to pending) so it can't auto-attribute again
    -- on a subsequent seat increment. The seat itself remains sold (walk-in keeps it).
    UPDATE bookings
       SET status       = 'cancelled',
           cancelled_at = now(),
           notes        = COALESCE(notes, '') ||
                          E'\n[auto-attribution reverted at ' || now()::text || ']'
     WHERE id = v_booking.id;

    -- Void the commission entry. We don't delete it so the audit trail stays intact.
    UPDATE commission_ledger
       SET status     = 'voided',
           settled_at = now()
     WHERE booking_id = v_booking.id
       AND status = 'accrued';

    INSERT INTO audit_log (action, entity_type, entity_id, performed_by, old_values, new_values)
    VALUES (
        'booking_auto_reverted', 'booking', v_booking.id, p_staff_id,
        jsonb_build_object('status', 'confirmed', 'confirmed_at', v_booking.confirmed_at),
        jsonb_build_object('status', 'cancelled')
    );

    RETURN QUERY SELECT v_booking.id, v_booking.departure_id, 'cancelled'::booking_status;
END;
$$;

COMMENT ON FUNCTION fn_revert_auto_attribution IS
'Staff override for auto-attribution. Cancels the booking, voids the commission, leaves seats_sold intact. 10-minute window after confirmation.';

COMMIT;
