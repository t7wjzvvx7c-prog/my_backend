-- ============================================================
-- Migration 009: fn_cancel_booking — agency authorization
-- ============================================================
-- The original fn_cancel_booking (migration 004) did not check that the
-- staff member invoking it belonged to the booking's agency. Combined
-- with the /bookings/code/:code/staff-cancel endpoint being authenticated
-- but not agency-scoped, this meant any logged-in agency staff could
-- cancel any pending booking — releasing a competitor's seat hold and
-- recording an audit row attributed to themselves.
--
-- This migration tightens the function: when invoked with a non-NULL
-- staff_id, the staff must belong to the booking's agency (or be
-- super_admin). When invoked with NULL — the passenger cancel path,
-- gated by the booking code itself acting as the secret — no agency
-- check is applied.
--
-- Idempotent (CREATE OR REPLACE).
-- ============================================================

BEGIN;

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

    -- Authz: when invoked by staff (non-NULL staff_id), they must belong to
    -- this booking's agency or be super_admin. NULL staff_id is the passenger
    -- self-cancel path; the code itself acts as the secret there.
    IF p_staff_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM staff_users su
             WHERE su.id = p_staff_id
               AND su.is_active = true
               AND (su.role = 'super_admin' OR su.agency_id = v_booking.agency_id)
        ) THEN
            RAISE EXCEPTION 'Staff % is not authorized for this agency', p_staff_id
                USING ERRCODE = 'P0003';
        END IF;
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
'ATOMIC cancellation. When staff_id is non-NULL, the staff must belong to the booking''s agency (or be super_admin). NULL staff_id is the passenger self-cancel path.';

COMMIT;
