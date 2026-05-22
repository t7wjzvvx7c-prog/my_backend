-- ============================================================
-- Migration 007: fn_refund_booking — reverse a confirmed booking
-- ============================================================
-- Until now the booking lifecycle was forward-only:
--    pending  → confirmed
--    pending  → cancelled / expired
-- A confirmed booking had no escape hatch. This migration adds
-- fn_refund_booking which:
--   * marks the booking 'cancelled'
--   * decrements seats_sold on the departure
--   * voids the commission ledger entry
--   * audits 'booking_refunded'
--
-- It rejects refunds when the commission has already been paid
-- (status='paid') — once a settlement period closes the platform
-- doesn't let SQL reverse it; that case escalates out-of-band.
--
-- Cash refund to the passenger happens off-app, same way the
-- original payment did.
--
-- Idempotent.
-- ============================================================

BEGIN;

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'booking_refunded';

CREATE OR REPLACE FUNCTION fn_refund_booking(
    p_code     VARCHAR,
    p_staff_id UUID,
    p_reason   TEXT DEFAULT NULL
)
RETURNS TABLE (
    booking_id     UUID,
    departure_id   UUID,
    seats_sold     INTEGER,
    commission_amount NUMERIC,
    status         booking_status
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_b      RECORD;
    v_d      RECORD;
    v_ledger RECORD;
BEGIN
    -- Lock the booking row.
    SELECT b.id, b.code, b.departure_id, b.agency_id, b.status,
           b.seat_count, b.confirmed_at, b.confirmation_source
      INTO v_b
      FROM bookings b
     WHERE b.code = upper(p_code)
       FOR UPDATE;

    IF v_b IS NULL THEN
        RAISE EXCEPTION 'Booking % not found', p_code USING ERRCODE = 'P0002';
    END IF;
    IF v_b.status <> 'confirmed' THEN
        RAISE EXCEPTION 'Booking is %, only confirmed bookings can be refunded', v_b.status
            USING ERRCODE = 'P0001';
    END IF;

    -- Authz: agency staff (own agency) or super_admin.
    IF NOT EXISTS (
        SELECT 1 FROM staff_users su
         WHERE su.id = p_staff_id
           AND su.is_active = true
           AND (su.role = 'super_admin' OR su.agency_id = v_b.agency_id)
    ) THEN
        RAISE EXCEPTION 'Staff % is not authorized for this agency', p_staff_id
            USING ERRCODE = 'P0003';
    END IF;

    -- Lock the commission ledger entry.
    SELECT cl.id, cl.status, cl.commission_amount
      INTO v_ledger
      FROM commission_ledger cl
     WHERE cl.booking_id = v_b.id
       FOR UPDATE;

    -- Refuse if the period has already settled. The agency must escalate
    -- through the platform admin for paid-period reversals so accounting
    -- doesn't get rewritten retroactively.
    IF v_ledger IS NOT NULL AND v_ledger.status = 'paid' THEN
        RAISE EXCEPTION 'Commission for this booking is already paid. Contact platform admin to reverse a settled period.'
            USING ERRCODE = 'P0001';
    END IF;

    -- Lock the departure for the seat-count adjustment.
    SELECT d.id, d.seats_sold, d.total_seats, d.status
      INTO v_d
      FROM departures d
     WHERE d.id = v_b.departure_id
       FOR UPDATE;

    -- Booking flip → cancelled.
    UPDATE bookings
       SET status       = 'cancelled',
           cancelled_at = now(),
           notes        = COALESCE(notes, '') ||
                          E'\n[refunded by ' || p_staff_id::text ||
                          ' at ' || now()::text ||
                          COALESCE(' — ' || p_reason, '') || ']'
     WHERE id = v_b.id;

    -- Decrement seats_sold (never below zero — confirmed booking always
    -- contributed seat_count to seats_sold, but defensive clamp anyway).
    UPDATE departures
       SET seats_sold = GREATEST(seats_sold - v_b.seat_count, 0),
           updated_by = p_staff_id
     WHERE id = v_d.id;

    -- Void the ledger entry. The trigger auto_status_on_full handles the
    -- 'full' → 'boarding' rebound on the departure side.
    IF v_ledger IS NOT NULL THEN
        UPDATE commission_ledger
           SET status     = 'voided',
               settled_at = now()
         WHERE id = v_ledger.id;
    END IF;

    INSERT INTO audit_log (action, entity_type, entity_id, performed_by, old_values, new_values)
    VALUES (
        'booking_refunded', 'booking', v_b.id, p_staff_id,
        jsonb_build_object(
            'status', 'confirmed',
            'confirmedAt', v_b.confirmed_at,
            'confirmationSource', v_b.confirmation_source,
            'commissionAmount', v_ledger.commission_amount
        ),
        jsonb_build_object(
            'status', 'cancelled',
            'reason', p_reason,
            'commissionVoided', v_ledger IS NOT NULL
        )
    );

    RETURN QUERY
    SELECT v_b.id,
           v_b.departure_id,
           (SELECT d.seats_sold FROM departures d WHERE d.id = v_d.id),
           COALESCE(v_ledger.commission_amount, 0::NUMERIC),
           'cancelled'::booking_status;
END;
$$;

COMMENT ON FUNCTION fn_refund_booking IS
'Reverse a confirmed booking. Decrements seats_sold, voids the commission ledger entry, logs audit. Rejects when commission status is already paid (closed period).';

COMMIT;
