-- ============================================================
-- Migration 016: Fix ambiguous "seats_sold" reference in fn_refund_booking
-- ============================================================
-- Same bug class as migrations 014 and 015. fn_refund_booking declares
-- RETURNS TABLE (..., seats_sold INTEGER, ...) so the bare `seats_sold`
-- inside `GREATEST(seats_sold - v_b.seat_count, 0)` on the UPDATE
-- departures clause is ambiguous: PL/pgSQL doesn't know whether it
-- means the OUT parameter or the table column. Runtime error:
--
--   ERROR: column reference "seats_sold" is ambiguous
--   QUERY:  UPDATE departures SET seats_sold = GREATEST(seats_sold - ..., 0)
--   CONTEXT: PL/pgSQL function fn_refund_booking(...) line N at SQL statement
--
-- Visible to staff trying to refund a confirmed booking → 500.
--
-- Fix: qualify as `departures.seats_sold` in the GREATEST expression.
-- CREATE OR REPLACE FUNCTION redefines in place; SECURITY DEFINER +
-- search_path are re-applied because they don't survive a re-definition.
-- Idempotent.
-- ============================================================

BEGIN;

CREATE OR REPLACE FUNCTION fn_refund_booking(
    p_code     VARCHAR,
    p_staff_id UUID,
    p_reason   TEXT DEFAULT NULL
)
RETURNS TABLE (
    booking_id        UUID,
    departure_id      UUID,
    seats_sold        INTEGER,
    commission_amount NUMERIC,
    status            booking_status
)
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public, pg_temp
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

    -- Refuse if the period has already settled.
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

    -- Decrement seats_sold. Qualify departures.seats_sold so PL/pgSQL
    -- doesn't confuse it with the OUT parameter `seats_sold` from the
    -- RETURNS TABLE clause. (This is the bug fix vs migration 007.)
    UPDATE departures
       SET seats_sold = GREATEST(departures.seats_sold - v_b.seat_count, 0),
           updated_by = p_staff_id
     WHERE id = v_d.id;

    -- Void the ledger entry.
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
'Reverse a confirmed booking. Decrements seats_sold, voids the commission ledger entry, logs audit. Rejects when commission status is already paid (closed period). Migration 016 qualifies departures.seats_sold to fix an ambiguous-reference error against the RETURNS TABLE OUT parameter of the same name.';

COMMIT;
