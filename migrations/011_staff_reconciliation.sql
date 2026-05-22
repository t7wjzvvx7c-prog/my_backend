-- ============================================================
-- Migration 011: Staff end-of-shift reconciliation
-- ============================================================
-- Additive only. Idempotent.
--
-- Adds two SECURITY DEFINER functions that power the agency-side
-- end-of-shift report. They roll up a single staff member's seat
-- activity and commission earnings for one calendar day in the
-- Africa/Douala timezone (the only zone the platform operates in).
--
-- ATTRIBUTION MODEL (cross-checked against migrations 004/005):
--   - 'seats_updated'      audit rows come from fn_sell_seats; they
--                          cover walk-in sales AND seats picked up by
--                          auto-attribution inside the same call.
--   - 'booking_confirmed'  audit rows come from fn_confirm_booking
--                          (manual QR scan); seats_updated is NOT
--                          written for this path.
-- The two action types are mutually exclusive, so summing the seat
-- count from both is safe — no double-counting.
--
-- For commission, bookings.confirmed_by is set in BOTH paths
-- (auto-attribution at migration 005 line 155, manual at fn_confirm_
-- booking) so commission_ledger ⨝ bookings on confirmed_by gives the
-- complete picture for one staff.
--
-- WHY SECURITY DEFINER: audit_log SELECT under RLS is gated to
-- super_admin/regulator only. A ticket seller asking "what did I do
-- today?" is a legitimate query that the existing policy can't express
-- without breaking the regulator's compliance posture, so we do the
-- read inside a definer function and check caller identity from the
-- RLS GUC instead. search_path is pinned per the project convention.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 1. Per-departure seat activity for one staff in one WAT day
-- ------------------------------------------------------------
-- One row per (departure) the staff touched on the given day. Each
-- row aggregates positive deltas as `seatsSold`, negative deltas as
-- `seatsRefunded`, and the net change. For a pure walk-in shift this
-- is the seller's full picture; QR confirmations show up in the
-- bookings function below.
CREATE OR REPLACE FUNCTION fn_staff_reconciliation_seats(
    p_staff_id uuid,
    p_date     date
)
RETURNS TABLE (
    "departureId"      uuid,
    "scheduledTime"    timestamptz,
    origin             varchar,
    destination        varchar,
    category           bus_category,
    "busNumber"        varchar,
    status             departure_status,
    "seatsSold"        int,
    "seatsRefunded"    int,
    "netDelta"         int,
    "transactionCount" int
)
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    v_from timestamptz := (p_date::timestamp AT TIME ZONE 'Africa/Douala');
    v_to   timestamptz := ((p_date + 1)::timestamp AT TIME ZONE 'Africa/Douala');
BEGIN
    -- Authz: caller must be the staff in question, or super_admin.
    -- Reading these GUCs only works when withRequestDb has set them;
    -- direct psql calls (no GUC) collapse to the deny branch.
    IF NOT (fn_request_staff() = p_staff_id OR fn_is_super_admin()) THEN
        RAISE EXCEPTION 'Not authorized to view this staff reconciliation'
            USING ERRCODE = 'P0003';
    END IF;

    RETURN QUERY
    SELECT
        d.id,
        d.scheduled_time,
        r.origin,
        r.destination,
        d.category,
        d.bus_number,
        d.status,
        COALESCE(SUM(GREATEST( (al.new_values->>'change')::int, 0)), 0)::int,
        COALESCE(SUM(GREATEST(-(al.new_values->>'change')::int, 0)), 0)::int,
        COALESCE(SUM( (al.new_values->>'change')::int ), 0)::int,
        COUNT(*)::int
    FROM audit_log al
    JOIN departures d ON d.id = al.entity_id
    JOIN routes     r ON r.id = d.route_id
    WHERE al.action       = 'seats_updated'
      AND al.entity_type  = 'departure'
      AND al.performed_by = p_staff_id
      AND al.created_at  >= v_from
      AND al.created_at  <  v_to
    GROUP BY d.id, d.scheduled_time, r.origin, r.destination, d.category, d.bus_number, d.status
    ORDER BY d.scheduled_time ASC;
END;
$$;

COMMENT ON FUNCTION fn_staff_reconciliation_seats IS
'Per-departure seat activity by one staff in one WAT day. SECURITY DEFINER bypasses RLS on audit_log; PL/pgSQL guard enforces caller-vs-target identity via the request-context GUCs.';


-- ------------------------------------------------------------
-- 2. Per-booking commission earned by one staff in one WAT day
-- ------------------------------------------------------------
-- Each row is one confirmed booking (auto-attributed OR QR-scanned)
-- with the commission_ledger entry attached. The seller's total
-- earnings for the day = SUM(commissionAmount) over these rows.
CREATE OR REPLACE FUNCTION fn_staff_reconciliation_bookings(
    p_staff_id uuid,
    p_date     date
)
RETURNS TABLE (
    "bookingId"        uuid,
    "bookingCode"      varchar,
    "passengerName"    varchar,
    "passengerPhone"   varchar,
    "departureId"      uuid,
    "scheduledTime"    timestamptz,
    origin             varchar,
    destination        varchar,
    "seatCount"        int,
    "farePerSeat"      numeric,
    "commissionAmount" numeric,
    currency           varchar,
    "confirmedAt"      timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    v_from timestamptz := (p_date::timestamp AT TIME ZONE 'Africa/Douala');
    v_to   timestamptz := ((p_date + 1)::timestamp AT TIME ZONE 'Africa/Douala');
BEGIN
    IF NOT (fn_request_staff() = p_staff_id OR fn_is_super_admin()) THEN
        RAISE EXCEPTION 'Not authorized to view this staff reconciliation'
            USING ERRCODE = 'P0003';
    END IF;

    RETURN QUERY
    SELECT
        b.id,
        b.code,
        b.passenger_name,
        b.passenger_phone,
        d.id,
        d.scheduled_time,
        r.origin,
        r.destination,
        cl.seat_count,
        cl.fare_per_seat,
        cl.commission_amount,
        cl.currency,
        b.confirmed_at
    FROM bookings           b
    JOIN commission_ledger  cl ON cl.booking_id = b.id
    JOIN departures         d  ON d.id = b.departure_id
    JOIN routes             r  ON r.id = d.route_id
    WHERE b.confirmed_by  = p_staff_id
      AND b.status        = 'confirmed'
      AND b.confirmed_at >= v_from
      AND b.confirmed_at <  v_to
    ORDER BY b.confirmed_at ASC;
END;
$$;

COMMENT ON FUNCTION fn_staff_reconciliation_bookings IS
'Per-booking commission attributable to one staff in one WAT day. Covers both auto-attributed (fn_sell_seats) and manual QR-scanned (fn_confirm_booking) confirmations because both set bookings.confirmed_by.';

COMMIT;
