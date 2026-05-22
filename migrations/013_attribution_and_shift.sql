-- ============================================================
-- Migration 013: Same-agency staff visibility + bulk shift
-- ============================================================
-- Two changes that together close two of the remaining agency-side
-- gaps:
--
-- 1. Loosen the staff_users SELECT policy so agency staff (admin AND
--    ticket_seller) can read other staff in their own agency. The old
--    policy let ticket_sellers see only themselves, which prevented
--    the dashboard from rendering "by Marie · 5m ago" attributions on
--    departure cards (the join to resolve `updated_by → name` returned
--    nothing).
--    Names + phones + roles in the same agency are not sensitive — the
--    sensitive field is `pin_hash`, which is column-level and never
--    appears in any FIELDS.staff projection. So loosening row-level
--    SELECT is safe.
--
-- 2. fn_bulk_shift_route_departures(p_route_id, p_date, p_minutes,
--    p_staff_id): atomic re-time of all of today's (or any date's)
--    non-departed departures on one route by ±N minutes. Closes the
--    "bus broke, delay all 14:00 by 30 min" operational gap. Writes a
--    single audit_log entry summarizing the batch instead of one per
--    row, so the regulator log stays legible.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 1. staff_users SELECT — same-agency visibility
-- ------------------------------------------------------------
-- Replaces the migration 010 policy. The new branch
--   (fn_is_agency_staff() AND agency_id = fn_request_agency())
-- subsumes the previous self-only branch (a staff's own row has
-- `agency_id = own_agency_id`).
DROP POLICY IF EXISTS staff_select ON staff_users;

CREATE POLICY staff_select ON staff_users
    FOR SELECT USING (
        fn_is_super_admin()
        OR (fn_is_agency_staff() AND agency_id = fn_request_agency())
        OR fn_is_regulator()
    );

-- ------------------------------------------------------------
-- 2. New audit action for the shift operation
-- ------------------------------------------------------------
-- ALTER TYPE ADD VALUE in a transaction is allowed since PG12 but the
-- new value cannot be referenced in the SAME transaction. The function
-- below references it via a literal; that's fine because functions are
-- DEFINED here, not EXECUTED — execution happens in subsequent
-- transactions where the enum value is fully visible.
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'departure_shifted';

-- ------------------------------------------------------------
-- 3. fn_bulk_shift_route_departures
-- ------------------------------------------------------------
-- Atomic batch UPDATE of every non-departed departure on `p_route_id`
-- whose scheduled_time falls in `[p_date 00:00 WAT, p_date+1 00:00 WAT)`.
-- Already-departed departures are skipped and reported separately.
--
-- The shift is bounded to ±360 minutes to prevent fat-finger disasters.
-- A unique-violation (would create two departures at the same time on
-- the same route) is converted into a clean P0099 so the route handler
-- can map it to a 409 instead of a 500.
CREATE OR REPLACE FUNCTION fn_bulk_shift_route_departures(
    p_route_id UUID,
    p_date     DATE,
    p_minutes  INT,
    p_staff_id UUID
)
RETURNS TABLE (
    "shifted"        INT,
    "skippedDeparted" INT
)
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    v_agency_id      UUID;
    v_caller_role    staff_role;
    v_from           TIMESTAMPTZ := (p_date::timestamp     AT TIME ZONE 'Africa/Douala');
    v_to             TIMESTAMPTZ := ((p_date + 1)::timestamp AT TIME ZONE 'Africa/Douala');
    v_interval       INTERVAL    := (p_minutes || ' minutes')::INTERVAL;
    v_shifted_count  INT;
    v_departed_count INT;
BEGIN
    IF p_minutes = 0 THEN
        RAISE EXCEPTION 'Shift must be non-zero' USING ERRCODE = 'P0001';
    END IF;
    IF p_minutes < -360 OR p_minutes > 360 THEN
        RAISE EXCEPTION 'Shift must be between -360 and +360 minutes'
            USING ERRCODE = 'P0001';
    END IF;

    SELECT agency_id INTO v_agency_id FROM routes WHERE id = p_route_id;
    IF v_agency_id IS NULL THEN
        RAISE EXCEPTION 'Route % not found', p_route_id USING ERRCODE = 'P0002';
    END IF;

    SELECT role INTO v_caller_role
    FROM staff_users
    WHERE id = p_staff_id
      AND is_active = true
      AND (role = 'super_admin' OR (role = 'admin' AND agency_id = v_agency_id));
    IF v_caller_role IS NULL THEN
        RAISE EXCEPTION 'Only super_admin or this agency''s admin can shift departures'
            USING ERRCODE = 'P0003';
    END IF;

    -- Count those we'll skip (already departed).
    SELECT COUNT(*) INTO v_departed_count
    FROM departures
    WHERE route_id = p_route_id
      AND scheduled_time >= v_from
      AND scheduled_time <  v_to
      AND status = 'departed';

    -- Bulk shift the non-departed ones in one statement. unique_violation
    -- means the new times would collide with another departure on the
    -- same route — surface a clean error instead of a generic 500.
    BEGIN
        WITH shifted AS (
            UPDATE departures
               SET scheduled_time = scheduled_time + v_interval,
                   updated_by     = p_staff_id
             WHERE route_id        = p_route_id
               AND scheduled_time >= v_from
               AND scheduled_time <  v_to
               AND status         <> 'departed'
            RETURNING id
        )
        SELECT COUNT(*) INTO v_shifted_count FROM shifted;
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'Shift would create duplicate scheduled times on this route. Try a different value.'
            USING ERRCODE = 'P0099';
    END;

    -- One audit row per batch (not per departure) — keeps the regulator
    -- audit feed legible. Action is 'departure_shifted'; entity points at
    -- the route since this is a route-level operation.
    INSERT INTO audit_log (action, entity_type, entity_id, performed_by, new_values)
    VALUES (
        'departure_shifted',
        'route',
        p_route_id,
        p_staff_id,
        jsonb_build_object(
            'date',            p_date,
            'minutes',         p_minutes,
            'shifted',         v_shifted_count,
            'skippedDeparted', v_departed_count
        )
    );

    RETURN QUERY SELECT v_shifted_count, v_departed_count;
END;
$$;

COMMENT ON FUNCTION fn_bulk_shift_route_departures IS
'Atomic batch shift of one route''s non-departed departures on one date by ±N minutes (bounded ±360). Returns counts. Already-departed rows are skipped. Unique-time collisions raise P0099 for a clean 409 mapping at the API edge.';

COMMIT;
