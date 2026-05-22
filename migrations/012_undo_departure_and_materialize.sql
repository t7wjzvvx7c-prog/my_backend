-- ============================================================
-- Migration 012: Undo departure + daily materialization
-- ============================================================
-- Two unrelated additive changes shipped together because both touch
-- agency-side operational labor:
--
-- 1. Allow `departed → boarding` for admin/super_admin within a 15-
--    minute undo window. Today the state machine treats `departed` as
--    terminal; that's correct for accounting but breaks the real-world
--    case where the bus comes back (mechanical issue) and operations
--    need a clean recovery path. The window keeps the audit trail
--    legible — you can't "un-depart" yesterday's bus.
--
-- 2. fn_materialize_route_departures(p_agency_id, p_date, p_staff_id):
--    iterate active routes for an agency and create today's
--    departures from each route's departure_times template. Idempotent
--    via the existing UNIQUE (route_id, scheduled_time) — calling
--    twice on the same day is a safe no-op for already-existing rows.
--    Eliminates the per-departure-per-day manual creation labor that
--    is currently the agency admin's biggest daily chore.
--
-- Both functions are SECURITY DEFINER with pinned search_path, in
-- line with the rest of the project's stored-procedure conventions.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 1. fn_update_departure_status — adds the 15-minute undo branch
-- ------------------------------------------------------------
-- CREATE OR REPLACE preserves ownership but DOES reset SECURITY
-- DEFINER and SET clauses, so we re-declare them inside the function
-- definition itself.
CREATE OR REPLACE FUNCTION fn_update_departure_status(
    p_departure_id  UUID,
    p_new_status    departure_status,
    p_staff_id      UUID
)
RETURNS TABLE (
    departure_id    UUID,
    old_status      departure_status,
    new_status      departure_status,
    departed_at     TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    v_current      RECORD;
    v_caller_role  staff_role;
    v_undo_window  INTERVAL := INTERVAL '15 minutes';
BEGIN
    -- ISOLATION: lock the row.
    SELECT d.id, d.status, d.agency_id, d.departed_at
    INTO v_current
    FROM departures d
    WHERE d.id = p_departure_id
    FOR UPDATE;

    IF v_current IS NULL THEN
        RAISE EXCEPTION 'Departure % not found', p_departure_id
            USING ERRCODE = 'P0002';
    END IF;

    -- Resolve caller role; reject if inactive or wrong agency.
    SELECT su.role INTO v_caller_role
    FROM staff_users su
    WHERE su.id = p_staff_id
      AND su.is_active = true
      AND (su.role = 'super_admin' OR su.agency_id = v_current.agency_id);

    IF v_caller_role IS NULL THEN
        RAISE EXCEPTION 'Staff % is not authorized for this agency', p_staff_id
            USING ERRCODE = 'P0003';
    END IF;

    -- State machine.
    --   not_boarding → boarding
    --   boarding     → full | departed
    --   full         → boarding | departed
    --   departed     → boarding (admin/super_admin only, within window)
    IF v_current.status = 'departed' THEN
        IF p_new_status <> 'boarding' THEN
            RAISE EXCEPTION 'Departed bus can only be reverted to boarding'
                USING ERRCODE = 'P0006';
        END IF;
        IF v_caller_role NOT IN ('admin', 'super_admin') THEN
            RAISE EXCEPTION 'Only admin or super_admin can undo a departure'
                USING ERRCODE = 'P0003';
        END IF;
        IF v_current.departed_at IS NULL
           OR (now() - v_current.departed_at) > v_undo_window THEN
            RAISE EXCEPTION 'Undo window expired (15 minutes after departure)'
                USING ERRCODE = 'P0001';
        END IF;
        -- Allowed; fall through to the UPDATE which clears departed_at.

    ELSIF v_current.status = 'not_boarding' AND p_new_status <> 'boarding' THEN
        RAISE EXCEPTION 'Invalid transition: not_boarding can only transition to boarding'
            USING ERRCODE = 'P0006';

    ELSIF v_current.status = 'boarding' AND p_new_status NOT IN ('full', 'departed') THEN
        RAISE EXCEPTION 'Invalid transition: boarding can only transition to full or departed'
            USING ERRCODE = 'P0006';

    ELSIF v_current.status = 'full' AND p_new_status NOT IN ('boarding', 'departed') THEN
        RAISE EXCEPTION 'Invalid transition: full can only transition to boarding or departed'
            USING ERRCODE = 'P0006';
    END IF;

    -- ATOMICITY: apply update. The CASE clears departed_at on any
    -- non-departed transition (covers the undo path too) — required by
    -- the chk_departed_at_valid CHECK constraint.
    UPDATE departures d
    SET status      = p_new_status,
        departed_at = CASE WHEN p_new_status = 'departed' THEN now() ELSE NULL END,
        updated_by  = p_staff_id
    WHERE d.id = p_departure_id;

    -- ATOMICITY: audit. Distinguish undo from a forward transition so
    -- the regulator log makes the operation legible.
    INSERT INTO audit_log (action, entity_type, entity_id, performed_by, old_values, new_values)
    VALUES (
        'status_changed',
        'departure',
        p_departure_id,
        p_staff_id,
        jsonb_build_object('status', v_current.status::text),
        jsonb_build_object(
            'status',     p_new_status::text,
            'undo',       (v_current.status = 'departed' AND p_new_status = 'boarding')
        )
    );

    RETURN QUERY
    SELECT
        d.id,
        v_current.status,
        d.status,
        d.departed_at,
        d.updated_at
    FROM departures d
    WHERE d.id = p_departure_id;
END;
$$;

COMMENT ON FUNCTION fn_update_departure_status IS
'ATOMIC status transition with state machine + 15-minute admin/super_admin undo for departed→boarding. Audit row carries new_values.undo=true to distinguish undo from forward transitions.';


-- ------------------------------------------------------------
-- 2. fn_materialize_route_departures — admin-triggered "generate today"
-- ------------------------------------------------------------
-- For each active route owned by p_agency_id, create a departure on
-- p_date for every HH:MM in route.departure_times. Idempotent — the
-- UNIQUE (route_id, scheduled_time) constraint causes
-- ON CONFLICT DO NOTHING to skip already-existing rows.
--
-- Returns one summary row: how many were created, how many already
-- existed, how many routes had no template times to materialize.
CREATE OR REPLACE FUNCTION fn_materialize_route_departures(
    p_agency_id UUID,
    p_date      DATE,
    p_staff_id  UUID
)
RETURNS TABLE (
    "created"      INT,
    "skipped"      INT,
    "routesProcessed" INT,
    "routesEmpty"  INT
)
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    v_caller_role staff_role;
    v_route       RECORD;
    v_time_text   TEXT;
    v_scheduled   TIMESTAMPTZ;
    v_inserted_id UUID;
    v_created     INT := 0;
    v_skipped     INT := 0;
    v_processed   INT := 0;
    v_empty       INT := 0;
BEGIN
    -- Authz: super_admin or admin of the requested agency.
    SELECT su.role INTO v_caller_role
    FROM staff_users su
    WHERE su.id = p_staff_id
      AND su.is_active = true
      AND (su.role = 'super_admin' OR (su.role = 'admin' AND su.agency_id = p_agency_id));

    IF v_caller_role IS NULL THEN
        RAISE EXCEPTION 'Only super_admin or this agency''s admin can materialize departures'
            USING ERRCODE = 'P0003';
    END IF;

    FOR v_route IN
        SELECT id, bus_capacity, category, departure_times
        FROM routes
        WHERE agency_id = p_agency_id
          AND is_active = true
    LOOP
        v_processed := v_processed + 1;

        IF v_route.departure_times IS NULL OR array_length(v_route.departure_times, 1) IS NULL THEN
            v_empty := v_empty + 1;
            CONTINUE;
        END IF;

        FOREACH v_time_text IN ARRAY v_route.departure_times LOOP
            -- Parse HH:MM → wall-clock time on p_date in Africa/Douala.
            -- A bad entry in the array is skipped silently rather than
            -- failing the whole batch; admins can fix the route later.
            BEGIN
                v_scheduled :=
                    (p_date::text || ' ' || v_time_text || ':00')::timestamp
                    AT TIME ZONE 'Africa/Douala';
            EXCEPTION WHEN OTHERS THEN
                CONTINUE;
            END;

            INSERT INTO departures (
                route_id, agency_id, scheduled_time,
                seats_sold, total_seats, category, status
            )
            VALUES (
                v_route.id, p_agency_id, v_scheduled,
                0, v_route.bus_capacity, v_route.category, 'not_boarding'
            )
            ON CONFLICT (route_id, scheduled_time) DO NOTHING
            RETURNING id INTO v_inserted_id;

            IF v_inserted_id IS NOT NULL THEN
                v_created := v_created + 1;
                INSERT INTO audit_log (action, entity_type, entity_id, performed_by, new_values)
                VALUES (
                    'departure_created',
                    'departure',
                    v_inserted_id,
                    p_staff_id,
                    jsonb_build_object(
                        'source', 'materialize_route_departures',
                        'route_id', v_route.id,
                        'scheduled_time', v_scheduled,
                        'date', p_date
                    )
                );
                v_inserted_id := NULL;  -- reset for next iteration
            ELSE
                v_skipped := v_skipped + 1;
            END IF;
        END LOOP;
    END LOOP;

    RETURN QUERY SELECT v_created, v_skipped, v_processed, v_empty;
END;
$$;

COMMENT ON FUNCTION fn_materialize_route_departures IS
'Generate today''s (or any date''s) departures from each active route''s departure_times template. Idempotent via UNIQUE (route_id, scheduled_time). Returns counts: created, skipped (already existed), routesProcessed, routesEmpty (no template).';

COMMIT;
