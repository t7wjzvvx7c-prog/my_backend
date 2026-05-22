-- ============================================================
-- Migration 015: Fix ambiguous "id" reference in fn_create_booking
-- ============================================================
-- Same bug pattern as migration 014. fn_create_booking declares
-- RETURNS TABLE (id UUID, ...) so its body's `UPDATE departures SET
-- seats_reserved = ... WHERE id = p_departure_id` line is ambiguous:
-- PL/pgSQL doesn't know whether `id` means the OUT parameter or the
-- column. Runtime error:
--
--   ERROR: column reference "id" is ambiguous
--   QUERY:  UPDATE departures SET seats_reserved = ... WHERE id = ...
--
-- Visible to the passenger booking screen (POST /bookings → 500).
--
-- The fix qualifies the column as `departures.id`. CREATE OR REPLACE
-- FUNCTION redefines in place; SECURITY DEFINER + search_path are
-- re-applied because they don't survive a re-definition. Idempotent —
-- safe to re-run.
-- ============================================================

BEGIN;

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
SECURITY DEFINER SET search_path = public, pg_temp
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

    -- Hold the seats softly. Qualify departures.id so PL/pgSQL doesn't
    -- confuse it with the OUT parameter `id` from the RETURNS TABLE
    -- clause. (This is the bug fix vs migration 004's body.)
    UPDATE departures
       SET seats_reserved = seats_reserved + p_seat_count
     WHERE departures.id = p_departure_id;

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
'ATOMIC booking reservation. Locks departure, validates capacity, soft-holds seats, generates short code. Migration 015 qualifies departures.id to fix an ambiguous-reference error against the RETURNS TABLE OUT parameter of the same name.';

COMMIT;
