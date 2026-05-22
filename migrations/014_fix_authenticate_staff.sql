-- ============================================================
-- Migration 014: Fix ambiguous "id" reference in fn_authenticate_staff
-- ============================================================
-- Migration 010's fn_authenticate_staff declared RETURNS TABLE (id uuid,
-- ...) — which means inside the function body, the bare identifier `id`
-- is ambiguous: it could refer to the OUT parameter or the table column.
-- The internal `UPDATE staff_users SET last_login = now() WHERE id =
-- v_staff_id` was therefore rejected at runtime with:
--
--   ERROR: column reference "id" is ambiguous
--   DETAIL: It could refer to either a PL/pgSQL variable or a table column.
--
-- The fix qualifies the column as `staff_users.id`. CREATE OR REPLACE
-- FUNCTION redefines the function in place; SECURITY DEFINER + search_path
-- settings are re-applied because they don't survive a re-definition.
-- Idempotent — re-running this migration is a no-op.
-- ============================================================

BEGIN;

CREATE OR REPLACE FUNCTION fn_authenticate_staff(
    p_phone text,
    p_pin   text
)
RETURNS TABLE (
    id          uuid,
    "agencyId"  uuid,
    phone       varchar,
    name        varchar,
    role        staff_role,
    "isActive"  boolean,
    "lastLogin" timestamptz,
    "createdAt" timestamptz,
    "updatedAt" timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    v_staff_id uuid;
BEGIN
    SELECT s.id INTO v_staff_id
      FROM staff_users s
     WHERE s.phone = p_phone
       AND s.pin_hash = crypt(p_pin, s.pin_hash)
       AND s.is_active = true;

    IF v_staff_id IS NULL THEN
        RETURN;
    END IF;

    -- Qualify staff_users.id so PL/pgSQL doesn't confuse it with the
    -- function's `id` OUT parameter from the RETURNS TABLE clause.
    UPDATE staff_users
       SET last_login = now()
     WHERE staff_users.id = v_staff_id;

    RETURN QUERY
    SELECT s.id, s.agency_id, s.phone, s.name, s.role, s.is_active,
           s.last_login, s.created_at, s.updated_at
      FROM staff_users s
     WHERE s.id = v_staff_id;
END;
$$;

COMMENT ON FUNCTION fn_authenticate_staff IS
'PIN verification for /auth/login. SECURITY DEFINER so it bypasses RLS on staff_users — the only auth-bootstrap query allowed to do so. Touches last_login atomically. Never returns pin_hash. Migration 014 qualifies staff_users.id to fix an ambiguous-reference error against the RETURNS TABLE OUT parameter of the same name.';

COMMIT;
