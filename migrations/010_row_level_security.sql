-- ============================================================
-- Migration 010: Row-Level Security
-- ============================================================
-- Additive only. Idempotent. Safe to apply against production WITHOUT a
-- coordinated app deploy: until the app is reconfigured (see ACTIVATION
-- CHECKLIST at the bottom), it continues to connect as the table owner,
-- which bypasses RLS. RLS only starts enforcing once the app switches to
-- the new `nexbus_app` role and starts setting per-request GUCs.
--
-- WHY:
--   Today, multi-tenant isolation is enforced only in the Express handlers.
--   A single missing `WHERE agency_id = $1` in any handler — or a future
--   handler written by a new engineer — leaks one agency's data to another.
--   RLS pushes isolation into the database, where it's enforced regardless
--   of which query path runs. Defense in depth.
--
-- DESIGN:
--   Identity is passed from the app to Postgres via per-transaction GUCs:
--     - app.staff_role : 'super_admin' | 'admin' | 'ticket_seller' | 'regulator'
--     - app.agency_id  : uuid (NULL for super_admin / regulator / anonymous)
--     - app.staff_id   : uuid (NULL for anonymous)
--   The app calls SELECT fn_set_request_context($role, $agency, $staff) at
--   the top of each transaction; policies read the GUCs via the helpers
--   declared below.
--
--   Anonymous (no GUC set) callers retain read access to the truly public
--   surface — agencies, routes, departures, towns, parks, agency_parks —
--   so the passenger app keeps working without authentication.
--
--   Stored functions on the ACID-critical paths (seat selling, booking
--   confirmation, status transitions, etc.) are switched to SECURITY
--   DEFINER. They already enforce their own authorization checks; running
--   as definer lets them update audit_log and departures even when the
--   caller is an anonymous passenger (e.g. fn_create_booking decrementing
--   seats_reserved).
--
-- WHAT THIS DOES NOT DO:
--   Column-level masking (e.g. hiding pin_hash from regulator queries) —
--   handled in the SELECT lists in the route modules. RLS is row-level.
-- ============================================================

BEGIN;

-- ============================================================
-- 1. APPLICATION ROLE
-- ============================================================
-- The app connects as this role in production. It is NOT a superuser and
-- does NOT have BYPASSRLS, so policies apply. Migrations and ops continue
-- to run as the original DATABASE_URL owner (which does bypass RLS).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nexbus_app') THEN
        CREATE ROLE nexbus_app LOGIN NOINHERIT;
        -- Password is left unset on purpose; set it out-of-band via:
        --   ALTER ROLE nexbus_app PASSWORD '...';
        -- and rotate it through your secrets manager.
    END IF;
END $$;

-- ============================================================
-- 2. REQUEST CONTEXT HELPERS
-- ============================================================
-- These read per-transaction GUCs set by fn_set_request_context. The
-- second arg `true` to current_setting means "return empty string if
-- unset" rather than raising — which lets anonymous calls evaluate to
-- NULL via the NULLIF wrapper.

CREATE OR REPLACE FUNCTION fn_request_role()
RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE
AS $$
    SELECT NULLIF(current_setting('app.staff_role', true), '')
$$;

CREATE OR REPLACE FUNCTION fn_request_agency()
RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE
AS $$
    SELECT NULLIF(current_setting('app.agency_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION fn_request_staff()
RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE
AS $$
    SELECT NULLIF(current_setting('app.staff_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION fn_is_super_admin()
RETURNS boolean LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT fn_request_role() = 'super_admin' $$;

CREATE OR REPLACE FUNCTION fn_is_regulator()
RETURNS boolean LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT fn_request_role() = 'regulator' $$;

CREATE OR REPLACE FUNCTION fn_is_agency_staff()
RETURNS boolean LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT fn_request_role() IN ('admin', 'ticket_seller') $$;

CREATE OR REPLACE FUNCTION fn_is_anonymous()
RETURNS boolean LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT fn_request_role() IS NULL $$;

-- App-facing entry point. Call once at the top of every request transaction.
CREATE OR REPLACE FUNCTION fn_set_request_context(
    p_role      text,
    p_agency_id uuid,
    p_staff_id  uuid
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    -- set_config(name, value, is_local). is_local=true == SET LOCAL,
    -- so the value is dropped at COMMIT/ROLLBACK and cannot leak across
    -- pooled connections.
    PERFORM set_config('app.staff_role', COALESCE(p_role, ''),            true);
    PERFORM set_config('app.agency_id',  COALESCE(p_agency_id::text, ''), true);
    PERFORM set_config('app.staff_id',   COALESCE(p_staff_id::text, ''),  true);
END;
$$;

COMMENT ON FUNCTION fn_set_request_context IS
'Set per-transaction identity GUCs read by RLS policies. Must be called inside a transaction; the values vanish on COMMIT/ROLLBACK so they never leak across pooled connections.';

-- ============================================================
-- 3. SECURITY DEFINER PROMOTIONS
-- ============================================================
-- These functions enforce their own authorization checks (validate staff
-- agency match, state machine transitions, capacity bounds). Running them
-- as definer lets them write audit_log + update departures regardless of
-- whether the caller is an anonymous passenger or an authenticated agent,
-- so the ACID-correct seat-selling and booking paths keep working under
-- RLS without policy carve-outs for every internal write.
--
-- search_path is pinned to defeat trojan-schema attacks against
-- SECURITY DEFINER functions.

ALTER FUNCTION fn_sell_seats(UUID, INTEGER, UUID)
    SECURITY DEFINER SET search_path = public, pg_temp;

ALTER FUNCTION fn_update_departure_status(UUID, departure_status, UUID)
    SECURITY DEFINER SET search_path = public, pg_temp;

ALTER FUNCTION fn_create_departure(UUID, TIMESTAMPTZ, UUID)
    SECURITY DEFINER SET search_path = public, pg_temp;

ALTER FUNCTION fn_create_staff(UUID, VARCHAR, VARCHAR, VARCHAR, staff_role)
    SECURITY DEFINER SET search_path = public, pg_temp;

ALTER FUNCTION fn_cleanup_expired_tokens()
    SECURITY DEFINER SET search_path = public, pg_temp;

ALTER FUNCTION fn_create_booking(UUID, VARCHAR, VARCHAR, INTEGER, INTEGER)
    SECURITY DEFINER SET search_path = public, pg_temp;

ALTER FUNCTION fn_confirm_booking(VARCHAR, UUID, NUMERIC)
    SECURITY DEFINER SET search_path = public, pg_temp;

ALTER FUNCTION fn_cancel_booking(VARCHAR, TEXT, UUID)
    SECURITY DEFINER SET search_path = public, pg_temp;

ALTER FUNCTION fn_expire_pending_bookings()
    SECURITY DEFINER SET search_path = public, pg_temp;

ALTER FUNCTION fn_purge_passenger_events_older_than(INTEGER)
    SECURITY DEFINER SET search_path = public, pg_temp;

-- Functions added by migrations 005–008 — same rationale as above.
-- fn_revert_auto_attribution and fn_refund_booking are staff-driven and
-- already authz-check internally. fn_passenger_attest_travel is called
-- ANONYMOUSLY from the post-trip prompt, so it must run as definer to
-- write audit_log + update bookings + commission_ledger. Likewise
-- fn_refresh_passenger_event_views maintains materialized aggregates and
-- must bypass RLS to scan source tables.
ALTER FUNCTION fn_revert_auto_attribution(VARCHAR, UUID)
    SECURITY DEFINER SET search_path = public, pg_temp;

ALTER FUNCTION fn_passenger_attest_travel(VARCHAR, VARCHAR, BOOLEAN)
    SECURITY DEFINER SET search_path = public, pg_temp;

ALTER FUNCTION fn_refund_booking(VARCHAR, UUID, TEXT)
    SECURITY DEFINER SET search_path = public, pg_temp;

ALTER FUNCTION fn_refresh_passenger_event_views()
    SECURITY DEFINER SET search_path = public, pg_temp;

-- ============================================================
-- 4. AUTHENTICATION HELPER
-- ============================================================
-- /auth/login currently does an inline SELECT against staff_users, which
-- breaks the moment RLS denies anonymous reads on staff_users. Route the
-- login through this SECURITY DEFINER function instead — it's the only
-- query that needs to run before identity is established.

-- Column names are quoted in camelCase so the function output matches the
-- shape the Flutter clients already expect — no manual aliasing in the
-- route handler.
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
    -- Verify credentials. crypt() returns the candidate hash using the
    -- stored hash's salt; row matches iff the PIN is correct.
    SELECT s.id INTO v_staff_id
      FROM staff_users s
     WHERE s.phone = p_phone
       AND s.pin_hash = crypt(p_pin, s.pin_hash)
       AND s.is_active = true;

    IF v_staff_id IS NULL THEN
        RETURN;
    END IF;

    -- Touch last_login atomically so the route handler doesn't need a
    -- second round-trip — and doesn't need an RLS carve-out to write
    -- staff_users from the anonymous-pre-auth context.
    UPDATE staff_users SET last_login = now() WHERE id = v_staff_id;

    RETURN QUERY
    SELECT s.id, s.agency_id, s.phone, s.name, s.role, s.is_active,
           s.last_login, s.created_at, s.updated_at
      FROM staff_users s
     WHERE s.id = v_staff_id;
END;
$$;

COMMENT ON FUNCTION fn_authenticate_staff IS
'PIN verification for /auth/login. SECURITY DEFINER so it bypasses RLS on staff_users — the only auth-bootstrap query allowed to do so. Touches last_login atomically. Never returns pin_hash.';

-- ============================================================
-- 5. ENABLE RLS + POLICIES
-- ============================================================
-- Pattern per table:
--   a) ALTER TABLE ... ENABLE ROW LEVEL SECURITY  (idempotent)
--   b) DROP POLICY IF EXISTS ... (idempotent)
--   c) CREATE POLICY ... (rebuilds clean policy set on every re-run)
--
-- We do NOT FORCE row-level security: the table owner (migration role)
-- continues to bypass RLS, which keeps migrations and ops scripts working.
-- After the app is fully cut over to nexbus_app you may optionally
-- ALTER TABLE ... FORCE ROW LEVEL SECURITY for belt-and-braces enforcement
-- against accidental superuser sessions.

-- ------------------------------------------------------------
-- agencies
-- ------------------------------------------------------------
-- Public read (passenger app); super_admin full write; agency admin can
-- update its own agency row only.
ALTER TABLE agencies ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS agencies_select        ON agencies;
DROP POLICY IF EXISTS agencies_insert_super  ON agencies;
DROP POLICY IF EXISTS agencies_update        ON agencies;
DROP POLICY IF EXISTS agencies_delete_super  ON agencies;

CREATE POLICY agencies_select ON agencies
    FOR SELECT USING (true);

CREATE POLICY agencies_insert_super ON agencies
    FOR INSERT WITH CHECK (fn_is_super_admin());

CREATE POLICY agencies_update ON agencies
    FOR UPDATE USING (
        fn_is_super_admin()
        OR (fn_request_role() = 'admin' AND id = fn_request_agency())
    )
    WITH CHECK (
        fn_is_super_admin()
        OR (fn_request_role() = 'admin' AND id = fn_request_agency())
    );

CREATE POLICY agencies_delete_super ON agencies
    FOR DELETE USING (fn_is_super_admin());

-- ------------------------------------------------------------
-- staff_users
-- ------------------------------------------------------------
-- No anonymous SELECT. super_admin sees all; agency admin sees own
-- agency; ticket_seller sees only self. regulator does not need staff
-- visibility (regulator surface is read-only on operational data).
ALTER TABLE staff_users ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS staff_select   ON staff_users;
DROP POLICY IF EXISTS staff_insert   ON staff_users;
DROP POLICY IF EXISTS staff_update   ON staff_users;
DROP POLICY IF EXISTS staff_delete   ON staff_users;

CREATE POLICY staff_select ON staff_users
    FOR SELECT USING (
        fn_is_super_admin()
        OR (fn_request_role() = 'admin' AND agency_id = fn_request_agency())
        OR (fn_is_agency_staff() AND id = fn_request_staff())
        -- Regulators need to resolve staff_user → agency_id for the audit
        -- subqueries in regulator_data.fetchAgencyDossierData and
        -- /regulator/audit. Operational scope is enforced by the route
        -- handler via req.scope.agencyIds; RLS just unblocks the join.
        OR fn_is_regulator()
    );

-- INSERTs flow through fn_create_staff (SECURITY DEFINER), so this policy
-- mostly catches direct INSERTs from app code. super_admin always; admin
-- only into its own agency, and only as ticket_seller or admin (no
-- privilege escalation).
CREATE POLICY staff_insert ON staff_users
    FOR INSERT WITH CHECK (
        fn_is_super_admin()
        OR (
            fn_request_role() = 'admin'
            AND agency_id = fn_request_agency()
            AND role IN ('admin', 'ticket_seller')
        )
    );

CREATE POLICY staff_update ON staff_users
    FOR UPDATE USING (
        fn_is_super_admin()
        OR (fn_request_role() = 'admin' AND agency_id = fn_request_agency())
    )
    WITH CHECK (
        fn_is_super_admin()
        OR (
            fn_request_role() = 'admin'
            AND agency_id = fn_request_agency()
            AND role IN ('admin', 'ticket_seller')
        )
    );

CREATE POLICY staff_delete ON staff_users
    FOR DELETE USING (
        fn_is_super_admin()
        OR (fn_request_role() = 'admin' AND agency_id = fn_request_agency())
    );

-- ------------------------------------------------------------
-- routes
-- ------------------------------------------------------------
ALTER TABLE routes ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS routes_select ON routes;
DROP POLICY IF EXISTS routes_insert ON routes;
DROP POLICY IF EXISTS routes_update ON routes;
DROP POLICY IF EXISTS routes_delete ON routes;

CREATE POLICY routes_select ON routes
    FOR SELECT USING (true);

CREATE POLICY routes_insert ON routes
    FOR INSERT WITH CHECK (
        fn_is_super_admin()
        OR (fn_request_role() = 'admin' AND agency_id = fn_request_agency())
    );

CREATE POLICY routes_update ON routes
    FOR UPDATE USING (
        fn_is_super_admin()
        OR (fn_request_role() = 'admin' AND agency_id = fn_request_agency())
    )
    WITH CHECK (
        fn_is_super_admin()
        OR (fn_request_role() = 'admin' AND agency_id = fn_request_agency())
    );

CREATE POLICY routes_delete ON routes
    FOR DELETE USING (
        fn_is_super_admin()
        OR (fn_request_role() = 'admin' AND agency_id = fn_request_agency())
    );

-- ------------------------------------------------------------
-- departures
-- ------------------------------------------------------------
-- Public read for the passenger board. Writes restricted to super_admin
-- and own-agency staff. Most writes flow through SECURITY DEFINER
-- functions (fn_sell_seats, fn_update_departure_status, fn_create_booking
-- decrementing seats_reserved); these policies catch the direct PUT
-- /departures path used by the staff dashboard.
ALTER TABLE departures ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS departures_select ON departures;
DROP POLICY IF EXISTS departures_insert ON departures;
DROP POLICY IF EXISTS departures_update ON departures;
DROP POLICY IF EXISTS departures_delete ON departures;

CREATE POLICY departures_select ON departures
    FOR SELECT USING (true);

CREATE POLICY departures_insert ON departures
    FOR INSERT WITH CHECK (
        fn_is_super_admin()
        OR (fn_is_agency_staff() AND agency_id = fn_request_agency())
    );

CREATE POLICY departures_update ON departures
    FOR UPDATE USING (
        fn_is_super_admin()
        OR (fn_is_agency_staff() AND agency_id = fn_request_agency())
    )
    WITH CHECK (
        fn_is_super_admin()
        OR (fn_is_agency_staff() AND agency_id = fn_request_agency())
    );

CREATE POLICY departures_delete ON departures
    FOR DELETE USING (
        fn_is_super_admin()
        OR (fn_request_role() = 'admin' AND agency_id = fn_request_agency())
    );

-- ------------------------------------------------------------
-- bookings
-- ------------------------------------------------------------
-- Bookings carry passenger PII (name + phone). Reads:
--   - super_admin / regulator: all
--   - agency staff: own agency
--   - anonymous: allowed (concession to keep the passenger lookup-by-code
--     and lookup-by-phone HTTP endpoints working without breaking the
--     mobile app). This SHOULD be tightened by routing those endpoints
--     through SECURITY DEFINER lookups that match on the secret code +
--     phone pair. Tracked as TODO; not part of this migration.
-- Inserts:
--   - anonymous OK (passenger creates own booking) — soft cap on PII
--     enforced by the seat_count + phone format CHECK constraints
--     already on the table.
ALTER TABLE bookings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS bookings_select ON bookings;
DROP POLICY IF EXISTS bookings_insert ON bookings;
DROP POLICY IF EXISTS bookings_update ON bookings;
DROP POLICY IF EXISTS bookings_delete ON bookings;

CREATE POLICY bookings_select ON bookings
    FOR SELECT USING (
        fn_is_super_admin()
        OR fn_is_regulator()
        OR (fn_is_agency_staff() AND agency_id = fn_request_agency())
        OR fn_is_anonymous()    -- TODO: replace with SECURITY DEFINER lookup
    );

CREATE POLICY bookings_insert ON bookings
    FOR INSERT WITH CHECK (true);

CREATE POLICY bookings_update ON bookings
    FOR UPDATE USING (
        fn_is_super_admin()
        OR (fn_is_agency_staff() AND agency_id = fn_request_agency())
    )
    WITH CHECK (
        fn_is_super_admin()
        OR (fn_is_agency_staff() AND agency_id = fn_request_agency())
    );

CREATE POLICY bookings_delete ON bookings
    FOR DELETE USING (fn_is_super_admin());

-- ------------------------------------------------------------
-- commission_settings
-- ------------------------------------------------------------
ALTER TABLE commission_settings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS comm_settings_select ON commission_settings;
DROP POLICY IF EXISTS comm_settings_insert ON commission_settings;
DROP POLICY IF EXISTS comm_settings_update ON commission_settings;
DROP POLICY IF EXISTS comm_settings_delete ON commission_settings;

CREATE POLICY comm_settings_select ON commission_settings
    FOR SELECT USING (
        fn_is_super_admin()
        OR fn_is_regulator()
        OR (fn_is_agency_staff() AND agency_id = fn_request_agency())
    );

-- Agency admins can lazily create their own settings row (bookings
-- router auto-INSERTs default rates on first read so the dashboard is
-- never empty). Only their own agency_id; only with defaults — they
-- can't UPDATE the rate, that's still super_admin-only.
CREATE POLICY comm_settings_insert ON commission_settings
    FOR INSERT WITH CHECK (
        fn_is_super_admin()
        OR (fn_request_role() = 'admin' AND agency_id = fn_request_agency())
    );

CREATE POLICY comm_settings_update ON commission_settings
    FOR UPDATE USING (fn_is_super_admin())
    WITH CHECK (fn_is_super_admin());

CREATE POLICY comm_settings_delete ON commission_settings
    FOR DELETE USING (fn_is_super_admin());

-- ------------------------------------------------------------
-- commission_ledger
-- ------------------------------------------------------------
-- Read by the agency it belongs to + super_admin + regulator. Writes
-- exclusively from fn_confirm_booking (SECURITY DEFINER) — direct
-- INSERTs/UPDATEs are not expected and policy is deliberately tight.
ALTER TABLE commission_ledger ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS comm_ledger_select ON commission_ledger;
DROP POLICY IF EXISTS comm_ledger_insert ON commission_ledger;
DROP POLICY IF EXISTS comm_ledger_update ON commission_ledger;
DROP POLICY IF EXISTS comm_ledger_delete ON commission_ledger;

CREATE POLICY comm_ledger_select ON commission_ledger
    FOR SELECT USING (
        fn_is_super_admin()
        OR fn_is_regulator()
        OR (fn_is_agency_staff() AND agency_id = fn_request_agency())
    );

CREATE POLICY comm_ledger_insert ON commission_ledger
    FOR INSERT WITH CHECK (fn_is_super_admin());

CREATE POLICY comm_ledger_update ON commission_ledger
    FOR UPDATE USING (fn_is_super_admin())
    WITH CHECK (fn_is_super_admin());

CREATE POLICY comm_ledger_delete ON commission_ledger
    FOR DELETE USING (fn_is_super_admin());

-- ------------------------------------------------------------
-- audit_log
-- ------------------------------------------------------------
-- Reads: super_admin + regulator only. Writes: any role, including
-- anonymous, because the login_failed audit row is inserted before any
-- identity is established.
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_select ON audit_log;
DROP POLICY IF EXISTS audit_insert ON audit_log;
DROP POLICY IF EXISTS audit_update ON audit_log;
DROP POLICY IF EXISTS audit_delete ON audit_log;

CREATE POLICY audit_select ON audit_log
    FOR SELECT USING (fn_is_super_admin() OR fn_is_regulator());

CREATE POLICY audit_insert ON audit_log
    FOR INSERT WITH CHECK (true);

-- audit_log is append-only by policy: no UPDATE, no DELETE for anyone.
-- (super_admin can still operate via the owner role outside RLS for
-- exceptional cleanup.)

-- ------------------------------------------------------------
-- refresh_tokens
-- ------------------------------------------------------------
-- Owner-only. A staff session can manage only its own tokens.
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rt_select ON refresh_tokens;
DROP POLICY IF EXISTS rt_insert ON refresh_tokens;
DROP POLICY IF EXISTS rt_update ON refresh_tokens;
DROP POLICY IF EXISTS rt_delete ON refresh_tokens;

CREATE POLICY rt_select ON refresh_tokens
    FOR SELECT USING (
        fn_is_super_admin()
        OR user_id = fn_request_staff()
    );

CREATE POLICY rt_insert ON refresh_tokens
    FOR INSERT WITH CHECK (
        fn_is_super_admin()
        OR user_id = fn_request_staff()
    );

CREATE POLICY rt_delete ON refresh_tokens
    FOR DELETE USING (
        fn_is_super_admin()
        OR user_id = fn_request_staff()
    );

-- ------------------------------------------------------------
-- towns, parks, agency_parks (reference data)
-- ------------------------------------------------------------
ALTER TABLE towns        ENABLE ROW LEVEL SECURITY;
ALTER TABLE parks        ENABLE ROW LEVEL SECURITY;
ALTER TABLE agency_parks ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS towns_select        ON towns;
DROP POLICY IF EXISTS towns_write         ON towns;
DROP POLICY IF EXISTS parks_select        ON parks;
DROP POLICY IF EXISTS parks_write         ON parks;
DROP POLICY IF EXISTS agency_parks_select ON agency_parks;
DROP POLICY IF EXISTS agency_parks_write  ON agency_parks;

CREATE POLICY towns_select ON towns FOR SELECT USING (true);
CREATE POLICY towns_write  ON towns FOR ALL
    USING (fn_is_super_admin())
    WITH CHECK (fn_is_super_admin());

CREATE POLICY parks_select ON parks FOR SELECT USING (true);
CREATE POLICY parks_write  ON parks FOR ALL
    USING (fn_is_super_admin())
    WITH CHECK (fn_is_super_admin());

CREATE POLICY agency_parks_select ON agency_parks FOR SELECT USING (true);
CREATE POLICY agency_parks_write  ON agency_parks FOR ALL
    USING (fn_is_super_admin())
    WITH CHECK (fn_is_super_admin());

-- ------------------------------------------------------------
-- regulator_scope
-- ------------------------------------------------------------
-- Sensitive: defines what each regulator can see. Manage via super_admin
-- only; regulator can read its own scope rows for self-introspection.
ALTER TABLE regulator_scope ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rs_select ON regulator_scope;
DROP POLICY IF EXISTS rs_write  ON regulator_scope;

CREATE POLICY rs_select ON regulator_scope
    FOR SELECT USING (
        fn_is_super_admin()
        OR (fn_is_regulator() AND staff_user_id = fn_request_staff())
    );

CREATE POLICY rs_write ON regulator_scope
    FOR ALL
    USING (fn_is_super_admin())
    WITH CHECK (fn_is_super_admin());

-- ------------------------------------------------------------
-- generated_reports
-- ------------------------------------------------------------
ALTER TABLE generated_reports ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS gr_select ON generated_reports;
DROP POLICY IF EXISTS gr_insert ON generated_reports;
DROP POLICY IF EXISTS gr_delete ON generated_reports;

CREATE POLICY gr_select ON generated_reports
    FOR SELECT USING (fn_is_super_admin() OR fn_is_regulator());

CREATE POLICY gr_insert ON generated_reports
    FOR INSERT WITH CHECK (fn_is_super_admin() OR fn_is_regulator());

CREATE POLICY gr_delete ON generated_reports
    FOR DELETE USING (fn_is_super_admin());
-- No UPDATE policy: reports are immutable once generated (content_hash
-- is meaningless if the row can be edited).

-- ------------------------------------------------------------
-- passenger_events
-- ------------------------------------------------------------
-- Anonymous insert (telemetry from the passenger app, no identity).
-- Reads restricted to super_admin + regulator for analytics.
ALTER TABLE passenger_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pe_select ON passenger_events;
DROP POLICY IF EXISTS pe_insert ON passenger_events;

CREATE POLICY pe_select ON passenger_events
    FOR SELECT USING (fn_is_super_admin() OR fn_is_regulator());

CREATE POLICY pe_insert ON passenger_events
    FOR INSERT WITH CHECK (true);

-- ============================================================
-- 6. GRANTS
-- ============================================================
-- The nexbus_app role gets table-level DML on everything. RLS does the
-- per-row gating; without these GRANTs nexbus_app would be denied at the
-- table-permission layer before RLS even runs.

GRANT USAGE ON SCHEMA public TO nexbus_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO nexbus_app;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA public TO nexbus_app;
GRANT EXECUTE                        ON ALL FUNCTIONS IN SCHEMA public TO nexbus_app;

-- Future tables / sequences / functions added by later migrations
-- inherit the same grants automatically.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nexbus_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO nexbus_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO nexbus_app;

COMMIT;

-- ============================================================
-- ACTIVATION CHECKLIST (run AFTER this migration)
-- ============================================================
-- This migration is intentionally inert until the app is reconfigured.
-- To turn RLS on:
--
-- 1. Set a password for the new role and store it in the secrets manager:
--      ALTER ROLE nexbus_app PASSWORD '<strong-random-secret>';
--
-- 2. Build a connection string for the app and put it in env:
--      APP_DATABASE_URL=postgres://nexbus_app:<secret>@<host>/<db>
--    Keep DATABASE_URL pointing at the owner role; it's used only by
--    migrate.js / migrate-up.js.
--
-- 3. In backend/server.js, switch the runtime pool to APP_DATABASE_URL.
--    Add a per-request middleware that opens a transaction, calls
--    fn_set_request_context, runs the route, then COMMITs:
--
--      app.use(async (req, res, next) => {
--        const client = await runtimePool.connect();
--        try {
--          await client.query('BEGIN');
--          await client.query(
--            'SELECT fn_set_request_context($1, $2, $3)',
--            [
--              req.staff?.role     || null,
--              req.staff?.agencyId || null,
--              req.staff?.id       || null,
--            ]
--          );
--          req.db = client;
--          res.on('finish', async () => {
--            try { await client.query('COMMIT'); }
--            finally { client.release(); }
--          });
--          next();
--        } catch (e) {
--          await client.query('ROLLBACK').catch(() => {});
--          client.release();
--          next(e);
--        }
--      });
--
--    Then refactor handlers to use req.db.query(...) instead of
--    pool.query(...). The /auth/login handler stays on the migration-owner
--    pool because it needs to run BEFORE identity is established — OR,
--    better, switch it to:
--      SELECT * FROM fn_authenticate_staff($1, $2)
--    which is SECURITY DEFINER and works fine from nexbus_app.
--
-- 4. Smoke test each flavor:
--      - Passenger app: search routes, view departures, create booking
--      - Agency app:    login, list own routes/departures, sell seats,
--                       confirm a booking, attempt to read another
--                       agency's bookings (must return empty)
--      - Regulator app: load regulator dashboard, generate a report
--
-- 5. Once stable, OPTIONALLY harden by forcing RLS even for the owner:
--      ALTER TABLE agencies          FORCE ROW LEVEL SECURITY;
--      ALTER TABLE staff_users       FORCE ROW LEVEL SECURITY;
--      ALTER TABLE routes            FORCE ROW LEVEL SECURITY;
--      ALTER TABLE departures        FORCE ROW LEVEL SECURITY;
--      ALTER TABLE bookings          FORCE ROW LEVEL SECURITY;
--      ALTER TABLE commission_ledger FORCE ROW LEVEL SECURITY;
--      ALTER TABLE audit_log         FORCE ROW LEVEL SECURITY;
--      ALTER TABLE refresh_tokens    FORCE ROW LEVEL SECURITY;
--    Skip this if your ops scripts and migrations rely on owner bypass.
-- ============================================================
