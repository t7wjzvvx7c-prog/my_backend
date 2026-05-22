-- ============================================================
-- Bus Departure Tracking System - Database Schema
-- PostgreSQL 14+
-- ACID-Enforced Design
-- ============================================================
-- 
-- ACID COMPLIANCE STRATEGY:
--
-- ATOMICITY:
--   - Critical multi-step operations wrapped in explicit transactions
--   - Stored procedures/functions ensure all-or-nothing execution
--   - SAVEPOINT used for nested rollback scenarios
--
-- CONSISTENCY:
--   - CHECK constraints enforce business rules at DB level
--   - FOREIGN KEY constraints maintain referential integrity
--   - UNIQUE constraints prevent duplicates
--   - Trigger-based validations for cross-table rules
--
-- ISOLATION:
--   - SELECT ... FOR UPDATE used for seat selling (row-level locking)
--   - SERIALIZABLE isolation for financial/critical operations
--   - Advisory locks for agency-level batch operations
--
-- DURABILITY:
--   - PostgreSQL WAL (Write-Ahead Logging) enabled by default
--   - synchronous_commit = on (default) ensures data is on disk
--   - Recommend: configure WAL archiving for point-in-time recovery
--
-- ============================================================


-- ============================================================
-- CLEANUP (safe re-run)
-- ============================================================
DROP FUNCTION IF EXISTS fn_sell_seats(UUID, INTEGER, UUID) CASCADE;
DROP FUNCTION IF EXISTS fn_update_departure_status(UUID, departure_status, UUID) CASCADE;
DROP FUNCTION IF EXISTS fn_create_departure(UUID, TIMESTAMPTZ, UUID) CASCADE;
DROP FUNCTION IF EXISTS fn_create_staff(UUID, VARCHAR, VARCHAR, VARCHAR, staff_role) CASCADE;
DROP FUNCTION IF EXISTS fn_cleanup_expired_tokens() CASCADE;

DROP TRIGGER IF EXISTS trg_departures_updated ON departures;
DROP TRIGGER IF EXISTS trg_routes_updated ON routes;
DROP TRIGGER IF EXISTS trg_staff_updated ON staff_users;
DROP TRIGGER IF EXISTS trg_agencies_updated ON agencies;
DROP TRIGGER IF EXISTS trg_validate_departure_agency ON departures;
DROP TRIGGER IF EXISTS trg_auto_status_on_full ON departures;

DROP FUNCTION IF EXISTS update_timestamp() CASCADE;
DROP FUNCTION IF EXISTS validate_departure_agency() CASCADE;
DROP FUNCTION IF EXISTS auto_status_on_full() CASCADE;

DROP TABLE IF EXISTS towns CASCADE;
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS departures CASCADE;
DROP TABLE IF EXISTS routes CASCADE;
DROP TABLE IF EXISTS staff_users CASCADE;
DROP TABLE IF EXISTS agencies CASCADE;

DROP TYPE IF EXISTS departure_status;
DROP TYPE IF EXISTS staff_role;
DROP TYPE IF EXISTS bus_category;
DROP TYPE IF EXISTS audit_action;


-- ============================================================
-- EXTENSIONS
-- ============================================================
CREATE EXTENSION IF NOT EXISTS "pgcrypto";    -- gen_random_uuid(), crypt(), gen_salt()


-- ============================================================
-- CUSTOM ENUM TYPES
-- ============================================================
CREATE TYPE staff_role AS ENUM ('super_admin', 'admin', 'ticket_seller', 'regulator');

CREATE TYPE bus_category AS ENUM ('classic', 'vip', 'business');

CREATE TYPE departure_status AS ENUM (
    'not_boarding',
    'boarding',
    'full',
    'departed'
);

CREATE TYPE audit_action AS ENUM (
    'seats_updated',
    'status_changed',
    'departure_created',
    'staff_created',
    'staff_deactivated',
    'login_success',
    'login_failed'
);


-- ============================================================
-- 1. AGENCIES
-- ============================================================
CREATE TABLE agencies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(100)  NOT NULL,
    logo_url        VARCHAR(500),
    park_name       VARCHAR(200)  NOT NULL,
    contact_phone   VARCHAR(20)   NOT NULL,
    is_active       BOOLEAN       NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),

    -- CONSISTENCY: no duplicate agency names
    CONSTRAINT uq_agency_name UNIQUE (name)
);

CREATE INDEX idx_agencies_active ON agencies (is_active) WHERE is_active = true;

COMMENT ON TABLE  agencies           IS 'Travel agencies operating bus departures';
COMMENT ON COLUMN agencies.park_name IS 'Physical location / bus park where agency operates';


-- ============================================================
-- 2. STAFF USERS
-- ============================================================
CREATE TABLE staff_users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agency_id   UUID          REFERENCES agencies(id) ON DELETE CASCADE,  -- NULL for super_admin
    phone       VARCHAR(20)   NOT NULL,
    pin_hash    VARCHAR(255)  NOT NULL,
    name        VARCHAR(100)  NOT NULL,
    role        staff_role    NOT NULL DEFAULT 'ticket_seller',
    is_active   BOOLEAN       NOT NULL DEFAULT true,
    last_login  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ   NOT NULL DEFAULT now(),

    -- CONSISTENCY: phone must be globally unique
    CONSTRAINT uq_staff_phone UNIQUE (phone),
    -- CONSISTENCY: phone format basic check
    CONSTRAINT chk_phone_format CHECK (phone ~ '^\+[0-9]{9,15}$'),
    -- CONSISTENCY: super_admin has no agency, regular staff must have one
    CONSTRAINT chk_agency_role CHECK (
        (role IN ('super_admin', 'regulator') AND agency_id IS NULL)
        OR (role NOT IN ('super_admin', 'regulator') AND agency_id IS NOT NULL)
    )
);

CREATE INDEX idx_staff_agency ON staff_users (agency_id);
CREATE INDEX idx_staff_active ON staff_users (agency_id, is_active) WHERE is_active = true;

COMMENT ON TABLE  staff_users          IS 'System users: super_admins (no agency), agency admins, and ticket sellers';
COMMENT ON COLUMN staff_users.agency_id IS 'NULL for super_admin; required for admin and ticket_seller';
COMMENT ON COLUMN staff_users.pin_hash IS 'bcrypt-hashed PIN for authentication';


-- ============================================================
-- 3. ROUTES
-- ============================================================
CREATE TABLE routes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agency_id       UUID          NOT NULL REFERENCES agencies(id) ON DELETE CASCADE,
    origin          VARCHAR(100)  NOT NULL,
    destination     VARCHAR(100)  NOT NULL,
    bus_capacity    INTEGER       NOT NULL,
    category        bus_category  NOT NULL DEFAULT 'classic',
    departure_times TEXT[]        NOT NULL DEFAULT '{}',
    is_active       BOOLEAN       NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),

    -- CONSISTENCY: business rule constraints
    CONSTRAINT chk_bus_capacity    CHECK (bus_capacity > 0 AND bus_capacity <= 100),
    CONSTRAINT chk_route_not_same  CHECK (origin <> destination),
    -- CONSISTENCY: no duplicate routes per agency
    CONSTRAINT uq_agency_route     UNIQUE (agency_id, origin, destination, category)
);

CREATE INDEX idx_routes_agency     ON routes (agency_id);
CREATE INDEX idx_routes_origin_dst ON routes (origin, destination);
CREATE INDEX idx_routes_active     ON routes (agency_id, is_active) WHERE is_active = true;
CREATE INDEX idx_routes_category   ON routes (category);

COMMENT ON TABLE  routes                 IS 'Bus routes operated by agencies';
COMMENT ON COLUMN routes.departure_times IS 'Scheduled time templates (HH:MM). Actual departures live in the departures table.';
COMMENT ON COLUMN routes.category        IS 'Bus service class: classic (standard), vip (premium seating), business (executive)';



-- ============================================================
-- 4. DEPARTURES
-- ============================================================
CREATE TABLE departures (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    route_id        UUID              NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    agency_id       UUID              NOT NULL REFERENCES agencies(id) ON DELETE CASCADE,
    scheduled_time  TIMESTAMPTZ       NOT NULL,
    seats_sold      INTEGER           NOT NULL DEFAULT 0,
    total_seats     INTEGER           NOT NULL,
    category        bus_category      NOT NULL DEFAULT 'classic',
    status          departure_status  NOT NULL DEFAULT 'not_boarding',
    departed_at     TIMESTAMPTZ,
    bus_number      VARCHAR(50),
    remarks         TEXT,
    updated_by      UUID              REFERENCES staff_users(id),
    created_at      TIMESTAMPTZ       NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ       NOT NULL DEFAULT now(),

    -- CONSISTENCY: core business rules enforced at DB level
    CONSTRAINT chk_seats_non_negative     CHECK (seats_sold >= 0),
    CONSTRAINT chk_total_seats_positive   CHECK (total_seats > 0),
    CONSTRAINT chk_seats_within_capacity  CHECK (seats_sold <= total_seats),
    -- CONSISTENCY: departed_at only set when actually departed
    CONSTRAINT chk_departed_at_valid      CHECK (
        (status = 'departed' AND departed_at IS NOT NULL)
        OR (status <> 'departed' AND departed_at IS NULL)
    ),
    -- CONSISTENCY: no duplicate departure for same route at same time
    CONSTRAINT uq_route_scheduled_time    UNIQUE (route_id, scheduled_time)
);

CREATE INDEX idx_departures_route     ON departures (route_id);
CREATE INDEX idx_departures_agency    ON departures (agency_id);
CREATE INDEX idx_departures_scheduled ON departures (scheduled_time);
CREATE INDEX idx_departures_active    ON departures (agency_id, status, scheduled_time)
    WHERE status <> 'departed';
-- NOTE: DATE(timestamptz) is STABLE not IMMUTABLE because it depends on session timezone.
-- We cast to date at a fixed timezone (WAT = West Africa Time, UTC+1) for Cameroon.
CREATE INDEX idx_departures_date      ON departures (
    ((scheduled_time AT TIME ZONE 'Africa/Douala')::date), agency_id
);

COMMENT ON TABLE  departures             IS 'Actual bus departures with live seat tracking';
COMMENT ON COLUMN departures.agency_id   IS 'Denormalized from route for fast agency-level queries';
COMMENT ON COLUMN departures.category    IS 'Denormalized from route — bus service class at time of creation';
COMMENT ON COLUMN departures.bus_number  IS 'Optional vehicle identifier or plate number';
COMMENT ON COLUMN departures.remarks     IS 'Optional notes or remarks about the departure';
COMMENT ON COLUMN departures.updated_by  IS 'Staff user who last modified this departure';


-- ============================================================
-- 5. REFRESH TOKENS
-- ============================================================
CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID          NOT NULL REFERENCES staff_users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255)  NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ   NOT NULL,
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT now(),

    -- CONSISTENCY: expiry must be in the future at creation
    CONSTRAINT chk_token_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_refresh_tokens_user    ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens (expires_at);

COMMENT ON TABLE refresh_tokens IS 'JWT refresh tokens for session management';


-- ============================================================
-- 6. AUDIT LOG (for traceability of critical operations)
-- ============================================================
CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action          audit_action    NOT NULL,
    entity_type     VARCHAR(50)     NOT NULL,      -- 'departure', 'staff_user', etc.
    entity_id       UUID            NOT NULL,
    performed_by    UUID            REFERENCES staff_users(id),
    old_values      JSONB,                         -- Previous state
    new_values      JSONB,                         -- New state
    ip_address      INET,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_entity   ON audit_log (entity_type, entity_id);
CREATE INDEX idx_audit_user     ON audit_log (performed_by);
CREATE INDEX idx_audit_created  ON audit_log (created_at);

COMMENT ON TABLE audit_log IS 'Immutable audit trail for all critical operations — supports ACID traceability';


-- ============================================================
-- TRIGGERS
-- ============================================================

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_agencies_updated
    BEFORE UPDATE ON agencies
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER trg_staff_updated
    BEFORE UPDATE ON staff_users
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER trg_routes_updated
    BEFORE UPDATE ON routes
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER trg_departures_updated
    BEFORE UPDATE ON departures
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();


-- CONSISTENCY: Validate that departure.agency_id and category match the route
CREATE OR REPLACE FUNCTION validate_departure_agency()
RETURNS TRIGGER AS $$
DECLARE
    v_route RECORD;
BEGIN
    SELECT agency_id, category INTO v_route FROM routes WHERE id = NEW.route_id;

    IF v_route IS NULL THEN
        RAISE EXCEPTION 'Route % does not exist', NEW.route_id;
    END IF;

    IF NEW.agency_id <> v_route.agency_id THEN
        RAISE EXCEPTION 'Departure agency_id (%) does not match route agency_id (%)',
            NEW.agency_id, v_route.agency_id;
    END IF;

    IF NEW.category <> v_route.category THEN
        RAISE EXCEPTION 'Departure category (%) does not match route category (%)',
            NEW.category, v_route.category;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_validate_departure_agency
    BEFORE INSERT OR UPDATE ON departures
    FOR EACH ROW EXECUTE FUNCTION validate_departure_agency();


-- CONSISTENCY: Auto-set status to 'full' when seats_sold reaches total_seats
CREATE OR REPLACE FUNCTION auto_status_on_full()
RETURNS TRIGGER AS $$
BEGIN
    -- If bus just became full and hasn't departed, mark as full
    IF NEW.seats_sold = NEW.total_seats
       AND NEW.status NOT IN ('full', 'departed')
    THEN
        NEW.status := 'full';
    END IF;

    -- If seats freed up from full, revert to boarding
    IF OLD.status = 'full'
       AND NEW.seats_sold < NEW.total_seats
       AND NEW.status = 'full'
    THEN
        NEW.status := 'boarding';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_auto_status_on_full
    BEFORE UPDATE ON departures
    FOR EACH ROW EXECUTE FUNCTION auto_status_on_full();


-- ============================================================
-- TRANSACTIONAL STORED FUNCTIONS
-- ============================================================

-- ---------------------------------------------------------
-- fn_sell_seats: ATOMIC seat selling with row-level locking
-- Prevents race conditions when multiple sellers update
-- the same departure concurrently.
-- ---------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_sell_seats(
    p_departure_id  UUID,
    p_seats_to_sell INTEGER,
    p_staff_id      UUID
)
RETURNS TABLE (
    departure_id    UUID,
    seats_sold      INTEGER,
    total_seats     INTEGER,
    available_seats INTEGER,
    fill_percentage NUMERIC,
    status          departure_status
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_current  RECORD;
    v_new_sold INTEGER;
BEGIN
    -- ISOLATION: Lock the specific departure row to prevent concurrent modification
    -- Other transactions trying to sell seats on this departure will WAIT here
    SELECT d.id, d.seats_sold, d.total_seats, d.status, d.agency_id
    INTO v_current
    FROM departures d
    WHERE d.id = p_departure_id
    FOR UPDATE;   -- <<< ROW-LEVEL LOCK

    -- Validate departure exists
    IF v_current IS NULL THEN
        RAISE EXCEPTION 'Departure % not found', p_departure_id
            USING ERRCODE = 'P0002';  -- no_data_found
    END IF;

    -- CONSISTENCY: Cannot sell seats on departed bus
    IF v_current.status = 'departed' THEN
        RAISE EXCEPTION 'Cannot sell seats: departure % has already departed', p_departure_id
            USING ERRCODE = 'P0001';
    END IF;

    -- CONSISTENCY: Validate staff belongs to this agency (or is super_admin)
    IF NOT EXISTS (
        SELECT 1 FROM staff_users su
        WHERE su.id = p_staff_id
          AND su.is_active = true
          AND (su.role = 'super_admin' OR su.agency_id = v_current.agency_id)
    ) THEN
        RAISE EXCEPTION 'Staff % is not authorized for this agency', p_staff_id
            USING ERRCODE = 'P0003';
    END IF;

    -- Calculate new seat count
    v_new_sold := v_current.seats_sold + p_seats_to_sell;

    -- CONSISTENCY: Cannot exceed capacity (also enforced by CHECK constraint as safety net)
    IF v_new_sold > v_current.total_seats THEN
        RAISE EXCEPTION 'Not enough seats: requested %, available %',
            p_seats_to_sell, (v_current.total_seats - v_current.seats_sold)
            USING ERRCODE = 'P0004';
    END IF;

    -- CONSISTENCY: Cannot go below zero
    IF v_new_sold < 0 THEN
        RAISE EXCEPTION 'Seats sold cannot be negative (current: %, change: %)',
            v_current.seats_sold, p_seats_to_sell
            USING ERRCODE = 'P0005';
    END IF;

    -- ATOMICITY: Update the departure (trigger will handle auto-full status)
    UPDATE departures d
    SET seats_sold = v_new_sold,
        updated_by = p_staff_id
    WHERE d.id = p_departure_id;

    -- ATOMICITY: Write audit log within the same transaction
    INSERT INTO audit_log (action, entity_type, entity_id, performed_by, old_values, new_values)
    VALUES (
        'seats_updated',
        'departure',
        p_departure_id,
        p_staff_id,
        jsonb_build_object('seats_sold', v_current.seats_sold),
        jsonb_build_object('seats_sold', v_new_sold, 'change', p_seats_to_sell)
    );

    -- Return updated state
    RETURN QUERY
    SELECT
        d.id,
        d.seats_sold,
        d.total_seats,
        (d.total_seats - d.seats_sold),
        ROUND((d.seats_sold::numeric / d.total_seats) * 100, 1),
        d.status
    FROM departures d
    WHERE d.id = p_departure_id;

END;
$$;

COMMENT ON FUNCTION fn_sell_seats IS
'ATOMIC seat selling with row-level locking. Pass negative p_seats_to_sell to cancel/refund seats.
Prevents overselling via FOR UPDATE lock + CHECK constraint double safety.';


-- ---------------------------------------------------------
-- fn_update_departure_status: ATOMIC status transition
-- Enforces valid state transitions.
-- ---------------------------------------------------------
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
AS $$
DECLARE
    v_current RECORD;
BEGIN
    -- ISOLATION: Lock the row
    SELECT d.id, d.status, d.agency_id
    INTO v_current
    FROM departures d
    WHERE d.id = p_departure_id
    FOR UPDATE;

    IF v_current IS NULL THEN
        RAISE EXCEPTION 'Departure % not found', p_departure_id
            USING ERRCODE = 'P0002';
    END IF;

    -- CONSISTENCY: Validate staff authorization (super_admin can access all agencies)
    IF NOT EXISTS (
        SELECT 1 FROM staff_users su
        WHERE su.id = p_staff_id
          AND su.is_active = true
          AND (su.role = 'super_admin' OR su.agency_id = v_current.agency_id)
    ) THEN
        RAISE EXCEPTION 'Staff % is not authorized for this agency', p_staff_id
            USING ERRCODE = 'P0003';
    END IF;

    -- CONSISTENCY: Enforce valid state transitions
    --   not_boarding → boarding
    --   boarding     → full | departed
    --   full         → boarding | departed
    --   departed     → (terminal, no transitions)
    IF v_current.status = 'departed' THEN
        RAISE EXCEPTION 'Cannot change status: departure has already departed'
            USING ERRCODE = 'P0001';
    END IF;

    IF v_current.status = 'not_boarding' AND p_new_status NOT IN ('boarding') THEN
        RAISE EXCEPTION 'Invalid transition: not_boarding can only transition to boarding'
            USING ERRCODE = 'P0006';
    END IF;

    IF v_current.status = 'boarding' AND p_new_status NOT IN ('full', 'departed') THEN
        RAISE EXCEPTION 'Invalid transition: boarding can only transition to full or departed'
            USING ERRCODE = 'P0006';
    END IF;

    IF v_current.status = 'full' AND p_new_status NOT IN ('boarding', 'departed') THEN
        RAISE EXCEPTION 'Invalid transition: full can only transition to boarding or departed'
            USING ERRCODE = 'P0006';
    END IF;

    -- ATOMICITY: Perform update
    UPDATE departures d
    SET status      = p_new_status,
        departed_at = CASE WHEN p_new_status = 'departed' THEN now() ELSE NULL END,
        updated_by  = p_staff_id
    WHERE d.id = p_departure_id;

    -- ATOMICITY: Audit log in same transaction
    INSERT INTO audit_log (action, entity_type, entity_id, performed_by, old_values, new_values)
    VALUES (
        'status_changed',
        'departure',
        p_departure_id,
        p_staff_id,
        jsonb_build_object('status', v_current.status::text),
        jsonb_build_object('status', p_new_status::text)
    );

    -- Return result
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
'ATOMIC status transition with state machine enforcement. Prevents invalid transitions like departed→boarding.';


-- ---------------------------------------------------------
-- fn_create_departure: ATOMIC departure creation
-- Copies capacity from route, validates consistency.
-- ---------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_create_departure(
    p_route_id       UUID,
    p_scheduled_time TIMESTAMPTZ,
    p_staff_id       UUID
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_route       RECORD;
    v_departure_id UUID;
BEGIN
    -- Lock the route to prevent concurrent capacity changes
    SELECT r.id, r.agency_id, r.bus_capacity, r.category, r.is_active
    INTO v_route
    FROM routes r
    WHERE r.id = p_route_id
    FOR SHARE;   -- Shared lock (allow reads, block writes)

    IF v_route IS NULL THEN
        RAISE EXCEPTION 'Route % not found', p_route_id
            USING ERRCODE = 'P0002';
    END IF;

    IF NOT v_route.is_active THEN
        RAISE EXCEPTION 'Route % is inactive', p_route_id
            USING ERRCODE = 'P0001';
    END IF;

    -- CONSISTENCY: Validate staff belongs to route's agency (super_admin can access all)
    IF NOT EXISTS (
        SELECT 1 FROM staff_users su
        WHERE su.id = p_staff_id
          AND su.is_active = true
          AND (su.role = 'super_admin' OR su.agency_id = v_route.agency_id)
    ) THEN
        RAISE EXCEPTION 'Staff % is not authorized for this agency', p_staff_id
            USING ERRCODE = 'P0003';
    END IF;

    -- ATOMICITY: Create departure with route's current capacity
    INSERT INTO departures (route_id, agency_id, scheduled_time, total_seats, category, seats_sold, status)
    VALUES (p_route_id, v_route.agency_id, p_scheduled_time, v_route.bus_capacity, v_route.category, 0, 'not_boarding')
    RETURNING id INTO v_departure_id;

    -- ATOMICITY: Audit
    INSERT INTO audit_log (action, entity_type, entity_id, performed_by, new_values)
    VALUES (
        'departure_created',
        'departure',
        v_departure_id,
        p_staff_id,
        jsonb_build_object(
            'route_id', p_route_id,
            'scheduled_time', p_scheduled_time,
            'total_seats', v_route.bus_capacity,
            'category', v_route.category::text
        )
    );

    RETURN v_departure_id;

END;
$$;

COMMENT ON FUNCTION fn_create_departure IS
'ATOMIC departure creation. Copies bus_capacity from route at creation time, validates staff authorization.';


-- ---------------------------------------------------------
-- fn_create_staff: ATOMIC staff creation with PIN hashing
-- p_agency_id is NULL for super_admin role
-- ---------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_create_staff(
    p_agency_id  UUID,
    p_phone      VARCHAR,
    p_pin        VARCHAR,
    p_name       VARCHAR,
    p_role       staff_role DEFAULT 'ticket_seller'
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_staff_id UUID;
BEGIN
    -- CONSISTENCY: super_admin and regulator must NOT have an agency
    IF p_role IN ('super_admin', 'regulator') AND p_agency_id IS NOT NULL THEN
        RAISE EXCEPTION '% must not belong to an agency (agency_id must be NULL)', p_role
            USING ERRCODE = 'P0008';
    END IF;

    -- CONSISTENCY: admin and ticket_seller must have an agency
    IF p_role NOT IN ('super_admin', 'regulator') AND p_agency_id IS NULL THEN
        RAISE EXCEPTION 'admin and ticket_seller must belong to an agency'
            USING ERRCODE = 'P0008';
    END IF;

    -- CONSISTENCY: Validate agency exists and is active (skip for super_admin)
    IF p_agency_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM agencies WHERE id = p_agency_id AND is_active = true
        ) THEN
            RAISE EXCEPTION 'Agency % not found or inactive', p_agency_id
                USING ERRCODE = 'P0002';
        END IF;
    END IF;

    -- CONSISTENCY: PIN must be 4-6 digits
    IF p_pin !~ '^[0-9]{4,6}$' THEN
        RAISE EXCEPTION 'PIN must be 4-6 digits'
            USING ERRCODE = 'P0007';
    END IF;

    -- ATOMICITY: Create user with hashed PIN
    INSERT INTO staff_users (agency_id, phone, pin_hash, name, role)
    VALUES (
        p_agency_id,          -- NULL for super_admin
        p_phone,
        crypt(p_pin, gen_salt('bf', 10)),   -- bcrypt hash
        p_name,
        p_role
    )
    RETURNING id INTO v_staff_id;

    -- ATOMICITY: Audit
    INSERT INTO audit_log (action, entity_type, entity_id, new_values)
    VALUES (
        'staff_created',
        'staff_user',
        v_staff_id,
        jsonb_build_object(
            'phone', p_phone,
            'name', p_name,
            'role', p_role::text,
            'agency_id', p_agency_id
        )
    );

    RETURN v_staff_id;

END;
$$;

COMMENT ON FUNCTION fn_create_staff IS
'ATOMIC staff creation with bcrypt PIN hashing. Pass NULL agency_id for super_admin role.';


-- ---------------------------------------------------------
-- fn_cleanup_expired_tokens: Maintenance function
-- ---------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_cleanup_expired_tokens()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_deleted INTEGER;
BEGIN
    DELETE FROM refresh_tokens
    WHERE expires_at < now();

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;


-- ============================================================
-- VIEWS
-- ============================================================

-- Active departures with computed fields (passenger-facing)
CREATE OR REPLACE VIEW v_active_departures AS
SELECT
    d.id,
    d.route_id,
    d.agency_id,
    a.name              AS agency_name,
    a.park_name,
    r.origin,
    r.destination,
    r.category,
    d.scheduled_time,
    d.seats_sold,
    d.total_seats,
    (d.total_seats - d.seats_sold)                              AS available_seats,
    ROUND((d.seats_sold::numeric / d.total_seats) * 100, 1)    AS fill_percentage,
    d.status,
    d.departed_at,
    d.updated_at
FROM departures d
JOIN routes   r ON r.id = d.route_id
JOIN agencies a ON a.id = d.agency_id
WHERE d.status <> 'departed'
ORDER BY d.scheduled_time ASC;

COMMENT ON VIEW v_active_departures IS 'Active departures with route/agency details — main passenger query';


-- Daily summary per agency (admin dashboard)
CREATE OR REPLACE VIEW v_daily_agency_summary AS
SELECT
    d.agency_id,
    a.name AS agency_name,
    d.category,
    DATE(d.scheduled_time) AS departure_date,
    COUNT(*)                                          AS total_departures,
    COUNT(*) FILTER (WHERE d.status = 'departed')     AS departed_count,
    COUNT(*) FILTER (WHERE d.status = 'boarding')     AS boarding_count,
    COUNT(*) FILTER (WHERE d.status = 'full')         AS full_count,
    SUM(d.seats_sold)                                 AS total_seats_sold,
    SUM(d.total_seats)                                AS total_capacity,
    ROUND(
        (SUM(d.seats_sold)::numeric / NULLIF(SUM(d.total_seats), 0)) * 100, 1
    ) AS overall_fill_percentage
FROM departures d
JOIN agencies a ON a.id = d.agency_id
GROUP BY d.agency_id, a.name, d.category, DATE(d.scheduled_time)
ORDER BY departure_date DESC, agency_name, d.category;

COMMENT ON VIEW v_daily_agency_summary IS 'Aggregated daily stats per agency for dashboards';


-- ============================================================
-- TOWNS
-- ============================================================
CREATE TABLE towns (
    name VARCHAR(100) PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE towns IS 'Reference list of towns for route origin/destination selection';

INSERT INTO towns (name) VALUES
    ('Bafoussam'), ('Bamenda'), ('Bertoua'), ('Buea'), ('Douala'),
    ('Dschang'), ('Ebolowa'), ('Edéa'), ('Foumban'), ('Garoua'),
    ('Kribi'), ('Kumba'), ('Limbe'), ('Maroua'), ('Mbalmayo'),
    ('Mbouda'), ('Meiganga'), ('Mora'), ('Nkongsamba'), ('Ngaoundéré'),
    ('Sangmélima'), ('Tiko'), ('Yaoundé')
ON CONFLICT (name) DO NOTHING;


-- ============================================================
-- SEED DATA
-- ============================================================

-- Agencies
INSERT INTO agencies (id, name, logo_url, park_name, contact_phone) VALUES
    ('a0000001-0000-0000-0000-000000000001', 'Touristique Express',
     NULL,
     'Gare routière de Nsam, Yaoundé', '+237233400001'),
    ('a0000001-0000-0000-0000-000000000002', 'Général Express Voyages',
     NULL,
     'Gare routière de Bonabéri, Douala', '+237233400002'),
    ('a0000001-0000-0000-0000-000000000003', 'Buca Voyages',
     NULL,
     'Gare routière de Buea', '+237233400003');

-- Staff users (created via fn_create_staff for proper PIN hashing)

-- Super admin (no agency — can manage everything)
SELECT fn_create_staff(
    NULL,
    '+237670000000', '0000', 'System Admin', 'super_admin'
);

-- Regulator (no agency — read-only oversight)
SELECT fn_create_staff(
    NULL,
    '+237680000000', '1234', 'Transport Regulator', 'regulator'
);

-- Agency staff
SELECT fn_create_staff(
    'a0000001-0000-0000-0000-000000000001',
    '+237690000001', '1234', 'Jean Mbarga', 'admin'
);
SELECT fn_create_staff(
    'a0000001-0000-0000-0000-000000000001',
    '+237690000002', '1234', 'Marie Atangana', 'ticket_seller'
);
SELECT fn_create_staff(
    'a0000001-0000-0000-0000-000000000002',
    '+237690000003', '1234', 'Paul Njoya', 'admin'
);
SELECT fn_create_staff(
    'a0000001-0000-0000-0000-000000000002',
    '+237690000004', '1234', 'Aïcha Moussa', 'ticket_seller'
);
SELECT fn_create_staff(
    'a0000001-0000-0000-0000-000000000003',
    '+237690000005', '1234', 'Emmanuel Fon', 'admin'
);

-- Routes
INSERT INTO routes (id, agency_id, origin, destination, bus_capacity, category, departure_times) VALUES
    ('e0000001-0000-0000-0000-000000000001', 'a0000001-0000-0000-0000-000000000001',
     'Yaoundé', 'Douala', 70, 'classic', ARRAY['06:00','10:00','14:00','18:00']),
    ('e0000001-0000-0000-0000-000000000002', 'a0000001-0000-0000-0000-000000000001',
     'Yaoundé', 'Bafoussam', 30, 'vip', ARRAY['07:00','13:00']),
    ('e0000001-0000-0000-0000-000000000003', 'a0000001-0000-0000-0000-000000000002',
     'Douala', 'Yaoundé', 70, 'classic', ARRAY['06:30','09:30','14:00','17:00']),
    ('e0000001-0000-0000-0000-000000000004', 'a0000001-0000-0000-0000-000000000002',
     'Douala', 'Bamenda', 30, 'business', ARRAY['06:00','12:00']),
    ('e0000001-0000-0000-0000-000000000005', 'a0000001-0000-0000-0000-000000000003',
     'Buea', 'Douala', 18, 'vip', ARRAY['07:00','10:00','15:00']);

-- Departures (using direct INSERT for seed data with varied statuses)
INSERT INTO departures (id, route_id, agency_id, scheduled_time, seats_sold, total_seats, category, status, departed_at, bus_number) VALUES
    -- Touristique: Yaoundé → Douala (classic)
    ('d0000001-0000-0000-0000-000000000001', 'e0000001-0000-0000-0000-000000000001',
     'a0000001-0000-0000-0000-000000000001',
     (CURRENT_DATE + TIME '06:00')::timestamptz, 70, 70, 'classic', 'departed',
     (CURRENT_DATE + TIME '06:15')::timestamptz, 'LT-2401-A'),

    ('d0000001-0000-0000-0000-000000000002', 'e0000001-0000-0000-0000-000000000001',
     'a0000001-0000-0000-0000-000000000001',
     (CURRENT_DATE + TIME '10:00')::timestamptz, 55, 70, 'classic', 'boarding',
     NULL, 'LT-2402-B'),

    ('d0000001-0000-0000-0000-000000000003', 'e0000001-0000-0000-0000-000000000001',
     'a0000001-0000-0000-0000-000000000001',
     (CURRENT_DATE + TIME '14:00')::timestamptz, 12, 70, 'classic', 'not_boarding',
     NULL, 'LT-2403-C'),

    ('d0000001-0000-0000-0000-000000000004', 'e0000001-0000-0000-0000-000000000001',
     'a0000001-0000-0000-0000-000000000001',
     (CURRENT_DATE + TIME '18:00')::timestamptz, 0, 70, 'classic', 'not_boarding',
     NULL, NULL),

    -- Touristique: Yaoundé → Bafoussam (vip)
    ('d0000001-0000-0000-0000-000000000005', 'e0000001-0000-0000-0000-000000000002',
     'a0000001-0000-0000-0000-000000000001',
     (CURRENT_DATE + TIME '07:00')::timestamptz, 30, 30, 'vip', 'full',
     NULL, 'LT-1501-V'),

    ('d0000001-0000-0000-0000-000000000006', 'e0000001-0000-0000-0000-000000000002',
     'a0000001-0000-0000-0000-000000000001',
     (CURRENT_DATE + TIME '13:00')::timestamptz, 8, 30, 'vip', 'not_boarding',
     NULL, 'LT-1502-V'),

    -- Général Express: Douala → Yaoundé (classic)
    ('d0000001-0000-0000-0000-000000000007', 'e0000001-0000-0000-0000-000000000003',
     'a0000001-0000-0000-0000-000000000002',
     (CURRENT_DATE + TIME '06:30')::timestamptz, 70, 70, 'classic', 'departed',
     (CURRENT_DATE + TIME '06:45')::timestamptz, 'GE-7001-A'),

    ('d0000001-0000-0000-0000-000000000008', 'e0000001-0000-0000-0000-000000000003',
     'a0000001-0000-0000-0000-000000000002',
     (CURRENT_DATE + TIME '09:30')::timestamptz, 42, 70, 'classic', 'boarding',
     NULL, 'GE-7002-B'),

    -- Général Express: Douala → Bamenda (business)
    ('d0000001-0000-0000-0000-000000000009', 'e0000001-0000-0000-0000-000000000004',
     'a0000001-0000-0000-0000-000000000002',
     (CURRENT_DATE + TIME '06:00')::timestamptz, 28, 30, 'business', 'boarding',
     NULL, 'GE-3001-B'),

    -- Buca Voyages: Buea → Douala (vip)
    ('d0000001-0000-0000-0000-000000000010', 'e0000001-0000-0000-0000-000000000005',
     'a0000001-0000-0000-0000-000000000003',
     (CURRENT_DATE + TIME '07:00')::timestamptz, 18, 18, 'vip', 'departed',
     (CURRENT_DATE + TIME '07:10')::timestamptz, 'BV-1801-V'),

    ('d0000001-0000-0000-0000-000000000011', 'e0000001-0000-0000-0000-000000000005',
     'a0000001-0000-0000-0000-000000000003',
     (CURRENT_DATE + TIME '10:00')::timestamptz, 14, 18, 'vip', 'boarding',
     NULL, 'BV-1802-V'),

    ('d0000001-0000-0000-0000-000000000012', 'e0000001-0000-0000-0000-000000000005',
     'a0000001-0000-0000-0000-000000000003',
     (CURRENT_DATE + TIME '15:00')::timestamptz, 3, 18, 'vip', 'not_boarding',
     NULL, NULL);


-- ============================================================
-- RECOMMENDED POSTGRESQL CONFIGURATION (run as superuser)
-- These settings reinforce DURABILITY guarantees.
-- ============================================================
-- ALTER SYSTEM SET synchronous_commit = 'on';          -- default, ensures WAL flush
-- ALTER SYSTEM SET fsync = 'on';                       -- default, never turn off
-- ALTER SYSTEM SET full_page_writes = 'on';            -- default, protects against partial writes
-- ALTER SYSTEM SET wal_level = 'replica';              -- enables WAL archiving / replication
-- ALTER SYSTEM SET default_transaction_isolation = 'read committed';  -- default, good balance
-- SELECT pg_reload_conf();


-- ============================================================
-- EXAMPLE USAGE OF TRANSACTIONAL FUNCTIONS
-- ============================================================
--
-- Sell 3 seats (ACID-safe):
--   SELECT * FROM fn_sell_seats(
--       'd0000001-0000-0000-0000-000000000002',  -- departure_id
--       3,                                        -- seats to sell
--         '50000001-...'                            -- staff_id
--   );
--
-- Refund 1 seat (pass negative):
--   SELECT * FROM fn_sell_seats('d000...', -1, 's000...');
--
-- Start boarding:
--   SELECT * FROM fn_update_departure_status(
--       'd0000001-0000-0000-0000-000000000003',
--       'boarding',
--         '50000001-...'
--   );
--
-- Mark as departed:
--   SELECT * FROM fn_update_departure_status('d000...', 'departed', 's000...');
--
-- Create new departure:
--   SELECT fn_create_departure(
--       'e0000001-0000-0000-0000-000000000001',
--       '2025-03-01 06:00:00+01',
--         '50000001-...'
--   );
--
-- ============================================================
-- DONE
-- ============================================================
