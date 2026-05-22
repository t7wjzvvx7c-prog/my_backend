-- ============================================================
-- Migration 002: Regulator Foundation
-- ============================================================
-- Additive only. Safe to run against an existing populated DB.
-- Every statement is idempotent (IF NOT EXISTS, ON CONFLICT DO NOTHING,
-- ALTER TYPE ... IF NOT EXISTS).
--
-- Effect on existing tables:
--   - agencies.park_name is preserved and continues to be the source of truth
--     for the agency app. A trigger mirrors changes into the new parks /
--     agency_parks tables so regulator queries can use the richer model
--     without breaking existing writes.
--
-- Rollback strategy: drop the four new tables, the sync trigger, and the
-- two indexes. The added enum value cannot be removed without rewriting
-- the type, so it is left in place; this is harmless.
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- 1. parks: first-class park entity (replaces free-text park_name)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS parks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(200) NOT NULL UNIQUE,
    city        VARCHAR(100) NOT NULL,
    region      VARCHAR(100),
    lat         NUMERIC(9,6),
    lng         NUMERIC(9,6),
    is_active   BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_parks_city ON parks (city) WHERE is_active = true;

-- ------------------------------------------------------------
-- 2. agency_parks: M:N between agencies and parks
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agency_parks (
    agency_id UUID NOT NULL REFERENCES agencies(id) ON DELETE CASCADE,
    park_id   UUID NOT NULL REFERENCES parks(id)    ON DELETE CASCADE,
    PRIMARY KEY (agency_id, park_id)
);

CREATE INDEX IF NOT EXISTS idx_agency_parks_park ON agency_parks (park_id);

-- ------------------------------------------------------------
-- 3. regulator_scope: which slice of the network a regulator can see
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS regulator_scope (
    staff_user_id UUID NOT NULL REFERENCES staff_users(id) ON DELETE CASCADE,
    scope_type    VARCHAR(20) NOT NULL CHECK (scope_type IN ('national','city','syndicat','park')),
    scope_value   VARCHAR(200) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (staff_user_id, scope_type, scope_value)
);

-- ------------------------------------------------------------
-- 4. generated_reports: hash-signed PDF audit trail
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS generated_reports (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template      VARCHAR(50) NOT NULL,
    scope_json    JSONB       NOT NULL,
    generated_by  UUID        REFERENCES staff_users(id),
    generated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    file_path     TEXT        NOT NULL,
    content_hash  CHAR(64)    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_template_time ON generated_reports (template, generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_generator    ON generated_reports (generated_by);

-- ------------------------------------------------------------
-- 5. New audit_log action for tracking regulator surface access
-- ------------------------------------------------------------
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'report_viewed';

-- ------------------------------------------------------------
-- 6. Backfill: populate parks + agency_parks from existing agencies
-- ------------------------------------------------------------
INSERT INTO parks (name, city)
SELECT DISTINCT park_name, park_name FROM agencies
ON CONFLICT (name) DO NOTHING;

INSERT INTO agency_parks (agency_id, park_id)
SELECT a.id, p.id
  FROM agencies a
  JOIN parks p ON p.name = a.park_name
ON CONFLICT DO NOTHING;

-- ------------------------------------------------------------
-- 7. Dual-write trigger: keep parks / agency_parks in sync as
--    the existing agency endpoints continue to write park_name
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION sync_agency_park()
RETURNS TRIGGER AS $$
DECLARE
    v_park_id UUID;
BEGIN
    -- Upsert the park, always returning the id (the no-op SET on conflict
    -- is the canonical PG idiom that lets RETURNING fire on conflict).
    INSERT INTO parks (name, city)
    VALUES (NEW.park_name, NEW.park_name)
    ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
    RETURNING id INTO v_park_id;

    IF TG_OP = 'INSERT' THEN
        INSERT INTO agency_parks (agency_id, park_id)
        VALUES (NEW.id, v_park_id)
        ON CONFLICT DO NOTHING;

    ELSIF TG_OP = 'UPDATE' AND OLD.park_name IS DISTINCT FROM NEW.park_name THEN
        DELETE FROM agency_parks WHERE agency_id = NEW.id;
        INSERT INTO agency_parks (agency_id, park_id)
        VALUES (NEW.id, v_park_id);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sync_agency_park ON agencies;
CREATE TRIGGER trg_sync_agency_park
    AFTER INSERT OR UPDATE OF park_name ON agencies
    FOR EACH ROW EXECUTE FUNCTION sync_agency_park();

-- ------------------------------------------------------------
-- 8. Audit-log indexes that regulator queries depend on
-- ------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_audit_action_time
    ON audit_log (action, created_at DESC);

COMMIT;
