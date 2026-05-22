-- ============================================================
-- Migration 003: Report-related audit_action values
-- ============================================================
-- Adds two enum values used by the regulator report endpoints
-- so report generation and downloads are themselves auditable.
-- Idempotent (uses IF NOT EXISTS).
-- ============================================================

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'report_generated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'report_downloaded';
