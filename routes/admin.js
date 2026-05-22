const express = require('express');

// Super-admin surface — endpoints that mutate platform-level config
// without bypassing the agency / regulator role boundaries enforced
// elsewhere. Mounted under /admin in server.js. Every route requires
// role='super_admin' on top of the standard authenticate middleware.
//
// Today this covers regulator scope management (list regulators with
// their scope rows; replace the scope set for one regulator). The
// existing /staff endpoints in server.js already handle creating
// the regulator user itself with role='regulator'; this module owns
// only the regulator_scope membership.
// All queries run on req.db (the per-request RLS-aware client from
// withRequestDb in server.js). pool is dropped from the destructure
// since it's no longer referenced; the constructor call site still
// passes it but the extra key is harmless.
module.exports = function createAdminRouter({
  authenticate,
  requireRole,
  ok,
  fail,
  serverError,
}) {
  const router = express.Router();

  router.use(authenticate);
  router.use(requireRole('super_admin'));

  // --------------------------------------------------------------
  // GET /admin/regulators
  //
  // Lists every staff_user with role='regulator', plus their current
  // scope rows from regulator_scope. Used by the super-admin UI to
  // render a "who can see what" view.
  //
  // Returns:
  //   [
  //     { id, name, phone, isActive, lastLogin,
  //       scopes: [ { scopeType, scopeValue, createdAt }, ... ] },
  //     ...
  //   ]
  // --------------------------------------------------------------
  router.get('/regulators', async (req, res) => {
    try {
      // Both queries run on the same request-scoped client; pg serializes
      // them on the connection, so Promise.all here means "issue back to
      // back", not "in parallel". Acceptable — both are small reads.
      const [staffRows, scopeRows] = await Promise.all([
        req.db.query(
          `SELECT id, name, phone,
                  is_active   AS "isActive",
                  last_login  AS "lastLogin",
                  created_at  AS "createdAt"
             FROM staff_users
            WHERE role = 'regulator'
            ORDER BY name ASC`,
        ),
        req.db.query(
          `SELECT staff_user_id AS "staffUserId",
                  scope_type    AS "scopeType",
                  scope_value   AS "scopeValue",
                  created_at    AS "createdAt"
             FROM regulator_scope
            ORDER BY scope_type ASC, scope_value ASC`,
        ),
      ]);

      const byStaff = new Map();
      for (const s of staffRows.rows) {
        byStaff.set(s.id, { ...s, scopes: [] });
      }
      for (const sc of scopeRows.rows) {
        const r = byStaff.get(sc.staffUserId);
        if (r) {
          r.scopes.push({
            scopeType: sc.scopeType,
            scopeValue: sc.scopeValue,
            createdAt: sc.createdAt,
          });
        }
      }
      ok(res, Array.from(byStaff.values()));
    } catch (err) {
      serverError(res, err);
    }
  });

  // --------------------------------------------------------------
  // PUT /admin/regulators/:id/scopes
  //
  // Replaces the entire scope set for one regulator. Atomic: either
  // every row is committed or none. Validates against the schema's
  // CHECK constraint (national | city | syndicat | park).
  //
  // Body: { scopes: [ { scopeType, scopeValue }, ... ] }
  //
  // Audit: 'staff_created' is reused as the action because the enum
  // does not yet have a dedicated 'scope_changed' value. The
  // entity_type='regulator_scope' disambiguates in the audit feed.
  // --------------------------------------------------------------
  router.put('/regulators/:id/scopes', async (req, res) => {
    const staffId = req.params.id;
    const scopes = Array.isArray(req.body?.scopes) ? req.body.scopes : null;
    if (scopes === null) return fail(res, 'Body must include scopes: [...]', 400);

    // Validate shape and values up front so the transaction below is
    // either entirely valid or rejected without touching the DB.
    const validTypes = new Set(['national', 'city', 'syndicat', 'park']);
    for (const s of scopes) {
      if (!s || typeof s.scopeType !== 'string' || typeof s.scopeValue !== 'string') {
        return fail(res, 'Each scope must have scopeType and scopeValue (string)', 400);
      }
      if (!validTypes.has(s.scopeType)) {
        return fail(res, `Invalid scopeType '${s.scopeType}'`, 400);
      }
      if (s.scopeValue.trim() === '') {
        return fail(res, 'scopeValue must not be empty', 400);
      }
    }

    // withRequestDb already opened the transaction. fail() / thrown errors
    // automatically trigger ROLLBACK via finalize(); successful exit
    // triggers COMMIT.
    const client = req.db;
    try {
      // Confirm the target user exists and has role='regulator'.
      const u = await client.query(
        `SELECT id, role FROM staff_users WHERE id = $1`,
        [staffId],
      );
      if (u.rows.length === 0) {
        return fail(res, 'Staff user not found', 404);
      }
      if (u.rows[0].role !== 'regulator') {
        return fail(res, 'Target user is not a regulator', 400);
      }

      await client.query(
        `DELETE FROM regulator_scope WHERE staff_user_id = $1`,
        [staffId],
      );

      for (const s of scopes) {
        await client.query(
          `INSERT INTO regulator_scope (staff_user_id, scope_type, scope_value)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING`,
          [staffId, s.scopeType, s.scopeValue.trim()],
        );
      }

      await client.query(
        `INSERT INTO audit_log
            (action, entity_type, entity_id, performed_by, new_values)
         VALUES ('staff_created', 'regulator_scope', $1, $2, $3)`,
        [staffId, req.staff.id, JSON.stringify({ scopes })],
      );

      // Echo back the canonical view (post-dedup, post-trim). Same client,
      // same tx — sees the rows we just wrote.
      const final = await client.query(
        `SELECT scope_type AS "scopeType",
                scope_value AS "scopeValue",
                created_at AS "createdAt"
           FROM regulator_scope
          WHERE staff_user_id = $1
          ORDER BY scope_type, scope_value`,
        [staffId],
      );
      ok(res, { staffId, scopes: final.rows });
    } catch (err) {
      serverError(res, err);
    }
  });

  return router;
};
