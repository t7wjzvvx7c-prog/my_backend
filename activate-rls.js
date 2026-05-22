#!/usr/bin/env node
// ============================================================
// RLS activation: rotate the nexbus_app role password and print
// the APP_DATABASE_URL the app needs. Idempotent.
// ============================================================
//
// Run AFTER migrations 010+ have been applied (those create the
// nexbus_app role and the policy set). Per migration 010's activation
// checklist, this script handles step 1 (password rotation) and step 2
// (printing the new connection string). Steps 3–5 (set the env var on
// your hosting platform, restart the backend, smoke-test) are manual
// because they depend on where you host.
//
// Usage:
//   DATABASE_URL=postgres://owner:pw@host/db node activate-rls.js
//
// On success, copy the printed APP_DATABASE_URL into your hosting
// platform's env config and restart the backend. The runtime pool will
// pick it up via the precedence rule in server.js (APP_DATABASE_URL
// wins over DATABASE_URL when set).
// ============================================================

const { Pool } = require('pg');
const crypto = require('crypto');
const readline = require('readline');

async function main() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    console.error('FATAL: DATABASE_URL must be set (the migration-owner connection string).');
    process.exit(1);
  }

  // Confirm — rotating the password without updating APP_DATABASE_URL
  // on the hosting platform will lock the running backend out of the DB.
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolve) => {
    rl.question(
      '\nThis will rotate the nexbus_app role password.\n' +
      'After this, you MUST update APP_DATABASE_URL on your hosting platform\n' +
      'and restart the backend, or the app will lose database access.\n\n' +
      'Continue? (y/N) ',
      resolve
    );
  });
  rl.close();
  if (answer.trim().toLowerCase() !== 'y') {
    console.log('Aborted.');
    process.exit(1);
  }

  const pool = new Pool({
    connectionString: dbUrl,
    ssl: { rejectUnauthorized: false },
  });

  try {
    // 1. Verify the role exists.
    const roleCheck = await pool.query(
      `SELECT 1 FROM pg_roles WHERE rolname = 'nexbus_app'`
    );
    if (roleCheck.rows.length === 0) {
      console.error('FATAL: nexbus_app role does not exist. Run `node migrate-up.js` to apply migration 010 first.');
      process.exit(1);
    }

    // 2. Generate a 32-char URL-safe password.
    // base64 minus +/= leaves [A-Za-z0-9], which is safe to inline in a
    // PostgreSQL string literal AND safe in a URL without encoding.
    const password = crypto.randomBytes(48).toString('base64')
      .replace(/[+/=]/g, '')
      .slice(0, 32);
    if (!/^[A-Za-z0-9]{32}$/.test(password)) {
      throw new Error('Generated password failed sanity check');
    }

    // 3. Rotate. Parameterized queries don't work for DDL, so we inline
    //    the literal — the regex above guarantees no escaping is needed.
    await pool.query(`ALTER ROLE nexbus_app PASSWORD '${password}'`);

    // 4. Build the APP_DATABASE_URL by substituting role + password.
    const u = new URL(dbUrl);
    u.username = 'nexbus_app';
    u.password = password;
    const appUrl = u.toString();

    const bar = '='.repeat(64);
    console.log('');
    console.log(bar);
    console.log('  RLS role password rotated.');
    console.log(bar);
    console.log('');
    console.log('  Set this on your hosting platform and restart the backend:');
    console.log('');
    console.log(`  APP_DATABASE_URL=${appUrl}`);
    console.log('');
    console.log('  Then smoke-test each flavor:');
    console.log('    • Passenger app — search routes, view departures, create a booking');
    console.log('    • Agency app    — log in, sell seats, confirm a booking,');
    console.log('                      try to read another agency\'s data (must be empty)');
    console.log('    • Regulator app — load dashboard, generate a report');
    console.log('');
    console.log('  Once stable, optionally harden by running:');
    console.log('    ALTER TABLE agencies, staff_users, routes, departures,');
    console.log('                 bookings, commission_ledger, audit_log,');
    console.log('                 refresh_tokens FORCE ROW LEVEL SECURITY;');
    console.log('  (See migration 010 footer for the full list.)');
    console.log(bar);
    console.log('');
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
