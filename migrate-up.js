const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

// Non-destructive migration runner. Applies every *.sql file in
// backend/migrations in lexical order (001_, 002_, ...). Each migration
// is expected to be idempotent — this runner does not yet maintain a
// schema_migrations table, so re-running a migration must be a no-op.
//
// Distinct from migrate.js, which re-applies the full schema_acid.sql
// (including DROP TABLE statements) and is destructive.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function run() {
  const dir = path.join(__dirname, 'migrations');
  if (!fs.existsSync(dir)) {
    console.log('No migrations directory; nothing to do.');
    await pool.end();
    return;
  }

  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  if (files.length === 0) {
    console.log('No migration files found.');
    await pool.end();
    return;
  }

  for (const file of files) {
    const sql = fs.readFileSync(path.join(dir, file), 'utf8');
    process.stdout.write(`Applying ${file}... `);
    try {
      await pool.query(sql);
      console.log('ok');
    } catch (err) {
      console.error(`failed: ${err.message}`);
      await pool.end();
      process.exit(1);
    }
  }

  await pool.end();
  console.log(`Applied ${files.length} migration(s).`);
}

run();
