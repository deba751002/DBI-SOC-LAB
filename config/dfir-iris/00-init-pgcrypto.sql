-- DFIR-IRIS's own schema migrations use gen_random_uuid() as a column
-- default, but never enable the extension that provides it themselves
-- (known upstream bug: github.com/dfir-iris/iris-web issues #388, #413).
-- Postgres 13+ has gen_random_uuid() built into pgcrypto's core, but the
-- function still isn't visible until the extension is created in this
-- specific database. Files here run automatically via Postgres's own
-- /docker-entrypoint-initdb.d/ convention, but ONLY the very first time a
-- fresh (empty) data directory is initialized - if iris-db already has data
-- from an earlier failed attempt, this won't run; wipe that volume first.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
