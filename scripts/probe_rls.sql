-- Probe: does the intended enforcement architecture actually hold in Postgres 16?
-- Every assertion here decides a design choice, so it is checked before any real
-- code is written. Run with: scripts/pg_local.sh psql -v ON_ERROR_STOP=1 -f scripts/probe_rls.sql
\set ON_ERROR_STOP on
\timing off
\pset pager off

DROP SCHEMA IF EXISTS probe CASCADE;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='probe_owner') THEN
    EXECUTE 'DROP OWNED BY probe_owner CASCADE'; EXECUTE 'DROP ROLE probe_owner';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='probe_app') THEN
    EXECUTE 'DROP OWNED BY probe_app CASCADE'; EXECUTE 'DROP ROLE probe_app';
  END IF;
END $$;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE ROLE probe_owner NOSUPERUSER NOBYPASSRLS;
CREATE ROLE probe_app   NOSUPERUSER NOBYPASSRLS LOGIN;
CREATE SCHEMA probe AUTHORIZATION probe_owner;

SET ROLE probe_owner;

CREATE TABLE probe.rows_t (id int primary key, org text, secret text, revenue numeric);
INSERT INTO probe.rows_t VALUES
  (1,'a','a-one',  100),
  (2,'a','a-two',  200),
  (3,'b','b-one', 3000);

-- The key table: what each caller may see. A policy reads this.
CREATE TABLE probe.grants_t (subject text, org text, may_see_revenue bool);
INSERT INTO probe.grants_t VALUES ('agent-x','a',false), ('agent-y','a',true);

-- Secret the app role must never read (stands in for the audit chain key).
CREATE TABLE probe.keys_t (k text);
INSERT INTO probe.keys_t VALUES ('super-secret-chain-key');

ALTER TABLE probe.rows_t ENABLE ROW LEVEL SECURITY;
ALTER TABLE probe.rows_t FORCE  ROW LEVEL SECURITY;   -- so the OWNER is bound too

-- Identity comes from a GUC. `true` => missing GUC yields NULL, not an error,
-- and NULL must deny (fail closed), which Q3 checks.
CREATE POLICY p_rows ON probe.rows_t FOR SELECT USING (
  org = (SELECT g.org FROM probe.grants_t g
          WHERE g.subject = current_setting('probe.subject', true))
);

-- Column masking lives in the view's target list, evaluated in the engine.
CREATE VIEW probe.shared_v WITH (security_barrier) AS
SELECT id, org,
       CASE WHEN (SELECT g.may_see_revenue FROM probe.grants_t g
                   WHERE g.subject = current_setting('probe.subject', true))
            THEN revenue END AS revenue
FROM probe.rows_t;

-- A definer function that reads a table the app role cannot.
CREATE FUNCTION probe.chain(txt text) RETURNS text
LANGUAGE sql SECURITY DEFINER STABLE AS
$$ SELECT encode(hmac($1, (SELECT k FROM probe.keys_t), 'sha256'), 'hex') $$;

-- A definer function that ESTABLISHES identity, so the app cannot simply assert
-- one. Verifies an HMAC over the claim with a key the app role cannot read.
CREATE FUNCTION probe.assume(claim text, sig text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE expect text;
BEGIN
  SELECT encode(hmac(claim, k, 'sha256'), 'hex') INTO expect FROM probe.keys_t;
  IF sig IS DISTINCT FROM expect THEN
    RAISE EXCEPTION 'bad signature';
  END IF;
  -- transaction-local (third arg true) so it cannot leak to the next pool user
  PERFORM set_config('probe.subject', claim, true);
  RETURN claim;
END $$;

GRANT USAGE ON SCHEMA probe TO probe_app;
GRANT SELECT ON probe.shared_v TO probe_app;
GRANT EXECUTE ON FUNCTION probe.chain(text), probe.assume(text,text) TO probe_app;
-- deliberately NO grant on probe.rows_t / grants_t / keys_t

RESET ROLE;

\echo '=== Q1: view over FORCE-RLS table applies the policy to a third-party role'
SET ROLE probe_app;
BEGIN;
SELECT set_config('probe.subject','agent-x',true);
SELECT 'Q1 rows visible to agent-x' AS q, string_agg(id::text,',' ORDER BY id) AS got,
       '1,2 (org a only)' AS want FROM probe.shared_v;
COMMIT;
RESET ROLE;

\echo '=== Q2: app role has no path to the base table'
SET ROLE probe_app;
BEGIN;
SELECT set_config('probe.subject','agent-x',true);
\echo '-- expect: permission denied for table rows_t'
SAVEPOINT s; SELECT count(*) FROM probe.rows_t; ROLLBACK TO s;
\echo '-- expect: permission denied for table grants_t'
SELECT count(*) FROM probe.grants_t;
COMMIT;
RESET ROLE;
