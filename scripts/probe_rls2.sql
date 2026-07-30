-- Probe part 2: the questions that decide whether identity can be forged by the
-- application role, and where the side channels actually are.
-- Assumes probe_rls.sql has run (schema probe, roles probe_owner/probe_app).
\pset pager off
\set ON_ERROR_STOP off

SET ROLE probe_owner;

-- A token is a signed claim. The DB verifies it with a key the app cannot read,
-- so the app role holds bearer tokens but cannot mint one.
CREATE OR REPLACE FUNCTION probe.verify(tok text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER STABLE AS $$
DECLARE parts text[]; expect text;
BEGIN
  IF tok IS NULL THEN RETURN NULL; END IF;
  parts := string_to_array(tok, '.');
  IF array_length(parts,1) <> 2 THEN RETURN NULL; END IF;
  SELECT encode(hmac(parts[1], k, 'sha256'),'hex') INTO expect FROM probe.keys_t;
  IF parts[2] IS DISTINCT FROM expect THEN RETURN NULL; END IF;   -- fail closed
  RETURN parts[1];
END $$;

-- Policy keyed on the VERIFIED subject, not on an app-assertable string.
DROP POLICY IF EXISTS p_rows ON probe.rows_t;
CREATE POLICY p_rows ON probe.rows_t FOR SELECT USING (
  org = (SELECT g.org FROM probe.grants_t g
          WHERE g.subject = probe.verify(current_setting('probe.token', true)))
);

CREATE OR REPLACE VIEW probe.shared_v WITH (security_barrier) AS
SELECT id, org,
       CASE WHEN (SELECT g.may_see_revenue FROM probe.grants_t g
                   WHERE g.subject = probe.verify(current_setting('probe.token', true)))
            THEN revenue END AS revenue
FROM probe.rows_t;
GRANT SELECT ON probe.shared_v TO probe_app;
GRANT EXECUTE ON FUNCTION probe.verify(text) TO probe_app;

-- Mint tokens as the owner (the app cannot do this).
SELECT 'agent-x.' || encode(hmac('agent-x', k, 'sha256'),'hex') AS tok_x,
       'agent-y.' || encode(hmac('agent-y', k, 'sha256'),'hex') AS tok_y
FROM probe.keys_t \gset

RESET ROLE;
SET ROLE probe_app;

\echo ''
\echo '=== Q3: no identity at all must DENY (fail closed), not error or leak'
BEGIN;
SELECT 'Q3 no token' AS q, count(*) AS got, 0 AS want FROM probe.shared_v;
COMMIT;

\echo ''
\echo '=== Q4: column masking is evaluated by the engine, per grant'
BEGIN;
SELECT set_config('probe.token', :'tok_x', true);
SELECT 'Q4 agent-x (no revenue grant)' AS q, id, revenue FROM probe.shared_v ORDER BY id;
COMMIT;
BEGIN;
SELECT set_config('probe.token', :'tok_y', true);
SELECT 'Q4 agent-y (revenue granted)' AS q, id, revenue FROM probe.shared_v ORDER BY id;
COMMIT;

\echo ''
\echo '=== Q5: THE CRUX — can the app role forge an identity by asserting it?'
BEGIN;
SELECT set_config('probe.subject','agent-y',true);          -- old-style forge
SELECT set_config('probe.token','agent-y.deadbeef',true);   -- bad signature
SELECT 'Q5 forged sig' AS q, count(*) AS got, 0 AS want FROM probe.shared_v;
COMMIT;
BEGIN;
SELECT set_config('probe.token','agent-y',true);            -- no signature part
SELECT 'Q5 unsigned' AS q, count(*) AS got, 0 AS want FROM probe.shared_v;
COMMIT;

\echo ''
\echo '=== Q6: can the app role mint a token (read the key / call hmac on it)?'
BEGIN;
\echo '-- expect: permission denied for table keys_t'
SELECT encode(hmac('agent-y', k, 'sha256'),'hex') FROM probe.keys_t;
COMMIT;

\echo ''
\echo '=== Q7: does a transaction-local token leak to the next transaction?'
BEGIN;
SELECT set_config('probe.token', :'tok_y', true);
SELECT count(*) FROM probe.shared_v;
COMMIT;
SELECT 'Q7 after commit' AS q, coalesce(current_setting('probe.token',true),'<null>') AS leaked,
       (SELECT count(*) FROM probe.shared_v) AS rows_now, 0 AS want_rows;

\echo ''
\echo '=== Q8: side channel — can the app read planner stats for a denied table?'
BEGIN;
SELECT set_config('probe.token', :'tok_x', true);
SELECT 'Q8 pg_stats rows' AS q, count(*) AS got, 0 AS want
  FROM pg_stats WHERE schemaname='probe' AND tablename='rows_t';
SELECT 'Q8 reltuples' AS q, reltuples AS got FROM pg_class
  WHERE oid='probe.rows_t'::regclass;
COMMIT;

\echo ''
\echo '=== Q9: side channel — does a leaky function see denied rows without a barrier?'
RESET ROLE; SET ROLE probe_owner;
CREATE OR REPLACE FUNCTION probe.leak(t text) RETURNS bool
LANGUAGE plpgsql COST 0.0000001 AS $$ BEGIN
  RAISE NOTICE 'LEAKED SECRET: %', t; RETURN true; END $$;
CREATE OR REPLACE VIEW probe.nobarrier_v AS SELECT id, org, secret FROM probe.rows_t;
CREATE OR REPLACE VIEW probe.barrier_v WITH (security_barrier) AS
  SELECT id, org, secret FROM probe.rows_t;
GRANT SELECT ON probe.nobarrier_v, probe.barrier_v TO probe_app;
GRANT EXECUTE ON FUNCTION probe.leak(text) TO probe_app;
RESET ROLE; SET ROLE probe_app;
BEGIN;
SELECT set_config('probe.token', :'tok_x', true);
\echo '-- RLS is on the base table, so b-one must NOT be leaked by either view'
SELECT count(*) FROM probe.nobarrier_v WHERE probe.leak(secret);
SELECT count(*) FROM probe.barrier_v   WHERE probe.leak(secret);
COMMIT;
RESET ROLE;
