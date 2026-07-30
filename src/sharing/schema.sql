-- Multi-org data sharing with delegated agent credentials.
--
-- The whole security argument rests on four structural facts, each verified in
-- PROBE_FINDINGS.md before this file was written:
--
--   1. Row and column limits are enforced by POSTGRES, from grant tables, via
--      RLS policies on FORCE-RLS base tables (Q1, Q4). Not by application code.
--   2. The application role `portal_app` holds NO privileges on base tables
--      (Q2). It can only SELECT from guarded views and EXECUTE definer
--      functions. A query that escapes the views fails at the database.
--   3. Identity is a SIGNED credential the database verifies for itself inside
--      a SECURITY DEFINER function, using a key `portal_app` cannot read
--      (Q5, Q6). The app cannot assert who it is; it can only present a token.
--   4. Identity is transaction-local (Q7), so it cannot leak to the next user
--      of a pooled connection.
--
-- Everything else in this file is bookkeeping in service of those four.

-- pgcrypto goes in its own schema, not `public`.
--
-- Every definer function below pins `search_path` so a caller cannot shadow an
-- unqualified name with an object of their own — which means `public` is not on
-- the path, and an extension installed there would be invisible (this failed
-- exactly that way the first time: "function hmac(text, bytea, unknown) does not
-- exist" from inside the audit trigger). Re-adding `public` to the path would
-- undo the hardening, so the extension moves instead.
DROP EXTENSION IF EXISTS pgcrypto CASCADE;
CREATE SCHEMA IF NOT EXISTS ext;
CREATE EXTENSION pgcrypto WITH SCHEMA ext;

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------
-- portal_owner owns the data and the policies. portal_app is what the service
-- connects as. The split is the point: it converts "we remembered to filter"
-- into "the database will not serve it".
--
-- These MUST be created before anything is granted to them. An earlier version
-- granted USAGE on `ext` above this block; it worked on every cluster where a
-- previous run had already created the roles, and failed only on a genuinely
-- fresh one with `role "portal_owner" does not exist`. Keep grants after the
-- roles they name.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='portal_owner') THEN
    CREATE ROLE portal_owner NOSUPERUSER NOBYPASSRLS NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='portal_app') THEN
    CREATE ROLE portal_app NOSUPERUSER NOBYPASSRLS LOGIN;
  END IF;
END $$;

-- USAGE on `ext` is required for the definer functions to resolve `hmac` at all;
-- without it the audit trigger fails with "function hmac(...) does not exist"
-- even though the search_path names the schema. EXECUTE on the functions is
-- public by default, and that is fine: hmac is only dangerous with the key, and
-- the key table is what portal_app cannot read.
GRANT USAGE ON SCHEMA ext TO portal_owner, portal_app;

DROP SCHEMA IF EXISTS portal CASCADE;
CREATE SCHEMA portal AUTHORIZATION portal_owner;

-- Keep the search_path off the public schema so an unqualified name in a
-- definer function cannot be shadowed by an object the caller created.
DO $$ BEGIN
  EXECUTE format('ALTER DATABASE %I SET search_path = portal, ext, pg_catalog',
                 current_database());
END $$;

SET ROLE portal_owner;
SET search_path = portal, ext, pg_catalog;

-- ===========================================================================
-- SECRETS — readable only by definer functions, never by portal_app
-- ===========================================================================
CREATE TABLE portal.signing_key (
    kid         text PRIMARY KEY,
    secret      bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE portal.signing_key IS
  'HMAC keys for credentials and the audit chain. portal_app has no grant here '
  '(probe Q6), so it can present tokens but never mint one.';

-- ===========================================================================
-- ORGS, PRINCIPALS
-- ===========================================================================
CREATE TABLE portal.org (
    org_id   text PRIMARY KEY,
    name     text NOT NULL
);

-- A principal is a human OR an agent. Non-human identities are first class,
-- which is the governance problem the project is about: `kind='agent'` carries
-- an owner_principal (the human it belongs to) and cannot hold a grant of its
-- own — it may only ever act under a delegation from a human.
CREATE TABLE portal.principal (
    principal_id     text PRIMARY KEY,
    org_id           text NOT NULL REFERENCES portal.org(org_id),
    kind             text NOT NULL CHECK (kind IN ('human','agent')),
    display_name     text NOT NULL,
    owner_principal  text REFERENCES portal.principal(principal_id),
    disabled_at      timestamptz,
    CONSTRAINT agent_has_owner CHECK (kind <> 'agent' OR owner_principal IS NOT NULL)
);

-- ===========================================================================
-- THE SHARED DATA (org A is the provider in the seeded scenario)
-- ===========================================================================
-- A deliberately realistic shape: rows carry an owning org, a region, a
-- classification, and columns of different sensitivity so that column-level
-- limits are meaningful rather than decorative.
CREATE TABLE portal.shipment (
    shipment_id     bigint PRIMARY KEY,
    owner_org       text NOT NULL REFERENCES portal.org(org_id),
    region          text NOT NULL,
    classification  text NOT NULL CHECK (classification IN ('public','internal','restricted')),
    partner_org     text REFERENCES portal.org(org_id),  -- who this row concerns
    carrier         text NOT NULL,
    status          text NOT NULL,
    units           int  NOT NULL,
    -- commercially sensitive: masked unless the grant says otherwise
    unit_cost_usd   numeric(12,2) NOT NULL,
    margin_pct      numeric(5,2)  NOT NULL,
    -- personal data: masked unless the grant says otherwise
    contact_email   text,
    contact_phone   text,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX shipment_owner_region ON portal.shipment (owner_org, region);

-- ===========================================================================
-- GRANTS — the authorization state RLS reads
-- ===========================================================================
-- A grant is (provider org) -> (grantee principal in another org), scoped to a
-- region predicate and a column set, with an expiry. `approved_by` is the human
-- on the provider side who signed off; a grant with no approval is not live.
CREATE TABLE portal.data_grant (
    grant_id        text PRIMARY KEY,
    provider_org    text NOT NULL REFERENCES portal.org(org_id),
    grantee_org     text NOT NULL REFERENCES portal.org(org_id),
    -- The grant is issued to a HUMAN analyst. Agents reach data only by
    -- delegation from this principal, never by holding a grant themselves.
    grantee_principal text NOT NULL REFERENCES portal.principal(principal_id),
    -- row scope
    region_scope    text[] NOT NULL,
    max_classification text NOT NULL
        CHECK (max_classification IN ('public','internal','restricted')),
    -- column scope: additive capabilities, absent => masked
    allow_cost      boolean NOT NULL DEFAULT false,
    allow_contact   boolean NOT NULL DEFAULT false,
    -- lifecycle
    requested_at    timestamptz NOT NULL DEFAULT now(),
    approved_at     timestamptz,
    approved_by     text REFERENCES portal.principal(principal_id),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    revoked_reason  text,
    CONSTRAINT grantee_is_human CHECK (true)  -- enforced by trigger below
);

CREATE INDEX data_grant_lookup ON portal.data_grant (grantee_principal, provider_org);

-- A grant is only usable while approved, unexpired, unrevoked. Expressed once,
-- here, so no policy can accidentally forget a clause.
CREATE OR REPLACE FUNCTION portal.grant_is_live(g portal.data_grant, at_time timestamptz)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT g.approved_at IS NOT NULL
     AND g.revoked_at IS NULL
     AND g.expires_at > at_time
$$;

-- Structural rule: grants are issued to humans only.
CREATE OR REPLACE FUNCTION portal.grant_grantee_must_be_human() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE k text;
BEGIN
  SELECT kind INTO k FROM portal.principal WHERE principal_id = NEW.grantee_principal;
  IF k <> 'human' THEN
    RAISE EXCEPTION 'grants are issued to humans; % is a %', NEW.grantee_principal, k;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER data_grant_human BEFORE INSERT OR UPDATE ON portal.data_grant
  FOR EACH ROW EXECUTE FUNCTION portal.grant_grantee_must_be_human();

-- ===========================================================================
-- DELEGATION — an agent acting for a human, with a chain and its own expiry
-- ===========================================================================
-- org B's agent acts for org B's analyst under org A's grant. The delegation
-- narrows: it can never widen the grant's row or column scope, and its own
-- expiry is capped by the grant's. Both are enforced by trigger, not by hope.
CREATE TABLE portal.delegation (
    delegation_id   text PRIMARY KEY,
    grant_id        text NOT NULL REFERENCES portal.data_grant(grant_id),
    -- who delegates (must be the grant's grantee, or a valid sub-delegator)
    delegator       text NOT NULL REFERENCES portal.principal(principal_id),
    -- who receives (an agent)
    delegatee       text NOT NULL REFERENCES portal.principal(principal_id),
    -- chain depth: 1 = human -> agent. >1 = agent -> agent (sub-delegation).
    depth           int  NOT NULL CHECK (depth BETWEEN 1 AND 3),
    parent_delegation text REFERENCES portal.delegation(delegation_id),
    -- narrowed scope (subset of the grant's)
    region_scope    text[] NOT NULL,
    allow_cost      boolean NOT NULL DEFAULT false,
    allow_contact   boolean NOT NULL DEFAULT false,
    -- purpose is recorded because a delegated credential without a stated
    -- purpose cannot be audited meaningfully
    purpose         text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    revoked_reason  text
);

CREATE INDEX delegation_lookup ON portal.delegation (delegatee, grant_id);

CREATE OR REPLACE FUNCTION portal.delegation_must_narrow() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE g portal.data_grant; pk text; parent portal.delegation;
BEGIN
  SELECT * INTO g FROM portal.data_grant WHERE grant_id = NEW.grant_id;

  -- the delegatee must be an agent
  SELECT kind INTO pk FROM portal.principal WHERE principal_id = NEW.delegatee;
  IF pk <> 'agent' THEN
    RAISE EXCEPTION 'delegatee % must be an agent, is %', NEW.delegatee, pk;
  END IF;

  IF NEW.depth = 1 THEN
    -- a first-hop delegation may only be created by the grant's own grantee
    IF NEW.delegator <> g.grantee_principal THEN
      RAISE EXCEPTION 'delegator % does not hold grant % (held by %)',
        NEW.delegator, NEW.grant_id, g.grantee_principal;
    END IF;
    IF NEW.parent_delegation IS NOT NULL THEN
      RAISE EXCEPTION 'depth-1 delegation cannot have a parent';
    END IF;
  ELSE
    -- a sub-delegation must chain to a parent held by the delegator, and
    -- narrow relative to THAT parent (not merely to the grant)
    IF NEW.parent_delegation IS NULL THEN
      RAISE EXCEPTION 'depth-% delegation requires a parent', NEW.depth;
    END IF;
    SELECT * INTO parent FROM portal.delegation WHERE delegation_id = NEW.parent_delegation;
    IF parent.delegatee <> NEW.delegator THEN
      RAISE EXCEPTION 'delegator % does not hold parent delegation %',
        NEW.delegator, NEW.parent_delegation;
    END IF;
    IF parent.depth <> NEW.depth - 1 THEN
      RAISE EXCEPTION 'depth must increase by exactly 1 along the chain';
    END IF;
    IF parent.grant_id <> NEW.grant_id THEN
      RAISE EXCEPTION 'sub-delegation must stay under the same grant';
    END IF;
    IF NOT (NEW.region_scope <@ parent.region_scope) THEN
      RAISE EXCEPTION 'sub-delegation regions % exceed parent %',
        NEW.region_scope, parent.region_scope;
    END IF;
    IF (NEW.allow_cost AND NOT parent.allow_cost)
       OR (NEW.allow_contact AND NOT parent.allow_contact) THEN
      RAISE EXCEPTION 'sub-delegation cannot widen column scope beyond parent';
    END IF;
    IF NEW.expires_at > parent.expires_at THEN
      RAISE EXCEPTION 'sub-delegation cannot outlive parent delegation';
    END IF;
  END IF;

  -- narrowing relative to the grant, always
  IF NOT (NEW.region_scope <@ g.region_scope) THEN
    RAISE EXCEPTION 'delegation regions % exceed grant scope %',
      NEW.region_scope, g.region_scope;
  END IF;
  IF (NEW.allow_cost AND NOT g.allow_cost) OR (NEW.allow_contact AND NOT g.allow_contact) THEN
    RAISE EXCEPTION 'delegation cannot widen the column scope of grant %', NEW.grant_id;
  END IF;
  IF NEW.expires_at > g.expires_at THEN
    RAISE EXCEPTION 'delegation cannot outlive grant % (expires %)',
      NEW.grant_id, g.expires_at;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER delegation_narrow BEFORE INSERT OR UPDATE ON portal.delegation
  FOR EACH ROW EXECUTE FUNCTION portal.delegation_must_narrow();

-- ===========================================================================
-- CREDENTIAL VERIFICATION — the database decides who the caller is
-- ===========================================================================
-- A credential is `payload_b64.hmac_hex`. The payload is JSON:
--   {sub, act_as, grant_id, delegation_id, exp, jti, chain:[...]}
-- portal_app cannot read signing_key, so it cannot mint or alter one (Q6).
--
-- verify_credential returns the parsed claims ONLY if the signature is valid
-- and the token is unexpired, and NULL otherwise — never an error, so that a
-- forged token is indistinguishable from an absent one and always denies (Q3).
CREATE OR REPLACE FUNCTION portal.verify_credential(tok text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = portal, ext, pg_catalog AS $$
DECLARE parts text[]; expect text; claims jsonb; key bytea;
BEGIN
  IF tok IS NULL OR tok = '' THEN RETURN NULL; END IF;
  parts := string_to_array(tok, '.');
  IF array_length(parts, 1) <> 2 THEN RETURN NULL; END IF;

  BEGIN
    claims := convert_from(decode(parts[1], 'base64'), 'utf8')::jsonb;
  EXCEPTION WHEN others THEN RETURN NULL;
  END;

  SELECT secret INTO key FROM portal.signing_key
   WHERE kid = coalesce(claims->>'kid', 'default');
  IF key IS NULL THEN RETURN NULL; END IF;

  -- pgcrypto exposes hmac(bytea,bytea,text) and hmac(text,text,text) but NOT
  -- hmac(text,bytea,text); the key is bytea, so the message is converted to
  -- bytea explicitly. This also makes the digest byte-for-byte identical to
  -- Python's hmac.new(key_bytes, payload.encode(), sha256).
  expect := encode(hmac(convert_to(parts[1], 'utf8'), key, 'sha256'), 'hex');
  -- constant-time-ish compare; lengths are fixed so a plain compare is fine here
  IF expect IS DISTINCT FROM parts[2] THEN RETURN NULL; END IF;

  -- expiry is inside the signed payload, so it cannot be extended by the holder
  IF (claims->>'exp') IS NULL
     OR to_timestamp((claims->>'exp')::double precision) <= now() THEN
    RETURN NULL;
  END IF;
  RETURN claims;
END $$;

-- The effective authorization of the current transaction, derived from the
-- verified credential joined against LIVE grant and delegation state.
--
-- This is the single source of truth every policy and every view reads. Its
-- result is the intersection of: the signed credential, the grant, and every
-- delegation hop. Any one of them being dead denies everything.
CREATE OR REPLACE FUNCTION portal.current_auth()
RETURNS TABLE (
    subject          text,
    acting_for       text,
    provider_org     text,
    grantee_org      text,
    grant_id         text,
    delegation_id    text,
    region_scope     text[],
    max_classification text,
    allow_cost       boolean,
    allow_contact    boolean,
    chain_depth      int
)
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = portal, ext, pg_catalog AS $$
DECLARE c jsonb; g portal.data_grant; d portal.delegation;
        eff_regions text[]; eff_cost boolean; eff_contact boolean; hop portal.delegation;
        guard int := 0;
BEGIN
  c := portal.verify_credential(current_setting('portal.credential', true));
  IF c IS NULL THEN RETURN; END IF;                    -- fail closed

  SELECT * INTO g FROM portal.data_grant WHERE data_grant.grant_id = c->>'grant_id';
  IF NOT FOUND OR NOT portal.grant_is_live(g, now()) THEN RETURN; END IF;

  -- The credential's subject must match the identity the grant/delegation says.
  IF c->>'delegation_id' IS NULL THEN
    -- direct human access: the subject must BE the grantee
    IF c->>'sub' IS DISTINCT FROM g.grantee_principal THEN RETURN; END IF;
    IF EXISTS (SELECT 1 FROM portal.principal p
                WHERE p.principal_id = g.grantee_principal AND p.disabled_at IS NOT NULL) THEN
      RETURN;
    END IF;
    RETURN QUERY SELECT g.grantee_principal, g.grantee_principal, g.provider_org,
                        g.grantee_org, g.grant_id, NULL::text, g.region_scope,
                        g.max_classification, g.allow_cost, g.allow_contact, 0;
    RETURN;
  END IF;

  -- delegated access.
  -- Qualified with the table alias because `delegation_id` is also an OUT
  -- parameter of this function, and plpgsql resolves the bare name to the
  -- variable ("column reference is ambiguous").
  SELECT * INTO d FROM portal.delegation dd WHERE dd.delegation_id = c->>'delegation_id';
  IF NOT FOUND OR d.grant_id <> g.grant_id THEN RETURN; END IF;
  IF d.delegatee IS DISTINCT FROM c->>'sub' THEN RETURN; END IF;
  IF d.revoked_at IS NOT NULL OR d.expires_at <= now() THEN RETURN; END IF;

  -- Walk the whole chain to the root. A revoked or expired hop ANYWHERE kills
  -- the credential, and the effective scope is the intersection of every hop.
  -- Without this walk, revoking a mid-chain delegation would leave a deeper one
  -- alive, which is exactly the delegation-chain abuse the attack suite probes.
  eff_regions := d.region_scope; eff_cost := d.allow_cost; eff_contact := d.allow_contact;
  hop := d;
  WHILE hop.parent_delegation IS NOT NULL LOOP
    guard := guard + 1;
    IF guard > 8 THEN RETURN; END IF;                  -- cycle guard, fail closed
    SELECT * INTO hop FROM portal.delegation dd WHERE dd.delegation_id = hop.parent_delegation;
    IF NOT FOUND THEN RETURN; END IF;
    IF hop.revoked_at IS NOT NULL OR hop.expires_at <= now() THEN RETURN; END IF;
    IF hop.grant_id <> g.grant_id THEN RETURN; END IF;
    SELECT array_agg(r) INTO eff_regions
      FROM unnest(eff_regions) r WHERE r = ANY (hop.region_scope);
    eff_cost    := eff_cost    AND hop.allow_cost;
    eff_contact := eff_contact AND hop.allow_contact;
  END LOOP;

  -- the root hop must be delegated by the grant's own grantee
  IF hop.delegator <> g.grantee_principal OR hop.depth <> 1 THEN RETURN; END IF;

  -- a disabled principal anywhere in the chain kills it
  IF EXISTS (SELECT 1 FROM portal.principal p
              WHERE p.principal_id IN (g.grantee_principal, d.delegatee, hop.delegator)
                AND p.disabled_at IS NOT NULL) THEN
    RETURN;
  END IF;

  -- intersect with the grant itself
  SELECT array_agg(r) INTO eff_regions
    FROM unnest(coalesce(eff_regions, '{}')) r WHERE r = ANY (g.region_scope);

  RETURN QUERY SELECT d.delegatee, g.grantee_principal, g.provider_org, g.grantee_org,
                      g.grant_id, d.delegation_id, coalesce(eff_regions, '{}'),
                      g.max_classification,
                      eff_cost AND g.allow_cost, eff_contact AND g.allow_contact,
                      d.depth;
END $$;

-- ===========================================================================
-- ROW LEVEL SECURITY
-- ===========================================================================
ALTER TABLE portal.shipment ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal.shipment FORCE  ROW LEVEL SECURITY;   -- binds the owner too

-- Classification ordering, so `max_classification` is a real ceiling.
CREATE OR REPLACE FUNCTION portal.class_rank(c text) RETURNS int
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE c WHEN 'public' THEN 1 WHEN 'internal' THEN 2 WHEN 'restricted' THEN 3 END
$$;

-- The policy. Everything it needs comes from current_auth(), which already
-- verified the credential and walked the delegation chain.
CREATE POLICY shipment_shared_read ON portal.shipment FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM portal.current_auth() a
     WHERE shipment.owner_org = a.provider_org
       AND shipment.region    = ANY (a.region_scope)
       AND portal.class_rank(shipment.classification) <= portal.class_rank(a.max_classification)
       -- a partner may only see rows that concern them, or unattributed rows
       AND (shipment.partner_org IS NULL OR shipment.partner_org = a.grantee_org)
  )
);

-- ===========================================================================
-- THE GUARDED VIEW — the only relation portal_app may read
-- ===========================================================================
-- Column masking is a CASE in the target list, evaluated by the engine against
-- the same current_auth() the row policy used (probe Q4). security_barrier is
-- defence in depth; probe Q9 showed base-table RLS already prevents the leak.
CREATE VIEW portal.shared_shipment WITH (security_barrier) AS
SELECT s.shipment_id, s.owner_org, s.region, s.classification, s.partner_org,
       s.carrier, s.status, s.units,
       CASE WHEN a.allow_cost    THEN s.unit_cost_usd END AS unit_cost_usd,
       CASE WHEN a.allow_cost    THEN s.margin_pct    END AS margin_pct,
       CASE WHEN a.allow_contact THEN s.contact_email END AS contact_email,
       CASE WHEN a.allow_contact THEN s.contact_phone END AS contact_phone,
       s.updated_at
  FROM portal.shipment s
  CROSS JOIN portal.current_auth() a;

-- ===========================================================================
-- AUDIT — append-only, hash-chained, reconstructable by both orgs
-- ===========================================================================
CREATE TABLE portal.audit_event (
    seq             bigserial PRIMARY KEY,
    at              timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- who
    subject         text,          -- the principal that presented the credential
    acting_for      text,          -- the human it acted for (delegation)
    grant_id        text,
    delegation_id   text,
    chain           jsonb,         -- the full delegation chain as presented
    provider_org    text,
    grantee_org     text,
    -- what
    action          text NOT NULL, -- read | grant.approve | grant.revoke | ...
    resource        text NOT NULL, -- e.g. shipment
    request         jsonb NOT NULL,-- the exact request as received
    -- outcome
    decision        text NOT NULL CHECK (decision IN ('allow','deny')),
    deny_reason     text,
    row_count       int,
    row_ids         bigint[],      -- exactly which rows were served
    columns_served  text[],        -- exactly which columns were unmasked
    columns_masked  text[],
    -- integrity
    prev_hash       text,
    hash            text
);

CREATE INDEX audit_event_grant ON portal.audit_event (grant_id, seq);
CREATE INDEX audit_event_subject ON portal.audit_event (subject, seq);

-- The chain is computed by a definer function using a key portal_app cannot
-- read, so the app can append but cannot forge a consistent history.
CREATE OR REPLACE FUNCTION portal.audit_chain_trigger() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = portal, ext, pg_catalog AS $$
DECLARE prev text; key bytea; payload text;
BEGIN
  SELECT hash INTO prev FROM portal.audit_event
   WHERE seq < NEW.seq ORDER BY seq DESC LIMIT 1;
  NEW.prev_hash := prev;
  SELECT secret INTO key FROM portal.signing_key WHERE kid = 'default';
  payload := concat_ws('|', coalesce(prev,''), NEW.seq::text, NEW.at::text,
      coalesce(NEW.subject,''), coalesce(NEW.acting_for,''), coalesce(NEW.grant_id,''),
      coalesce(NEW.delegation_id,''), NEW.action, NEW.resource,
      NEW.request::text, NEW.decision, coalesce(NEW.deny_reason,''),
      coalesce(NEW.row_count,-1)::text, coalesce(NEW.row_ids::text,''),
      coalesce(NEW.columns_served::text,''), coalesce(NEW.columns_masked::text,''));
  NEW.hash := encode(hmac(convert_to(payload, 'utf8'), key, 'sha256'), 'hex');
  RETURN NEW;
END $$;
CREATE TRIGGER audit_chain BEFORE INSERT ON portal.audit_event
  FOR EACH ROW EXECUTE FUNCTION portal.audit_chain_trigger();

-- Append-only, enforced by the database rather than by convention.
CREATE OR REPLACE FUNCTION portal.audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_event is append-only (attempted % )', TG_OP; END $$;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON portal.audit_event
  FOR EACH ROW EXECUTE FUNCTION portal.audit_immutable();

-- Appending to the audit trail is a definer function, not an INSERT privilege.
--
-- The first version granted `INSERT ON audit_event` to portal_app, which fails
-- anyway the moment you want `RETURNING seq` (that needs SELECT too). Routing
-- appends through a function is strictly better: portal_app ends up with
-- **zero privileges on every base table**, so the claim is absolute rather than
-- "no privileges except one", and the entry point can refuse to be lied to.
--
-- `subject`/`acting_for` etc. are still supplied by the caller, because only the
-- caller knows the request it served. What the caller CANNOT do is set `at`,
-- `seq`, `prev_hash` or `hash`: those come from the database and the chain key.
CREATE OR REPLACE FUNCTION portal.audit_append(
    p_subject text, p_acting_for text, p_grant_id text, p_delegation_id text,
    p_chain jsonb, p_provider_org text, p_grantee_org text, p_action text,
    p_resource text, p_request jsonb, p_decision text, p_deny_reason text,
    p_row_count int, p_row_ids bigint[], p_columns_served text[],
    p_columns_masked text[])
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path = portal, ext, pg_catalog AS $$
DECLARE s bigint;
BEGIN
  INSERT INTO portal.audit_event
    (subject, acting_for, grant_id, delegation_id, chain, provider_org, grantee_org,
     action, resource, request, decision, deny_reason, row_count, row_ids,
     columns_served, columns_masked)
  VALUES (p_subject, p_acting_for, p_grant_id, p_delegation_id, p_chain,
          p_provider_org, p_grantee_org, p_action, p_resource, p_request,
          p_decision, p_deny_reason, p_row_count, p_row_ids, p_columns_served,
          p_columns_masked)
  RETURNING seq INTO s;
  RETURN s;
END $$;

-- Verify the chain. Returns the first divergent seq, or NULL if intact.
CREATE OR REPLACE FUNCTION portal.audit_verify()
RETURNS TABLE (checked bigint, first_bad_seq bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = portal, ext, pg_catalog AS $$
DECLARE r record; key bytea; prev text := NULL; expect text; n bigint := 0; bad bigint := NULL;
BEGIN
  SELECT secret INTO key FROM portal.signing_key WHERE kid='default';
  FOR r IN SELECT * FROM portal.audit_event ORDER BY seq LOOP
    n := n + 1;
    expect := encode(hmac(convert_to(concat_ws('|', coalesce(prev,''), r.seq::text, r.at::text,
        coalesce(r.subject,''), coalesce(r.acting_for,''), coalesce(r.grant_id,''),
        coalesce(r.delegation_id,''), r.action, r.resource, r.request::text,
        r.decision, coalesce(r.deny_reason,''), coalesce(r.row_count,-1)::text,
        coalesce(r.row_ids::text,''), coalesce(r.columns_served::text,''),
        coalesce(r.columns_masked::text,'')), 'utf8'), key, 'sha256'), 'hex');
    IF bad IS NULL AND (r.hash IS DISTINCT FROM expect OR r.prev_hash IS DISTINCT FROM prev) THEN
      bad := r.seq;
    END IF;
    prev := r.hash;
  END LOOP;
  RETURN QUERY SELECT n, bad;
END $$;

-- ---------------------------------------------------------------------------
-- Audit views for BOTH sides of the share. The spec asks for granting AND
-- consuming organizations to reconstruct access, and they must see different
-- things: the provider sees who touched its data; the consumer sees what its
-- own people and agents did, without learning about other partners' activity.
--
-- The viewing org is derived from a SIGNED audit credential, never from a bare
-- GUC. A plain `current_setting('portal.viewer_org')` would be settable by
-- portal_app itself — precisely the forgery probe Q5 ruled out — which would let
-- either org read the other's trail by asserting a different name.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION portal.viewer_org() RETURNS text
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = portal, ext, pg_catalog AS $$
DECLARE c jsonb; o text;
BEGIN
  c := portal.verify_credential(current_setting('portal.audit_credential', true));
  IF c IS NULL THEN RETURN NULL; END IF;               -- fail closed
  o := c->>'audit_org';
  IF o IS NULL THEN RETURN NULL; END IF;
  -- the credential's subject must be a live human in the org it claims
  IF NOT EXISTS (SELECT 1 FROM portal.principal p
                  WHERE p.principal_id = c->>'sub' AND p.org_id = o
                    AND p.kind = 'human' AND p.disabled_at IS NULL) THEN
    RETURN NULL;
  END IF;
  RETURN o;
END $$;

CREATE VIEW portal.audit_provider_view WITH (security_barrier) AS
SELECT seq, at, subject, acting_for, grant_id, delegation_id, chain,
       grantee_org AS counterparty_org, action, resource, request, decision,
       deny_reason, row_count, row_ids, columns_served, columns_masked
  FROM portal.audit_event
 WHERE provider_org = portal.viewer_org();

CREATE VIEW portal.audit_consumer_view WITH (security_barrier) AS
SELECT seq, at, subject, acting_for, grant_id, delegation_id, chain,
       provider_org AS counterparty_org, action, resource, request, decision,
       deny_reason, row_count, row_ids, columns_served, columns_masked
  FROM portal.audit_event
 WHERE grantee_org = portal.viewer_org();

-- ===========================================================================
-- WRITE PATH for governance state — definer functions, fully audited
-- ===========================================================================
-- portal_app cannot INSERT into data_grant/delegation directly. It calls these,
-- which validate and audit. Approval and revocation are the two operations a
-- provider org performs, so they are the two that must be attributable.
CREATE OR REPLACE FUNCTION portal.approve_grant(p_grant_id text, p_approver text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = portal, ext, pg_catalog AS $$
DECLARE g portal.data_grant; ak text; ao text;
BEGIN
  SELECT * INTO g FROM portal.data_grant WHERE grant_id = p_grant_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'no such grant %', p_grant_id; END IF;
  SELECT kind, org_id INTO ak, ao FROM portal.principal WHERE principal_id = p_approver;
  -- Only a HUMAN on the PROVIDER side may approve a share of provider data.
  IF ak IS DISTINCT FROM 'human' THEN
    RAISE EXCEPTION 'approver % must be a human (is %)', p_approver, coalesce(ak,'unknown');
  END IF;
  IF ao IS DISTINCT FROM g.provider_org THEN
    RAISE EXCEPTION 'approver % (org %) cannot approve a grant over % data',
      p_approver, ao, g.provider_org;
  END IF;
  UPDATE portal.data_grant SET approved_at = now(), approved_by = p_approver
   WHERE grant_id = p_grant_id;
  INSERT INTO portal.audit_event (subject, grant_id, provider_org, grantee_org,
      action, resource, request, decision, row_count)
  VALUES (p_approver, p_grant_id, g.provider_org, g.grantee_org,
      'grant.approve', 'data_grant',
      jsonb_build_object('grant_id', p_grant_id, 'approver', p_approver), 'allow', 1);
END $$;

CREATE OR REPLACE FUNCTION portal.revoke_grant(p_grant_id text, p_actor text, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = portal, ext, pg_catalog AS $$
DECLARE g portal.data_grant;
BEGIN
  SELECT * INTO g FROM portal.data_grant WHERE grant_id = p_grant_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'no such grant %', p_grant_id; END IF;
  UPDATE portal.data_grant SET revoked_at = now(), revoked_reason = p_reason
   WHERE grant_id = p_grant_id AND revoked_at IS NULL;
  INSERT INTO portal.audit_event (subject, grant_id, provider_org, grantee_org,
      action, resource, request, decision, row_count)
  VALUES (p_actor, p_grant_id, g.provider_org, g.grantee_org,
      'grant.revoke', 'data_grant',
      jsonb_build_object('grant_id', p_grant_id, 'reason', p_reason), 'allow', 1);
END $$;

CREATE OR REPLACE FUNCTION portal.revoke_delegation(p_delegation_id text, p_actor text, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = portal, ext, pg_catalog AS $$
DECLARE d portal.delegation; g portal.data_grant;
BEGIN
  SELECT * INTO d FROM portal.delegation WHERE delegation_id = p_delegation_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'no such delegation %', p_delegation_id; END IF;
  SELECT * INTO g FROM portal.data_grant WHERE grant_id = d.grant_id;
  UPDATE portal.delegation SET revoked_at = now(), revoked_reason = p_reason
   WHERE delegation_id = p_delegation_id AND revoked_at IS NULL;
  INSERT INTO portal.audit_event (subject, acting_for, grant_id, delegation_id,
      provider_org, grantee_org, action, resource, request, decision, row_count)
  VALUES (p_actor, d.delegator, d.grant_id, p_delegation_id, g.provider_org, g.grantee_org,
      'delegation.revoke', 'delegation',
      jsonb_build_object('delegation_id', p_delegation_id, 'reason', p_reason), 'allow', 1);
END $$;

-- ===========================================================================
-- PRIVILEGES — portal_app gets views and functions, never base tables
-- ===========================================================================
RESET ROLE;
SET search_path = portal, ext, pg_catalog;

GRANT USAGE ON SCHEMA portal TO portal_app;

-- Views only.
GRANT SELECT ON portal.shared_shipment      TO portal_app;
GRANT SELECT ON portal.audit_provider_view  TO portal_app;
GRANT SELECT ON portal.audit_consumer_view  TO portal_app;

-- Audit appends go through a definer function, so portal_app needs NO privilege
-- on audit_event itself — not even INSERT. Combined with the views above, this
-- leaves portal_app with zero privileges on every base table in the schema,
-- which `tests/test_privileges.py` asserts directly against the catalog.
GRANT EXECUTE ON FUNCTION portal.audit_append(
  text,text,text,text,jsonb,text,text,text,text,jsonb,text,text,int,bigint[],
  text[],text[]) TO portal_app;
-- SELECT on audit_event is deliberately NOT granted: the app reads audit
-- through the two org-scoped views, so a bug cannot serve one org's trail to
-- the other. audit_verify() is a definer function for integrity checks.

-- Read-only catalog of what the caller may see, for the portal UI/CLI.
GRANT EXECUTE ON FUNCTION portal.current_auth()          TO portal_app;
GRANT EXECUTE ON FUNCTION portal.verify_credential(text) TO portal_app;
GRANT EXECUTE ON FUNCTION portal.audit_verify()          TO portal_app;
GRANT EXECUTE ON FUNCTION portal.approve_grant(text,text)             TO portal_app;
GRANT EXECUTE ON FUNCTION portal.revoke_grant(text,text,text)         TO portal_app;
GRANT EXECUTE ON FUNCTION portal.revoke_delegation(text,text,text)    TO portal_app;
GRANT EXECUTE ON FUNCTION portal.viewer_org()            TO portal_app;
GRANT EXECUTE ON FUNCTION portal.class_rank(text)        TO portal_app;

-- Explicitly ensure no future-privilege surprise: revoke anything ambient.
REVOKE ALL ON portal.shipment       FROM portal_app;
REVOKE ALL ON portal.data_grant     FROM portal_app;
REVOKE ALL ON portal.delegation     FROM portal_app;
REVOKE ALL ON portal.signing_key    FROM portal_app;
REVOKE ALL ON portal.principal      FROM portal_app;
REVOKE ALL ON portal.org            FROM portal_app;
REVOKE ALL ON portal.audit_event    FROM portal_app;
