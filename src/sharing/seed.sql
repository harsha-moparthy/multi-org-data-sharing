-- The seeded two-org scenario.
--
-- northwind (provider) shares a scoped slice of its shipment data with
-- meridian (consumer). Meridian's analyst holds the grant; meridian's agent
-- does the actual reading under a delegation. A third org, `contoso`, exists
-- only so that "another partner's rows" is a real category rather than a
-- hypothetical one — several attacks try to reach it.
-- Seeding runs as the bootstrap superuser, NOT as portal_owner. That is not a
-- shortcut: `shipment` is FORCE ROW LEVEL SECURITY with a SELECT-only policy, so
-- portal_owner itself cannot insert into it (verified — the first seed attempt
-- failed with "new row violates row-level security policy"). There is
-- deliberately no write policy on the shared table: the portal is a read path,
-- and provider-side data loading is an administrative operation outside it.
SET search_path = portal, pg_catalog;

INSERT INTO portal.org (org_id, name) VALUES
  ('northwind', 'Northwind Logistics'),
  ('meridian',  'Meridian Retail Group'),
  ('contoso',   'Contoso Freight');

INSERT INTO portal.principal (principal_id, org_id, kind, display_name, owner_principal) VALUES
  -- provider side
  ('nw-dana',    'northwind', 'human', 'Dana Ruiz (Data Steward)',    NULL),
  ('nw-omar',    'northwind', 'human', 'Omar Silva (Ops Lead)',       NULL),
  -- consumer side
  ('mr-priya',   'meridian',  'human', 'Priya Raman (Analyst)',       NULL),
  ('mr-tomas',   'meridian',  'human', 'Tomas Beck (Analyst)',        NULL),
  -- the non-human identities: agents belonging to specific humans
  ('mr-agent-1', 'meridian',  'agent', 'Meridian Planning Agent',     'mr-priya'),
  ('mr-agent-2', 'meridian',  'agent', 'Meridian Sub-Agent (tools)',  'mr-agent-1'),
  ('mr-agent-x', 'meridian',  'agent', 'Meridian Unauthorized Agent', 'mr-tomas'),
  -- third party
  ('co-lena',    'contoso',   'human', 'Lena Fischer (Analyst)',      NULL),
  ('co-agent-1', 'contoso',   'agent', 'Contoso Routing Agent',       'co-lena');

-- ---------------------------------------------------------------------------
-- The shared data. 24 rows spanning 3 regions x 3 classifications, with rows
-- belonging to meridian, to contoso, and to nobody in particular, so that the
-- correct answer to "what may meridian's agent see" is a specific, non-obvious
-- subset rather than "all" or "none".
-- ---------------------------------------------------------------------------
INSERT INTO portal.shipment
  (shipment_id, owner_org, region, classification, partner_org, carrier, status,
   units, unit_cost_usd, margin_pct, contact_email, contact_phone) VALUES
  -- EU rows concerning meridian (in scope for the seeded grant)
  (1001,'northwind','EU','public',    'meridian','DHL',  'delivered', 120,  4.50, 12.5,'ops1@meridian.example','+49-30-1111'),
  (1002,'northwind','EU','internal',  'meridian','DHL',  'in_transit', 80,  6.25, 18.0,'ops2@meridian.example','+49-30-2222'),
  (1003,'northwind','EU','internal',  'meridian','UPS',  'delayed',    45, 11.00, 22.5,'ops3@meridian.example','+49-30-3333'),
  (1004,'northwind','EU','restricted','meridian','UPS',  'held',       12, 48.00, 41.0,'legal@meridian.example','+49-30-4444'),
  -- EU rows concerning nobody (shared infrastructure rows: also in scope)
  (1005,'northwind','EU','public',     NULL,     'FedEx','delivered', 300,  2.10,  8.0, NULL, NULL),
  (1006,'northwind','EU','internal',   NULL,     'FedEx','in_transit',150,  3.75, 14.0, NULL, NULL),
  -- EU rows concerning CONTOSO (must never be visible to meridian)
  (1007,'northwind','EU','public',    'contoso','DHL',  'delivered',  95,  5.00, 11.0,'ops@contoso.example','+49-30-5555'),
  (1008,'northwind','EU','internal',  'contoso','UPS',  'in_transit', 60,  7.50, 16.5,'ops@contoso.example','+49-30-6666'),
  (1009,'northwind','EU','restricted','contoso','UPS',  'held',        8, 52.00, 44.0,'legal@contoso.example','+49-30-7777'),
  -- UK rows concerning meridian (in scope for the seeded grant)
  (1010,'northwind','UK','public',    'meridian','Royal','delivered', 210,  3.90, 10.0,'uk1@meridian.example','+44-20-1111'),
  (1011,'northwind','UK','internal',  'meridian','Royal','in_transit',175,  5.60, 15.5,'uk2@meridian.example','+44-20-2222'),
  (1012,'northwind','UK','restricted','meridian','DPD',  'held',       20, 39.00, 38.0,'uk3@meridian.example','+44-20-3333'),
  (1013,'northwind','UK','internal',   NULL,     'DPD',  'delayed',    88,  4.20, 13.0, NULL, NULL),
  (1014,'northwind','UK','public',    'contoso','Royal','delivered',  55,  4.80, 12.0,'uk@contoso.example','+44-20-4444'),
  -- APAC rows: OUTSIDE the seeded grant's region scope entirely
  (1015,'northwind','APAC','public',    'meridian','SF', 'delivered', 400,  1.80,  6.5,'apac1@meridian.example','+81-3-1111'),
  (1016,'northwind','APAC','internal',  'meridian','SF', 'in_transit',330,  2.40,  9.0,'apac2@meridian.example','+81-3-2222'),
  (1017,'northwind','APAC','restricted','meridian','SF', 'held',       15, 61.00, 47.0,'apac3@meridian.example','+81-3-3333'),
  (1018,'northwind','APAC','internal',  NULL,     'SF',  'delayed',   140,  2.95, 10.5, NULL, NULL),
  (1019,'northwind','APAC','public',   'contoso','SF',   'delivered', 260,  2.05,  7.5,'apac@contoso.example','+81-3-4444'),
  -- rows owned by MERIDIAN itself (a different provider org: never in scope
  -- for a grant whose provider is northwind, even for meridian's own people)
  (2001,'meridian','EU','internal',  'northwind','DHL', 'in_transit', 70,  8.10, 20.0,'ops@northwind.example','+49-30-8888'),
  (2002,'meridian','UK','public',     NULL,      'Royal','delivered',180,  3.30,  9.5, NULL, NULL),
  -- rows owned by CONTOSO (a third provider)
  (3001,'contoso','EU','internal',   'northwind','UPS', 'delayed',    33,  9.90, 24.0,'ops@northwind.example','+49-30-9999'),
  (3002,'contoso','APAC','public',    NULL,      'SF',  'delivered', 240,  2.20,  8.5, NULL, NULL),
  (3003,'contoso','UK','restricted', 'meridian','DPD',  'held',       10, 55.00, 45.0,'legal@meridian.example','+44-20-5555');

-- ---------------------------------------------------------------------------
-- The seeded grant: northwind -> meridian's analyst Priya.
--   rows:    regions EU + UK, up to 'internal' (so RESTRICTED rows are out),
--            and only rows concerning meridian or nobody.
--   columns: cost allowed, contact NOT allowed.
-- Expected visible set is therefore: 1001,1002,1003,1005,1006,1010,1011,1013
-- with unit_cost_usd/margin_pct present and contact_email/phone masked.
-- `expected.py` derives this independently from the fixture, so the test does
-- not take the system's word for its own answer.
-- ---------------------------------------------------------------------------
INSERT INTO portal.data_grant
  (grant_id, provider_org, grantee_org, grantee_principal, region_scope,
   max_classification, allow_cost, allow_contact, expires_at) VALUES
  ('g-main', 'northwind', 'meridian', 'mr-priya', ARRAY['EU','UK'],
   'internal', true, false, now() + interval '30 days');
SELECT portal.approve_grant('g-main', 'nw-dana');

-- A second grant used by expiry/revocation scenarios, deliberately short-lived.
INSERT INTO portal.data_grant
  (grant_id, provider_org, grantee_org, grantee_principal, region_scope,
   max_classification, allow_cost, allow_contact, expires_at) VALUES
  ('g-short', 'northwind', 'meridian', 'mr-tomas', ARRAY['EU'],
   'public', false, false, now() + interval '2 seconds');
SELECT portal.approve_grant('g-short', 'nw-dana');

-- A grant that was requested but NEVER approved: reads under it must deny.
INSERT INTO portal.data_grant
  (grant_id, provider_org, grantee_org, grantee_principal, region_scope,
   max_classification, allow_cost, allow_contact, expires_at) VALUES
  ('g-unapproved', 'northwind', 'meridian', 'mr-priya', ARRAY['EU','UK','APAC'],
   'restricted', true, true, now() + interval '30 days');

-- A grant to the OTHER partner, so cross-partner confusion is testable.
INSERT INTO portal.data_grant
  (grant_id, provider_org, grantee_org, grantee_principal, region_scope,
   max_classification, allow_cost, allow_contact, expires_at) VALUES
  ('g-contoso', 'northwind', 'contoso', 'co-lena', ARRAY['EU','UK','APAC'],
   'restricted', true, true, now() + interval '30 days');
SELECT portal.approve_grant('g-contoso', 'nw-dana');

-- ---------------------------------------------------------------------------
-- Delegations. The headline one: Priya delegates to her planning agent, but
-- narrows it — EU only, and no cost columns. So the agent legitimately sees
-- LESS than the human who delegated to it, which is the property that makes
-- delegated credentials worth having.
-- Expected visible set for mr-agent-1: 1001,1002,1003,1005,1006
-- with cost AND contact both masked.
-- ---------------------------------------------------------------------------
INSERT INTO portal.delegation
  (delegation_id, grant_id, delegator, delegatee, depth, parent_delegation,
   region_scope, allow_cost, allow_contact, purpose, expires_at) VALUES
  ('d-agent1', 'g-main', 'mr-priya', 'mr-agent-1', 1, NULL,
   ARRAY['EU'], false, false, 'weekly EU replenishment planning',
   now() + interval '7 days');

-- A depth-2 sub-delegation: the planning agent hands a narrower credential to
-- a tool agent. Same regions, still no cost, shorter life.
INSERT INTO portal.delegation
  (delegation_id, grant_id, delegator, delegatee, depth, parent_delegation,
   region_scope, allow_cost, allow_contact, purpose, expires_at) VALUES
  ('d-agent2', 'g-main', 'mr-agent-1', 'mr-agent-2', 2, 'd-agent1',
   ARRAY['EU'], false, false, 'carrier lookup subtask',
   now() + interval '1 day');


