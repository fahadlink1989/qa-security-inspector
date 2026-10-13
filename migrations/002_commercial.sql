CREATE TABLE IF NOT EXISTS inspector_scan_history (
 workspace_id uuid NOT NULL REFERENCES inspector_workspaces(id),
 kind text NOT NULL CHECK(kind IN ('web','auth','code','network','performance')),
 id text NOT NULL, project_id text NOT NULL, asset_id text,
 recorded_at timestamptz NOT NULL, data jsonb NOT NULL,
 PRIMARY KEY(workspace_id,kind,id)
);
CREATE INDEX IF NOT EXISTS inspector_history_page ON inspector_scan_history(workspace_id,recorded_at DESC,kind,id);
CREATE INDEX IF NOT EXISTS inspector_history_target ON inspector_scan_history(workspace_id,asset_id,recorded_at DESC);
CREATE INDEX IF NOT EXISTS inspector_history_project ON inspector_scan_history(workspace_id,project_id,recorded_at DESC);
CREATE TABLE IF NOT EXISTS inspector_email_outbox (
 id uuid PRIMARY KEY, workspace_id uuid REFERENCES inspector_workspaces(id),
 purpose text NOT NULL, payload text, status text NOT NULL DEFAULT 'queued',
 attempts integer NOT NULL DEFAULT 0, available_at timestamptz NOT NULL DEFAULT now(),
 lease_token uuid, lease_until timestamptz, provider_id text UNIQUE,
 created_at timestamptz NOT NULL DEFAULT now(), accepted_at timestamptz,
 delivered_at timestamptz, last_error text,
 CHECK(status IN ('queued','sending','accepted','delivered','bounced','failed'))
);
CREATE INDEX IF NOT EXISTS inspector_email_claim ON inspector_email_outbox(status,available_at,lease_until);
CREATE INDEX IF NOT EXISTS inspector_email_workspace ON inspector_email_outbox(workspace_id,created_at DESC);
CREATE TABLE IF NOT EXISTS inspector_email_events (
 id text PRIMARY KEY, provider_id text NOT NULL, kind text NOT NULL,
 occurred_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS inspector_email_provider_events ON inspector_email_events(provider_id,occurred_at DESC);
CREATE TABLE IF NOT EXISTS inspector_password_resets (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES inspector_users(id),
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS inspector_password_reset_user ON inspector_password_resets(user_id);
CREATE TABLE IF NOT EXISTS inspector_billing (
 workspace_id uuid PRIMARY KEY REFERENCES inspector_workspaces(id),
 customer_id text UNIQUE, subscription_id text UNIQUE, status text NOT NULL DEFAULT 'unsubscribed',
 price_id text, period_end timestamptz, cancel_at_period_end boolean NOT NULL DEFAULT false,
 checkout_id text, checkout_url text, checkout_expires_at timestamptz,
 verified_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS inspector_billing_events (
 id text PRIMARY KEY, workspace_id uuid REFERENCES inspector_workspaces(id),
 kind text NOT NULL, received_at timestamptz NOT NULL DEFAULT now()
);
-- Backfill the legacy JSON arrays atomically before compacting workspace metadata.
INSERT INTO inspector_scan_history(workspace_id,kind,id,project_id,asset_id,recorded_at,data)
SELECT w.id,'web',s->>'id',s->>'projectId',s->>'assetId',
 coalesce(s->>'completedAt',s->>'scannedAt',s->>'startedAt',w.created_at::text)::timestamptz,s
FROM inspector_workspaces w CROSS JOIN LATERAL jsonb_array_elements(coalesce(w.state->'scans','[]')) s
ON CONFLICT DO NOTHING;
INSERT INTO inspector_scan_history(workspace_id,kind,id,project_id,asset_id,recorded_at,data)
SELECT w.id,f.kind,s->>'id',p->>'id',coalesce(s->>'assetId',s->>'networkTargetId'),
 coalesce(s->>'completedAt',s->>'scannedAt',s->>'startedAt',w.created_at::text)::timestamptz,
 s||jsonb_build_object('projectId',p->>'id')
FROM inspector_workspaces w CROSS JOIN LATERAL jsonb_array_elements(coalesce(w.state->'projects','[]')) p
CROSS JOIN (VALUES('auth','authScans'),('code','codeScans'),('network','networkScans'),('performance','performanceScans')) f(kind,field)
CROSS JOIN LATERAL jsonb_array_elements(coalesce(p->f.field,'[]')) s
ON CONFLICT DO NOTHING;
UPDATE inspector_workspaces w SET state=jsonb_set(jsonb_set(w.state,'{scans}','[]'),'{projects}',
 coalesce((SELECT jsonb_agg(p-'authScans'-'codeScans'-'networkScans'-'performanceScans')
 FROM jsonb_array_elements(coalesce(w.state->'projects','[]')) p),'[]'))
WHERE jsonb_array_length(coalesce(state->'scans','[]'))>0 OR EXISTS(
 SELECT 1 FROM jsonb_array_elements(coalesce(w.state->'projects','[]')) p
 WHERE p ?| ARRAY['authScans','codeScans','networkScans','performanceScans']);
