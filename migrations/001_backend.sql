CREATE TABLE IF NOT EXISTS inspector_workspaces (
 id uuid PRIMARY KEY, name text NOT NULL, state jsonb NOT NULL,
 revision bigint NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS inspector_users (
 id uuid PRIMARY KEY, email text UNIQUE NOT NULL, password_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS inspector_memberships (
 workspace_id uuid NOT NULL REFERENCES inspector_workspaces(id),
 user_id uuid NOT NULL REFERENCES inspector_users(id),
 role text NOT NULL CHECK (role IN ('owner','member','viewer')),
 PRIMARY KEY (workspace_id,user_id)
);
CREATE TABLE IF NOT EXISTS inspector_sessions (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES inspector_users(id),
 workspace_id uuid NOT NULL REFERENCES inspector_workspaces(id),
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS inspector_sessions_expiry ON inspector_sessions(expires_at);
CREATE TABLE IF NOT EXISTS inspector_jobs (
 id text PRIMARY KEY, workspace_id uuid NOT NULL REFERENCES inspector_workspaces(id),
 data jsonb NOT NULL, payload text, status text NOT NULL DEFAULT 'queued',
 attempts integer NOT NULL DEFAULT 0, max_attempts integer NOT NULL DEFAULT 3,
 available_at timestamptz NOT NULL DEFAULT now(), lease_until timestamptz,
 lease_token uuid, created_at timestamptz NOT NULL DEFAULT now(),
 dedupe_key text, UNIQUE(workspace_id,dedupe_key),
 CHECK (status IN ('queued','running','completed','completed_with_gaps','failed'))
);
CREATE INDEX IF NOT EXISTS inspector_jobs_claim ON inspector_jobs(status,available_at,lease_until);
CREATE INDEX IF NOT EXISTS inspector_jobs_workspace ON inspector_jobs(workspace_id,created_at DESC);
CREATE TABLE IF NOT EXISTS inspector_rate_limits (
 key text PRIMARY KEY, count integer NOT NULL DEFAULT 1, expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS inspector_worker_heartbeats (
 id text PRIMARY KEY, last_seen timestamptz NOT NULL DEFAULT now()
);


CREATE TABLE IF NOT EXISTS inspector_recovery_codes (
 user_id uuid PRIMARY KEY REFERENCES inspector_users(id), token_hash text UNIQUE NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS inspector_invitations (
 id uuid PRIMARY KEY, workspace_id uuid NOT NULL REFERENCES inspector_workspaces(id),
 email text NOT NULL, role text NOT NULL CHECK(role IN ('member','viewer')),
 token_hash text UNIQUE NOT NULL, created_by uuid NOT NULL REFERENCES inspector_users(id),
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 accepted_at timestamptz, revoked_at timestamptz
);
CREATE TABLE IF NOT EXISTS inspector_account_events (
 id bigserial PRIMARY KEY, workspace_id uuid REFERENCES inspector_workspaces(id),
 actor_id uuid REFERENCES inspector_users(id), action text NOT NULL, detail jsonb NOT NULL DEFAULT '{}',
 created_at timestamptz NOT NULL DEFAULT now()
);
