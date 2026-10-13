CREATE OR REPLACE FUNCTION inspector_scan_scope(kind text, data jsonb) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
 SELECT jsonb_build_array(kind,data->>'projectId',coalesce(data->>'assetId',data->>'networkTargetId',data->>'repositoryUrl',data->'repository'->>'url',data->>'url',data->>'repository','unknown'),CASE WHEN kind='auth' THEN data->'auth'->>'method' ELSE '' END)::text
$$;
ALTER TABLE inspector_scan_history ADD COLUMN IF NOT EXISTS scope_key text GENERATED ALWAYS AS (inspector_scan_scope(kind,data)) STORED;
CREATE INDEX IF NOT EXISTS inspector_history_scope ON inspector_scan_history(workspace_id,kind,scope_key,recorded_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS inspector_latest_scans (
 workspace_id uuid NOT NULL,kind text NOT NULL,scope_key text NOT NULL,profile text NOT NULL,
 scan_id text NOT NULL,recorded_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,kind,scope_key,profile),
 FOREIGN KEY(workspace_id,kind,scan_id) REFERENCES inspector_scan_history(workspace_id,kind,id)
);
CREATE TABLE IF NOT EXISTS inspector_current_risks (
 workspace_id uuid NOT NULL,kind text NOT NULL,scope_key text NOT NULL,fingerprint text NOT NULL,
 scan_id text NOT NULL,observed_at timestamptz NOT NULL,first_seen timestamptz NOT NULL,data jsonb NOT NULL,
 PRIMARY KEY(workspace_id,kind,scope_key,fingerprint),
 FOREIGN KEY(workspace_id,kind,scan_id) REFERENCES inspector_scan_history(workspace_id,kind,id)
);
CREATE INDEX IF NOT EXISTS inspector_current_risk_scan ON inspector_current_risks(workspace_id,kind,scan_id);
CREATE OR REPLACE FUNCTION inspector_project_scan() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE f jsonb; first_time timestamptz;
BEGIN
 INSERT INTO inspector_latest_scans(workspace_id,kind,scope_key,profile,scan_id,recorded_at)
 VALUES(NEW.workspace_id,NEW.kind,NEW.scope_key,coalesce(NEW.data->>'mode','standard'),NEW.id,NEW.recorded_at)
 ON CONFLICT(workspace_id,kind,scope_key,profile) DO UPDATE SET scan_id=excluded.scan_id,recorded_at=excluded.recorded_at
 WHERE (excluded.recorded_at,excluded.scan_id)>=(inspector_latest_scans.recorded_at,inspector_latest_scans.scan_id);
 IF NEW.kind='performance' OR coalesce(NEW.data->>'status','completed') IN ('failed','queued','running') THEN RETURN NEW; END IF;
 FOR f IN SELECT value FROM jsonb_array_elements(coalesce(NEW.data->'findings','[]')) LOOP
  IF coalesce(f->>'fingerprint',f->>'id') IS NULL THEN CONTINUE; END IF;
  first_time:=coalesce(nullif(f->>'firstSeen','')::timestamptz,NEW.recorded_at);
  INSERT INTO inspector_current_risks(workspace_id,kind,scope_key,fingerprint,scan_id,observed_at,first_seen,data)
  VALUES(NEW.workspace_id,NEW.kind,NEW.scope_key,coalesce(f->>'fingerprint',f->>'id'),NEW.id,NEW.recorded_at,first_time,f)
  ON CONFLICT(workspace_id,kind,scope_key,fingerprint) DO UPDATE SET
   first_seen=least(inspector_current_risks.first_seen,excluded.first_seen),
   data=CASE WHEN (excluded.observed_at,excluded.scan_id)>=(inspector_current_risks.observed_at,inspector_current_risks.scan_id) THEN excluded.data ELSE inspector_current_risks.data END,
   scan_id=CASE WHEN (excluded.observed_at,excluded.scan_id)>=(inspector_current_risks.observed_at,inspector_current_risks.scan_id) THEN excluded.scan_id ELSE inspector_current_risks.scan_id END,
   observed_at=greatest(inspector_current_risks.observed_at,excluded.observed_at);
 END LOOP;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS inspector_scan_projection ON inspector_scan_history;
CREATE TRIGGER inspector_scan_projection AFTER INSERT OR UPDATE OF data ON inspector_scan_history FOR EACH ROW EXECUTE FUNCTION inspector_project_scan();
-- Backfill once. The trigger and these rows commit atomically with the migration.
CREATE TABLE IF NOT EXISTS inspector_migrations (name text PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now());
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM inspector_migrations WHERE name='003_history_read_models') THEN
  UPDATE inspector_scan_history SET data=data;
  INSERT INTO inspector_migrations(name) VALUES('003_history_read_models');
 END IF;
END $$;
