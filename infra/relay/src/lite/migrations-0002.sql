-- For a relay created before environments: the table, and devices' registrations kept whole.
CREATE TABLE IF NOT EXISTS environments (
  environment_id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  http_base_url TEXT NOT NULL,
  ws_base_url TEXT NOT NULL,
  lan_url TEXT,
  linked_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
ALTER TABLE devices ADD COLUMN registration_json TEXT;
