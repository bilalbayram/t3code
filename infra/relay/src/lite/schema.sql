-- One person's relay: every registered device belongs to the same user, so nothing is keyed by user.

CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  platform TEXT NOT NULL,
  bundle_id TEXT,
  aps_environment TEXT,
  push_token TEXT,
  preferences_json TEXT NOT NULL,
  registration_json TEXT,
  updated_at TEXT NOT NULL
);

-- The Live Activity running on a device, if any: its update token, when it was armed, and what it shows.
CREATE TABLE IF NOT EXISTS live_activities (
  device_id TEXT PRIMARY KEY,
  activity_push_token TEXT,
  armed_at TEXT,
  last_aggregate_json TEXT,
  last_delivery_at TEXT,
  ended_at TEXT
);

-- The latest published state of each thread.
CREATE TABLE IF NOT EXISTS activity_rows (
  environment_id TEXT NOT NULL,
  thread_id TEXT NOT NULL,
  state_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (environment_id, thread_id)
);

-- Each linked T3 server: where the app reaches it through the relay (its tunnel) and on the LAN.
CREATE TABLE IF NOT EXISTS environments (
  environment_id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  http_base_url TEXT NOT NULL,
  ws_base_url TEXT NOT NULL,
  lan_url TEXT,
  -- The Cloudflare Tunnel the server runs (RelayManagedEndpointRuntimeConfig), for recovery.
  runtime_json TEXT,
  linked_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
