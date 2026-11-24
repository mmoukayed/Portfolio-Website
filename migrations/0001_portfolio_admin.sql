CREATE TABLE IF NOT EXISTS app_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS portfolio_content (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  content_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO portfolio_content (id, content_json, updated_at)
VALUES (
  1,
  '{"heroIntro":"I’m Mohamad Moukayed, an engineering student building across robotics, embedded systems, electronics, and software. I enjoy practical problems where hardware and software have to work together.","featuredTitle":"Custom Chocolate 3D Printer","featuredSummary":"A custom 3D printer designed to extrude chocolate, built around NEMA stepper motors, a Raspberry Pi 5, and Klipper firmware.","featuredDescription":"The project brings together a motion platform, stepper motor control, and printer firmware to turn chocolate into a printable material. The machine is controlled by a Raspberry Pi 5 running Klipper.","competition":"Hack My Robot","team":"0hmSec","competitionDescription":"Won first place at the NYUAD Hack My Robot competition as part of team 0hmSec.","email":"","github":"","linkedin":""}',
  0
);

CREATE TABLE IF NOT EXISTS admin_passkeys (
  credential_id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);

CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hash TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS admin_sessions_expiry_idx ON admin_sessions (expires_at);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
  ceremony_id TEXT PRIMARY KEY,
  ceremony_type TEXT NOT NULL,
  challenge TEXT NOT NULL,
  session_hash TEXT NOT NULL DEFAULT '',
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS webauthn_challenges_expiry_idx ON webauthn_challenges (expires_at);

CREATE TABLE IF NOT EXISTS admin_attempts (
  kind TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (kind, client_ip)
);
