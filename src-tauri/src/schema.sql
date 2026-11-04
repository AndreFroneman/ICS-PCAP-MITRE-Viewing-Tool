-- One SQLite file per case. Packet bytes stay in the pcap, not in this file.
-- IF NOT EXISTS so reopening a case does not try to rebuild it.

CREATE TABLE IF NOT EXISTS case_meta (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  summary TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS investigators (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT '',
  organisation TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS evidence_files (
  id TEXT PRIMARY KEY,
  original_name TEXT NOT NULL,
  source_path TEXT NOT NULL DEFAULT '',
  stored_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  format TEXT NOT NULL,
  link_type INTEGER,
  packet_count INTEGER,
  imported_at TEXT NOT NULL,
  warnings TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS custody_events (
  id INTEGER PRIMARY KEY,
  evidence_id TEXT NOT NULL REFERENCES evidence_files(id),
  at TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  sha256 TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS packet_index (
  evidence_id TEXT NOT NULL REFERENCES evidence_files(id),
  n INTEGER NOT NULL,
  ts REAL NOT NULL,
  file_offset INTEGER NOT NULL,
  cap_len INTEGER NOT NULL,
  orig_len INTEGER NOT NULL,
  link_type INTEGER NOT NULL,
  PRIMARY KEY (evidence_id, n)
);

CREATE TABLE IF NOT EXISTS packets (
  evidence_id TEXT NOT NULL,
  n INTEGER NOT NULL,
  engine TEXT NOT NULL,
  ts REAL NOT NULL,
  len INTEGER NOT NULL,
  mac_src TEXT NOT NULL DEFAULT '',
  mac_dst TEXT NOT NULL DEFAULT '',
  src TEXT NOT NULL DEFAULT '',
  dst TEXT NOT NULL DEFAULT '',
  src_port INTEGER NOT NULL DEFAULT 0,
  dst_port INTEGER NOT NULL DEFAULT 0,
  ip_proto INTEGER NOT NULL DEFAULT 0,
  proto TEXT NOT NULL DEFAULT '',
  info TEXT NOT NULL DEFAULT '',
  layers INTEGER NOT NULL DEFAULT 0,
  app_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (evidence_id, n, engine)
);

CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(evidence_id, src);
CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(evidence_id, dst);
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(evidence_id, ts);
CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(evidence_id, proto);

CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL,
  a TEXT NOT NULL,
  b TEXT NOT NULL,
  proto TEXT NOT NULL,
  a_port INTEGER NOT NULL DEFAULT 0,
  b_port INTEGER NOT NULL DEFAULT 0,
  packets INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  a_to_b INTEGER NOT NULL,
  b_to_a INTEGER NOT NULL,
  start_ts REAL NOT NULL,
  end_ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  mac TEXT NOT NULL DEFAULT '',
  hostname TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'unknown',
  confidence TEXT NOT NULL DEFAULT 'low',
  hypothesis TEXT NOT NULL DEFAULT '',
  alternate_hypothesis TEXT NOT NULL DEFAULT '',
  first_seen REAL,
  last_seen REAL
);

CREATE TABLE IF NOT EXISTS asset_evidence (
  asset_id TEXT NOT NULL,
  evidence_id TEXT NOT NULL,
  packet_n INTEGER NOT NULL,
  detail TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL,
  engine TEXT NOT NULL,
  rule_id TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  meaning TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL DEFAULT 'low',
  triage_level INTEGER NOT NULL DEFAULT 1,
  claim_status TEXT NOT NULL DEFAULT 'possible',
  alternative_explanation TEXT NOT NULL DEFAULT '',
  validation TEXT NOT NULL DEFAULT 'pending',
  validated_by TEXT NOT NULL DEFAULT '',
  validated_at TEXT,
  techniques TEXT NOT NULL DEFAULT '[]',
  technique_support TEXT NOT NULL DEFAULT 'possible'
);

CREATE TABLE IF NOT EXISTS finding_packets (
  finding_id TEXT NOT NULL,
  evidence_id TEXT NOT NULL,
  packet_n INTEGER NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (finding_id, packet_n)
);

CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  finding_id TEXT,
  body TEXT NOT NULL,
  author TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fingerprints (
  id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL,
  asset_id TEXT,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  packet_n INTEGER NOT NULL,
  observed_fact TEXT NOT NULL,
  hypothesis TEXT NOT NULL DEFAULT '',
  attribution_note TEXT NOT NULL DEFAULT 'Observed technical fact. Not evidence of nationality or sponsorship.'
);

CREATE TABLE IF NOT EXISTS activity_log (
  id INTEGER PRIMARY KEY,
  at TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
