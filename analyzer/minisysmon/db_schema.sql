CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  event_type TEXT NOT NULL,
  pid INTEGER,
  ppid INTEGER,
  process_guid TEXT,
  raw_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(event_type, ts);
CREATE INDEX IF NOT EXISTS idx_events_guid_ts ON events(process_guid, ts);

CREATE TABLE IF NOT EXISTS processes (
  process_guid TEXT PRIMARY KEY,
  host TEXT,
  pid INTEGER,
  ppid INTEGER,
  image TEXT,
  cmdline TEXT,
  first_seen TEXT,
  last_seen TEXT,
  ended INTEGER DEFAULT 0,

  parent_guid TEXT,
  score INTEGER DEFAULT 0,

  risk_path_tier INTEGER DEFAULT 0,
  cmd_flags TEXT DEFAULT "",
  base64_sus INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_proc_pid_ts ON processes(pid, first_seen);
CREATE INDEX IF NOT EXISTS idx_proc_parent ON processes(parent_guid);

CREATE TABLE IF NOT EXISTS netflows (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  process_guid TEXT,
  pid INTEGER,
  src_ip TEXT, src_port INTEGER,
  dst_ip TEXT, dst_port INTEGER,
  FOREIGN KEY(process_guid) REFERENCES processes(process_guid)
);

CREATE INDEX IF NOT EXISTS idx_nf_guid_ts ON netflows(process_guid, ts);
CREATE INDEX IF NOT EXISTS idx_nf_dst ON netflows(dst_ip, dst_port);

CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  process_guid TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  technique TEXT,
  severity INTEGER DEFAULT 0,
  evidence TEXT DEFAULT "",
  FOREIGN KEY(process_guid) REFERENCES processes(process_guid)
);

CREATE INDEX IF NOT EXISTS idx_tags_guid ON tags(process_guid);
CREATE INDEX IF NOT EXISTS idx_tags_rule ON tags(rule_id);
