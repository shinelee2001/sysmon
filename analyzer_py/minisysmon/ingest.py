import json
import sqlite3
from pathlib import Path
from typing import Any, Dict


def _safe_get(d: Dict[str, Any], key: str, default=None):
    v = d.get(key, default)
    return v if v is not None else default


def ingest_jsonl(conn: sqlite3.Connection, jsonl_path: Path) -> int:
    """
    Expected minimal event formats (collector output):
      proc_start: ts, event_type, pid, ppid, image, cmdline, host, process_guid
      proc_end:   ts, event_type, pid, process_guid
      net_connect:ts, event_type, pid, process_guid, src_ip, src_port, dst_ip, dst_port
    """
    n = 0
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            evt = json.loads(line)
            n += 1

            ts = str(_safe_get(evt, "ts", ""))
            event_type = str(_safe_get(evt, "event_type", "unknown"))
            pid = _safe_get(evt, "pid")
            ppid = _safe_get(evt, "ppid")
            process_guid = _safe_get(evt, "process_guid")
            raw_json = line

            conn.execute(
                "INSERT INTO events(ts, event_type, pid, ppid, process_guid, raw_json) VALUES(?,?,?,?,?,?)",
                (ts, event_type, pid, ppid, process_guid, raw_json),
            )

            if event_type == "proc_start":
                host = _safe_get(evt, "host")
                image = _safe_get(evt, "image")
                cmdline = _safe_get(evt, "cmdline")
                conn.execute(
                    """
                    INSERT INTO processes(process_guid, host, pid, ppid, image, cmdline, first_seen, last_seen, ended)
                    VALUES(?,?,?,?,?,?,?, ?, 0)
                    ON CONFLICT(process_guid) DO UPDATE SET
                      host=COALESCE(excluded.host, processes.host),
                      pid=COALESCE(excluded.pid, processes.pid),
                      ppid=COALESCE(excluded.ppid, processes.ppid),
                      image=COALESCE(excluded.image, processes.image),
                      cmdline=COALESCE(excluded.cmdline, processes.cmdline),
                      first_seen=COALESCE(processes.first_seen, excluded.first_seen),
                      last_seen=excluded.last_seen
                    """,
                    (process_guid, host, pid, ppid, image, cmdline, ts, ts),
                )

            elif event_type == "proc_end":
                conn.execute(
                    """
                    UPDATE processes
                    SET last_seen = ?, ended = 1
                    WHERE process_guid = ?
                    """,
                    (ts, process_guid),
                )

            elif event_type == "net_connect":
                conn.execute(
                    """
                    INSERT INTO netflows(ts, process_guid, pid, src_ip, src_port, dst_ip, dst_port)
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        ts,
                        process_guid,
                        pid,
                        _safe_get(evt, "src_ip"),
                        _safe_get(evt, "src_port"),
                        _safe_get(evt, "dst_ip"),
                        _safe_get(evt, "dst_port"),
                    ),
                )

    conn.commit()
    return n
