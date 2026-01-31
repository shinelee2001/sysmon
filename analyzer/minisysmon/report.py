import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List


def _fetch_top_processes(conn: sqlite3.Connection, limit: int = 20) -> List[Dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT process_guid, score, image, cmdline, first_seen, parent_guid,
               risk_path_tier, cmd_flags, base64_sus
        FROM processes
        ORDER BY score DESC, first_seen DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    out = []
    for r in rows:
        tags = conn.execute(
            """
            SELECT rule_id, technique, severity, evidence
            FROM tags
            WHERE process_guid=?
            ORDER BY severity DESC
            """,
            (r["process_guid"],),
        ).fetchall()

        out.append({
            "process_guid": r["process_guid"],
            "score": r["score"],
            "image": r["image"],
            "cmdline": r["cmdline"],
            "first_seen": r["first_seen"],
            "parent_guid": r["parent_guid"],
            "enrich": {
                "risk_path_tier": r["risk_path_tier"],
                "cmd_flags": r["cmd_flags"],
                "base64_sus": bool(r["base64_sus"]),
            },
            "tags": [dict(t) for t in tags],
        })
    return out


def _fetch_top_connections(conn: sqlite3.Connection, limit: int = 50) -> List[Dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT nf.process_guid, p.image, p.score, nf.dst_ip, nf.dst_port, COUNT(*) AS cnt
        FROM netflows nf
        LEFT JOIN processes p ON p.process_guid = nf.process_guid
        GROUP BY nf.process_guid, nf.dst_ip, nf.dst_port
        ORDER BY p.score DESC, cnt DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def _build_chain(conn: sqlite3.Connection, leaf_guid: str, max_depth: int = 4) -> List[Dict[str, Any]]:
    chain = []
    guid = leaf_guid
    depth = 0
    while guid and depth < max_depth:
        r = conn.execute(
            "SELECT process_guid, image, cmdline, score, first_seen, parent_guid FROM processes WHERE process_guid=?",
            (guid,),
        ).fetchone()
        if not r:
            break
        chain.append({
            "process_guid": r["process_guid"],
            "image": r["image"],
            "cmdline": r["cmdline"],
            "score": r["score"],
            "first_seen": r["first_seen"],
        })
        guid = r["parent_guid"]
        depth += 1
    chain.reverse()
    return chain


def _fetch_top_chains(conn: sqlite3.Connection, limit: int = 20) -> List[Dict[str, Any]]:
    leaves = conn.execute(
        """
        SELECT process_guid, score
        FROM processes
        ORDER BY score DESC, first_seen DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    out = []
    for r in leaves:
        chain = _build_chain(conn, r["process_guid"])
        out.append({
            "leaf_guid": r["process_guid"],
            "leaf_score": r["score"],
            "chain": chain,
        })
    return out


def build_report(conn: sqlite3.Connection) -> Dict[str, Any]:
    generated_at = conn.execute("SELECT datetime('now') AS now").fetchone()["now"]
    return {
        "generated_at": generated_at,
        "top_processes": _fetch_top_processes(conn, 20),
        "top_chains": _fetch_top_chains(conn, 20),
        "top_connections": _fetch_top_connections(conn, 50),
    }


def write_report(out_path: Path, report_obj: Dict[str, Any]) -> None:
    out_path.write_text(json.dumps(report_obj, indent=2, ensure_ascii=False), encoding="utf-8")
