import sqlite3
from pathlib import Path
from typing import Any, Dict, List

import yaml


def load_rules(path: Path) -> List[Dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("rules must be a list")
    return rules


def _match_contains(hay: str, needles: list[str]) -> bool:
    h = (hay or "").lower()
    return any(n.lower() in h for n in needles)


def _match_image_endswith(image: str, suffixes: list[str]) -> bool:
    im = (image or "").lower().replace("/", "\\")
    return any(im.endswith(s.lower()) for s in suffixes)


def apply_rules(conn: sqlite3.Connection, rules: List[Dict[str, Any]]) -> None:
    procs = conn.execute(
        "SELECT process_guid, first_seen, image, cmdline, parent_guid FROM processes"
    ).fetchall()

    # 간단 parent lookup 캐시
    proc_by_guid = {p["process_guid"]: p for p in procs}

    for p in procs:
        guid = p["process_guid"]
        ts = p["first_seen"]
        image = p["image"] or ""
        cmdline = p["cmdline"] or ""
        parent_guid = p["parent_guid"]
        parent = proc_by_guid.get(parent_guid) if parent_guid else None
        parent_image = (parent["image"] if parent else "") or ""
        parent_cmd = (parent["cmdline"] if parent else "") or ""

        for rule in rules:
            rid = rule.get("id", "rule.unknown")
            technique = rule.get("technique")
            severity = int(rule.get("severity", 0))
            evidence = rule.get("evidence", "")

            cond = rule.get("if", {})

            ok = True
            if "image_endswith" in cond:
                ok &= _match_image_endswith(image, cond["image_endswith"])
            if "cmd_contains" in cond:
                ok &= _match_contains(cmdline, cond["cmd_contains"])
            if "parent_image_endswith" in cond:
                ok &= _match_image_endswith(parent_image, cond["parent_image_endswith"])
            if "parent_cmd_contains" in cond:
                ok &= _match_contains(parent_cmd, cond["parent_cmd_contains"])

            if not ok:
                continue

            conn.execute(
                """
                INSERT INTO tags(ts, process_guid, rule_id, technique, severity, evidence)
                VALUES(?,?,?,?,?,?)
                """,
                (ts, guid, rid, technique, severity, evidence),
            )
            conn.execute(
                "UPDATE processes SET score=score+? WHERE process_guid=?",
                (severity, guid),
            )

    conn.commit()
