import sqlite3


def correlate_parent_child(conn: sqlite3.Connection) -> None:
    """
    Very simple correlation:
      child.ppid == parent.pid
      parent.first_seen <= child.first_seen
      same host (if host exists)
      parent not ended before child starts (if ended time exists, we keep it simple here)
    """
    rows = conn.execute(
        """
        SELECT c.process_guid AS child_guid, c.host AS host, c.ppid AS ppid, c.first_seen AS child_ts
        FROM processes c
        WHERE c.parent_guid IS NULL AND c.ppid IS NOT NULL
        """
    ).fetchall()

    for r in rows:
        child_guid = r["child_guid"]
        host = r["host"]
        ppid = r["ppid"]
        child_ts = r["child_ts"]

        parent = conn.execute(
            """
            SELECT p.process_guid
            FROM processes p
            WHERE p.pid = ?
              AND ( ? IS NULL OR p.host = ? )
              AND p.first_seen <= ?
            ORDER BY p.first_seen DESC
            LIMIT 1
            """,
            (ppid, host, host, child_ts),
        ).fetchone()

        if parent:
            conn.execute(
                "UPDATE processes SET parent_guid=? WHERE process_guid=?",
                (parent["process_guid"], child_guid),
            )

    conn.commit()
