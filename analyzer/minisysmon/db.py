import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).with_name("db_schema.sql")


def init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")

    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(schema)
    return conn
