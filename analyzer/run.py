import argparse
from pathlib import Path

from minisysmon.db import init_db
from minisysmon.ingest import ingest_jsonl
from minisysmon.correlate import correlate_parent_child
from minisysmon.enrich import enrich_processes
from minisysmon.tagger import load_rules, apply_rules
from minisysmon.report import build_report, write_report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--input",
        required=False,
        default="telemetry-raw.jsonl",
        help="telemetry-raw.jsonl path (optional)"
    )
    ap.add_argument("--db", default="minisysmon.db", help="sqlite db path")
    ap.add_argument("--rules", default=str(Path(__file__).parent / "minisysmon" / "rules" / "mitre_rules.yaml"))
    ap.add_argument("--out", default="report.json", help="output report.json path")
    args = ap.parse_args()

    db_path = Path(args.db)
    input_path = Path(args.input)
    rules_path = Path(args.rules)
    out_path = Path(args.out)

    conn = init_db(db_path)

    if input_path.exists():
        n_events = ingest_jsonl(conn, input_path)
    else:
        print(f"[!] input file not found: {input_path}")
        print("[!] skipping ingest (0 events)")
        n_events = 0

    correlate_parent_child(conn)
    enrich_processes(conn)

    rules = load_rules(rules_path)
    apply_rules(conn, rules)

    report_obj = build_report(conn)
    write_report(out_path, report_obj)

    print(f"[+] Ingested events: {n_events}")
    print(f"[+] DB: {db_path}")
    print(f"[+] Report: {out_path}")


if __name__ == "__main__":
    main()
