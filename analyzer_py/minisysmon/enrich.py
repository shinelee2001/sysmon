import re
import sqlite3

HIGH_RISK_PATH_HINTS = [
    r"\\Users\\[^\\]+\\AppData\\Local\\Temp\\",
    r"\\Users\\[^\\]+\\Downloads\\",
    r"\\Users\\[^\\]+\\Desktop\\",
    r"\\AppData\\Roaming\\",
]

LOW_RISK_PATH_HINTS = [
    r"\\Windows\\System32\\",
    r"\\Program Files\\",
    r"\\Program Files \(x86\)\\",
]

CMD_FLAG_KEYWORDS = [
    "-enc", "frombase64string", "iex", "invoke-", "downloadstring", "bypass", "hidden", "nop",
]

BASE64_LIKE = re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b")  # 길이 기반


def _tier_from_image(image: str | None) -> int:
    if not image:
        return 0
    s = image
    for pat in HIGH_RISK_PATH_HINTS:
        if re.search(pat, s, re.IGNORECASE):
            return 2
    for pat in LOW_RISK_PATH_HINTS:
        if re.search(pat, s, re.IGNORECASE):
            return 0
    return 1  # unknown / medium


def enrich_processes(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        "SELECT process_guid, image, cmdline FROM processes"
    ).fetchall()

    for r in rows:
        guid = r["process_guid"]
        image = r["image"] or ""
        cmdline = r["cmdline"] or ""

        tier = _tier_from_image(image)

        flags = []
        low_cmd = cmdline.lower()
        for kw in CMD_FLAG_KEYWORDS:
            if kw in low_cmd:
                flags.append(kw)

        base64_sus = 1 if BASE64_LIKE.search(cmdline) else 0

        # 점수(아주 단순)
        score = 0
        if tier == 2:
            score += 15
        elif tier == 1:
            score += 5
        score += 8 * len(flags)
        if base64_sus:
            score += 15

        conn.execute(
            """
            UPDATE processes
            SET risk_path_tier=?, cmd_flags=?, base64_sus=?, score=score+?
            WHERE process_guid=?
            """,
            (tier, ",".join(flags), base64_sus, score, guid),
        )

    conn.commit()
