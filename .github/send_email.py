#!/usr/bin/env python3
"""Send a campaign of personalized emails via Gmail SMTP, with sent tracking.

Usage: python .github/send_email.py <campaign.json> <sent_email.json>

Skips recipients already present in the sent log, sends the rest one by one, and
appends each successful send to the sent log so the workflow can commit it and
avoid resending the same addresses on the next scheduled run.
"""
import json
import os
import smtplib
import ssl
import sys
import time
from email.message import EmailMessage
from pathlib import Path


def send_one(user, app_password, to, subject, body):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"KineGrant <{user}>"
    msg["To"] = to
    msg["Reply-To"] = user
    msg.set_content(body)
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ctx, timeout=40) as s:
        s.login(user, app_password)
        s.send_message(msg)


def main():
    user = os.environ["GMAIL_USER"].strip()
    app_password = (
        os.environ["GMAIL_APP_PASSWORD"]
        .replace(" ", "")
        .replace("\n", "")
        .replace("\r", "")
        .strip()
    )
    campaign_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".github/campaign.json")
    sent_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(".github/sent_email.json")

    rows = json.loads(campaign_path.read_text(encoding="utf-8"))
    sent = []
    if sent_path.exists():
        sent = json.loads(sent_path.read_text(encoding="utf-8"))
    sent_to = {r["to"] for r in sent}
    pending = [r for r in rows if r["to"] not in sent_to]

    print(f"pending={len(pending)} already_sent={len(sent)}")
    ok = 0
    for i, row in enumerate(pending):
        try:
            send_one(user, app_password, row["to"], row["subject"], row["body"])
            sent.append({"to": row["to"], "company": row.get("company", ""), "ts": time.time()})
            sent_path.write_text(json.dumps(sent, ensure_ascii=False, indent=2), encoding="utf-8")
            ok += 1
            print(f"[{i + 1}/{len(pending)}] SENT {row['to']}")
        except Exception as exc:
            print(f"[{i + 1}/{len(pending)}] FAIL {row['to']}: {type(exc).__name__} {str(exc)[:160]}")
        time.sleep(8)
    print(f"DONE ok={ok}/{len(pending)}")


if __name__ == "__main__":
    main()
