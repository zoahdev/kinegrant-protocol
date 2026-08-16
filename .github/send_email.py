#!/usr/bin/env python3
"""Send a campaign of personalized emails via Gmail SMTP (run from GitHub Actions)."""

import json
import os
import smtplib
import ssl
import sys
import time
from email.message import EmailMessage


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
    app_password = os.environ["GMAIL_APP_PASSWORD"].replace(" ", "").replace("\n", "").replace("\r", "").strip()
    path = sys.argv[1] if len(sys.argv) > 1 else ".github/campaign.json"
    rows = json.load(open(path, encoding="utf-8"))
    ok = 0
    for i, row in enumerate(rows):
        try:
            send_one(user, app_password, row["to"], row["subject"], row["body"])
            ok += 1
            print(f"[{i + 1}/{len(rows)}] SENT {row['to']}")
        except Exception as exc:
            print(f"[{i + 1}/{len(rows)}] FAIL {row['to']}: {type(exc).__name__} {str(exc)[:160]}")
        time.sleep(8)
    print(f"DONE ok={ok}/{len(rows)}")


if __name__ == "__main__":
    main()