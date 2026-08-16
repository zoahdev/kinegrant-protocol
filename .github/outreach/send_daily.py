#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Daily outreach batch sender (run from GitHub Actions).

Sends at most --limit unsent recipients via 163 SMTP, appends to sent.json, and
leaves sent.json updated for the workflow to commit. Credentials come from env.
"""
import json
import os
import smtplib
import ssl
import sys
import time
from argparse import ArgumentParser
from email.message import EmailMessage
from pathlib import Path


def send_one(host, port, user, auth, to, subject, body):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"KineGrant <{user}>"
    msg["To"] = to
    msg["Reply-To"] = user
    msg.set_content(body)
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(host, port, context=ctx, timeout=40) as s:
        s.login(user, auth)
        s.send_message(msg)


def main():
    ap = ArgumentParser()
    ap.add_argument("outdir", help="directory containing campaign.json and sent.json")
    ap.add_argument("--limit", type=int, default=8)
    ap.add_argument("--sleep", type=int, default=45)
    args = ap.parse_args()

    host = os.environ.get("MAIL163_HOST", "smtp.163.com")
    port = int(os.environ.get("MAIL163_PORT", "465"))
    user = os.environ["MAIL163_USER"]
    auth = os.environ["MAIL163_AUTH"]

    outdir = Path(args.outdir)
    campaign = json.loads((outdir / "campaign.json").read_text(encoding="utf-8"))
    sent_path = outdir / "sent.json"
    sent = []
    if sent_path.exists():
        sent = json.loads(sent_path.read_text(encoding="utf-8"))
    sent_to = {r["to"] for r in sent}

    n = 0
    for i, r in enumerate(campaign):
        if r["to"] in sent_to:
            continue
        if n >= args.limit:
            print(f"LIMIT {args.limit} reached; {sum(1 for x in campaign if x['to'] not in sent_to) - n} left for next run.")
            break
        try:
            send_one(host, port, user, auth, r["to"], r["subject"], r["body"])
            sent.append({"to": r["to"], "company": r.get("company", ""), "ts": time.time()})
            sent_path.write_text(json.dumps(sent, ensure_ascii=False, indent=2), encoding="utf-8")
            n += 1
            print(f"[{i+1}/{len(campaign)}] SENT {r.get('company') or r['to']}")
        except Exception as exc:
            print(f"[{i+1}/{len(campaign)}] FAIL {r.get('company') or r['to']}: {type(exc).__name__} {str(exc)[:140]}")
        time.sleep(args.sleep)

    print(f"DONE sent_total={len(sent)}")


if __name__ == "__main__":
    main()
