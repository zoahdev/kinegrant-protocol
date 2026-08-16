#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check Gmail INBOX for new replies and forward a notification to a fallback
inbox (163) via Gmail SMTP. Runs from GitHub Actions (which can reach Gmail).
"""
import email
import imaplib
import os
import smtplib
import ssl
import sys
import time
from email.header import decode_header
from email.message import EmailMessage


def dec(s):
    out = []
    for part, enc in decode_header(s or ""):
        if isinstance(part, bytes):
            out.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(part)
    return "".join(out)


def body_text(msg):
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type() == "text/plain":
                try:
                    return p.get_content().strip()
                except Exception:
                    continue
    else:
        try:
            return msg.get_content().strip()
        except Exception:
            return ""
    return ""


def fetch_new(user, auth):
    M = imaplib.IMAP4_SSL("imap.gmail.com", 993, ssl_context=ssl.create_default_context())
    M.login(user, auth)
    M.select("INBOX")
    typ, data = M.search(None, "(UNSEEN)")
    ids = data[0].split() if data and data[0] else []
    rows = []
    for i in ids[-20:]:  # at most the 20 newest unread
        typ, d = M.fetch(i, "(RFC822)")
        if typ != "OK" or not d or not d[0]:
            continue
        raw = d[0][1]
        msg = email.message_from_bytes(raw)
        frm = dec(msg.get("From", ""))
        subj = dec(msg.get("Subject", ""))
        date = msg.get("Date", "")
        txt = body_text(msg)[:1200]
        rows.append({"from": frm, "subject": subj, "date": date, "body": txt})
    # mark them seen so we do not re-notify
    for i in ids[-20:]:
        try:
            M.store(i, "+FLAGS", "\\Seen")
        except Exception:
            pass
    M.logout()
    return rows


def notify(user, auth, to, rows):
    msg = EmailMessage()
    msg["Subject"] = f"[KineGrant 回信提醒] {len(rows)} 封新回复"
    msg["From"] = f"KineGrant <{user}>"
    msg["To"] = to
    parts = []
    for r in rows:
        parts.append(f"来自: {r['from']}\n主题: {r['subject']}\n时间: {r['date']}\n\n{r['body']}\n\n----------")
    msg.set_content("\n\n".join(parts) if parts else "(no rows)")
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ctx, timeout=40) as s:
        s.login(user, auth)
        s.send_message(msg)


def main():
    user = os.environ["GMAIL_USER"]
    auth = os.environ["GMAIL_APP_PASSWORD"].replace(" ", "")
    notify_to = os.environ.get("NOTIFY_TO", "18377360711@163.com")
    rows = fetch_new(user, auth)
    print(f"new_replies={len(rows)}")
    for r in rows:
        print(f"- {r['from']} | {r['subject']}")
    if rows:
        try:
            notify(user, auth, notify_to, rows)
            print("notified", notify_to)
        except Exception as e:
            print("notify_failed", type(e).__name__, str(e)[:160])


if __name__ == "__main__":
    main()
