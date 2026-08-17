#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dump the failed recipient addresses from recent Gmail bounce messages."""
import email
import imaplib
import os
import re
import ssl
from email.header import decode_header


def dec(s):
    out = []
    for part, enc in decode_header(s or ""):
        out.append(part.decode(enc or "utf-8", errors="replace") if isinstance(part, bytes) else part)
    return "".join(out)


def body_text(msg):
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type() == "text/plain":
                try:
                    return p.get_content()
                except Exception:
                    continue
    else:
        try:
            return msg.get_content()
        except Exception:
            return ""
    return ""


def extract_failed(body):
    m = re.search(r"wasn'?t delivered to\s*<?([^\s>,;]+)", body, re.I)
    if m:
        return m.group(1).strip("<>")
    m = re.search(r"The following address[^<]*<([^>]+)>", body)
    if m:
        return m.group(1)
    m = re.search(r"Final-Recipient:\s*rfc822;\s*([^\s;]+)", body)
    if m:
        return m.group(1)
    m = re.search(r"for\s+<([^>]+)>", body)
    if m:
        return m.group(1)
    return None


def failed_from_headers(msg):
    for h in ("X-Failed-Recipients", "Original-Recipient"):
        v = msg.get(h)
        if v:
            return v.strip().strip("<>")
    return None


def is_bounce(msg):
    frm = dec(msg.get("From", "")).lower()
    subj = dec(msg.get("Subject", "")).lower()
    return ("mailer-daemon" in frm or "postmaster" in frm
            or "delivery status notification" in subj or "undelivered" in subj
            or "returned" in subj)


def main():
    user = os.environ["GMAIL_USER"]
    auth = os.environ["GMAIL_APP_PASSWORD"].replace(" ", "")
    M = imaplib.IMAP4_SSL("imap.gmail.com", 993, ssl_context=ssl.create_default_context())
    M.login(user, auth)
    M.select("INBOX")
    typ, data = M.search(None, "ALL")
    ids = data[0].split() if data and data[0] else []
    found = {}
    for i in ids[-80:]:
        typ, d = M.fetch(i, "(RFC822)")
        if typ != "OK" or not d or not d[0]:
            continue
        msg = email.message_from_bytes(d[0][1])
        if not is_bounce(msg):
            continue
        subj = dec(msg.get("Subject", ""))
        failed = failed_from_headers(msg) or extract_failed(body_text(msg))
        if failed:
            found[failed.lower()] = subj
    print(f"bounced_recipients={len(found)}")
    for addr, subj in sorted(found.items()):
        print(f"- {addr} | {subj[:80]}")
    M.logout()


if __name__ == "__main__":
    main()
