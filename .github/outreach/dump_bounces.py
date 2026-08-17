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
    # "The following address failed: <x@y>", "Final-Recipient: rfc822;x@y"
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


def main():
    user = os.environ["GMAIL_USER"]
    auth = os.environ["GMAIL_APP_PASSWORD"].replace(" ", "")
    M = imaplib.IMAP4_SSL("imap.gmail.com", 993, ssl_context=ssl.create_default_context())
    M.login(user, auth)
    M.select("INBOX")
    typ, data = M.search(None, '(FROM "mailer-daemon")')
    ids = data[0].split() if data and data[0] else []
    found = {}
    for i in ids[-40:]:
        typ, d = M.fetch(i, "(RFC822)")
        if typ != "OK" or not d or not d[0]:
            continue
        msg = email.message_from_bytes(d[0][1])
        subj = dec(msg.get("Subject", ""))
        if "delivery status" not in subj.lower() and "undelivered" not in subj.lower() and "returned" not in subj.lower():
            continue
        body = body_text(msg)
        failed = extract_failed(body)
        if failed:
            found[failed] = subj
    print(f"bounced_recipients={len(found)}")
    for addr, subj in sorted(found.items()):
        print(f"- {addr} | {subj[:80]}")
    M.logout()


if __name__ == "__main__":
    main()
