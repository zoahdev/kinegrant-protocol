#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One-time reminder: Youth Open Source Seed Fund opens 2026-09-01.

Runs daily from GitHub Actions. Before the target date it does nothing.
On/after 2026-09-01 it emails the applicant once, then records state so the
workflow can commit it to the outreach-state branch (main is protected).
"""
import json
import os
import smtplib
import ssl
import sys
from datetime import date
from email.message import EmailMessage
from pathlib import Path

TARGET = date(2026, 9, 1)
TO = "a0917212213@gmail.com"
STATE_PATH = Path(".github/outreach/seed-fund-reminder-sent.json")

SUBJECT = "【KineGrant】青年开源基金「种子计划」今天开放申报（9/1-10/31）"
BODY = """zoah，早上好！

今天（2026-09-01）是「青年开源专项基金 种子计划」第二批申报开放日。
申报期：2026-09-01 至 10-31；结果公布：11/15-20。

申请草稿已备好（申请主体：zoah；邮箱：a0917212213@gmail.com；金额：8 万元）。

申报步骤：
1. 打开申报入口：沐曦官网 metax-tech.com 新闻公告里找「青年开源专项基金 种子计划」申报链接；或浏览器搜索「青年开源专项基金 种子计划 申报」。
2. 用 a0917212213@gmail.com 注册/登录。
3. 新建申请，把草稿内容逐项复制进表单（项目名称、方向、简介、开源情况、发展计划、资助用途）。
4. 检查后提交，截图留档。
5. 卡住的地方截图发给 Codex 处理。

—— KineGrant 自动化提醒
"""


def send(user, app_password):
    msg = EmailMessage()
    msg["Subject"] = SUBJECT
    msg["From"] = f"KineGrant <{user}>"
    msg["To"] = TO
    msg["Reply-To"] = user
    msg.set_content(BODY)
    ctx = ssl.create_default_context()
    pw = app_password.replace(" ", "").replace("\n", "").replace("\r", "")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ctx, timeout=40) as s:
        s.login(user, pw)
        s.send_message(msg)


def main():
    if date.today() < TARGET:
        print("SKIP before target date")
        return
    if STATE_PATH.exists():
        print("SKIP already sent")
        return
    user = os.environ["GMAIL_USER"]
    pw = os.environ["GMAIL_APP_PASSWORD"]
    try:
        send(user, pw)
    except Exception as exc:
        print(f"FAIL send: {type(exc).__name__} {str(exc)[:160]}")
        sys.exit(1)
    STATE_PATH.write_text(
        json.dumps({"sent": True, "to": TO, "date": str(date.today())}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print("SENT_OK", TO)


if __name__ == "__main__":
    main()
