name: seed-fund-reminder

on:
  schedule:
    - cron: "0 1 * * *"   # 01:00 UTC = 09:00 Beijing, daily
  workflow_dispatch:

permissions:
  contents: write

jobs:
  remind:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97
        with:
          python-version: "3.12"
      - name: Send reminder (once, on/after 2026-09-01)
        run: python .github/outreach/seed_fund_reminder.py
        env:
          GMAIL_USER: ${{ secrets.GMAIL_USER }}
          GMAIL_APP_PASSWORD: ${{ secrets.GMAIL_APP_PASSWORD }}
      - name: Persist sent state to outreach-state branch
        if: success()
        run: |
          if [ ! -f .github/outreach/seed-fund-reminder-sent.json ]; then
            echo "no state change; nothing to persist"
            exit 0
          fi
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git fetch origin outreach-state
          git checkout outreach-state
          git add .github/outreach/seed-fund-reminder-sent.json
          git commit -m "chore(outreach): mark seed-fund reminder sent"
          git push origin outreach-state
          git checkout main
