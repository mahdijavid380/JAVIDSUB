name: JAVIDSUB Auto Update

on:
  schedule:
    - cron: "0 */4 * * *" # اجرا هر ۴ ساعت یک‌بار
  workflow_dispatch: # امکان اجرای دستی

jobs:
  update-sub:
    runs-on: ubuntu-latest
    timeout-minutes: 90

    steps:
      - name: Checkout Repo
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Dependencies
        run: pip install requests

      - name: Run Merge Script
        env:
          MY_SUBS_LIST: ${{ secrets.MY_SUBS_LIST }}
          # فیلتر سلامت قوی (۳ راند تست TCP برای هر کانفیگ)
          ENABLE_HEALTH_CHECK: "true"
          MAX_OUTPUT: "2000"
          CHECK_ROUNDS: "3"
          HEALTH_TIMEOUT: "5"
          MAX_CONCURRENT_CHECKS: "200"
          PYTHONUNBUFFERED: "1"
        run: python process.py

      - name: Upload Artifacts (اختیاری)
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: javidsub-configs
          path: |
            JAVIDSUB*.txt
          retention-days: 7

      - name: Push Results
        run: |
          git config --global user.name "JAVID-BOT"
          git config --global user.email "bot@javid.com"
          git add -A
          git commit -m "Update: $(date -u)" || exit 0
          git push
