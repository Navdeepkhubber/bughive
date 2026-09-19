#!/usr/bin/env bash
# Install off-peak cron jobs for bughive.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="$HOME/.dsh/logs"

# Fetch H1 disclosures every Sunday 22:00 UTC (= Monday 03:30 IST, off-peak)
CRON_FETCH="0 22 * * 0 cd $ROOT && /usr/bin/env bash -lc 'set -a; source .env; set +a; npm run fetch' >> $LOG/fetch.log 2>&1"

# Classify queue every Monday 00:30 UTC (off-peak)
CRON_CLASSIFY="30 0 * * 1 cd $ROOT && DSH_PROFILE=web dsh --profile web --once 'process the bounty queue' >> $LOG/classify.log 2>&1"

# Daily status snapshot at 23:00 UTC (off-peak)
CRON_STATUS="0 23 * * * cd $ROOT && ./bughive status >> $LOG/status.log 2>&1"

( crontab -l 2>/dev/null | grep -v 'bughive\|dsh-bounty-pipeline' ; \
  echo "$CRON_FETCH" ; \
  echo "$CRON_CLASSIFY" ; \
  echo "$CRON_STATUS" ) | crontab -

echo "✓ crontab installed:"
crontab -l | grep -E 'bughive|bounty'
