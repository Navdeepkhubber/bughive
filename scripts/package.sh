#!/usr/bin/env bash
set -euo pipefail
NAME="dsh-bounty-pipeline-$(date +%Y%m%d-%H%M%S).zip"
cd "$(dirname "$0")/.."
zip -r "$NAME" . \
  -x "node_modules/*" -x ".env" -x "*.log" \
  -x ".dsh/*" -x "recon/output/*" -x "observability/events.jsonl" \
  -x "memory/facts.db" -x "reports/*" -x "__pycache__/*" -x "*.pyc"
echo "✓ $NAME"
