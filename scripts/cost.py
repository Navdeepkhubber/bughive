#!/usr/bin/env python3
"""Print current DeepSeek V4.1 Flash rate + estimated cost."""
import sys
from datetime import datetime, timezone

PEAK_HOURS = [(1, 4), (6, 10)]  # UTC, Mon-Fri

def is_peak(dt=None):
    dt = dt or datetime.now(timezone.utc)
    if dt.weekday() >= 5:  # Sat/Sun
        return False
    h = dt.hour
    return any(start <= h < end for start, end in PEAK_HOURS)

def rate(kind):
    peak = is_peak()
    if kind == "cache_hit_input":
        return 0.006 if peak else 0.003
    if kind == "cache_miss_input":
        return 0.30 if peak else 0.15
    if kind == "output":
        return 1.20 if peak else 0.60
    raise ValueError(kind)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        now = datetime.now(timezone.utc)
        status = "PEAK" if is_peak(now) else "OFF-PEAK"
        print(f"{now.isoformat()} — {status}")
        print(f"  cache-hit input:  ${rate('cache_hit_input'):.4f}/1M")
        print(f"  cache-miss input: ${rate('cache_miss_input'):.2f}/1M")
        print(f"  output:           ${rate('output'):.2f}/1M")
        sys.exit(0)

    # cost <cache_hit_tokens> <cache_miss_tokens> <output_tokens>
    ch, cm, out = map(int, sys.argv[1:4])
    cost = (ch * rate("cache_hit_input") + cm * rate("cache_miss_input") + out * rate("output")) / 1_000_000
    print(f"${cost:.4f}")
