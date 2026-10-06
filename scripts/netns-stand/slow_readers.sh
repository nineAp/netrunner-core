#!/bin/bash
# 4 slow readers (3 MB/s each) + 1 unthrottled, 25 s, then report who survived.
for i in 1 2 3 4; do
  curl -s --limit-rate 3M -m 25 -o /dev/null -w "slow$i %{size_download}B exit=%{exitcode}\n" http://203.0.113.80:8080/big &
done
curl -s -m 25 -o /dev/null -w "fast %{size_download}B %{speed_download}B/s exit=%{exitcode}\n" http://203.0.113.80:8080/big &
sleep 12
python3 "$(dirname "$0")/probe.py" "slow-readers-running" 8 203.0.113.80 8080 9999
wait
