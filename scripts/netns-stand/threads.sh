#!/bin/bash
# usage: threads.sh <pid>  -> per-thread cpu seconds (utime, stime) sorted
TCK=$(getconf CLK_TCK)
for t in /proc/$1/task/*; do
  tid=${t##*/}; comm=$(cat $t/comm 2>/dev/null); read -r -a f < <(sed 's/^.*) //' $t/stat 2>/dev/null)
  # after stripping "pid (comm) ", field 0 = state; utime = f[11], stime = f[12]
  echo "$(awk -v u=${f[11]} -v s=${f[12]} -v t=$TCK 'BEGIN{printf "%.2f %.2f", u/t, s/t}') $tid $comm"
done | sort -rn | head -8
