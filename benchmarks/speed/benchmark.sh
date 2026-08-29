#!/bin/bash
# run_speed_benchmark.sh
# Drives satori run for pyspector.yml, semgrep.yml, bandit.yml against one repo
# (or all 8 confirmed benchmark repos, via "full"), N times each, and greps
# timing/throughput/resource numbers from console output.
#
# Usage: ./run_speed_benchmark.sh
# You will be prompted for a repo (owner/name) or the word "full", and the
# number of repetitions per tool.

set -uo pipefail

# ---------- config ----------
CPU=16384
MEMORY=122880

# Satori's own default timeout is 3600s. Flask (10k LoC) took ~18s in Semgrep;
# if that scaled anywhere near linearly, Home Assistant (~3M LoC, 300x larger)
# could approach or exceed 3600s and get killed mid-scan by Satori itself.
# Set a generous ceiling here so the biggest repos aren't truncated.
TIMEOUT=10800

PLAYBOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAILED_RUNS_DIR="$PLAYBOOK_DIR/failed_runs"

# The 8 confirmed benchmark repos, in ascending LoC order.
FULL_REPO_LIST=(
  "pallets/flask"
  "pallets/click"
  "scrapy/scrapy"
  "fastapi/fastapi"
  "keras-team/keras"
  "ansible/ansible"
  "django/django"
  "pandas-dev/pandas"
)

# ---------- input ----------
read -rp "GitHub repo to scan (owner/name), or 'full' for all 8 benchmark repos: " REPO_INPUT
read -rp "Number of repetitions per tool (e.g. 1 for a test run, 5 for real): " REPS

if ! [[ "$REPS" =~ ^[0-9]+$ ]] || [ "$REPS" -lt 1 ]; then
  echo "Repetitions must be a positive integer." >&2
  exit 1
fi

if [ "$REPO_INPUT" == "full" ]; then
  REPOS=("${FULL_REPO_LIST[@]}")
elif [[ "$REPO_INPUT" =~ ^[^/]+/[^/]+$ ]]; then
  REPOS=("$REPO_INPUT")
else
  echo "Repository must be in owner/name format, or 'full'." >&2
  exit 1
fi

echo
echo "Repos to scan: ${REPOS[*]}"
echo "Repetitions per tool: $REPS"
echo

# ---------- CSV output (for later graphing / paper use) ----------
CSV_FILE="$PLAYBOOK_DIR/benchmark_results_$(date +%Y%m%d_%H%M%S).csv"
echo "repo,loc,tool,median_time_s,throughput_locsec" > "$CSV_FILE"

# ---------- cross-repo summary storage ----------
declare -a SUMMARY_REPO=()
declare -a SUMMARY_LOC=()
declare -a SUMMARY_PYSPECTOR_MEDIAN=()
declare -a SUMMARY_PYSPECTOR_THROUGHPUT=()
declare -a SUMMARY_SEMGREP_MEDIAN=()
declare -a SUMMARY_SEMGREP_THROUGHPUT=()
declare -a SUMMARY_BANDIT_MEDIAN=()
declare -a SUMMARY_BANDIT_THROUGHPUT=()

# ---------- overall successful-run statistics ----------

declare -a ALL_PYSPECTOR_TIMES=()
declare -a ALL_PYSPECTOR_THROUGHPUT=()

declare -a ALL_SEMGREP_TIMES=()
declare -a ALL_SEMGREP_THROUGHPUT=()

declare -a ALL_BANDIT_TIMES=()
declare -a ALL_BANDIT_THROUGHPUT=()

# PySpector resource measurements across all successful runs.
declare -a ALL_PYSPECTOR_MEMORY_MB=()
declare -a ALL_PYSPECTOR_CPU_CORES=()
declare -a ALL_PYSPECTOR_CPU_PCT=()

# Tracks any run whose tool never produced its expected output block at all —
# distinct from a field simply not matching a grep pattern (which shows as N/A).
declare -a FAILURES=()

# ---------- helpers ----------

# Extracts the first regex-captured group (via \K) from a block of text, or prints N/A.
grep_field() {
  local pattern="$1"
  local text="$2"
  local match

  match=$(grep -oP "$pattern" <<< "$text" | head -1)

  if [ -z "$match" ]; then
    echo "N/A"
  else
    echo "$match"
  fi
}

run_satori() {
  local playbook="$1"
  local repo="$2"

  satori run "$playbook" \
    --repo "$repo" \
    --cpu "$CPU" \
    --memory "$MEMORY" \
    --timeout "$TIMEOUT" \
    --visibility unlisted \
    --output 2>&1
}

# Records a run that never produced its tool's expected output block at all
# (as opposed to a field that simply didn't match a grep pattern, which is
# reported as N/A). Saves the full raw output to a log file for inspection,
# since that context would otherwise be lost once $OUT goes out of scope.
log_failure() {
  local repo="$1" tool="$2" run_idx="$3" rc="$4" out="$5"

  mkdir -p "$FAILED_RUNS_DIR"

  local safe_repo="${repo//\//_}"
  local logfile="$FAILED_RUNS_DIR/${safe_repo}_${tool}_run${run_idx}_$(date +%Y%m%d_%H%M%S).log"

  echo "$out" > "$logfile"

  FAILURES+=("$repo|$tool|$run_idx|$rc|$logfile")

  echo "  !!! FAILED: $tool run $run_idx for $repo (satori exit code: $rc). Raw output saved to: $logfile" >&2
}

# Strips time suffixes down to a plain seconds float where possible.
# Supports:
#   23.456s
#   0m23.456s
#   1h02m03.456s
seconds_only() {
  local val="$1"

  if [[ "$val" =~ ([0-9]+)h([0-9]+)m([0-9.]+)s ]]; then
    awk \
      -v h="${BASH_REMATCH[1]}" \
      -v m="${BASH_REMATCH[2]}" \
      -v s="${BASH_REMATCH[3]}" \
      'BEGIN { printf "%.3f", (h*3600)+(m*60)+s }'
  elif [[ "$val" =~ ([0-9]+)m([0-9.]+)s ]]; then
    awk \
      -v m="${BASH_REMATCH[1]}" \
      -v s="${BASH_REMATCH[2]}" \
      'BEGIN { printf "%.3f", (m*60)+s }'
  elif [[ "$val" =~ ([0-9.]+)s ]]; then
    echo "${BASH_REMATCH[1]}"
  else
    echo ""
  fi
}

# Calculates throughput for one run from its measured time.
throughput_from_time() {
  local time_str="$1"
  local loc="$2"
  local secs

  secs=$(seconds_only "$time_str")

  local loc_clean="${loc//,/}"

  if [ -z "$secs" ] \
    || [ "$secs" == "0" ] \
    || [ -z "$loc_clean" ] \
    || [ "$loc_clean" == "N/A" ] \
    || [ "$loc_clean" == "FAILED" ]; then
    echo "N/A"
    return
  fi

  awk -v l="$loc_clean" -v s="$secs" \
    'BEGIN { printf "%.0f LoC/sec", l/s }'
}

# Calculates the median of an array of time strings.
median_of() {
  local arr=("$@")
  local vals=()

  for v in "${arr[@]}"; do
    local s
    s=$(seconds_only "$v")
    [ -n "$s" ] && vals+=("$s")
  done

  local n=${#vals[@]}

  if [ "$n" -eq 0 ]; then
    echo "N/A"
    return
  fi

  IFS=$'\n' sorted=($(sort -n <<<"${vals[*]}"))
  unset IFS

  local mid=$((n / 2))

  if (( n % 2 == 1 )); then
    echo "${sorted[$mid]}s"
  else
    awk \
      -v a="${sorted[$((mid-1))]}" \
      -v b="${sorted[$mid]}" \
      'BEGIN { printf "%.3fs", (a+b)/2 }'
  fi
}

# Calculates the median of throughput strings in the form:
#   12345 LoC/sec
median_throughput() {
  local arr=("$@")
  local vals=()

  for v in "${arr[@]}"; do
    if [[ "$v" =~ ^([0-9,]+)[[:space:]]+LoC/sec$ ]]; then
      vals+=("${BASH_REMATCH[1]//,/}")
    fi
  done

  local n=${#vals[@]}

  if [ "$n" -eq 0 ]; then
    echo "N/A"
    return
  fi

  IFS=$'\n' sorted=($(sort -n <<<"${vals[*]}"))
  unset IFS

  local mid=$((n / 2))

  if (( n % 2 == 1 )); then
    awk -v v="${sorted[$mid]}" \
      'BEGIN { printf "%.0f LoC/sec", v }'
  else
    awk \
      -v a="${sorted[$((mid-1))]}" \
      -v b="${sorted[$mid]}" \
      'BEGIN { printf "%.0f LoC/sec", (a+b)/2 }'
  fi
}

# Calculates the arithmetic mean of an array of numeric values.
mean_numeric() {
  local arr=("$@")
  local n=${#arr[@]}

  if [ "$n" -eq 0 ]; then
    echo "N/A"
    return
  fi

  local values="${arr[*]}"

  awk -v values="$values" '
    BEGIN {
      n = split(values, a, " ")
      sum = 0

      for (i = 1; i <= n; i++)
        sum += a[i]

      printf "%.3f", sum / n
    }
  '
}

# Calculates the arithmetic mean of an array of time strings.
mean_of() {
  local arr=("$@")
  local vals=()

  for v in "${arr[@]}"; do
    local s
    s=$(seconds_only "$v")
    [ -n "$s" ] && vals+=("$s")
  done

  local n=${#vals[@]}

  if [ "$n" -eq 0 ]; then
    echo "N/A"
    return
  fi

  local values="${vals[*]}"

  awk -v values="$values" '
    BEGIN {
      n = split(values, a, " ")
      sum = 0

      for (i = 1; i <= n; i++)
        sum += a[i]

      printf "%.3fs", sum / n
    }
  '
}

# Calculates the arithmetic mean of throughput strings.
mean_throughput() {
  local arr=("$@")
  local vals=()

  for v in "${arr[@]}"; do
    if [[ "$v" =~ ^([0-9,]+)[[:space:]]+LoC/sec$ ]]; then
      vals+=("${BASH_REMATCH[1]//,/}")
    fi
  done

  local n=${#vals[@]}

  if [ "$n" -eq 0 ]; then
    echo "N/A"
    return
  fi

  local values="${vals[*]}"

  awk -v values="$values" '
    BEGIN {
      n = split(values, a, " ")
      sum = 0

      for (i = 1; i <= n; i++)
        sum += a[i]

      printf "%.0f LoC/sec", sum / n
    }
  '
}

# Calculates the arithmetic mean of MB values.
mean_mb() {
  local arr=("$@")
  local vals=()

  for v in "${arr[@]}"; do
    if [[ "$v" =~ ^([0-9.]+)[[:space:]]+MB$ ]]; then
      vals+=("${BASH_REMATCH[1]}")
    fi
  done

  local n=${#vals[@]}

  if [ "$n" -eq 0 ]; then
    echo "N/A"
    return
  fi

  local mean
  mean=$(mean_numeric "${vals[@]}")

  awk -v m="$mean" \
    'BEGIN { printf "%.1f MB", m }'
}

# Calculates the arithmetic mean of CPU-core utilization values.
# Input format:
#   1.0 / 2 logical cores
mean_cpu_cores() {
  local arr=("$@")
  local vals=()

  for v in "${arr[@]}"; do
    if [[ "$v" =~ ^([0-9.]+)[[:space:]]*/ ]]; then
      vals+=("${BASH_REMATCH[1]}")
    fi
  done

  local n=${#vals[@]}

  if [ "$n" -eq 0 ]; then
    echo "N/A"
    return
  fi

  local mean
  mean=$(mean_numeric "${vals[@]}")

  local logical_cores=""

  for v in "${arr[@]}"; do
    if [[ "$v" =~ ^[0-9.]+[[:space:]]*/[[:space:]]*([0-9]+)[[:space:]]+logical[[:space:]]+cores$ ]]; then
      logical_cores="${BASH_REMATCH[1]}"
      break
    fi
  done

  if [ -n "$logical_cores" ]; then
    echo "$mean / $logical_cores logical cores"
  else
    echo "$mean logical cores"
  fi
}

# Calculates the arithmetic mean of CPU utilization values.
# Input format:
#   104% (multi-core, can exceed 100%)
mean_cpu_pct() {
  local arr=("$@")
  local vals=()

  for v in "${arr[@]}"; do
    if [[ "$v" =~ ^([0-9.]+)% ]]; then
      vals+=("${BASH_REMATCH[1]}")
    fi
  done

  local n=${#vals[@]}

  if [ "$n" -eq 0 ]; then
    echo "N/A"
    return
  fi

  local mean
  mean=$(mean_numeric "${vals[@]}")

  awk -v m="$mean" \
    'BEGIN { printf "%.1f%% (multi-core, can exceed 100%%)", m }'
}

# ---------- box drawing helpers (fixed interior width, so all rows align) ----------
ROW_WIDTH=72

print_border() {
  printf '╔%s╗\n' "$(printf '═%.0s' $(seq 1 $((ROW_WIDTH+2))))"
}

print_separator() {
  printf '╠%s╣\n' "$(printf '═%.0s' $(seq 1 $((ROW_WIDTH+2))))"
}

print_bottom() {
  printf '╚%s╝\n' "$(printf '═%.0s' $(seq 1 $((ROW_WIDTH+2))))"
}

print_row() {
  printf '║ %-*s ║\n' "$ROW_WIDTH" "$1"
}

# ---------- per-repo benchmark ----------
run_benchmark_for_repo() {
  local repo="$1"

  declare -a PYSPECTOR_TIMES=()
  declare -a PYSPECTOR_THROUGHPUT=()
  declare -a PYSPECTOR_MEM=()
  declare -a PYSPECTOR_CPU_CORES=()
  declare -a PYSPECTOR_CPU_PCT=()

  declare -a SEMGREP_TIMES=()
  declare -a SEMGREP_THROUGHPUT=()

  declare -a BANDIT_TIMES=()
  declare -a BANDIT_THROUGHPUT=()

  local TOTAL_LOC=""

  echo "=== [$repo] Running PySpector ($REPS run(s)) ==="

  for i in $(seq 1 "$REPS"); do
    echo "  Run $i/$REPS..."

    local OUT
    OUT=$(run_satori "$PLAYBOOK_DIR/pyspector.yml" "$repo")
    local rc=$?

    local SCAN_TIME THROUGHPUT MEM LOC CPU_CORES CPU_PCT

    if ! grep -q "PYSPECTOR SCAN STATISTICS" <<< "$OUT"; then
      log_failure "$repo" "pyspector" "$i" "$rc" "$OUT"

      SCAN_TIME="FAILED"
      THROUGHPUT="FAILED"
      MEM="FAILED"
      LOC="FAILED"
      CPU_CORES="FAILED"
      CPU_PCT="FAILED"
    else
      # Use the label as an anchor and capture the value after it.
      # The previous regexes assumed a specific number of whitespace-separated
      # fields between the label and value, which was too brittle for the ASCII
      # stats table formatting.
      SCAN_TIME=$(grep_field 'Total scan time.*?\K[0-9.]+s' "$OUT")
      THROUGHPUT=$(grep_field 'Throughput.*?\K[0-9,]+ LoC/sec' "$OUT")
      MEM=$(grep_field 'Peak memory usage.*?\K[0-9,]+ MB' "$OUT")
      LOC=$(grep_field 'Lines of code scanned.*?\K[0-9,]+' "$OUT")

      if grep -q "too quickly to sample" <<< "$OUT"; then
        CPU_CORES="too fast to sample"
        CPU_PCT="too fast to sample"
      else
        CPU_CORES=$(grep_field 'CPU cores utilized.*?\K[0-9.]+ / [0-9]+ logical cores' "$OUT")
        CPU_PCT=$(grep_field 'Avg CPU utilization.*?\K[0-9.]+%[^║|]*' "$OUT")
      fi
    fi

    PYSPECTOR_TIMES+=("$SCAN_TIME")
    PYSPECTOR_THROUGHPUT+=("$THROUGHPUT")
    PYSPECTOR_MEM+=("$MEM")
    PYSPECTOR_CPU_CORES+=("$CPU_CORES")
    PYSPECTOR_CPU_PCT+=("$CPU_PCT")

    # Add successful runs to global aggregates.
    [ "$SCAN_TIME" != "FAILED" ] && [ "$SCAN_TIME" != "N/A" ] \
      && ALL_PYSPECTOR_TIMES+=("$SCAN_TIME")

    [ "$THROUGHPUT" != "FAILED" ] && [ "$THROUGHPUT" != "N/A" ] \
      && ALL_PYSPECTOR_THROUGHPUT+=("$THROUGHPUT")

    [ "$MEM" != "FAILED" ] && [ "$MEM" != "N/A" ] \
      && ALL_PYSPECTOR_MEMORY_MB+=("$MEM")

    # CPU measurements are only aggregated when they were actually sampled.
    if [[ "$CPU_CORES" =~ ^[0-9.]+[[:space:]]*/[[:space:]]*[0-9]+[[:space:]]+logical[[:space:]]+cores$ ]]; then
      ALL_PYSPECTOR_CPU_CORES+=("$CPU_CORES")
    fi

    if [[ "$CPU_PCT" =~ ^[0-9.]+% ]]; then
      ALL_PYSPECTOR_CPU_PCT+=("$CPU_PCT")
    fi

    # Take LoC from the first successful PySpector run.
    # This keeps a single consistent denominator for all tools.
    if [ -z "$TOTAL_LOC" ] \
      && [ "$LOC" != "N/A" ] \
      && [ "$LOC" != "FAILED" ]; then
      TOTAL_LOC="$LOC"
    fi

    echo "    scan time: $SCAN_TIME | throughput: $THROUGHPUT | mem: $MEM | cpu cores: $CPU_CORES | cpu%: $CPU_PCT"
  done

  echo

  if [ -z "$TOTAL_LOC" ]; then
    echo "WARNING: could not determine total LoC for $repo from PySpector output. Bandit/Semgrep throughput will be N/A." >&2
  fi

  echo "=== [$repo] Running Semgrep ($REPS run(s)) ==="

  for i in $(seq 1 "$REPS"); do
    echo "  Run $i/$REPS..."

    local OUT REAL_TIME RUN_THROUGHPUT

    OUT=$(run_satori "$PLAYBOOK_DIR/semgrep.yml" "$repo")
    local rc=$?

    if ! grep -qP '^real\s' <<< "$OUT"; then
      log_failure "$repo" "semgrep" "$i" "$rc" "$OUT"

      REAL_TIME="FAILED"
      RUN_THROUGHPUT="FAILED"
    else
      REAL_TIME=$(grep_field 'real\s+\K\S+' "$OUT")
      RUN_THROUGHPUT=$(throughput_from_time "$REAL_TIME" "$TOTAL_LOC")
    fi

    SEMGREP_TIMES+=("$REAL_TIME")
    SEMGREP_THROUGHPUT+=("$RUN_THROUGHPUT")

    [ "$REAL_TIME" != "FAILED" ] && [ "$REAL_TIME" != "N/A" ] \
      && ALL_SEMGREP_TIMES+=("$REAL_TIME")

    [ "$RUN_THROUGHPUT" != "FAILED" ] && [ "$RUN_THROUGHPUT" != "N/A" ] \
      && ALL_SEMGREP_THROUGHPUT+=("$RUN_THROUGHPUT")

    echo "    real time: $REAL_TIME | throughput: $RUN_THROUGHPUT"
  done

  echo

  echo "=== [$repo] Running Bandit ($REPS run(s)) ==="

  for i in $(seq 1 "$REPS"); do
    echo "  Run $i/$REPS..."

    local OUT REAL_TIME RUN_THROUGHPUT

    OUT=$(run_satori "$PLAYBOOK_DIR/bandit.yml" "$repo")
    local rc=$?

    if ! grep -qP '^real\s' <<< "$OUT"; then
      log_failure "$repo" "bandit" "$i" "$rc" "$OUT"

      REAL_TIME="FAILED"
      RUN_THROUGHPUT="FAILED"
    else
      REAL_TIME=$(grep_field 'real\s+\K\S+' "$OUT")
      RUN_THROUGHPUT=$(throughput_from_time "$REAL_TIME" "$TOTAL_LOC")
    fi

    BANDIT_TIMES+=("$REAL_TIME")
    BANDIT_THROUGHPUT+=("$RUN_THROUGHPUT")

    [ "$REAL_TIME" != "FAILED" ] && [ "$REAL_TIME" != "N/A" ] \
      && ALL_BANDIT_TIMES+=("$REAL_TIME")

    [ "$RUN_THROUGHPUT" != "FAILED" ] && [ "$RUN_THROUGHPUT" != "N/A" ] \
      && ALL_BANDIT_THROUGHPUT+=("$RUN_THROUGHPUT")

    echo "    real time: $REAL_TIME | throughput: $RUN_THROUGHPUT"
  done

  echo

  # ---------- per-repo medians ----------
  local PYSPECTOR_MEDIAN SEMGREP_MEDIAN BANDIT_MEDIAN
  local PYSPECTOR_THROUGHPUT_MEDIAN SEMGREP_THROUGHPUT_MEDIAN BANDIT_THROUGHPUT_MEDIAN

  PYSPECTOR_MEDIAN=$(median_of "${PYSPECTOR_TIMES[@]}")
  SEMGREP_MEDIAN=$(median_of "${SEMGREP_TIMES[@]}")
  BANDIT_MEDIAN=$(median_of "${BANDIT_TIMES[@]}")

  PYSPECTOR_THROUGHPUT_MEDIAN=$(median_throughput "${PYSPECTOR_THROUGHPUT[@]}")
  SEMGREP_THROUGHPUT_MEDIAN=$(median_throughput "${SEMGREP_THROUGHPUT[@]}")
  BANDIT_THROUGHPUT_MEDIAN=$(median_throughput "${BANDIT_THROUGHPUT[@]}")

  # ---------- per-repo report ----------
  print_border
  print_row "SPEED BENCHMARK SUMMARY — $repo ($REPS run(s))"
  print_separator
  print_row "Total LoC (from PySpector): ${TOTAL_LOC:-N/A}"
  print_separator
  print_row "$(printf '%-12s %-14s %-20s' 'Tool' 'Median time' 'Throughput')"
  print_separator
  print_row "$(printf '%-12s %-14s %-20s' 'PySpector' "$PYSPECTOR_MEDIAN" "$PYSPECTOR_THROUGHPUT_MEDIAN")"
  print_row "$(printf '%-12s %-14s %-20s' 'Semgrep' "$SEMGREP_MEDIAN" "$SEMGREP_THROUGHPUT_MEDIAN")"
  print_row "$(printf '%-12s %-14s %-20s' 'Bandit' "$BANDIT_MEDIAN" "$BANDIT_THROUGHPUT_MEDIAN")"
  print_separator
  print_row "PySpector resource usage (last run):"
  print_row "  Peak memory:          ${PYSPECTOR_MEM[-1]:-N/A}"
  print_row "  CPU cores utilized:   ${PYSPECTOR_CPU_CORES[-1]:-N/A}"
  print_row "  Avg CPU utilization:  ${PYSPECTOR_CPU_PCT[-1]:-N/A}"
  print_bottom

  echo
  echo "Raw per-run values:"
  echo "  PySpector scan times:   ${PYSPECTOR_TIMES[*]}"
  echo "  PySpector throughput:   ${PYSPECTOR_THROUGHPUT[*]}"
  echo "  Semgrep real times:     ${SEMGREP_TIMES[*]}"
  echo "  Semgrep throughput:     ${SEMGREP_THROUGHPUT[*]}"
  echo "  Bandit real times:      ${BANDIT_TIMES[*]}"
  echo "  Bandit throughput:      ${BANDIT_THROUGHPUT[*]}"
  echo

  # ---------- record for cross-repo summary + CSV ----------
  SUMMARY_REPO+=("$repo")
  SUMMARY_LOC+=("${TOTAL_LOC:-N/A}")

  SUMMARY_PYSPECTOR_MEDIAN+=("$PYSPECTOR_MEDIAN")
  SUMMARY_PYSPECTOR_THROUGHPUT+=("$PYSPECTOR_THROUGHPUT_MEDIAN")

  SUMMARY_SEMGREP_MEDIAN+=("$SEMGREP_MEDIAN")
  SUMMARY_SEMGREP_THROUGHPUT+=("$SEMGREP_THROUGHPUT_MEDIAN")

  SUMMARY_BANDIT_MEDIAN+=("$BANDIT_MEDIAN")
  SUMMARY_BANDIT_THROUGHPUT+=("$BANDIT_THROUGHPUT_MEDIAN")

  # Strip thousands-separator commas from throughput values before writing CSV,
  # since a comma inside a field would be misread as a column delimiter.
  local ps_tp_csv sg_tp_csv bd_tp_csv

  ps_tp_csv=$(echo "$PYSPECTOR_THROUGHPUT_MEDIAN" | grep -oP '^\S+' | tr -d ',' || echo N/A)
  sg_tp_csv=$(echo "$SEMGREP_THROUGHPUT_MEDIAN" | grep -oP '^\S+' | tr -d ',' || echo N/A)
  bd_tp_csv=$(echo "$BANDIT_THROUGHPUT_MEDIAN" | grep -oP '^\S+' | tr -d ',' || echo N/A)

  local loc_csv="${TOTAL_LOC//,/}"

  echo "$repo,$loc_csv,pyspector,$(seconds_only "$PYSPECTOR_MEDIAN"),$ps_tp_csv" >> "$CSV_FILE"
  echo "$repo,$loc_csv,semgrep,$(seconds_only "$SEMGREP_MEDIAN"),$sg_tp_csv" >> "$CSV_FILE"
  echo "$repo,$loc_csv,bandit,$(seconds_only "$BANDIT_MEDIAN"),$bd_tp_csv" >> "$CSV_FILE"
}

# ---------- run ----------
for repo in "${REPOS[@]}"; do
  run_benchmark_for_repo "$repo"
done

# ---------- cross-repo summary ----------
if [ "${#REPOS[@]}" -gt 1 ]; then
  echo

  ROW_WIDTH=130

  print_border
  print_row "CROSS-REPO SUMMARY (${#REPOS[@]} repos, $REPS run(s) each)"
  print_separator

  print_row "$(printf '%-22s %-10s %-14s %-16s %-14s %-16s %-14s %-16s' \
    'Repo' 'LoC' 'PySpector' 'PS Throughput' 'Semgrep' 'SG Throughput' 'Bandit' 'BD Throughput')"

  print_separator

  for idx in "${!SUMMARY_REPO[@]}"; do
    print_row "$(printf '%-22s %-10s %-14s %-16s %-14s %-16s %-14s %-16s' \
      "${SUMMARY_REPO[$idx]}" \
      "${SUMMARY_LOC[$idx]}" \
      "${SUMMARY_PYSPECTOR_MEDIAN[$idx]}" \
      "${SUMMARY_PYSPECTOR_THROUGHPUT[$idx]}" \
      "${SUMMARY_SEMGREP_MEDIAN[$idx]}" \
      "${SUMMARY_SEMGREP_THROUGHPUT[$idx]}" \
      "${SUMMARY_BANDIT_MEDIAN[$idx]}" \
      "${SUMMARY_BANDIT_THROUGHPUT[$idx]}")"
  done

  print_bottom
fi

# ---------- overall benchmark averages ----------
#
# These are arithmetic means across ALL successful runs for each scanner.
# With 8 repos x 5 runs, this is 40 runs per scanner when nothing failed.
#
# Throughput is averaged from the actual per-run throughput measurements.
#
# PySpector resource consumption is averaged across all successful PySpector
# runs:
#   - Peak memory
#   - CPU cores utilized
#   - Avg CPU utilization
#
# CPU resource values are only included when PySpector successfully sampled
# them. Runs reporting "too quickly to sample" are excluded from those
# specific resource averages rather than being treated as zero.

echo
ROW_WIDTH=72

OVERALL_PYSPECTOR_MEAN=$(mean_of "${ALL_PYSPECTOR_TIMES[@]}")
OVERALL_PYSPECTOR_THROUGHPUT=$(mean_throughput "${ALL_PYSPECTOR_THROUGHPUT[@]}")

OVERALL_SEMGREP_MEAN=$(mean_of "${ALL_SEMGREP_TIMES[@]}")
OVERALL_SEMGREP_THROUGHPUT=$(mean_throughput "${ALL_SEMGREP_THROUGHPUT[@]}")

OVERALL_BANDIT_MEAN=$(mean_of "${ALL_BANDIT_TIMES[@]}")
OVERALL_BANDIT_THROUGHPUT=$(mean_throughput "${ALL_BANDIT_THROUGHPUT[@]}")

OVERALL_PYSPECTOR_MEMORY=$(mean_mb "${ALL_PYSPECTOR_MEMORY_MB[@]}")
OVERALL_PYSPECTOR_CPU_CORES=$(mean_cpu_cores "${ALL_PYSPECTOR_CPU_CORES[@]}")
OVERALL_PYSPECTOR_CPU_PCT=$(mean_cpu_pct "${ALL_PYSPECTOR_CPU_PCT[@]}")

PYSPECTOR_SUCCESSFUL_RUNS="${#ALL_PYSPECTOR_TIMES[@]}"
SEMGREP_SUCCESSFUL_RUNS="${#ALL_SEMGREP_TIMES[@]}"
BANDIT_SUCCESSFUL_RUNS="${#ALL_BANDIT_TIMES[@]}"

PYSPECTOR_CPU_SAMPLED="${#ALL_PYSPECTOR_CPU_CORES[@]}"

EXPECTED_TOTAL_RUNS=$((${#REPOS[@]} * REPS))

print_border
print_row "OVERALL BENCHMARK AVERAGES — ${#REPOS[@]} repo(s), $REPS run(s) each"
print_separator
print_row "Arithmetic mean across all successful runs"
print_separator
print_row "$(printf '%-12s %-14s %-20s' 'Tool' 'Average time' 'Avg throughput')"
print_separator
print_row "$(printf '%-12s %-14s %-20s' 'PySpector' "$OVERALL_PYSPECTOR_MEAN" "$OVERALL_PYSPECTOR_THROUGHPUT")"
print_row "$(printf '%-12s %-14s %-20s' 'Semgrep' "$OVERALL_SEMGREP_MEAN" "$OVERALL_SEMGREP_THROUGHPUT")"
print_row "$(printf '%-12s %-14s %-20s' 'Bandit' "$OVERALL_BANDIT_MEAN" "$OVERALL_BANDIT_THROUGHPUT")"
print_separator

print_row "PySpector average resource consumption:"
print_row "  Peak memory:          $OVERALL_PYSPECTOR_MEMORY"
print_row "  CPU cores utilized:   $OVERALL_PYSPECTOR_CPU_CORES"
print_row "  Avg CPU utilization:  $OVERALL_PYSPECTOR_CPU_PCT"
print_row "  CPU resource samples: $PYSPECTOR_CPU_SAMPLED / $PYSPECTOR_SUCCESSFUL_RUNS"
print_separator

print_row "Successful runs:"
print_row "  PySpector:             $PYSPECTOR_SUCCESSFUL_RUNS / $EXPECTED_TOTAL_RUNS"
print_row "  Semgrep:               $SEMGREP_SUCCESSFUL_RUNS / $EXPECTED_TOTAL_RUNS"
print_row "  Bandit:                $BANDIT_SUCCESSFUL_RUNS / $EXPECTED_TOTAL_RUNS"
print_bottom

echo
echo "Full results written to: $CSV_FILE"
echo "Columns: repo,loc,tool,median_time_s,throughput_locsec — ready for pandas/numpy import."

echo

if [ "${#FAILURES[@]}" -gt 0 ]; then
  echo "⚠ ${#FAILURES[@]} run(s) never produced expected output and were excluded from medians/averages/throughput:"

  for f in "${FAILURES[@]}"; do
    IFS='|' read -r frepo ftool frun frc flog <<< "$f"
    echo "  - $frepo / $ftool / run $frun (satori exit code $frc) → $flog"
  done

  echo "Inspect the log files above to determine cause (timeout, clone failure, container crash, etc.)."
else
  echo "No failed runs detected — every tool produced its expected output on every run."
fi
