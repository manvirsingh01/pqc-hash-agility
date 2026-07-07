#!/bin/bash
# =============================================================================
# bench_shuffled.sh — Noise-reduced benchmark with randomised backend ordering
#
# Runs multiple independent rounds, but SHUFFLES the order of backends in
# each round. This eliminates systematic ordering bias (cache warming,
# thermal throttle, OS scheduler drift) that could favour whichever
# backend runs first or last.
#
# All results go into ONE combined CSV with round + run_order columns,
# so you can analyse ordering effects and compute confidence intervals
# from a single file.
#
# CPU controls: frequency lock, turbo disable, core pinning (same as
# bench_controlled.sh but with shuffled ordering).
#
# Usage:
#   cd <build-dir>
#   sudo bash /path/to/repo/bench_shuffled.sh [options]
#
# Options:
#   --rounds  N    independent rounds (default: 10)
#   --iters   N    iterations per operation (default: 5000)
#   --warmup  N    warmup iterations (default: 500)
#   --core    N    CPU core to pin to (default: 0)
#   --settle  N    seconds to idle before EACH backend run (default: 3)
#   --no-lock      skip CPU frequency locking
#   --no-haraka    skip Haraka backend
#   --csv     PATH output CSV path (default: results/shuffled_benchmark.csv)
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(pwd)"
RESULTS_DIR="$ROOT/results"
mkdir -p "$RESULTS_DIR"

ROUNDS=10
ITERS=5000
WARMUP=500
CORE=0
LOCK_CPU=1
NO_HARAKA=0
SETTLE=3
CSV_OUT="$RESULTS_DIR/shuffled_benchmark.csv"

while [ $# -gt 0 ]; do
  case "$1" in
    --rounds)    ROUNDS="$2";   shift 2 ;;
    --iters)     ITERS="$2";    shift 2 ;;
    --warmup)    WARMUP="$2";   shift 2 ;;
    --core)      CORE="$2";     shift 2 ;;
    --settle)    SETTLE="$2";   shift 2 ;;
    --no-lock)   LOCK_CPU=0;    shift ;;
    --no-haraka) NO_HARAKA=1;   shift ;;
    --csv)       CSV_OUT="$2";  shift 2 ;;
    --help|-h)
      sed -n '2,/^# ====/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) shift ;;
  esac
done

# ── Detect available backends ──
BACKENDS=()
for b in bench_shake bench_turboshake bench_k12 bench_blake3 bench_xoodyak; do
  [ -x "./$b" ] && BACKENDS+=("$b")
done
if [ "$NO_HARAKA" = "0" ] && [ -x "./bench_haraka" ]; then
  BACKENDS+=("bench_haraka")
fi
# liboqs production reference — separate series (hash_backend "SHAKE-liboqs"),
# shuffled along with the rest but not part of the hash-substitution baseline.
if [ -x "./bench_liboqs" ]; then
  BACKENDS+=("bench_liboqs")
fi

if [ ${#BACKENDS[@]} -eq 0 ]; then
  echo "ERROR: No benchmark binaries found. Run setup.sh first."
  exit 1
fi

echo "========================================================="
echo " PQC Shuffled Benchmark (noise-reduced)"
echo ""
echo " Each round shuffles the backend execution order to"
echo " eliminate systematic ordering bias (cache warming,"
echo " thermal throttle, OS scheduler drift)."
echo ""
echo " Rounds      : $ROUNDS"
echo " Iterations  : $ITERS per operation"
echo " Warmup      : $WARMUP"
echo " Core pin    : $CORE"
echo " Settle wait : ${SETTLE}s before each backend run"
echo " CPU lock    : $([ "$LOCK_CPU" = "1" ] && echo "YES" || echo "NO")"
echo " Backends    : ${BACKENDS[*]}"
echo " Output CSV  : $CSV_OUT"
echo "========================================================="
echo ""

# ── CPU controls ──
RESTORE_GOVERNOR=""
OLD_TURBO=""
if [ "$LOCK_CPU" = "1" ]; then
  if command -v cpupower &>/dev/null; then
    OLD_GOV=$(cat /sys/devices/system/cpu/cpu${CORE}/cpufreq/scaling_governor 2>/dev/null || echo "unknown")
    if cpupower frequency-set --governor performance &>/dev/null 2>&1; then
      echo "[cpu] Governor → performance (was: $OLD_GOV)"
      RESTORE_GOVERNOR="$OLD_GOV"
    fi
  else
    echo "[cpu] cpupower not found — frequency may vary"
  fi

  if [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
    OLD_TURBO=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)
    echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || true
    echo "[cpu] Intel turbo boost → disabled"
  fi

  sleep 2
fi

cleanup() {
  if [ -n "$RESTORE_GOVERNOR" ]; then
    cpupower frequency-set --governor "$RESTORE_GOVERNOR" &>/dev/null 2>&1 || true
  fi
  if [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ] && [ "${OLD_TURBO:-}" = "0" ]; then
    echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ── Real-time launcher (tail-latency control) ──
# SCHED_FIFO stops other tasks preempting the benchmark mid-measurement,
# the main source of high-percentile outliers. Falls back to nice -20.
LAUNCHER="taskset -c $CORE"
if chrt -f 99 true 2>/dev/null; then
  LAUNCHER="chrt -f 99 taskset -c $CORE"
  echo "[noise] Real-time priority: SCHED_FIFO 99 (via chrt)"
elif nice -n -20 true 2>/dev/null; then
  LAUNCHER="nice -n -20 taskset -c $CORE"
  echo "[noise] Priority: nice -20 (chrt unavailable)"
else
  echo "[noise] Default priority (run as root for SCHED_FIFO)"
fi

# ── System info ──
export BENCH_CFLAGS="-O3 -march=native (setup.sh; haraka backend adds -maes -msse4.1 on x86_64)"
export BENCH_LAUNCHER="$LAUNCHER"
bash "$REPO/system_info.sh" "$RESULTS_DIR/system_info.txt"
echo ""

# ── Combined CSV header ──
# Derived dynamically from the first benchmark's own CSV header so the
# script never goes stale when pqc_bench.c gains new columns.
HEADER_WRITTEN=0

# ── Shuffle function ──
shuffle_array() {
  local i n tmp
  n=${#BACKENDS[@]}
  for (( i = n - 1; i > 0; i-- )); do
    j=$(( RANDOM % (i + 1) ))
    tmp="${SHUFFLED[$i]}"
    SHUFFLED[$i]="${SHUFFLED[$j]}"
    SHUFFLED[$j]="$tmp"
  done
}

# ── Run rounds ──
TOTAL_RUNS=$(( ROUNDS * ${#BACKENDS[@]} ))
RUN_NUM=0

for ROUND in $(seq 1 "$ROUNDS"); do
  # Create shuffled copy of backends
  SHUFFLED=("${BACKENDS[@]}")
  shuffle_array

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Round $ROUND / $ROUNDS"
  echo "  Order: ${SHUFFLED[*]}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  ORDER_IN_ROUND=0
  for BENCH in "${SHUFFLED[@]}"; do
    ORDER_IN_ROUND=$((ORDER_IN_ROUND + 1))
    RUN_NUM=$((RUN_NUM + 1))
    echo ""
    echo "  [$RUN_NUM/$TOTAL_RUNS] Round $ROUND, order $ORDER_IN_ROUND: $BENCH"

    # Settle wait: drain thermal/frequency carryover from the previous run
    [ "$SETTLE" -gt 0 ] && sleep "$SETTLE"

    # Run benchmark, output to temp CSV
    rm -f pqc_benchmark_results.csv
    $LAUNCHER "./$BENCH" \
      --iterations "$ITERS" \
      --warmup "$WARMUP" 2>&1 | grep -E "SELFTEST|Benchmarking|median|CSV" | head -10

    # Parse the temp CSV and append to combined CSV with round + order columns
    if [ -f pqc_benchmark_results.csv ]; then
      if [ "$HEADER_WRITTEN" = "0" ]; then
        ORIG_HEADER=$(head -1 pqc_benchmark_results.csv)
        echo "round,run_order,backend_binary,$ORIG_HEADER" > "$CSV_OUT"
        HEADER_WRITTEN=1
      fi
      tail -n +2 pqc_benchmark_results.csv | while IFS= read -r line; do
        echo "$ROUND,$ORDER_IN_ROUND,$BENCH,$line" >> "$CSV_OUT"
      done
      rm -f pqc_benchmark_results.csv
    fi
  done

  # Cooldown between rounds
  if [ "$ROUND" -lt "$ROUNDS" ]; then
    echo ""
    echo "  [cooldown] 5s between rounds..."
    sleep 5
  fi
done

# ── Summary ──
TOTAL_ROWS=$(( $(wc -l < "$CSV_OUT") - 1 ))
echo ""
echo "========================================================="
echo " DONE"
echo ""
echo " Rounds           : $ROUNDS"
echo " Backends          : ${#BACKENDS[@]}"
echo " Total rows        : $TOTAL_ROWS"
echo " Output            : $CSV_OUT"
echo ""
echo " Each round used a different random backend order."
echo " The run_order column lets you detect ordering effects."
echo ""
echo " Analysis:"
echo "   python3 $REPO/compute_ci.py --dir results/ --baseline SHAKE"
echo "========================================================="
