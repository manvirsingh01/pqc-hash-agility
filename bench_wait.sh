#!/bin/bash
# =============================================================================
# bench_wait.sh — Wait-time (cooldown-isolated) benchmark
#
# Third noise-reduction setup, alongside bench_controlled.sh (fixed order)
# and bench_shuffled.sh (random order):
#
#   Before EVERY backend run the script idles for a configurable WAIT time
#   so the CPU returns to a cold, thermally settled baseline. Every backend
#   therefore starts from the same thermal/frequency state, which removes
#   run-to-run carryover — the main cause of drifting medians and long
#   tails when many benchmarks execute back-to-back.
#
# Covers ALL algorithms for the library baseline and every custom backend:
#   bench_shake       — library ML-KEM-512/768/1024 + ML-DSA-44/65/87
#   bench_turboshake / bench_k12 / bench_blake3 / bench_xoodyak /
#   bench_haraka      — same algorithms with custom hash backends
#
# CPU controls: frequency lock, turbo disable, core pinning, SCHED_FIFO.
# Output: ONE combined CSV (round, run_order, wait_s columns prepended)
# including the full raw energy (RAPL) and memory (RSS/heap) columns.
#
# Usage:
#   cd <build-dir>
#   sudo bash /path/to/repo/bench_wait.sh [options]
#
# Options:
#   --rounds  N    independent rounds (default: 5)
#   --iters   N    iterations per operation (default: 5000)
#   --warmup  N    warmup iterations (default: 500)
#   --wait    N    idle seconds BEFORE each backend run (default: 15)
#   --core    N    CPU core to pin to (default: 0)
#   --no-lock      skip CPU frequency locking (VMs/containers)
#   --no-haraka    skip Haraka backend
#   --csv     PATH output CSV (default: results/wait_benchmark.csv)
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(pwd)"
RESULTS_DIR="$ROOT/results"
mkdir -p "$RESULTS_DIR"

ROUNDS=5
ITERS=5000
WARMUP=500
WAIT=15
CORE=0
LOCK_CPU=1
NO_HARAKA=0
CSV_OUT="$RESULTS_DIR/wait_benchmark.csv"

while [ $# -gt 0 ]; do
  case "$1" in
    --rounds)    ROUNDS="$2";   shift 2 ;;
    --iters)     ITERS="$2";    shift 2 ;;
    --warmup)    WARMUP="$2";   shift 2 ;;
    --wait)      WAIT="$2";     shift 2 ;;
    --core)      CORE="$2";     shift 2 ;;
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

if [ ${#BACKENDS[@]} -eq 0 ]; then
  echo "ERROR: No benchmark binaries found. Run setup.sh first."
  exit 1
fi

echo "========================================================="
echo " PQC Wait-Time Benchmark (cooldown-isolated)"
echo ""
echo " The CPU idles ${WAIT}s before EVERY backend run so all"
echo " backends start from the same settled thermal state."
echo ""
echo " Rounds      : $ROUNDS"
echo " Iterations  : $ITERS per operation"
echo " Warmup      : $WARMUP"
echo " Wait time   : ${WAIT}s before each run"
echo " Core pin    : $CORE"
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
bash "$REPO/system_info.sh" "$RESULTS_DIR/wait_system_info.txt"
echo ""

# ── Combined CSV header (derived from the first run, never hardcoded) ──
HEADER_WRITTEN=0

# ── Run rounds ──
TOTAL_RUNS=$(( ROUNDS * ${#BACKENDS[@]} ))
RUN_NUM=0

for ROUND in $(seq 1 "$ROUNDS"); do
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Round $ROUND / $ROUNDS"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  ORDER_IN_ROUND=0
  for BENCH in "${BACKENDS[@]}"; do
    ORDER_IN_ROUND=$((ORDER_IN_ROUND + 1))
    RUN_NUM=$((RUN_NUM + 1))
    echo ""
    echo "  [$RUN_NUM/$TOTAL_RUNS] Round $ROUND, order $ORDER_IN_ROUND: $BENCH"
    echo "  [wait] idling ${WAIT}s (thermal settle)..."
    sleep "$WAIT"

    rm -f pqc_benchmark_results.csv
    $LAUNCHER "./$BENCH" \
      --iterations "$ITERS" \
      --warmup "$WARMUP" 2>&1 | grep -E "SELFTEST|Benchmarking|median|CSV" | head -10

    if [ -f pqc_benchmark_results.csv ]; then
      if [ "$HEADER_WRITTEN" = "0" ]; then
        ORIG_HEADER=$(head -1 pqc_benchmark_results.csv)
        echo "round,run_order,wait_s,backend_binary,$ORIG_HEADER" > "$CSV_OUT"
        HEADER_WRITTEN=1
      fi
      tail -n +2 pqc_benchmark_results.csv | while IFS= read -r line; do
        echo "$ROUND,$ORDER_IN_ROUND,$WAIT,$BENCH,$line" >> "$CSV_OUT"
      done
      rm -f pqc_benchmark_results.csv
    fi
  done
done

# ── Summary ──
TOTAL_ROWS=$(( $(wc -l < "$CSV_OUT") - 1 ))
echo ""
echo "========================================================="
echo " DONE"
echo ""
echo " Rounds      : $ROUNDS"
echo " Backends    : ${#BACKENDS[@]}"
echo " Wait time   : ${WAIT}s before every run"
echo " Total rows  : $TOTAL_ROWS"
echo " Output      : $CSV_OUT"
echo " System info : results/wait_system_info.txt"
echo ""
echo " Analysis:"
echo "   python3 $REPO/compute_ci.py --shuffled $CSV_OUT"
echo "========================================================="
