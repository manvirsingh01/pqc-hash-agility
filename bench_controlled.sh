#!/bin/bash
# =============================================================================
# bench_controlled.sh — Controlled benchmark runner for statistical rigor
#
# Runs multiple independent benchmark rounds with CPU frequency locking,
# core pinning, and turbo boost disabled. Produces replicated CSV data
# suitable for confidence interval computation via compute_ci.py.
#
# Usage:
#   cd <build-dir>
#   sudo bash /path/to/repo/bench_controlled.sh [options]
#
# Options:
#   --rounds N     Number of independent rounds (default: 10)
#   --iters  N     Iterations per operation per round (default: 5000)
#   --warmup N     Warmup iterations (default: 500)
#   --core   N     CPU core to pin to (default: 0)
#   --settle N     Seconds to idle before EACH backend run (default: 3)
#   --no-lock      Skip CPU frequency locking (for VMs/containers)
#
# Noise / tail-latency controls applied automatically:
#   - SCHED_FIFO real-time priority via chrt (falls back to nice -20)
#   - Per-backend settle wait so thermal state does not carry over
#   - The benchmark binary itself locks pages (mlockall) and requests
#     SCHED_FIFO internally, and reports outlier-robust trimmed-mean stats
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(pwd)"
RESULTS_DIR="$ROOT/results/replications"
mkdir -p "$RESULTS_DIR"

ROUNDS=10
ITERS=5000
WARMUP=500
CORE=0
LOCK_CPU=1
SETTLE=3

while [ $# -gt 0 ]; do
  case "$1" in
    --rounds)  ROUNDS="$2"; shift 2 ;;
    --iters)   ITERS="$2";  shift 2 ;;
    --warmup)  WARMUP="$2"; shift 2 ;;
    --core)    CORE="$2";   shift 2 ;;
    --settle)  SETTLE="$2"; shift 2 ;;
    --no-lock) LOCK_CPU=0;  shift ;;
    --help|-h)
      sed -n '2,/^# ====/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) shift ;;
  esac
done

echo "========================================================="
echo " PQC Controlled Benchmark Runner"
echo " Rounds         : $ROUNDS"
echo " Iterations     : $ITERS  (per operation per round)"
echo " Warmup         : $WARMUP"
echo " Pinned core    : $CORE"
echo " Settle wait    : ${SETTLE}s before each backend run"
echo " CPU lock       : $([ "$LOCK_CPU" = "1" ] && echo "YES" || echo "NO (--no-lock)")"
echo " Output dir     : results/replications/"
echo "========================================================="
echo ""

# ── CPU Controls ──
RESTORE_GOVERNOR=""
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
    echo "[cpu] Restored governor: $RESTORE_GOVERNOR"
  fi
  if [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ] && [ "${OLD_TURBO:-}" = "0" ]; then
    echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || true
    echo "[cpu] Restored turbo boost"
  fi
}
trap cleanup EXIT

# ── Real-time launcher (tail-latency control) ──
# SCHED_FIFO stops other tasks preempting the benchmark mid-measurement,
# which is the main source of high-percentile outliers. Fall back to
# nice -20 when RT scheduling is not permitted.
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

# ── Generate system info ──
bash "$REPO/system_info.sh" "$RESULTS_DIR/system_info.txt"

# ── Detect available benchmarks ──
BENCHES=""
for b in bench_shake bench_turboshake bench_k12 bench_blake3 bench_xoodyak bench_haraka; do
  [ -x "./$b" ] && BENCHES="$BENCHES $b"
done

if [ -z "$BENCHES" ]; then
  echo "ERROR: No benchmark binaries found. Run setup.sh first."
  exit 1
fi
echo ""
echo "Backends found: $BENCHES"
echo ""

# ── Combined CSV header ──
COMBINED_CSV="$RESULTS_DIR/../controlled_benchmark.csv"
HEADER_WRITTEN=0

# ── Run rounds ──
for ROUND in $(seq 1 "$ROUNDS"); do
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Round $ROUND / $ROUNDS"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  ORDER=0
  for BENCH in $BENCHES; do
    ORDER=$((ORDER + 1))
    CSV_OUT="$RESULTS_DIR/round${ROUND}_${BENCH}.csv"
    echo "  [$BENCH] → $(basename "$CSV_OUT")"

    # Settle wait: let the CPU drain thermal/frequency state left by the
    # previous backend so it cannot inflate this backend's tail latency.
    [ "$SETTLE" -gt 0 ] && sleep "$SETTLE"

    rm -f pqc_benchmark_results.csv
    $LAUNCHER "./$BENCH" \
      --iterations "$ITERS" \
      --warmup "$WARMUP" \
      --csv-append 2>&1 | tail -5

    if [ -f pqc_benchmark_results.csv ]; then
      mv pqc_benchmark_results.csv "$CSV_OUT"

      # Append to combined CSV with round + run_order columns
      if [ "$HEADER_WRITTEN" = "0" ]; then
        ORIG_HEADER=$(head -1 "$CSV_OUT")
        echo "round,run_order,backend_binary,$ORIG_HEADER" > "$COMBINED_CSV"
        HEADER_WRITTEN=1
      fi
      tail -n +2 "$CSV_OUT" | while IFS= read -r line; do
        echo "$ROUND,$ORDER,$BENCH,$line" >> "$COMBINED_CSV"
      done
    fi
  done

  if [ "$ROUND" -lt "$ROUNDS" ]; then
    echo "  [cooldown] sleeping 5s..."
    sleep 5
  fi
done

COMBINED_ROWS=$(( $(wc -l < "$COMBINED_CSV" 2>/dev/null || echo 1) - 1 ))
PER_ROUND_COUNT=$(ls "$RESULTS_DIR"/*.csv 2>/dev/null | wc -l)

echo ""
echo "========================================================="
echo " DONE — $ROUNDS rounds × $(echo "$BENCHES" | wc -w) backends"
echo ""
echo " Combined CSV : results/controlled_benchmark.csv ($COMBINED_ROWS rows)"
echo " Per-round    : results/replications/ ($PER_ROUND_COUNT files)"
echo ""
echo " Analyse:"
echo "   python3 $REPO/compute_ci.py --shuffled results/controlled_benchmark.csv"
echo "   python3 $REPO/compute_ci.py --dir results/replications"
echo "========================================================="
