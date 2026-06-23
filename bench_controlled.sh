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
#   --no-lock      Skip CPU frequency locking (for VMs/containers)
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

while [ $# -gt 0 ]; do
  case "$1" in
    --rounds)  ROUNDS="$2"; shift 2 ;;
    --iters)   ITERS="$2";  shift 2 ;;
    --warmup)  WARMUP="$2"; shift 2 ;;
    --core)    CORE="$2";   shift 2 ;;
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

# ── Run rounds ──
for ROUND in $(seq 1 "$ROUNDS"); do
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Round $ROUND / $ROUNDS"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  for BENCH in $BENCHES; do
    CSV_OUT="$RESULTS_DIR/round${ROUND}_${BENCH}.csv"
    echo "  [$BENCH] → $(basename "$CSV_OUT")"

    taskset -c "$CORE" "./$BENCH" \
      --iterations "$ITERS" \
      --warmup "$WARMUP" \
      --csv-append 2>&1 | tail -5

    [ -f pqc_benchmark_results.csv ] && mv pqc_benchmark_results.csv "$CSV_OUT"
  done

  if [ "$ROUND" -lt "$ROUNDS" ]; then
    echo "  [cooldown] sleeping 5s..."
    sleep 5
  fi
done

echo ""
echo "========================================================="
echo " DONE — $ROUNDS rounds × $(echo "$BENCHES" | wc -w) backends"
echo ""
echo " Results: results/replications/"
ls -la "$RESULTS_DIR"/*.csv 2>/dev/null | wc -l
echo " CSV files generated"
echo ""
echo " Next: python3 $REPO/compute_ci.py"
echo "========================================================="
