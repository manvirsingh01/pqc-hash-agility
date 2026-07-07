#!/bin/bash
# =============================================================================
# pure_bench.sh — Benchmark ML-KEM + ML-DSA pure stock implementations
#
# Uses the UNMODIFIED liboqs implementations — no custom hash backends,
# no PQClean forks, no parameter tweaks. Just the standard algorithms
# exactly as they ship in liboqs.
#
# Algorithms:
#   ML-KEM-512 / 768 / 1024   (FIPS 203, keygen + encaps + decaps)
#   ML-DSA-44  / 65  / 87     (FIPS 204, keygen + sign + verify)
#
# Output (in results/pure/ directory):
#   pure_benchmark.csv          — timing + correctness for all 6 algorithms
#   pure_system_info.txt        — system hardware + build configuration
#
# Usage:
#   cd <build-dir>            # directory where setup.sh was run
#   bash /path/to/repo/pure_bench.sh [--iters N] [--warmup N]
#
# Options:
#   --iters  N    iterations per operation (default 200)
#   --warmup N    warmup iterations        (default 20)
# =============================================================================
set -euo pipefail

ITERS=200
WARMUP=20
REPO="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(pwd)"
RESULTS_DIR="$ROOT/results/pure"
mkdir -p "$RESULTS_DIR"

while [ $# -gt 0 ]; do
  case "$1" in
    --iters)  ITERS="$2";  shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,/^# ====/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) shift ;;
  esac
done

OQS_INC="$ROOT/liboqs/build/include"
OQS_STATIC="$ROOT/liboqs/build/lib/liboqs.a"

[ -f "$OQS_STATIC" ] || { echo "ERROR: $OQS_STATIC not found — run setup.sh first"; exit 1; }

echo "========================================================="
echo " PQC Pure Implementation Benchmark"
echo ""
echo " Benchmarks ML-KEM and ML-DSA with their STOCK liboqs"
echo " implementations. No custom hash backends. No modifications."
echo ""
echo " Iterations  : $ITERS"
echo " Warmup      : $WARMUP"
echo " Output      : results/pure/"
echo "========================================================="
echo ""

# ── Real-time launcher (noise reduction) ──
# SCHED_FIFO stops other tasks preempting the benchmark mid-measurement,
# the main source of high-percentile outliers. Falls back to nice -20.
LAUNCHER=""
if chrt -f 99 true 2>/dev/null; then
  LAUNCHER="chrt -f 99"
  echo "[noise] Real-time priority: SCHED_FIFO 99 (via chrt)"
elif nice -n -20 true 2>/dev/null; then
  LAUNCHER="nice -n -20"
  echo "[noise] Priority: nice -20 (chrt unavailable)"
else
  echo "[noise] Default priority (run as root for SCHED_FIFO)"
fi

# ── Generate system info ──
export BENCH_CFLAGS="-O3 (pure_bench.c against stock liboqs, built with -O3 -march=native)"
export BENCH_LAUNCHER="${LAUNCHER:-none (default priority)}"
bash "$REPO/pure_system_info.sh" "$RESULTS_DIR/pure_system_info.txt"

# Per-iteration raw data: every timed sample is appended to
# results/raw/pure_raw.csv (one row per iteration).
RAW_DIR="$ROOT/results/raw"
mkdir -p "$RAW_DIR"
export PQC_RAW_DIR="$RAW_DIR"
export PQC_RAW_TAG="pure"
echo ""

# ── Build pure_bench if not present ──
if [ ! -x "./pure_bench" ]; then
  echo "[build] Compiling pure_bench..."
  gcc -O3 -I "$OQS_INC" \
      -o pure_bench \
      "$REPO/src/bench/pure_bench.c" \
      "$OQS_STATIC" -lcrypto -lm
  echo "[build] Done."
  echo ""
fi

# ── Optional: pin CPU governor ──
if command -v cpupower &>/dev/null 2>&1; then
  if cpupower frequency-set --governor performance &>/dev/null 2>&1; then
    echo "[info] CPU governor → performance"
    trap 'cpupower frequency-set --governor schedutil &>/dev/null 2>&1 || true' EXIT
  fi
else
  echo "[info] cpupower not found — CPU may use variable frequency"
fi
echo ""

# ── Run benchmark ──
$LAUNCHER ./pure_bench \
  --iters  "$ITERS" \
  --warmup "$WARMUP" \
  --csv    "$RESULTS_DIR/pure_benchmark.csv"

ROWS=$(wc -l < "$RESULTS_DIR/pure_benchmark.csv" 2>/dev/null || echo 0)
echo ""
echo "========================================================="
echo " DONE"
echo ""
echo " results/pure/pure_benchmark.csv      — $ROWS rows (incl. header)"
echo " results/pure/pure_system_info.txt    — system info"
echo ""
echo " CSV columns:"
echo "   algorithm, type, operation, correctness, iterations,"
echo "   mean_ns, median_ns, min_ns, max_ns, stddev_ns, p95_ns, p99_ns,"
echo "   ops_per_sec, pk_bytes, sk_bytes, ct_or_sig_bytes, ss_bytes,"
echo "   nist_level"
echo "========================================================="
