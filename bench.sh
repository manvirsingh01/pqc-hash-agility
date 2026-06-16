#!/bin/bash
# =============================================================================
# bench.sh — Unbiased PQC Hash-Agility Benchmark Runner
#
# Runs all six hash-backend benchmark binaries sequentially, each with a
# fixed iteration count (not time-based), sequential (single-threaded)
# execution, and wall-clock timing via clock_gettime(CLOCK_MONOTONIC).
#
# Design choices for unbiased results:
#   • Fixed --iterations count (not duration-limited) so results are
#     reproducible regardless of CPU speed variation.
#   • Sequential execution — no async, no threads, no parallel runs.
#   • clock_gettime(CLOCK_MONOTONIC) — portable wall-clock timer,
#     independent of CPU frequency or architecture.
#   • Optional CPU governor pin (perf mode) to reduce DVFS jitter.
#   • All six backends run back-to-back in the same environment.
#
# Usage:
#   cd <build-dir>            # where setup.sh was run
#   bash /path/to/bench.sh [--iters N] [--warmup N] [--no-haraka]
#
# Output:  pqc_benchmark_results.csv
# =============================================================================
set -euo pipefail

ITERS=1000
WARMUP=100
NO_HARAKA=0
CSV="pqc_benchmark_results.csv"

for arg in "$@"; do
  case "$arg" in
    --iters)    shift; ITERS="$1" ;;
    --warmup)   shift; WARMUP="$1" ;;
    --no-haraka) NO_HARAKA=1 ;;
    --csv)      shift; CSV="$1" ;;
    --help|-h)
      echo "Usage: bench.sh [--iters N] [--warmup N] [--no-haraka] [--csv PATH]"
      exit 0 ;;
  esac
done

ARCH="$(uname -m)"

echo "======================================================="
echo " PQC Hash-Agility Benchmark"
echo " Arch       : $ARCH"
echo " Iterations : $ITERS  (per operation, fixed count)"
echo " Warmup     : $WARMUP"
echo " Output CSV : $CSV"
echo "======================================================="
echo ""

# ── Optional: pin CPU governor to performance mode (reduces DVFS jitter) ──
if command -v cpupower &>/dev/null; then
  if cpupower frequency-set --governor performance &>/dev/null; then
    echo "[info] CPU governor set to 'performance'"
    trap 'cpupower frequency-set --governor schedutil &>/dev/null || true' EXIT
  fi
else
  echo "[info] cpupower not found — CPU frequency may vary (results may have jitter)"
fi
echo ""

# ── Verify binaries exist ──────────────────────────────────────────────────
for b in bench_shake bench_turboshake bench_k12 bench_blake3 bench_xoodyak; do
  [ -x "./$b" ] || { echo "ERROR: $b not found. Run bash setup.sh first."; exit 1; }
done
if [ "$NO_HARAKA" = "0" ]; then
  [ -x "./bench_haraka" ] || { echo "WARNING: bench_haraka not found; skipping Haraka."; NO_HARAKA=1; }
fi

# ── Sequential benchmark runs ─────────────────────────────────────────────
rm -f "$CSV"

echo "--- [1/6] SHAKE baseline (FIPS-approved, liboqs built-in) ---"
./bench_shake --iterations "$ITERS" --warmup "$WARMUP"

echo ""
echo "--- [2/6] TurboSHAKE (n_r=12, RFC 9861) ---"
./bench_turboshake --iterations "$ITERS" --warmup "$WARMUP" --csv-append

echo ""
echo "--- [3/6] KangarooTwelve (tree-hash, RFC 9861) ---"
./bench_k12 --iterations "$ITERS" --warmup "$WARMUP" --csv-append

echo ""
echo "--- [4/6] BLAKE3 (portable, all SIMD disabled) ---"
./bench_blake3 --iterations "$ITERS" --warmup "$WARMUP" --csv-append

echo ""
echo "--- [5/6] Xoodyak (Xoodoo[12] permutation) ---"
./bench_xoodyak --iterations "$ITERS" --warmup "$WARMUP" --csv-append

if [ "$NO_HARAKA" = "0" ]; then
  echo ""
  echo "--- [6/6] Haraka (AES-based; AES-NI/NEON) ---"
  ./bench_haraka --iterations "$ITERS" --warmup "$WARMUP" --csv-append
else
  echo ""
  echo "--- [6/6] Haraka: SKIPPED ---"
fi

echo ""
echo "======================================================="
echo " Done."
echo " CSV rows : $(wc -l < "$CSV") (incl. header)"
echo " File     : $(pwd)/$CSV"
echo ""
echo " Columns:"
echo "   algorithm, operation, hash_backend, keccak_rounds,"
echo "   fips_compliant, median_cycles, cpb, wall_ns_mean,"
echo "   pk_bytes, sk_bytes, ct_or_sig_bytes, ss_bytes,"
echo "   nist_level, ... (35 columns total)"
echo "======================================================="
