#!/bin/bash
# =============================================================================
# bench.sh — PQC Hash-Agility Benchmark Runner
#
# Produces TWO separate CSV files:
#
#   1. custom_benchmark.csv
#      Our custom hash-backend implementations (all 6 backends × 6 algorithms).
#      Uses the forked PQClean static libs and OQS adapter shims.
#
#   2. library_default_benchmark.csv
#      Every KEM and SIG algorithm built into liboqs, using the library's own
#      standard implementations.  No custom code — pure library behaviour.
#
# Usage:
#   cd <build-dir>            # directory where setup.sh was run
#   bash /path/to/repo/bench.sh [options]
#
# Options:
#   --iters   N    iterations per operation for custom bench  (default 1000)
#   --liters  N    iterations per operation for default bench (default 200)
#   --warmup  N    warmup iterations before timing            (default 100)
#   --no-haraka    skip Haraka backend
#   --custom-only  run custom_benchmark.csv only
#   --default-only run library_default_benchmark.csv only
# =============================================================================
set -euo pipefail

ITERS=1000
LITERS=200
WARMUP=100
NO_HARAKA=0
CUSTOM_ONLY=0
DEFAULT_ONLY=0
REPO="$(cd "$(dirname "$0")" && pwd)"

for arg in "$@"; do
  case "$arg" in
    --iters)        shift; ITERS="$1" ;;
    --liters)       shift; LITERS="$1" ;;
    --warmup)       shift; WARMUP="$1" ;;
    --no-haraka)    NO_HARAKA=1 ;;
    --custom-only)  CUSTOM_ONLY=1 ;;
    --default-only) DEFAULT_ONLY=1 ;;
    --help|-h)
      sed -n '2,/^# ====/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
      exit 0 ;;
  esac
done

ARCH="$(uname -m)"

echo "========================================================="
echo " PQC Hash-Agility Benchmark Suite"
echo " Arch          : $ARCH"
echo " Custom iters  : $ITERS  (per operation)"
echo " Default iters : $LITERS (per operation)"
echo " Warmup        : $WARMUP"
echo " Output:"
echo "   custom_benchmark.csv           — our 6 backends × 6 algorithms"
echo "   library_default_benchmark.csv  — all liboqs built-in algorithms"
echo "========================================================="
echo ""

# ── Generate system info ──
bash "$REPO/system_info.sh" system_info.txt
echo ""

# ── Optional: pin CPU to performance governor (reduces timing jitter) ──
if command -v cpupower &>/dev/null 2>&1; then
  if cpupower frequency-set --governor performance &>/dev/null 2>&1; then
    echo "[info] CPU governor → performance"
    trap 'cpupower frequency-set --governor schedutil &>/dev/null 2>&1 || true' EXIT
  fi
else
  echo "[info] cpupower not found — CPU may use variable frequency (results may jitter)"
fi
echo ""

# ══════════════════════════════════════════════════════════════════════
# CSV 1: CUSTOM BENCHMARK
# ══════════════════════════════════════════════════════════════════════
if [ "$DEFAULT_ONLY" = "0" ]; then

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo " CSV 1/2: custom_benchmark.csv"
  echo " (our forked PQClean backends, correctness + timing)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""

  # Check binaries
  for b in bench_shake bench_turboshake bench_k12 bench_blake3 bench_xoodyak; do
    [ -x "./$b" ] || { echo "ERROR: $b not found — run bash setup.sh first"; exit 1; }
  done
  if [ "$NO_HARAKA" = "0" ] && [ ! -x "./bench_haraka" ]; then
    echo "WARNING: bench_haraka not found; skipping (pass --no-haraka to suppress)"
    NO_HARAKA=1
  fi

  rm -f custom_benchmark.csv

  echo "--- [1/6] SHAKE  (FIPS-approved SHAKE/SHA-3, liboqs built-in) ---"
  ./bench_shake \
    --iterations "$ITERS" \
    --warmup "$WARMUP"

  echo ""
  echo "--- [2/6] TurboSHAKE  (n_r=12, RFC 9861) ---"
  ./bench_turboshake \
    --iterations "$ITERS" \
    --warmup "$WARMUP" \
    --csv-append

  echo ""
  echo "--- [3/6] KangarooTwelve  (tree hash, RFC 9861) ---"
  ./bench_k12 \
    --iterations "$ITERS" \
    --warmup "$WARMUP" \
    --csv-append

  echo ""
  echo "--- [4/6] BLAKE3  (portable XOF, all SIMD disabled) ---"
  ./bench_blake3 \
    --iterations "$ITERS" \
    --warmup "$WARMUP" \
    --csv-append

  echo ""
  echo "--- [5/6] Xoodyak  (Xoodoo[12] permutation) ---"
  ./bench_xoodyak \
    --iterations "$ITERS" \
    --warmup "$WARMUP" \
    --csv-append

  if [ "$NO_HARAKA" = "0" ]; then
    echo ""
    echo "--- [6/6] Haraka  (AES-NI on x86_64 / NEON on aarch64) ---"
    ./bench_haraka \
      --iterations "$ITERS" \
      --warmup "$WARMUP" \
      --csv-append
  else
    echo ""
    echo "--- [6/6] Haraka  SKIPPED ---"
  fi

  # Rename pqc_benchmark_results.csv → custom_benchmark.csv
  [ -f pqc_benchmark_results.csv ] && mv pqc_benchmark_results.csv custom_benchmark.csv

  CUSTOM_ROWS=$(wc -l < custom_benchmark.csv 2>/dev/null || echo 0)
  echo ""
  echo "✓ custom_benchmark.csv  —  $CUSTOM_ROWS rows (incl. header)"

fi  # end CSV 1

# ══════════════════════════════════════════════════════════════════════
# CSV 2: DEFAULT LIBRARY BENCHMARK
# ══════════════════════════════════════════════════════════════════════
if [ "$CUSTOM_ONLY" = "0" ]; then

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo " CSV 2/2: library_default_benchmark.csv"
  echo " (ALL liboqs built-in KEM + SIG algorithms, correctness + timing)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""

  # Build liboqs_bench if not present
  if [ ! -x "./liboqs_bench" ]; then
    echo "[build] Compiling liboqs_bench..."
    make -f "$REPO/src/bench/Makefile" REPO="$REPO" liboqs_bench
    echo ""
  fi

  ./liboqs_bench \
    --iters  "$LITERS" \
    --warmup "$WARMUP" \
    --csv    library_default_benchmark.csv

  DEFAULT_ROWS=$(wc -l < library_default_benchmark.csv 2>/dev/null || echo 0)
  echo ""
  echo "✓ library_default_benchmark.csv  —  $DEFAULT_ROWS rows (incl. header)"

fi  # end CSV 2

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "========================================================="
echo " DONE"
echo ""
if [ "$DEFAULT_ONLY" = "0" ]; then
  echo " custom_benchmark.csv"
  echo "   Columns: algorithm, operation, hash_backend, keccak_rounds,"
  echo "            fips_compliant, median_cycles, cpb, wall_ns_mean,"
  echo "            wall_ns_median, wall_ns_min, wall_ns_max, wall_ns_stddev,"
  echo "            pk_bytes, sk_bytes, ct_or_sig_bytes, ss_bytes, nist_level"
  echo ""
fi
if [ "$CUSTOM_ONLY" = "0" ]; then
  echo " library_default_benchmark.csv"
  echo "   Columns: library, algorithm, type, operation,"
  echo "            correctness, iterations,"
  echo "            mean_ns, median_ns, min_ns, max_ns,"
  echo "            stddev_ns, p95_ns, p99_ns, ops_per_sec,"
  echo "            pk_bytes, sk_bytes, ct_or_sig_bytes, ss_bytes, nist_level"
  echo ""
fi
echo "========================================================="
