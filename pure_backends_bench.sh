#!/bin/bash
# =============================================================================
# pure_backends_bench.sh — Pure-style benchmark of the six hash backends
#
# Benchmarks the project's six hash-substituted backends (shake baseline,
# turboshake, k12, blake3, xoodyak, haraka) inside ML-KEM and ML-DSA using
# the SAME simple raw methodology as pure_bench.sh: plain wall-clock timing,
# one warmup pass, one timed loop. Nothing about the algorithms, the compiler
# flags of the already-built backend libraries, or the hardware settings is
# changed — the pre-built static libs and adapter objects from setup.sh are
# linked exactly as they are.
#
# Algorithms (per backend):
#   ML-KEM-512 / 768 / 1024   (FIPS 203, keygen + encaps + decaps)
#   ML-DSA-44  / 65  / 87     (FIPS 204, keygen + sign + verify)
#
# Output:
#   results/pure_backends/pure_backends_benchmark.csv   — all 6 backends
#   results/pure_backends/pure_backends_system_info.txt — system info
#   results/raw/pure_backends_raw.csv                   — per-iteration raw
#
# Usage:
#   cd <build-dir>            # directory where setup.sh was run
#   bash /path/to/repo/pure_backends_bench.sh [--iters N] [--warmup N]
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
RESULTS_DIR="$ROOT/results/pure_backends"
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

# Same paths and flags as setup.sh — the libs are NOT rebuilt, only the
# thin pure-style harness is compiled and linked against them.
OQS_INC="$ROOT/liboqs/build/include"
OQS_STATIC="$ROOT/liboqs/build/lib/liboqs.a"
XKCP_LIB="$ROOT/XKCP/bin/generic64/libXKCP.a"
BASE_CFLAGS="-O3 -march=native"
case "$(uname -m)" in
  x86_64)          HARAKA_CFLAGS="-maes -msse4.1 -O3" ;;
  aarch64|arm64)   HARAKA_CFLAGS="-march=native -O3"  ;;
  *)               HARAKA_CFLAGS="$BASE_CFLAGS"       ;;
esac

[ -f "$OQS_STATIC" ] || { echo "ERROR: $OQS_STATIC not found — run setup.sh first"; exit 1; }

BACKENDS=""
for tag in shake turboshake k12 blake3 xoodyak haraka; do
  if [ -f "$ROOT/pqc_${tag}_kem.o" ] && [ -f "$ROOT/pqc_${tag}_dsa.o" ]; then
    BACKENDS="$BACKENDS $tag"
  fi
done
[ -n "$BACKENDS" ] || { echo "ERROR: no backend adapter objects found — run setup.sh first"; exit 1; }

echo "========================================================="
echo " PQC Pure Backend Benchmark"
echo ""
echo " Six hash backends in ML-KEM + ML-DSA, measured with the"
echo " same simple raw wall-clock methodology as pure_bench.sh."
echo " No algorithm, compiler-flag or hardware changes."
echo ""
echo " Backends    :$BACKENDS"
echo " Iterations  : $ITERS"
echo " Warmup      : $WARMUP"
echo " Output      : results/pure_backends/"
echo "========================================================="
echo ""

# ── Real-time launcher (noise reduction) ──
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
export BENCH_CFLAGS="$BASE_CFLAGS (harness; backend libs as built by setup.sh, unchanged)"
export BENCH_LAUNCHER="${LAUNCHER:-none (default priority)}"
bash "$REPO/pure_system_info.sh" "$RESULTS_DIR/pure_backends_system_info.txt"

# Per-iteration raw data. The combined CSV and the raw file are both
# appended to by the six per-backend binaries, so start both fresh to
# keep them exactly matching this run.
RAW_DIR="$ROOT/results/raw"
mkdir -p "$RAW_DIR"
export PQC_RAW_DIR="$RAW_DIR"
export PQC_RAW_TAG="pure_backends"
COMBINED_CSV="$RESULTS_DIR/pure_backends_benchmark.csv"
rm -f "$COMBINED_CSV" "$RAW_DIR/pure_backends_raw.csv"
echo ""

# ── Build one pure-style binary per backend ──
for tag in $BACKENDS; do
  UTAG=$(echo "$tag" | tr '[:lower:]' '[:upper:]')
  HFLAGS="$BASE_CFLAGS"; [ "$tag" = "haraka" ] && HFLAGS="$HARAKA_CFLAGS"

  KLIBS=""
  for v in 512 768 1024; do
    KLIBS="$KLIBS PQClean/crypto_kem/ml-kem-$v/$tag/libml-kem-${v}_${tag}.a"
  done
  SLIBS=""
  STAG="$tag"; [ "$tag" = "turboshake" ] && STAG="turbo"
  for v in 44 65 87; do
    SLIBS="$SLIBS PQClean/crypto_sign/ml-dsa-$v/$tag/libml-dsa-${v}_${STAG}.a"
  done

  EXTRALIB=""
  case "$tag" in
    turboshake|k12|xoodyak) EXTRALIB="$XKCP_LIB" ;;
    blake3)                 EXTRALIB="$ROOT/PQClean/common/BLAKE3/libblake3.a" ;;
    haraka)                 EXTRALIB="$ROOT/PQClean/common/Haraka/libharaka.a" ;;
  esac

  echo "[build] pure_bench_${tag}"
  gcc $HFLAGS -DUSE_${UTAG} -I "$OQS_INC" -I "$ROOT" \
      -c "$REPO/src/bench/pure_backends_bench.c" -o "pure_backends_${tag}.o"
  gcc $HFLAGS \
      "pure_backends_${tag}.o" "pqc_${tag}_kem.o" "pqc_${tag}_dsa.o" \
      $KLIBS $SLIBS \
      PQClean/common/fips202_turbo.o PQClean/common/randombytes_turbo.o \
      $EXTRALIB \
      "$OQS_STATIC" -lcrypto -lm -o "pure_bench_${tag}"
done
echo ""

# ── Run all backends ──
for tag in $BACKENDS; do
  echo "━━━ backend: $tag ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  sleep 3   # settle: drain thermal state left by the previous backend
  $LAUNCHER "./pure_bench_${tag}" \
    --iters  "$ITERS" \
    --warmup "$WARMUP" \
    --csv    "$COMBINED_CSV"
  echo ""
done

ROWS=$(wc -l < "$COMBINED_CSV" 2>/dev/null || echo 0)
RAWROWS=$(wc -l < "$RAW_DIR/pure_backends_raw.csv" 2>/dev/null || echo 0)
echo "========================================================="
echo " DONE"
echo ""
echo " results/pure_backends/pure_backends_benchmark.csv — $ROWS rows (incl. header)"
echo " results/raw/pure_backends_raw.csv                  — $RAWROWS rows (incl. header)"
echo " results/pure_backends/pure_backends_system_info.txt"
echo ""
echo " CSV columns:"
echo "   backend, algorithm, type, operation, correctness, iterations,"
echo "   mean_ns, median_ns, min_ns, max_ns, stddev_ns, p95_ns, p99_ns,"
echo "   ops_per_sec, pk_bytes, sk_bytes, ct_or_sig_bytes, ss_bytes,"
echo "   nist_level"
echo "========================================================="
