#!/bin/bash
# =============================================================================
# file_sign_bench.sh — Hash + sign a payload file with all six hash backends
#
# Takes a user-supplied payload file and, for each of the six hash backends
# (shake baseline, turboshake, k12, blake3, xoodyak, haraka):
#
#   1. Hashes the payload with the backend's hash function (the exact
#      H/CRH-role construction the backend substitutes into ML-DSA:
#      domain byte 0x3F, 32-byte digest) and records the digest hex code.
#   2. Signs the payload with ML-DSA-44 / 65 / 87 built on that backend
#      and verifies the signatures.
#   3. Benchmarks every operation (hash, sign, verify) over N rounds with
#      per-round wall-clock ns AND cycle-counter readings (rdtsc on x86_64,
#      CNTVCT_EL0 timer ticks on aarch64), as in the earlier raw CSVs.
#
# Nothing about the algorithms, the compiler flags of the already-built
# backend libraries, or the hardware settings is changed — the pre-built
# static libs and adapter objects from setup.sh are linked exactly as they
# are; only the thin harness is compiled.
#
# Output:
#   results/file_sign/file_sign_benchmark.csv   — aggregate stats (ns + cycles
#                                                 + payload info + rounds)
#   results/file_sign/file_sign_hashes.csv      — digest hex codes, signature
#                                                 sizes/fingerprints, payload
#                                                 info, verification results
#   results/file_sign/file_sign_system_info.txt — system info for this run
#   results/raw/file_sign_raw.csv               — per-round raw ns + cycles
#
# Usage:
#   cd <build-dir>            # directory where setup.sh was run
#   bash /path/to/repo/file_sign_bench.sh [--file PAYLOAD] [--iters N] [--warmup N]
#
# Options:
#   --file PATH   payload file to hash + sign (default: a generated
#                 1 MiB random sample at results/file_sign/sample_payload.bin)
#   --iters  N    rounds per operation (default 200)
#   --warmup N    warmup rounds        (default 20)
# =============================================================================
set -euo pipefail

ITERS=200
WARMUP=20
PAYLOAD=""
REPO="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(pwd)"
RESULTS_DIR="$ROOT/results/file_sign"
mkdir -p "$RESULTS_DIR"

while [ $# -gt 0 ]; do
  case "$1" in
    --file)   PAYLOAD="$2"; shift 2 ;;
    --iters)  ITERS="$2";  shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,/^# ====/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) shift ;;
  esac
done

# ── Payload ──
if [ -z "$PAYLOAD" ]; then
  PAYLOAD="$RESULTS_DIR/sample_payload.bin"
  if [ ! -f "$PAYLOAD" ]; then
    head -c 1048576 /dev/urandom > "$PAYLOAD"
    echo "[payload] No --file given — generated 1 MiB random sample: $PAYLOAD"
  else
    echo "[payload] No --file given — reusing existing sample: $PAYLOAD"
  fi
fi
[ -f "$PAYLOAD" ] || { echo "ERROR: payload file not found: $PAYLOAD"; exit 1; }
PAYLOAD="$(cd "$(dirname "$PAYLOAD")" && pwd)/$(basename "$PAYLOAD")"
PAYLOAD_BYTES=$(wc -c < "$PAYLOAD")
PAYLOAD_SHA256=$(sha256sum "$PAYLOAD" | cut -d' ' -f1)

# Same paths and flags as setup.sh — the libs are NOT rebuilt, only the
# thin harness is compiled and linked against them.
OQS_INC="$ROOT/liboqs/build/include"
OQS_STATIC="$ROOT/liboqs/build/lib/liboqs.a"
XKCP_LIB="$ROOT/XKCP/bin/generic64/libXKCP.a"
XKCP_HDRS="$ROOT/XKCP/bin/generic64/libXKCP.a.headers"
BASE_CFLAGS="-O3 -march=native"
case "$(uname -m)" in
  x86_64)          HARAKA_CFLAGS="-maes -msse4.1 -O3" ;;
  aarch64|arm64)   HARAKA_CFLAGS="-march=native -O3"  ;;
  *)               HARAKA_CFLAGS="$BASE_CFLAGS"       ;;
esac
INCS="-I $OQS_INC -I $ROOT -I $ROOT/PQClean/common -I $ROOT/PQClean/common/BLAKE3 -I $ROOT/PQClean/common/Haraka -I $XKCP_HDRS"

[ -f "$OQS_STATIC" ] || { echo "ERROR: $OQS_STATIC not found — run setup.sh first"; exit 1; }

BACKENDS=""
for tag in shake turboshake k12 blake3 xoodyak haraka; do
  [ -f "$ROOT/pqc_${tag}_dsa.o" ] && BACKENDS="$BACKENDS $tag"
done
[ -n "$BACKENDS" ] || { echo "ERROR: no backend adapter objects found — run setup.sh first"; exit 1; }

echo "========================================================="
echo " PQC File Hash + Sign Benchmark"
echo ""
echo " Hashes and ML-DSA-signs a payload file with all six hash"
echo " backends; per-round wall-clock ns + cycle-counter raw data."
echo " No algorithm, compiler-flag or hardware changes."
echo ""
echo " Payload     : $PAYLOAD"
echo "               $PAYLOAD_BYTES bytes, sha256 $PAYLOAD_SHA256"
echo " Backends    :$BACKENDS"
echo " Rounds      : $ITERS (+$WARMUP warmup)"
echo " Output      : results/file_sign/"
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

# ── Generate system info (+ payload section) ──
export BENCH_CFLAGS="$BASE_CFLAGS (harness; backend libs as built by setup.sh, unchanged)"
export BENCH_LAUNCHER="${LAUNCHER:-none (default priority)}"
SYSINFO="$RESULTS_DIR/file_sign_system_info.txt"
bash "$REPO/pure_system_info.sh" "$SYSINFO"
{
  echo ""
  echo "── Payload (this benchmark run) ──"
  echo "File        : $PAYLOAD"
  echo "Size        : $PAYLOAD_BYTES bytes"
  echo "SHA-256     : $PAYLOAD_SHA256"
  echo "Rounds      : $ITERS per operation (+$WARMUP warmup)"
} >> "$SYSINFO"

# Per-round raw data. The two combined CSVs and the raw file are all
# appended to by the six per-backend binaries, so start them fresh to
# keep them exactly matching this run.
RAW_DIR="$ROOT/results/raw"
mkdir -p "$RAW_DIR"
export PQC_RAW_DIR="$RAW_DIR"
export PQC_RAW_TAG="file_sign"
COMBINED_CSV="$RESULTS_DIR/file_sign_benchmark.csv"
HASHES_CSV="$RESULTS_DIR/file_sign_hashes.csv"
rm -f "$COMBINED_CSV" "$HASHES_CSV" "$RAW_DIR/file_sign_raw.csv"
echo ""

# ── Build one harness binary per backend ──
for tag in $BACKENDS; do
  UTAG=$(echo "$tag" | tr '[:lower:]' '[:upper:]')
  HFLAGS="$BASE_CFLAGS"; [ "$tag" = "haraka" ] && HFLAGS="$HARAKA_CFLAGS"

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

  echo "[build] file_sign_${tag}"
  gcc $HFLAGS -DUSE_${UTAG} $INCS \
      -c "$REPO/src/bench/file_sign_bench.c" -o "file_sign_${tag}.o"
  gcc $HFLAGS \
      "file_sign_${tag}.o" "pqc_${tag}_dsa.o" \
      $SLIBS \
      PQClean/common/fips202_turbo.o PQClean/common/randombytes_turbo.o \
      $EXTRALIB \
      "$OQS_STATIC" -lcrypto -lm -o "file_sign_${tag}"
done
echo ""

# ── Run all backends ──
for tag in $BACKENDS; do
  echo "━━━ backend: $tag ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  sleep 3   # settle: drain thermal state left by the previous backend
  $LAUNCHER "./file_sign_${tag}" \
    --file    "$PAYLOAD" \
    --iters   "$ITERS" \
    --warmup  "$WARMUP" \
    --csv     "$COMBINED_CSV" \
    --hashcsv "$HASHES_CSV"
  echo ""
done

ROWS=$(wc -l < "$COMBINED_CSV" 2>/dev/null || echo 0)
HROWS=$(wc -l < "$HASHES_CSV" 2>/dev/null || echo 0)
RAWROWS=$(wc -l < "$RAW_DIR/file_sign_raw.csv" 2>/dev/null || echo 0)
echo "========================================================="
echo " DONE"
echo ""
echo " results/file_sign/file_sign_benchmark.csv   — $ROWS rows (incl. header)"
echo " results/file_sign/file_sign_hashes.csv      — $HROWS rows (incl. header)"
echo " results/raw/file_sign_raw.csv               — $RAWROWS rows (incl. header)"
echo " results/file_sign/file_sign_system_info.txt"
echo ""
echo " Benchmark CSV columns:"
echo "   backend, algorithm, operation, payload_file, payload_bytes,"
echo "   correctness, rounds, mean_ns, median_ns, min_ns, max_ns,"
echo "   stddev_ns, p95_ns, p99_ns, ops_per_sec, mean_cycles,"
echo "   median_cycles, cycle_unit, payload_mb_per_sec, out_bytes, nist_level"
echo " Hashes CSV columns:"
echo "   backend, record, algorithm, construction, payload_file,"
echo "   payload_bytes, payload_sha256, rounds, output_bytes, output_hex,"
echo "   verify"
echo " Raw CSV columns:"
echo "   backend, algorithm, operation, iteration, ns, cycles, cycle_unit"
echo "========================================================="
