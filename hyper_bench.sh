#!/bin/bash
# =============================================================================
# hyper_bench.sh — Interactive PQC Hyperparameter Benchmark
#
# Explore how cryptographic hyperparameters affect PQC performance.
# Similar to kem_k_bench.sh (which varies ML-KEM's k value), this script
# provides fine-grained control over all tunable parameters for both
# ML-KEM and ML-DSA algorithms.
#
# ML-KEM parameters:
#   k          — module rank (1-8)
#   Profile    — compression profile (A: du=10,dv=4,eta1=3 or B: du=11,dv=5,eta1=2)
#
# ML-DSA parameters:
#   K          — matrix rows (1-12)
#   L          — matrix columns (1-12)
#   tau        — challenge weight (1-64)
#   omega      — hint budget (1-256)
#
# Recompiles PQClean source with patched params and benchmarks correctness
# + timing for keygen/encaps/decaps (KEM) or keygen/sign/verify (DSA).
#
# For each parameter combination, generates BOTH benchmark types:
#   custom  — user-selected (tweaked) hyperparameters
#   library — standard default parameters (baseline comparison)
#
# Output: kem_hyper_benchmark.csv or dsa_hyper_benchmark.csv
#
# Usage:
#   cd <build-dir>
#   bash /path/to/repo/hyper_bench.sh [--iters N] [--warmup N]
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(pwd)"
ITERS=1000
WARMUP=100

while [ $# -gt 0 ]; do
  case "$1" in
    --iters)  ITERS="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,/^# ====/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) shift ;;
  esac
done

ARCH="$(uname -m)"
PQCLEAN="$ROOT/PQClean"
PQCLEAN_CUSTOM="$REPO/PQClean_custom"
OQS_INC="$ROOT/liboqs/build/include"
OQS_STATIC="$ROOT/liboqs/build/lib/liboqs.a"
XKCP_LIB="$ROOT/XKCP/bin/generic64/libXKCP.a"
XKCP_HDRS="$ROOT/XKCP/bin/generic64/libXKCP.a.headers"
BLAKE3_DIR="$PQCLEAN/common/BLAKE3"
HARAKA_DIR="$PQCLEAN/common/Haraka"
COMMON_DIR="$PQCLEAN/common"

if [ "$ARCH" = "x86_64" ]; then
  HARAKA_CFLAGS="-maes -msse4.1"
else
  HARAKA_CFLAGS=""
fi

BLAKE3_FLAGS="-DBLAKE3_USE_NEON=0 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512"

for f in "$OQS_STATIC" "$XKCP_LIB"; do
  [ -f "$f" ] || { echo "ERROR: $f not found. Run setup.sh first."; exit 1; }
done

# ── Generate system info ──
bash "$REPO/system_info.sh" system_info.txt

# ── Backend selection ──
select_backends() {
  echo ""
  echo "  Hash backends:"
  echo "  ───────────────────────────────────────────"
  echo "  1) shake       — FIPS SHAKE/SHA-3"
  echo "  2) turboshake  — TurboSHAKE (n_r=12)"
  echo "  3) k12         — KangarooTwelve"
  echo "  4) blake3      — BLAKE3 XOF"
  echo "  5) xoodyak     — Xoodyak / Xoodoo[12]"
  echo "  6) haraka      — Haraka (AES-NI / NEON)"
  echo "  7) ALL         — All 6 backends"
  echo ""
  read -rp "  Select backend [1-7]: " BC
  case "$BC" in
    1) BACKENDS=("shake") ;;
    2) BACKENDS=("turboshake") ;;
    3) BACKENDS=("k12") ;;
    4) BACKENDS=("blake3") ;;
    5) BACKENDS=("xoodyak") ;;
    6) BACKENDS=("haraka") ;;
    7) BACKENDS=("shake" "turboshake" "k12" "blake3" "xoodyak" "haraka") ;;
    *) echo "Invalid selection"; exit 1 ;;
  esac
}

# ═══════════════════════════════════════════════════════════════
# Main menu
# ═══════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   PQC Hyperparameter Benchmark                         ║"
echo "║                                                         ║"
echo "║   Tweak cryptographic parameters and measure impact     ║"
echo "║   on performance, key sizes, and correctness.           ║"
echo "║                                                         ║"
echo "║   Generates both custom and library benchmarks.         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Algorithm family:"
echo "  ───────────────────────────────────────────"
echo "  1) ML-KEM  — Key Encapsulation (FIPS 203)"
echo "     Tweak: k (module rank), compression profile (du/dv/eta1)"
echo ""
echo "  2) ML-DSA  — Digital Signature (FIPS 204)"
echo "     Tweak: K (rows), L (cols), tau (challenge), omega (hints)"
echo ""
read -rp "  Select [1-2]: " FAMILY

HBUILD="$ROOT/.hyper_build"
mkdir -p "$HBUILD"

echo ""
echo "[build] Compiling common objects..."
gcc -O3 -march=native -I"$COMMON_DIR" -c -o "$HBUILD/fips202.o" "$COMMON_DIR/fips202.c"
gcc -O3 -march=native -I"$COMMON_DIR" -c -o "$HBUILD/randombytes.o" "$COMMON_DIR/randombytes.c"
COMMON_OBJS="$HBUILD/fips202.o $HBUILD/randombytes.o"

# ═══════════════════════════════════════════════════════════════
#  ML-KEM HYPERPARAMETER BENCHMARK
# ═══════════════════════════════════════════════════════════════
if [ "$FAMILY" = "1" ]; then

  CSV="kem_hyper_benchmark.csv"

  echo ""
  echo "  ── ML-KEM Compression Profile ──"
  echo ""
  echo "  The compression profile determines the ciphertext encoding."
  echo "  Each profile is tied to specific source code (bit-packing)."
  echo ""
  echo "  ┌──────────┬───────┬───────┬──────────┬────────────────────────┐"
  echo "  │ Profile  │ eta1  │ du    │ dv       │ Notes                  │"
  echo "  ├──────────┼───────┼───────┼──────────┼────────────────────────┤"
  echo "  │ A        │   3   │  10   │   4      │ 512/768 style          │"
  echo "  │          │       │       │          │ More aggressive compr. │"
  echo "  ├──────────┼───────┼───────┼──────────┼────────────────────────┤"
  echo "  │ B        │   2   │  11   │   5      │ 1024 style             │"
  echo "  │          │       │       │          │ Conservative compr.    │"
  echo "  └──────────┴───────┴───────┴──────────┴────────────────────────┘"
  echo ""
  read -rp "  Select profile [A/B]: " PROFILE
  PROFILE=$(echo "$PROFILE" | tr '[:lower:]' '[:upper:]')

  if [ "$PROFILE" = "A" ]; then
    ETA1=3; ETA2=2; DU=10; DV=4
    POLYCOMP=128; PVCOMP_K=320
    KEM_TEMPLATE="ml-kem-512"
    PROF_LABEL="A (du=10, dv=4, eta1=3)"
    DEF_K=2
  elif [ "$PROFILE" = "B" ]; then
    ETA1=2; ETA2=2; DU=11; DV=5
    POLYCOMP=160; PVCOMP_K=352
    KEM_TEMPLATE="ml-kem-1024"
    PROF_LABEL="B (du=11, dv=5, eta1=2)"
    DEF_K=4
  else
    echo "ERROR: Invalid profile. Use A or B."; exit 1
  fi

  echo ""
  echo "  ── k values (module rank) ──"
  echo ""
  echo "  Standard:  k=2 (ML-KEM-512), k=3 (768), k=4 (1024)"
  echo "  Research:  k=1 (very small), k=5..8 (larger lattice)"
  echo ""
  echo "  ┌───────┬──────────────────────────────────────────────┐"
  echo "  │  k    │ Description                                  │"
  echo "  ├───────┼──────────────────────────────────────────────┤"
  echo "  │  1    │ Very small (research only, weak security)    │"
  echo "  │  2    │ Standard: ML-KEM-512 (NIST Level 1)         │"
  echo "  │  3    │ Standard: ML-KEM-768 (NIST Level 3)         │"
  echo "  │  4    │ Standard: ML-KEM-1024 (NIST Level 5)        │"
  echo "  │ 5-8   │ Extended (research, stronger lattice)        │"
  echo "  └───────┴──────────────────────────────────────────────┘"
  echo ""
  read -rp "  k values [space-separated, 1-8]: " K_INPUT
  K_VALUES=($K_INPUT)

  for k in "${K_VALUES[@]}"; do
    if ! [[ "$k" =~ ^[1-8]$ ]]; then
      echo "ERROR: k=$k is out of range (1-8)"; exit 1
    fi
  done

  select_backends

  CUSTOM_TOTAL=$(( ${#K_VALUES[@]} * ${#BACKENDS[@]} ))
  LIBRARY_TOTAL=${#BACKENDS[@]}
  TOTAL=$((LIBRARY_TOTAL + CUSTOM_TOTAL))
  echo ""
  echo "  ───────────────────────────────────────────"
  echo "  Family       : ML-KEM"
  echo "  Profile      : $PROF_LABEL"
  echo "  k values     : ${K_VALUES[*]}"
  echo "  Backends     : ${BACKENDS[*]}"
  echo "  Library runs : $LIBRARY_TOTAL (default k=$DEF_K per backend)"
  echo "  Custom runs  : $CUSTOM_TOTAL"
  echo "  Total runs   : $TOTAL"
  echo "  Iterations   : $ITERS"
  echo "  Warmup       : $WARMUP"
  echo "  Output CSV   : $CSV"
  echo "  ───────────────────────────────────────────"
  echo ""
  read -rp "  Press ENTER to start... "

  echo "backend,algorithm,profile,k,eta1,eta2,du,dv,type,operation,correctness,iterations,mean_ns,median_ns,min_ns,max_ns,stddev_ns,p95_ns,p99_ns,ops_per_sec,pk_bytes,sk_bytes,ct_bytes,ss_bytes" > "$ROOT/$CSV"

  # ── KEM compile + benchmark function ──
  run_kem_bench() {
    local K=$1 BACKEND=$2 BENCH_TYPE=$3

    local PK_BYTES=$((384 * K + 32))
    local SK_BYTES=$((768 * K + 96))
    local CT_BYTES=$((K * PVCOMP_K + POLYCOMP))

    local SRC_DIR
    if [ "$BACKEND" = "shake" ]; then
      SRC_DIR="$PQCLEAN/crypto_kem/$KEM_TEMPLATE/clean"
    else
      SRC_DIR="$PQCLEAN_CUSTOM/crypto_kem/$KEM_TEMPLATE/$BACKEND"
    fi

    if [ ! -d "$SRC_DIR" ]; then
      echo "  [SKIP] $SRC_DIR not found"
      return
    fi

    local VDIR="$HBUILD/kem-k${K}-${BACKEND}-P${PROFILE}-${BENCH_TYPE}"
    rm -rf "$VDIR"; mkdir -p "$VDIR"
    cp "$SRC_DIR"/*.c "$SRC_DIR"/*.h "$VDIR/" 2>/dev/null || true

    local PREFIX
    PREFIX=$(grep -o 'PQCLEAN_[A-Z0-9_]*_crypto_kem_keypair' "$VDIR/api.h" 2>/dev/null | head -1 | sed 's/_crypto_kem_keypair//' || echo "")
    if [ -z "$PREFIX" ]; then
      echo "  [SKIP] Cannot detect function prefix from api.h"
      return
    fi

    cat > "$VDIR/params.h" << PEOF
#ifndef HYPER_KEM_PARAMS_H
#define HYPER_KEM_PARAMS_H
#define KYBER_N 256
#define KYBER_Q 3329
#define KYBER_SYMBYTES 32
#define KYBER_SSBYTES  32
#define KYBER_POLYBYTES 384
#define KYBER_POLYVECBYTES (KYBER_K * KYBER_POLYBYTES)
#define KYBER_K $K
#define KYBER_ETA1 $ETA1
#define KYBER_ETA2 $ETA2
#define KYBER_POLYCOMPRESSEDBYTES    $POLYCOMP
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * $PVCOMP_K)
#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)
#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)
#endif
PEOF

    cat > "$VDIR/api.h" << AEOF
#ifndef HYPER_KEM_API_H
#define HYPER_KEM_API_H
#include <stdint.h>
#define ${PREFIX}_CRYPTO_SECRETKEYBYTES  $SK_BYTES
#define ${PREFIX}_CRYPTO_PUBLICKEYBYTES  $PK_BYTES
#define ${PREFIX}_CRYPTO_CIPHERTEXTBYTES $CT_BYTES
#define ${PREFIX}_CRYPTO_BYTES           32
#define ${PREFIX}_CRYPTO_ALGNAME "ML-KEM-k${K}-P${PROFILE}"
int ${PREFIX}_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int ${PREFIX}_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int ${PREFIX}_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif
AEOF

    local CFLAGS_V="-O3 -march=native -Wall -I$VDIR -I$COMMON_DIR -I$OQS_INC -I$XKCP_HDRS -I$BLAKE3_DIR -I$HARAKA_DIR $BLAKE3_FLAGS $HARAKA_CFLAGS"

    local OBJ_FILES=""
    local COMPILE_OK=1
    local SRC_FILE OBJ
    for SRC_FILE in "$VDIR"/*.c; do
      [ -f "$SRC_FILE" ] || continue
      OBJ="$VDIR/$(basename "$SRC_FILE" .c).o"
      if ! gcc $CFLAGS_V -c -o "$OBJ" "$SRC_FILE" 2>&1; then
        echo "  [ERROR] compile $(basename "$SRC_FILE")"
        COMPILE_OK=0; break
      fi
      OBJ_FILES="$OBJ_FILES $OBJ"
    done
    [ "$COMPILE_OK" = "1" ] || return

    local LIB="$VDIR/libmlkem_hyper.a"
    ar rcs "$LIB" $OBJ_FILES

    local BENCH_C="$VDIR/bench_hyper.c"
    cat > "$BENCH_C" << 'BENCHEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <time.h>
#include "api.h"
#include "params.h"
static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
typedef struct {
    uint64_t mean, median, mn, mx, sd, p95, p99;
    double ops;
} Stats;
static Stats compute(uint64_t *s, int n) {
    Stats r = {0};
    qsort(s, (size_t)n, sizeof(uint64_t), cmp_u64);
    r.mn = s[0]; r.mx = s[n - 1];
    r.median = (n & 1) ? s[n / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
    r.p95 = s[(int)(n * 0.95)];
    r.p99 = s[(int)(n * 0.99)];
    double sum = 0, sum2 = 0;
    for (int i = 0; i < n; i++) {
        double v = (double)s[i]; sum += v; sum2 += v * v;
    }
    r.mean = (uint64_t)(sum / n);
    double var = sum2 / n - (sum / n) * (sum / n);
    r.sd = (uint64_t)sqrt(var < 0 ? 0 : var);
    r.ops = r.mean > 0 ? 1e9 / (double)r.mean : 0;
    return r;
}
BENCHEOF

    cat >> "$BENCH_C" << MAINEOF
int main(int argc, char **argv) {
    int iters = 1000, warmup = 100;
    const char *csv = NULL, *backend = "unknown", *profile = "?", *bench_type = "custom";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iters") && i + 1 < argc)   iters = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--warmup") && i + 1 < argc) warmup = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--csv") && i + 1 < argc)    csv = argv[++i];
        else if (!strcmp(argv[i], "--backend") && i + 1 < argc) backend = argv[++i];
        else if (!strcmp(argv[i], "--profile") && i + 1 < argc) profile = argv[++i];
        else if (!strcmp(argv[i], "--type") && i + 1 < argc)   bench_type = argv[++i];
    }
    int k_val = KYBER_K;
    uint8_t pk[${PREFIX}_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[${PREFIX}_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[${PREFIX}_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss1[${PREFIX}_CRYPTO_BYTES];
    uint8_t ss2[${PREFIX}_CRYPTO_BYTES];
    uint64_t *ts = malloc(sizeof(uint64_t) * (size_t)iters);

    const char *correct = "FAIL";
    if (${PREFIX}_crypto_kem_keypair(pk, sk) == 0 &&
        ${PREFIX}_crypto_kem_enc(ct, ss1, pk) == 0 &&
        ${PREFIX}_crypto_kem_dec(ss2, ct, sk) == 0 &&
        memcmp(ss1, ss2, ${PREFIX}_CRYPTO_BYTES) == 0)
        correct = "PASS";

    char algo[64];
    snprintf(algo, sizeof(algo), "ML-KEM-k%d-P%s", k_val, profile);
    printf("  %-12s %-24s %s  [%s]  (pk=%d sk=%d ct=%d)\n",
           backend, algo, correct, bench_type,
           ${PREFIX}_CRYPTO_PUBLICKEYBYTES,
           ${PREFIX}_CRYPTO_SECRETKEYBYTES,
           ${PREFIX}_CRYPTO_CIPHERTEXTBYTES);

    if (strcmp(correct, "PASS") != 0) {
        fprintf(stderr, "  CORRECTNESS FAILED\n");
        free(ts); return 1;
    }

    for (int i = 0; i < warmup; i++) {
        ${PREFIX}_crypto_kem_keypair(pk, sk);
        ${PREFIX}_crypto_kem_enc(ct, ss1, pk);
        ${PREFIX}_crypto_kem_dec(ss2, ct, sk);
    }

    FILE *fp = csv ? fopen(csv, "a") : NULL;
    const char *ops[] = {"keygen", "encaps", "decaps"};
    for (int op = 0; op < 3; op++) {
        if (op == 0) {
            for (int i = 0; i < iters; i++) { uint64_t t = now_ns(); ${PREFIX}_crypto_kem_keypair(pk, sk); ts[i] = now_ns() - t; }
        } else if (op == 1) {
            ${PREFIX}_crypto_kem_keypair(pk, sk);
            for (int i = 0; i < iters; i++) { uint64_t t = now_ns(); ${PREFIX}_crypto_kem_enc(ct, ss1, pk); ts[i] = now_ns() - t; }
        } else {
            ${PREFIX}_crypto_kem_enc(ct, ss1, pk);
            for (int i = 0; i < iters; i++) { uint64_t t = now_ns(); ${PREFIX}_crypto_kem_dec(ss2, ct, sk); ts[i] = now_ns() - t; }
        }
        Stats st = compute(ts, iters);
        printf("    %-8s  median=%" PRIu64 "ns  ops/s=%.1f\n", ops[op], st.median, st.ops);
        if (fp) {
            fprintf(fp, "%s,%s,%s,%d,%d,%d,%d,%d,%s,%s,%s,%d,"
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%.2f,%d,%d,%d,%d\n",
                backend, algo, profile, k_val, $ETA1, $ETA2, $DU, $DV,
                bench_type, ops[op], correct, iters,
                st.mean, st.median, st.mn, st.mx, st.sd, st.p95, st.p99, st.ops,
                ${PREFIX}_CRYPTO_PUBLICKEYBYTES,
                ${PREFIX}_CRYPTO_SECRETKEYBYTES,
                ${PREFIX}_CRYPTO_CIPHERTEXTBYTES,
                ${PREFIX}_CRYPTO_BYTES);
        }
    }
    if (fp) fclose(fp);
    free(ts);
    return 0;
}
MAINEOF

    local LINK_LIBS="$LIB $COMMON_OBJS $BLAKE3_DIR/libblake3.a $HARAKA_DIR/libharaka.a $XKCP_LIB $OQS_STATIC -lcrypto -lm"
    local BENCH_BIN="$VDIR/bench_hyper"

    if ! gcc $CFLAGS_V -o "$BENCH_BIN" "$BENCH_C" $LINK_LIBS 2>&1; then
      echo "  [ERROR] link failed"
      return
    fi

    echo "  [OK] Running benchmark..."
    "$BENCH_BIN" --iters "$ITERS" --warmup "$WARMUP" --csv "$ROOT/$CSV" --backend "$BACKEND" --profile "$PROFILE" --type "$BENCH_TYPE"
  }

  COMBO=0

  # ── Phase 1: Library benchmark (standard default parameters) ──
  echo ""
  echo "═══════════════════════════════════════════════════════════"
  echo "  Phase 1: Library (default k=$DEF_K)"
  echo "═══════════════════════════════════════════════════════════"

  K=$DEF_K
  PK_BYTES=$((384 * K + 32))
  SK_BYTES=$((768 * K + 96))
  CT_BYTES=$((K * PVCOMP_K + POLYCOMP))

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ML-KEM  k=$K  eta1=$ETA1  du=$DU  dv=$DV  [library default]"
  echo "  PK=${PK_BYTES}B  SK=${SK_BYTES}B  CT=${CT_BYTES}B"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  for BACKEND in "${BACKENDS[@]}"; do
    COMBO=$((COMBO + 1))
    echo ""
    echo "  [$COMBO/$TOTAL] $BACKEND / k=$K / profile $PROFILE [library]"
    run_kem_bench "$DEF_K" "$BACKEND" "library"
  done

  # ── Phase 2: Custom benchmark (user-selected parameters) ──
  echo ""
  echo "═══════════════════════════════════════════════════════════"
  echo "  Phase 2: Custom (user-selected k values)"
  echo "═══════════════════════════════════════════════════════════"

  for K in "${K_VALUES[@]}"; do
    PK_BYTES=$((384 * K + 32))
    SK_BYTES=$((768 * K + 96))
    CT_BYTES=$((K * PVCOMP_K + POLYCOMP))

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  ML-KEM  k=$K  eta1=$ETA1  du=$DU  dv=$DV  [custom]"
    echo "  PK=${PK_BYTES}B  SK=${SK_BYTES}B  CT=${CT_BYTES}B"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    for BACKEND in "${BACKENDS[@]}"; do
      COMBO=$((COMBO + 1))
      echo ""
      echo "  [$COMBO/$TOTAL] $BACKEND / k=$K / profile $PROFILE [custom]"
      run_kem_bench "$K" "$BACKEND" "custom"
    done
  done

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ML-KEM Hyperparameter Benchmark DONE"
  echo ""
  ROWS=$(wc -l < "$ROOT/$CSV" 2>/dev/null || echo 0)
  echo "  Results      : $CSV ($ROWS rows)"
  echo "  System info  : system_info.txt"
  echo ""
  echo "  Benchmark types:"
  echo "    library — standard default parameters (k=$DEF_K)"
  echo "    custom  — user-selected parameters (k=${K_VALUES[*]})"
  echo ""
  echo "  CSV columns:"
  echo "    backend, algorithm, profile, k, eta1, eta2, du, dv,"
  echo "    type, operation, correctness, iterations,"
  echo "    mean_ns, median_ns, min_ns, max_ns,"
  echo "    stddev_ns, p95_ns, p99_ns, ops_per_sec,"
  echo "    pk_bytes, sk_bytes, ct_bytes, ss_bytes"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"


# ═══════════════════════════════════════════════════════════════
#  ML-DSA HYPERPARAMETER BENCHMARK
# ═══════════════════════════════════════════════════════════════
elif [ "$FAMILY" = "2" ]; then

  CSV="dsa_hyper_benchmark.csv"

  echo ""
  echo "  ── ML-DSA Code Base ──"
  echo ""
  echo "  Choose the base code variant. This determines eta, gamma1,"
  echo "  gamma2, and packing code (hardcoded bit-manipulation)."
  echo "  K, L, tau, and omega are then freely adjustable."
  echo ""
  echo "  ┌────────┬─────┬──────────┬──────────────┬─────────────┐"
  echo "  │ Base   │ eta │ gamma1   │ gamma2       │ ctildebytes │"
  echo "  ├────────┼─────┼──────────┼──────────────┼─────────────┤"
  echo "  │ 1) 44  │  2  │ 2^17     │ (Q-1)/88     │     32      │"
  echo "  │ 2) 65  │  4  │ 2^19     │ (Q-1)/32     │     48      │"
  echo "  │ 3) 87  │  2  │ 2^19     │ (Q-1)/32     │     64      │"
  echo "  └────────┴─────┴──────────┴──────────────┴─────────────┘"
  echo ""
  read -rp "  Select base [1-3]: " DSA_BASE

  case "$DSA_BASE" in
    1)
      DSA_TEMPLATE="ml-dsa-44"
      DSA_ETA=2; DSA_GAMMA1_BITS=17; DSA_GAMMA2_DIV=88
      DSA_CTILDE=32; DSA_POLYETA=96; DSA_POLYZ=576; DSA_POLYW1=192
      BASE_LABEL="44-base (eta=2, gamma1=2^17, gamma2=(Q-1)/88)"
      DEF_K_D=4; DEF_L_D=4; DEF_TAU_D=39; DEF_OMEGA_D=80
      ;;
    2)
      DSA_TEMPLATE="ml-dsa-65"
      DSA_ETA=4; DSA_GAMMA1_BITS=19; DSA_GAMMA2_DIV=32
      DSA_CTILDE=48; DSA_POLYETA=128; DSA_POLYZ=640; DSA_POLYW1=128
      BASE_LABEL="65-base (eta=4, gamma1=2^19, gamma2=(Q-1)/32)"
      DEF_K_D=6; DEF_L_D=5; DEF_TAU_D=49; DEF_OMEGA_D=55
      ;;
    3)
      DSA_TEMPLATE="ml-dsa-87"
      DSA_ETA=2; DSA_GAMMA1_BITS=19; DSA_GAMMA2_DIV=32
      DSA_CTILDE=64; DSA_POLYETA=96; DSA_POLYZ=640; DSA_POLYW1=128
      BASE_LABEL="87-base (eta=2, gamma1=2^19, gamma2=(Q-1)/32)"
      DEF_K_D=8; DEF_L_D=7; DEF_TAU_D=60; DEF_OMEGA_D=75
      ;;
    *) echo "Invalid selection"; exit 1 ;;
  esac

  echo ""
  echo "  ── K values (matrix rows) ──"
  echo ""
  echo "  Standard: K=4 (DSA-44), K=6 (DSA-65), K=8 (DSA-87)"
  echo "  Range: 1-12"
  echo ""
  read -rp "  K values [space-separated]: " K_DSA_INPUT
  K_DSA_VALUES=($K_DSA_INPUT)

  for v in "${K_DSA_VALUES[@]}"; do
    if ! [[ "$v" =~ ^[0-9]+$ ]] || [ "$v" -lt 1 ] || [ "$v" -gt 12 ]; then
      echo "ERROR: K=$v is out of range (1-12)"; exit 1
    fi
  done

  echo ""
  echo "  ── L values (matrix columns) ──"
  echo ""
  echo "  Standard: L=4 (DSA-44), L=5 (DSA-65), L=7 (DSA-87)"
  echo "  Range: 1-12"
  echo ""
  read -rp "  L values [space-separated]: " L_DSA_INPUT
  L_DSA_VALUES=($L_DSA_INPUT)

  for v in "${L_DSA_VALUES[@]}"; do
    if ! [[ "$v" =~ ^[0-9]+$ ]] || [ "$v" -lt 1 ] || [ "$v" -gt 12 ]; then
      echo "ERROR: L=$v is out of range (1-12)"; exit 1
    fi
  done

  echo ""
  echo "  ── tau values (challenge weight) ──"
  echo ""
  echo "  Number of +/-1 coefficients in challenge polynomial."
  echo "  Standard: tau=39 (DSA-44), tau=49 (DSA-65), tau=60 (DSA-87)"
  echo "  Range: 1-64 (limited by 64-bit sign mask)"
  echo ""
  read -rp "  tau values [space-separated]: " TAU_INPUT
  TAU_VALUES=($TAU_INPUT)

  for v in "${TAU_VALUES[@]}"; do
    if ! [[ "$v" =~ ^[0-9]+$ ]] || [ "$v" -lt 1 ] || [ "$v" -gt 64 ]; then
      echo "ERROR: tau=$v is out of range (1-64)"; exit 1
    fi
  done

  echo ""
  echo "  ── omega values (hint budget) ──"
  echo ""
  echo "  Maximum number of nonzero hint coefficients."
  echo "  Standard: omega=80 (DSA-44), omega=55 (DSA-65), omega=75 (DSA-87)"
  echo "  Range: 1-256"
  echo ""
  read -rp "  omega values [space-separated]: " OMEGA_INPUT
  OMEGA_VALUES=($OMEGA_INPUT)

  for v in "${OMEGA_VALUES[@]}"; do
    if ! [[ "$v" =~ ^[0-9]+$ ]] || [ "$v" -lt 1 ] || [ "$v" -gt 256 ]; then
      echo "ERROR: omega=$v is out of range (1-256)"; exit 1
    fi
  done

  select_backends

  CUSTOM_TOTAL=$(( ${#K_DSA_VALUES[@]} * ${#L_DSA_VALUES[@]} * ${#TAU_VALUES[@]} * ${#OMEGA_VALUES[@]} * ${#BACKENDS[@]} ))
  LIBRARY_TOTAL=${#BACKENDS[@]}
  TOTAL=$((LIBRARY_TOTAL + CUSTOM_TOTAL))
  echo ""
  echo "  ───────────────────────────────────────────"
  echo "  Family       : ML-DSA"
  echo "  Code base    : $BASE_LABEL"
  echo "  K values     : ${K_DSA_VALUES[*]}"
  echo "  L values     : ${L_DSA_VALUES[*]}"
  echo "  tau values   : ${TAU_VALUES[*]}"
  echo "  omega values : ${OMEGA_VALUES[*]}"
  echo "  Backends     : ${BACKENDS[*]}"
  echo "  Library runs : $LIBRARY_TOTAL (default K=$DEF_K_D L=$DEF_L_D tau=$DEF_TAU_D omega=$DEF_OMEGA_D)"
  echo "  Custom runs  : $CUSTOM_TOTAL"
  echo "  Total runs   : $TOTAL"
  echo "  Iterations   : $ITERS"
  echo "  Warmup       : $WARMUP"
  echo "  Output CSV   : $CSV"
  echo "  ───────────────────────────────────────────"
  echo ""
  read -rp "  Press ENTER to start... "

  echo "backend,algorithm,base,K,L,eta,tau,beta,gamma1_bits,gamma2_div,omega,ctildebytes,type,operation,correctness,iterations,mean_ns,median_ns,min_ns,max_ns,stddev_ns,p95_ns,p99_ns,ops_per_sec,pk_bytes,sk_bytes,sig_bytes" > "$ROOT/$CSV"

  DSA_Q=8380417

  # ── DSA compile + benchmark function ──
  run_dsa_bench() {
    local K_D=$1 L_D=$2 TAU_D=$3 OMEGA_D=$4 BACKEND=$5 BENCH_TYPE=$6

    local BETA_D=$((TAU_D * DSA_ETA))
    local GAMMA1_D=$((1 << DSA_GAMMA1_BITS))

    if [ "$BETA_D" -ge "$GAMMA1_D" ]; then
      echo ""
      echo "  [SKIP] K=$K_D L=$L_D tau=$TAU_D: beta=$BETA_D >= gamma1=$GAMMA1_D (signing would loop forever)"
      return
    fi

    local PK_D=$((32 + K_D * 320))
    local SK_D=$((128 + (K_D + L_D) * DSA_POLYETA + K_D * 416))
    local POLYVECH_D=$((OMEGA_D + K_D))
    local SIG_D=$((DSA_CTILDE + L_D * DSA_POLYZ + POLYVECH_D))

    local SRC_DIR
    if [ "$BACKEND" = "shake" ]; then
      SRC_DIR="$PQCLEAN/crypto_sign/$DSA_TEMPLATE/clean"
    else
      SRC_DIR="$PQCLEAN_CUSTOM/crypto_sign/$DSA_TEMPLATE/$BACKEND"
    fi

    if [ ! -d "$SRC_DIR" ]; then
      echo "  [SKIP] $SRC_DIR not found"
      return
    fi

    local VDIR="$HBUILD/dsa-K${K_D}L${L_D}t${TAU_D}o${OMEGA_D}-${BACKEND}-${BENCH_TYPE}"
    rm -rf "$VDIR"; mkdir -p "$VDIR"
    cp "$SRC_DIR"/*.c "$SRC_DIR"/*.h "$VDIR/" 2>/dev/null || true

    local PREFIX
    PREFIX=$(grep -o 'PQCLEAN_[A-Z0-9_]*_crypto_sign_keypair' "$VDIR/api.h" 2>/dev/null | head -1 | sed 's/_crypto_sign_keypair//' || echo "")
    if [ -z "$PREFIX" ]; then
      echo "  [SKIP] Cannot detect function prefix from api.h"
      return
    fi

    local GAMMA1_C="(1 << $DSA_GAMMA1_BITS)"
    local GAMMA2_C
    if [ "$DSA_GAMMA2_DIV" = "88" ]; then
      GAMMA2_C="(($DSA_Q-1)/88)"
    else
      GAMMA2_C="(($DSA_Q-1)/32)"
    fi

    cat > "$VDIR/params.h" << PEOF
#ifndef HYPER_DSA_PARAMS_H
#define HYPER_DSA_PARAMS_H

#define SEEDBYTES 32
#define CRHBYTES 64
#define TRBYTES 64
#define RNDBYTES 32
#define N 256
#define Q $DSA_Q
#define D 13
#define ROOT_OF_UNITY 1753

#define K $K_D
#define L $L_D
#define ETA $DSA_ETA
#define TAU $TAU_D
#define BETA $BETA_D
#define GAMMA1 $GAMMA1_C
#define GAMMA2 $GAMMA2_C
#define OMEGA $OMEGA_D
#define CTILDEBYTES $DSA_CTILDE

#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416
#define POLYVECH_PACKEDBYTES (OMEGA + K)

#define POLYZ_PACKEDBYTES   $DSA_POLYZ
#define POLYW1_PACKEDBYTES  $DSA_POLYW1
#define POLYETA_PACKEDBYTES $DSA_POLYETA

#define ${PREFIX}_CRYPTO_PUBLICKEYBYTES (SEEDBYTES + K*POLYT1_PACKEDBYTES)
#define ${PREFIX}_CRYPTO_SECRETKEYBYTES (2*SEEDBYTES + TRBYTES + L*POLYETA_PACKEDBYTES + K*POLYETA_PACKEDBYTES + K*POLYT0_PACKEDBYTES)
#define ${PREFIX}_CRYPTO_BYTES (CTILDEBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)

#endif
PEOF

    cat > "$VDIR/api.h" << AEOF
#ifndef HYPER_DSA_API_H
#define HYPER_DSA_API_H
#include <stddef.h>
#include <stdint.h>
#include "params.h"

#define ${PREFIX}_CRYPTO_ALGNAME "ML-DSA-K${K_D}L${L_D}"

int ${PREFIX}_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

int ${PREFIX}_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen, const uint8_t *sk);

int ${PREFIX}_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen, const uint8_t *pk);

int ${PREFIX}_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);

int ${PREFIX}_crypto_sign_ctx(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);

int ${PREFIX}_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);

int ${PREFIX}_crypto_sign_open_ctx(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);

int ${PREFIX}_crypto_sign(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen, const uint8_t *sk);

int ${PREFIX}_crypto_sign_open(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen, const uint8_t *pk);

#endif
AEOF

    local CFLAGS_V="-O3 -march=native -Wall -I$VDIR -I$COMMON_DIR -I$OQS_INC -I$XKCP_HDRS -I$BLAKE3_DIR -I$HARAKA_DIR $BLAKE3_FLAGS $HARAKA_CFLAGS"

    local OBJ_FILES=""
    local COMPILE_OK=1
    local SRC_FILE OBJ
    for SRC_FILE in "$VDIR"/*.c; do
      [ -f "$SRC_FILE" ] || continue
      OBJ="$VDIR/$(basename "$SRC_FILE" .c).o"
      if ! gcc $CFLAGS_V -c -o "$OBJ" "$SRC_FILE" 2>&1; then
        echo "  [ERROR] compile $(basename "$SRC_FILE")"
        COMPILE_OK=0; break
      fi
      OBJ_FILES="$OBJ_FILES $OBJ"
    done
    [ "$COMPILE_OK" = "1" ] || return

    local LIB="$VDIR/libmldsa_hyper.a"
    ar rcs "$LIB" $OBJ_FILES

    local BENCH_C="$VDIR/bench_hyper.c"
    cat > "$BENCH_C" << 'BENCHEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <time.h>
#include "api.h"
#include "params.h"
static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
typedef struct {
    uint64_t mean, median, mn, mx, sd, p95, p99;
    double ops;
} Stats;
static Stats compute(uint64_t *s, int n) {
    Stats r = {0};
    qsort(s, (size_t)n, sizeof(uint64_t), cmp_u64);
    r.mn = s[0]; r.mx = s[n - 1];
    r.median = (n & 1) ? s[n / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
    r.p95 = s[(int)(n * 0.95)];
    r.p99 = s[(int)(n * 0.99)];
    double sum = 0, sum2 = 0;
    for (int i = 0; i < n; i++) {
        double v = (double)s[i]; sum += v; sum2 += v * v;
    }
    r.mean = (uint64_t)(sum / n);
    double var = sum2 / n - (sum / n) * (sum / n);
    r.sd = (uint64_t)sqrt(var < 0 ? 0 : var);
    r.ops = r.mean > 0 ? 1e9 / (double)r.mean : 0;
    return r;
}
BENCHEOF

    cat >> "$BENCH_C" << MAINEOF
int main(int argc, char **argv) {
    int iters = 1000, warmup = 100;
    const char *csv = NULL, *backend = "unknown", *base = "?", *bench_type = "custom";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iters") && i + 1 < argc)    iters = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--warmup") && i + 1 < argc)  warmup = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--csv") && i + 1 < argc)     csv = argv[++i];
        else if (!strcmp(argv[i], "--backend") && i + 1 < argc) backend = argv[++i];
        else if (!strcmp(argv[i], "--base") && i + 1 < argc)    base = argv[++i];
        else if (!strcmp(argv[i], "--type") && i + 1 < argc)    bench_type = argv[++i];
    }

    uint8_t pk[${PREFIX}_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[${PREFIX}_CRYPTO_SECRETKEYBYTES];
    uint8_t sig[${PREFIX}_CRYPTO_BYTES];
    size_t siglen;
    const uint8_t msg[] = "PQC hyperparameter benchmark test message";
    const size_t msglen = sizeof(msg) - 1;
    uint64_t *ts = malloc(sizeof(uint64_t) * (size_t)iters);

    const char *correct = "FAIL";
    if (${PREFIX}_crypto_sign_keypair(pk, sk) == 0 &&
        ${PREFIX}_crypto_sign_signature(sig, &siglen, msg, msglen, sk) == 0 &&
        ${PREFIX}_crypto_sign_verify(sig, siglen, msg, msglen, pk) == 0)
        correct = "PASS";

    char algo[64];
    snprintf(algo, sizeof(algo), "ML-DSA-K%dL%d", K, L);
    printf("  %-12s %-20s %s  [%s]  (pk=%d sk=%d sig=%d)\n",
           backend, algo, correct, bench_type,
           ${PREFIX}_CRYPTO_PUBLICKEYBYTES,
           ${PREFIX}_CRYPTO_SECRETKEYBYTES,
           ${PREFIX}_CRYPTO_BYTES);

    if (strcmp(correct, "PASS") != 0) {
        fprintf(stderr, "  CORRECTNESS FAILED\n");
        free(ts); return 1;
    }

    for (int i = 0; i < warmup; i++) {
        ${PREFIX}_crypto_sign_keypair(pk, sk);
        ${PREFIX}_crypto_sign_signature(sig, &siglen, msg, msglen, sk);
        ${PREFIX}_crypto_sign_verify(sig, siglen, msg, msglen, pk);
    }

    FILE *fp = csv ? fopen(csv, "a") : NULL;
    const char *ops[] = {"keygen", "sign", "verify"};
    for (int op = 0; op < 3; op++) {
        if (op == 0) {
            for (int i = 0; i < iters; i++) { uint64_t t = now_ns(); ${PREFIX}_crypto_sign_keypair(pk, sk); ts[i] = now_ns() - t; }
        } else if (op == 1) {
            ${PREFIX}_crypto_sign_keypair(pk, sk);
            for (int i = 0; i < iters; i++) { uint64_t t = now_ns(); ${PREFIX}_crypto_sign_signature(sig, &siglen, msg, msglen, sk); ts[i] = now_ns() - t; }
        } else {
            ${PREFIX}_crypto_sign_signature(sig, &siglen, msg, msglen, sk);
            for (int i = 0; i < iters; i++) { uint64_t t = now_ns(); ${PREFIX}_crypto_sign_verify(sig, siglen, msg, msglen, pk); ts[i] = now_ns() - t; }
        }
        Stats st = compute(ts, iters);
        printf("    %-8s  median=%" PRIu64 "ns  ops/s=%.1f\n", ops[op], st.median, st.ops);
        if (fp) {
            fprintf(fp, "%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s,%s,%d,"
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%.2f,%d,%d,%d\n",
                backend, algo, base, K, L, $DSA_ETA, $TAU_D, $BETA_D,
                $DSA_GAMMA1_BITS, $DSA_GAMMA2_DIV, $OMEGA_D, $DSA_CTILDE,
                bench_type, ops[op], correct, iters,
                st.mean, st.median, st.mn, st.mx, st.sd, st.p95, st.p99, st.ops,
                ${PREFIX}_CRYPTO_PUBLICKEYBYTES,
                ${PREFIX}_CRYPTO_SECRETKEYBYTES,
                ${PREFIX}_CRYPTO_BYTES);
        }
    }
    if (fp) fclose(fp);
    free(ts);
    return 0;
}
MAINEOF

    local LINK_LIBS="$LIB $COMMON_OBJS $BLAKE3_DIR/libblake3.a $HARAKA_DIR/libharaka.a $XKCP_LIB $OQS_STATIC -lcrypto -lm"
    local BENCH_BIN="$VDIR/bench_hyper"

    if ! gcc $CFLAGS_V -o "$BENCH_BIN" "$BENCH_C" $LINK_LIBS 2>&1; then
      echo "  [ERROR] link failed"
      return
    fi

    echo "  [OK] Running benchmark..."
    "$BENCH_BIN" --iters "$ITERS" --warmup "$WARMUP" --csv "$ROOT/$CSV" --backend "$BACKEND" --base "$DSA_BASE" --type "$BENCH_TYPE"
  }

  COMBO=0

  # ── Phase 1: Library benchmark (standard default parameters) ──
  echo ""
  echo "═══════════════════════════════════════════════════════════"
  echo "  Phase 1: Library (default K=$DEF_K_D L=$DEF_L_D tau=$DEF_TAU_D omega=$DEF_OMEGA_D)"
  echo "═══════════════════════════════════════════════════════════"

  DEF_BETA_D=$((DEF_TAU_D * DSA_ETA))
  DEF_PK_D=$((32 + DEF_K_D * 320))
  DEF_SK_D=$((128 + (DEF_K_D + DEF_L_D) * DSA_POLYETA + DEF_K_D * 416))
  DEF_POLYVECH_D=$((DEF_OMEGA_D + DEF_K_D))
  DEF_SIG_D=$((DSA_CTILDE + DEF_L_D * DSA_POLYZ + DEF_POLYVECH_D))

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ML-DSA  K=$DEF_K_D  L=$DEF_L_D  tau=$DEF_TAU_D  omega=$DEF_OMEGA_D  beta=$DEF_BETA_D  [library default]"
  echo "  PK=${DEF_PK_D}B  SK=${DEF_SK_D}B  SIG=${DEF_SIG_D}B"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  for BACKEND in "${BACKENDS[@]}"; do
    COMBO=$((COMBO + 1))
    echo ""
    echo "  [$COMBO/$TOTAL] $BACKEND / K=$DEF_K_D L=$DEF_L_D tau=$DEF_TAU_D omega=$DEF_OMEGA_D [library]"
    run_dsa_bench "$DEF_K_D" "$DEF_L_D" "$DEF_TAU_D" "$DEF_OMEGA_D" "$BACKEND" "library"
  done

  # ── Phase 2: Custom benchmark (user-selected parameters) ──
  echo ""
  echo "═══════════════════════════════════════════════════════════"
  echo "  Phase 2: Custom (user-selected parameters)"
  echo "═══════════════════════════════════════════════════════════"

  for K_D in "${K_DSA_VALUES[@]}"; do
    for L_D in "${L_DSA_VALUES[@]}"; do
      for TAU_D in "${TAU_VALUES[@]}"; do
        for OMEGA_D in "${OMEGA_VALUES[@]}"; do

          BETA_D=$((TAU_D * DSA_ETA))
          GAMMA1_D=$((1 << DSA_GAMMA1_BITS))

          if [ "$BETA_D" -ge "$GAMMA1_D" ]; then
            echo ""
            echo "  [SKIP] K=$K_D L=$L_D tau=$TAU_D: beta=$BETA_D >= gamma1=$GAMMA1_D (signing would loop forever)"
            continue
          fi

          PK_D=$((32 + K_D * 320))
          SK_D=$((128 + (K_D + L_D) * DSA_POLYETA + K_D * 416))
          POLYVECH_D=$((OMEGA_D + K_D))
          SIG_D=$((DSA_CTILDE + L_D * DSA_POLYZ + POLYVECH_D))

          echo ""
          echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
          echo "  ML-DSA  K=$K_D  L=$L_D  tau=$TAU_D  omega=$OMEGA_D  beta=$BETA_D  [custom]"
          echo "  PK=${PK_D}B  SK=${SK_D}B  SIG=${SIG_D}B"
          echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

          for BACKEND in "${BACKENDS[@]}"; do
            COMBO=$((COMBO + 1))
            echo ""
            echo "  [$COMBO/$TOTAL] $BACKEND / K=$K_D L=$L_D tau=$TAU_D omega=$OMEGA_D [custom]"
            run_dsa_bench "$K_D" "$L_D" "$TAU_D" "$OMEGA_D" "$BACKEND" "custom"
          done
        done
      done
    done
  done

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ML-DSA Hyperparameter Benchmark DONE"
  echo ""
  ROWS=$(wc -l < "$ROOT/$CSV" 2>/dev/null || echo 0)
  echo "  Results      : $CSV ($ROWS rows)"
  echo "  System info  : system_info.txt"
  echo ""
  echo "  Benchmark types:"
  echo "    library — standard default parameters (K=$DEF_K_D L=$DEF_L_D tau=$DEF_TAU_D omega=$DEF_OMEGA_D)"
  echo "    custom  — user-selected parameters"
  echo ""
  echo "  CSV columns:"
  echo "    backend, algorithm, base, K, L, eta, tau, beta,"
  echo "    gamma1_bits, gamma2_div, omega, ctildebytes,"
  echo "    type, operation, correctness, iterations,"
  echo "    mean_ns, median_ns, min_ns, max_ns,"
  echo "    stddev_ns, p95_ns, p99_ns, ops_per_sec,"
  echo "    pk_bytes, sk_bytes, sig_bytes"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

else
  echo "ERROR: Invalid selection. Choose 1 (ML-KEM) or 2 (ML-DSA)."
  exit 1
fi

rm -rf "$HBUILD"
