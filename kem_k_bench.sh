#!/bin/bash
# kem_k_bench.sh — Interactive ML-KEM benchmark with variable k values (1–8)
#
# Lets you choose:
#   1. Which hash backend (shake/turboshake/k12/blake3/xoodyak/haraka)
#   2. Which k value (1–8) — the module rank in ML-KEM
#
# Standard ML-KEM: k=2 (512), k=3 (768), k=4 (1024)
# Research:        k=1, k=5..8 (non-standard module ranks)
#
# Recompiles ML-KEM with that k value and benchmarks keygen/encaps/decaps.
# Results go to kem_k_benchmark.csv.

set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(pwd)"
ITERS=1000
WARMUP=100
CSV="kem_k_benchmark.csv"

for i in "$@"; do
  case "$i" in
    --iters)   shift; ITERS="$1"; shift ;;
    --warmup)  shift; WARMUP="$1"; shift ;;
    --csv)     shift; CSV="$1"; shift ;;
    *) ;;
  esac
done

ARCH="$(uname -m)"
PQCLEAN="$ROOT/PQClean"
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

# ── k-value parameter lookup ──
get_eta1()    { [ "$1" -le 2 ] && echo 3 || echo 2; }
get_eta2()    { echo 2; }
get_polycomp(){ [ "$1" -le 3 ] && echo 128 || echo 160; }
get_pvcomp_k(){ [ "$1" -le 3 ] && echo 320 || echo 352; }
get_du()      { [ "$1" -le 3 ] && echo 10 || echo 11; }
get_dv()      { [ "$1" -le 3 ] && echo 4 || echo 5; }

# ── Template base: pick closest standard variant ──
get_template() {
  local k=$1
  if [ "$k" -le 2 ]; then echo "ml-kem-512"
  elif [ "$k" -eq 3 ]; then echo "ml-kem-768"
  else echo "ml-kem-1024"
  fi
}

# ── Interactive menu ──
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   ML-KEM Variable-k Benchmark                      ║"
echo "║                                                     ║"
echo "║   Choose a hash backend and k value to benchmark    ║"
echo "║   ML-KEM with custom module rank (k=1..8)          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Hash backends:"
echo "  ─────────────────────────────────────────────"
echo "  1) shake       — FIPS SHAKE/SHA-3 (liboqs built-in)"
echo "  2) turboshake  — TurboSHAKE (n_r=12, RFC 9861)"
echo "  3) k12         — KangarooTwelve (tree hash)"
echo "  4) blake3      — BLAKE3 XOF (portable)"
echo "  5) xoodyak     — Xoodyak / Xoodoo[12]"
echo "  6) haraka      — Haraka (AES-NI / NEON)"
echo "  7) ALL         — Run all 6 backends"
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
  *) echo "Invalid"; exit 1 ;;
esac

echo ""
echo "  k values (ML-KEM module rank):"
echo "  ─────────────────────────────────────────────"
echo "  Standard:  k=2 (ML-KEM-512), k=3 (768), k=4 (1024)"
echo "  Research:  k=1 (very small), k=5..8 (larger lattice)"
echo ""
read -rp "  k values [space-separated, 1-8]: " K_INPUT
K_VALUES=($K_INPUT)

for k in "${K_VALUES[@]}"; do
  if ! [[ "$k" =~ ^[1-8]$ ]]; then
    echo "ERROR: k=$k is out of range (1-8)"; exit 1
  fi
done

echo ""
echo "  ─────────────────────────────────────────────"
echo "  Backends   : ${BACKENDS[*]}"
echo "  k values   : ${K_VALUES[*]}"
echo "  Iterations : $ITERS"
echo "  Warmup     : $WARMUP"
echo "  Output CSV : $CSV"
echo "  ─────────────────────────────────────────────"
echo ""
read -rp "  Press ENTER to start... "

# ── CSV header ──
if [ ! -f "$CSV" ]; then
  echo "backend,k_value,algorithm,type,operation,correctness,iterations,mean_ns,median_ns,min_ns,max_ns,stddev_ns,p95_ns,p99_ns,ops_per_sec,pk_bytes,sk_bytes,ct_bytes,ss_bytes,eta1,eta2,du_bits,dv_bits" > "$CSV"
fi

KBUILD="$ROOT/.kem_k_build"
mkdir -p "$KBUILD"

# ── Compile common objects once ──
echo ""
echo "[build] Compiling common objects..."
COMMON_OBJS="$KBUILD/fips202.o $KBUILD/randombytes.o"
gcc -O3 -march=native -I"$COMMON_DIR" -c -o "$KBUILD/fips202.o" "$COMMON_DIR/fips202.c"
gcc -O3 -march=native -I"$COMMON_DIR" -c -o "$KBUILD/randombytes.o" "$COMMON_DIR/randombytes.c"

# ── Main loop ──
for K in "${K_VALUES[@]}"; do
  ETA1=$(get_eta1 "$K")
  ETA2=$(get_eta2 "$K")
  POLYCOMP=$(get_polycomp "$K")
  PVCOMP_K=$(get_pvcomp_k "$K")
  DU=$(get_du "$K")
  DV=$(get_dv "$K")

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  k=$K  ETA1=$ETA1  ETA2=$ETA2  du=$DU  dv=$DV"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  TEMPLATE=$(get_template "$K")

  for BACKEND in "${BACKENDS[@]}"; do
    echo ""
    echo "  ── $BACKEND / k=$K ──"

    # Source directory
    if [ "$BACKEND" = "shake" ]; then
      SRC_DIR="$PQCLEAN/crypto_kem/$TEMPLATE/clean"
    else
      SRC_DIR="$PQCLEAN/crypto_kem/$TEMPLATE/$BACKEND"
    fi

    if [ ! -d "$SRC_DIR" ]; then
      echo "  [SKIP] $SRC_DIR not found"
      continue
    fi

    # Build directory
    VDIR="$KBUILD/k${K}-${BACKEND}"
    rm -rf "$VDIR"
    mkdir -p "$VDIR"
    cp "$SRC_DIR"/*.c "$SRC_DIR"/*.h "$VDIR/" 2>/dev/null || true

    # Get the function name prefix from the copied api.h
    PREFIX=$(grep -o 'PQCLEAN_[A-Z0-9_]*_crypto_kem_keypair' "$VDIR/api.h" 2>/dev/null | head -1 | sed 's/_crypto_kem_keypair//' || echo "")
    if [ -z "$PREFIX" ]; then
      echo "  [SKIP] Cannot detect function prefix from api.h"
      continue
    fi

    # Compute key/ct sizes for this k
    POLYVEC_BYTES=$((K * 384))
    PK_BYTES=$((POLYVEC_BYTES + 32))
    SK_BYTES=$((POLYVEC_BYTES + PK_BYTES + 64))
    PVCOMP_BYTES=$((K * PVCOMP_K))
    CT_BYTES=$((PVCOMP_BYTES + POLYCOMP))

    # Patch params.h with the desired k value
    cat > "$VDIR/params.h" << PEOF
#ifndef PARAMS_K${K}_H
#define PARAMS_K${K}_H

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

    # Patch api.h — replace hardcoded sizes with computed values for this k
    cat > "$VDIR/api.h" << AEOF
#ifndef API_K${K}_H
#define API_K${K}_H
#include <stdint.h>

#define ${PREFIX}_CRYPTO_SECRETKEYBYTES  $SK_BYTES
#define ${PREFIX}_CRYPTO_PUBLICKEYBYTES  $PK_BYTES
#define ${PREFIX}_CRYPTO_CIPHERTEXTBYTES $CT_BYTES
#define ${PREFIX}_CRYPTO_BYTES           32
#define ${PREFIX}_CRYPTO_ALGNAME "ML-KEM-k${K}"

int ${PREFIX}_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int ${PREFIX}_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int ${PREFIX}_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
AEOF

    # CFLAGS
    CFLAGS_V="-O3 -march=native -Wall -I$VDIR -I$COMMON_DIR -I$OQS_INC -I$XKCP_HDRS -I$BLAKE3_DIR -I$HARAKA_DIR $BLAKE3_FLAGS $HARAKA_CFLAGS"

    # Compile all variant .c to .o
    OBJ_FILES=""
    COMPILE_OK=1
    for SRC_FILE in "$VDIR"/*.c; do
      OBJ="$VDIR/$(basename "$SRC_FILE" .c).o"
      if ! gcc $CFLAGS_V -c -o "$OBJ" "$SRC_FILE" 2>&1; then
        echo "  [ERROR] compile $(basename "$SRC_FILE")"
        COMPILE_OK=0
        break
      fi
      OBJ_FILES="$OBJ_FILES $OBJ"
    done
    [ "$COMPILE_OK" = "1" ] || continue

    # Create static library
    LIB="$VDIR/libmlkem_k${K}_${BACKEND}.a"
    ar rcs "$LIB" $OBJ_FILES

    # Write the benchmark driver
    BENCH_C="$VDIR/bench_k.c"
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
    return (uint64_t)ts.tv_sec*1000000000ULL + (uint64_t)ts.tv_nsec;
}
static int cmp_u64(const void *a, const void *b) {
    uint64_t x=*(const uint64_t*)a, y=*(const uint64_t*)b;
    return (x>y)-(x<y);
}
typedef struct { uint64_t mean,median,mn,mx,sd,p95,p99; double ops; int n; } Stats;
static Stats compute(uint64_t *s, int n) {
    Stats r={0}; r.n=n;
    qsort(s,(size_t)n,sizeof(uint64_t),cmp_u64);
    r.mn=s[0]; r.mx=s[n-1];
    r.median=(n&1)?s[n/2]:(s[n/2-1]+s[n/2])/2;
    r.p95=s[(int)(n*0.95)]; r.p99=s[(int)(n*0.99)];
    double sum=0,sum2=0;
    for(int i=0;i<n;i++){double v=(double)s[i];sum+=v;sum2+=v*v;}
    r.mean=(uint64_t)(sum/n);
    double var=sum2/n-(sum/n)*(sum/n);
    r.sd=(uint64_t)sqrt(var<0?0:var);
    r.ops=r.mean>0?1e9/(double)r.mean:0;
    return r;
}

BENCHEOF

    # Append the main function with actual function names substituted
    cat >> "$BENCH_C" << MAINEOF
int main(int argc, char **argv) {
    int iters=1000,warmup=100;
    const char *csv=NULL,*backend="unknown";

    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--iters")&&i+1<argc) iters=atoi(argv[++i]);
        else if(!strcmp(argv[i],"--warmup")&&i+1<argc) warmup=atoi(argv[++i]);
        else if(!strcmp(argv[i],"--csv")&&i+1<argc) csv=argv[++i];
        else if(!strcmp(argv[i],"--backend")&&i+1<argc) backend=argv[++i];
    }

    int k_val = KYBER_K;
    uint8_t pk[${PREFIX}_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[${PREFIX}_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[${PREFIX}_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss1[${PREFIX}_CRYPTO_BYTES];
    uint8_t ss2[${PREFIX}_CRYPTO_BYTES];
    uint64_t *ts = malloc(sizeof(uint64_t)*(size_t)iters);

    const char *correct="FAIL";
    if(${PREFIX}_crypto_kem_keypair(pk,sk)==0 &&
       ${PREFIX}_crypto_kem_enc(ct,ss1,pk)==0 &&
       ${PREFIX}_crypto_kem_dec(ss2,ct,sk)==0 &&
       memcmp(ss1,ss2,${PREFIX}_CRYPTO_BYTES)==0)
        correct="PASS";

    char algo[32];
    snprintf(algo,sizeof(algo),"ML-KEM-k%d",k_val);
    printf("  %-12s %-16s %s  (pk=%d sk=%d ct=%d ss=%d)\n",
           backend,algo,correct,
           ${PREFIX}_CRYPTO_PUBLICKEYBYTES,
           ${PREFIX}_CRYPTO_SECRETKEYBYTES,
           ${PREFIX}_CRYPTO_CIPHERTEXTBYTES,
           ${PREFIX}_CRYPTO_BYTES);

    if(strcmp(correct,"PASS")!=0){ fprintf(stderr,"  CORRECTNESS FAILED\n"); free(ts); return 1; }

    for(int i=0;i<warmup;i++){
        ${PREFIX}_crypto_kem_keypair(pk,sk);
        ${PREFIX}_crypto_kem_enc(ct,ss1,pk);
        ${PREFIX}_crypto_kem_dec(ss2,ct,sk);
    }

    FILE *fp=csv?fopen(csv,"a"):NULL;
    const char *ops[]={"keygen","encaps","decaps"};
    for(int op=0;op<3;op++){
        if(op==0){
            for(int i=0;i<iters;i++){uint64_t t=now_ns();${PREFIX}_crypto_kem_keypair(pk,sk);ts[i]=now_ns()-t;}
        }else if(op==1){
            ${PREFIX}_crypto_kem_keypair(pk,sk);
            for(int i=0;i<iters;i++){uint64_t t=now_ns();${PREFIX}_crypto_kem_enc(ct,ss1,pk);ts[i]=now_ns()-t;}
        }else{
            ${PREFIX}_crypto_kem_enc(ct,ss1,pk);
            for(int i=0;i<iters;i++){uint64_t t=now_ns();${PREFIX}_crypto_kem_dec(ss2,ct,sk);ts[i]=now_ns()-t;}
        }
        Stats st=compute(ts,iters);
        printf("    %-8s  median=%"PRIu64"ns  ops/s=%.1f\n",ops[op],st.median,st.ops);
        if(fp){
            fprintf(fp,"%s,%d,%s,KEM,%s,%s,%d,"
                "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64","
                "%"PRIu64",%"PRIu64",%"PRIu64","
                "%.2f,%d,%d,%d,%d,%d,%d,%d,%d\n",
                backend,k_val,algo,ops[op],correct,iters,
                st.mean,st.median,st.mn,st.mx,st.sd,st.p95,st.p99,st.ops,
                ${PREFIX}_CRYPTO_PUBLICKEYBYTES,
                ${PREFIX}_CRYPTO_SECRETKEYBYTES,
                ${PREFIX}_CRYPTO_CIPHERTEXTBYTES,
                ${PREFIX}_CRYPTO_BYTES,
                KYBER_ETA1,KYBER_ETA2,$DU,$DV);
        }
    }
    if(fp) fclose(fp);
    free(ts);
    return 0;
}
MAINEOF

    # Compile and link the benchmark
    BENCH_BIN="$VDIR/bench_k"

    LINK_LIBS="$LIB $COMMON_OBJS $BLAKE3_DIR/libblake3.a $HARAKA_DIR/libharaka.a $XKCP_LIB $OQS_STATIC -lcrypto -lm"

    if ! gcc $CFLAGS_V -o "$BENCH_BIN" "$BENCH_C" $LINK_LIBS 2>&1; then
      echo "  [ERROR] link failed"
      continue
    fi

    echo "  [OK] Running benchmark..."
    "$BENCH_BIN" --iters "$ITERS" --warmup "$WARMUP" --csv "$ROOT/$CSV" --backend "$BACKEND"

  done
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  DONE"
echo ""
echo "  Results    : $CSV"
echo "  System info: system_info.txt"
echo ""
echo "  CSV columns:"
echo "    backend, k_value, algorithm, type, operation,"
echo "    correctness, iterations,"
echo "    mean_ns, median_ns, min_ns, max_ns,"
echo "    stddev_ns, p95_ns, p99_ns, ops_per_sec,"
echo "    pk_bytes, sk_bytes, ct_bytes, ss_bytes,"
echo "    eta1, eta2, du_bits, dv_bits"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

rm -rf "$KBUILD"
