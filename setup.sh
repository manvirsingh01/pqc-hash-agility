#!/bin/bash
# =============================================================================
# setup.sh — PQC Hash-Agility Benchmark Setup
#
# Builds the complete ML-KEM / ML-DSA hash-agility benchmark suite on any
# Linux machine (x86_64 or aarch64).
#
# Usage (as root, from the directory containing this repo):
#   git clone <repo-url>
#   cd pqc-hash-agility
#   bash setup.sh
#
# Then run benchmarks with:
#   bash bench.sh
#
# Backends built:
#   shake      — liboqs built-in (FIPS-approved SHAKE/SHA3)
#   turboshake — PQClean fork (TurboSHAKE128/256, n_r=12)
#   k12        — PQClean fork (KangarooTwelve)
#   blake3     — PQClean fork (BLAKE3 XOF, portable)
#   xoodyak    — PQClean fork (Xoodyak/Xoodoo[12])
#   haraka     — PQClean fork (Haraka-256/512; AES-NI on x86_64, NEON on aarch64)
#
# Algorithms:
#   ML-KEM-512 / 768 / 1024   (FIPS 203 key encapsulation)
#   ML-DSA-44  / 65  / 87     (FIPS 204 digital signatures)
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(pwd)"
ARCH="$(uname -m)"
NPROC="$(nproc)"

echo "=== PQC Hash-Agility Setup ==="
echo "    Repo  : $REPO"
echo "    Root  : $ROOT"
echo "    Arch  : $ARCH"
echo "    Cores : $NPROC"
echo ""

# ── 1. System dependencies ────────────────────────────────────────────────────
echo "[1/15] Installing system packages..."
apt-get update -qq
# xsltproc is required by XKCP's Makefile generator
apt-get install -y \
  git build-essential cmake gcc g++ make \
  libssl-dev ninja-build rsync xsltproc

# ── 2. Clone upstream repositories at pinned commits ─────────────────────────
echo "[2/15] Cloning upstream repos..."

[ -d PQClean ] || git clone --depth=1 https://github.com/PQClean/PQClean.git
[ -d XKCP    ] || git clone           https://github.com/XKCP/XKCP.git
[ -d liboqs  ] || git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git

# PQClean — pinned commit
(cd PQClean && \
  git fetch --depth=1 origin 202a8f96315f9ed219387a50f7e40d04af037ea8 2>/dev/null || true && \
  git checkout 202a8f96315f9ed219387a50f7e40d04af037ea8)

# XKCP — pinned commit + initialise XKCBuild submodule
# (XKCP uses a git submodule for its build system; --depth=1 would break it)
(cd XKCP && \
  git checkout d71b764513a6c3163b3cfc919dd6f974d98a6c53 && \
  git submodule update --init --recursive)

# liboqs — pinned commit
(cd liboqs && \
  git fetch --depth=1 origin f986aea60a9f3cb4055474aa212538bb0b14f1fe 2>/dev/null || true && \
  git checkout f986aea60a9f3cb4055474aa212538bb0b14f1fe)

# ── 3. Build XKCP (TurboSHAKE / KangarooTwelve / Xoodyak) ───────────────────
echo "[3/15] Building XKCP generic64 library..."
(cd XKCP && make -j"$NPROC" generic64/libXKCP.a)
XKCP_HDRS="$ROOT/XKCP/bin/generic64/libXKCP.a.headers"
XKCP_LIB="$ROOT/XKCP/bin/generic64/libXKCP.a"

# ── 4. Build liboqs (full build — all ML-KEM + ML-DSA variants) ──────────────
# On x86_64: build WITHOUT -march=native to force scalar Keccak (no AVX2 dispatch).
# On aarch64: keep -march=native (needed for NEON assembly); parity is already
#             matched since XKCP generic64 and liboqs aarch64 are at similar tiers.
echo "[4/15] Building liboqs (static + shared, Release)..."
if [ "$ARCH" = "x86_64" ]; then
  OQS_CFLAGS="-O3"
  # Explicitly disable ALL SIMD instruction sets in liboqs so SHAKE uses
  # the same scalar Keccak as XKCP generic64. OQS_DIST_BUILD=OFF alone is
  # not enough — cmake auto-detects AVX2 at compile time on x86_64.
  OQS_ARCH_FLAGS="-DOQS_USE_AVX_INSTRUCTIONS=OFF -DOQS_USE_AVX2_INSTRUCTIONS=OFF -DOQS_USE_AVX512_INSTRUCTIONS=OFF -DOQS_USE_AES_INSTRUCTIONS=OFF -DOQS_USE_SSE2_INSTRUCTIONS=OFF -DOQS_USE_BMI1_INSTRUCTIONS=OFF -DOQS_USE_BMI2_INSTRUCTIONS=OFF -DOQS_USE_PCLMULQDQ_INSTRUCTIONS=OFF -DOQS_USE_POPCNT_INSTRUCTIONS=OFF -DOQS_USE_ADX_INSTRUCTIONS=OFF"
else
  OQS_CFLAGS="-O3 -march=native"
  # Disable aarch64-optimized assembly (assembler compatibility + scalar parity)
  OQS_ARCH_FLAGS="-DOQS_ENABLE_KEM_kyber_512_aarch64=OFF -DOQS_ENABLE_KEM_kyber_768_aarch64=OFF -DOQS_ENABLE_KEM_kyber_1024_aarch64=OFF"
fi
(cd liboqs && cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="$OQS_CFLAGS" \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=OFF \
    -DOQS_USE_OPENSSL=OFF \
    $OQS_ARCH_FLAGS \
    -GNinja && \
  ninja -C build -j"$NPROC")
OQS_INC="$ROOT/liboqs/build/include"
OQS_LIB_DIR="$ROOT/liboqs/build/lib"
# Use the static archive so bench_shake needs no LD_LIBRARY_PATH at runtime
OQS_STATIC="$OQS_LIB_DIR/liboqs.a"

# ── 5. Drop in custom backend sources ─────────────────────────────────────────
echo "[5/15] Installing custom PQClean backend sources..."
cp -r "$REPO/src/common/BLAKE3" PQClean/common/
cp -r "$REPO/src/common/Haraka" PQClean/common/

for tag in turboshake k12 blake3 xoodyak haraka; do
  for v in 512 768 1024; do
    dst="PQClean/crypto_kem/ml-kem-$v/$tag"
    mkdir -p "$dst"
    cp -r "$REPO/PQClean_custom/crypto_kem/ml-kem-$v/$tag/." "$dst/"
  done
  for v in 44 65 87; do
    dst="PQClean/crypto_sign/ml-dsa-$v/$tag"
    mkdir -p "$dst"
    cp -r "$REPO/PQClean_custom/crypto_sign/ml-dsa-$v/$tag/." "$dst/"
  done
done

# ── 6. Copy adapter sources + bench harness, fix hardcoded /root paths ────────
echo "[6/15] Copying adapters and fixing include paths..."
cp "$REPO"/src/pqc_bench.c .
for tag in turboshake k12 blake3 xoodyak haraka; do
  cp "$REPO/src/adapters/pqc_${tag}_kem.c" "$REPO/src/adapters/pqc_${tag}_kem.h" .
  cp "$REPO/src/adapters/pqc_${tag}_dsa.c" "$REPO/src/adapters/pqc_${tag}_dsa.h" .
  sed -i "s#/root/PQClean#$ROOT/PQClean#g" "pqc_${tag}_kem.c" "pqc_${tag}_dsa.c"
done
sed -i "s#/root/XKCP#$ROOT/XKCP#g" \
  PQClean/crypto_kem/ml-kem-{512,768,1024}/{turboshake,k12}/Makefile

# ── 7. Select Haraka backend for this architecture ────────────────────────────
echo "[7/15] Configuring Haraka backend for arch: $ARCH..."
BUILD_HARAKA=0
HARAKA_DIR=PQClean/common/Haraka

if [ "$ARCH" = "x86_64" ]; then
  cp "$HARAKA_DIR/haraka_x86.c" "$HARAKA_DIR/haraka.c"
  HARAKA_CFLAGS="-maes -msse4.1 -O3"
  BUILD_HARAKA=1
  echo "    Haraka: x86_64 AES-NI"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
  HARAKA_CFLAGS="-march=native -O3"
  BUILD_HARAKA=1
  echo "    Haraka: aarch64 ARM-NEON"
else
  echo "    Haraka: SKIPPED (arch=$ARCH)"
fi

# ── 8. Common helper objects ───────────────────────────────────────────────────
# Base CFLAGS: x86_64 uses -O3 only (scalar parity); aarch64 adds -march=native
if [ "$ARCH" = "x86_64" ]; then
  BASE_CFLAGS="-O3"
else
  BASE_CFLAGS="-O3 -march=native"
fi

echo "[8/15] Compiling common helper objects..."
gcc $BASE_CFLAGS -I PQClean/common -c PQClean/common/fips202.c     -o PQClean/common/fips202_turbo.o
gcc $BASE_CFLAGS -I PQClean/common -c PQClean/common/randombytes.c -o PQClean/common/randombytes_turbo.o

# ── 9. Build BLAKE3 portable (all SIMD disabled for cross-arch compatibility) ─
echo "[9/15] Building BLAKE3 portable library..."
BLAKE3_DIR=PQClean/common/BLAKE3
BLAKE3_FLAGS="-DBLAKE3_USE_NEON=0 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512"
for src in blake3 blake3_dispatch blake3_portable; do
  gcc -O3 $BLAKE3_FLAGS -c "$BLAKE3_DIR/$src.c" -o "$BLAKE3_DIR/$src.o"
done
ar rcs "$BLAKE3_DIR/libblake3.a" "$BLAKE3_DIR"/{blake3,blake3_dispatch,blake3_portable}.o

# ── 10. Build Haraka common lib ───────────────────────────────────────────────
echo "[10/15] Building Haraka common library..."
if [ "$BUILD_HARAKA" = "1" ]; then
  gcc $HARAKA_CFLAGS -I "$HARAKA_DIR" -c "$HARAKA_DIR/haraka.c" -o "$HARAKA_DIR/haraka.o"
  ar rcs "$HARAKA_DIR/libharaka.a" "$HARAKA_DIR/haraka.o"
fi

# ── 11. Per-backend compiler flags ────────────────────────────────────────────
declare -A EXTRA
EXTRA[turboshake]="-I$XKCP_HDRS"
EXTRA[k12]="-I$XKCP_HDRS"
EXTRA[blake3]="-I$ROOT/PQClean/common/BLAKE3 $BLAKE3_FLAGS"
EXTRA[xoodyak]="-I$XKCP_HDRS"
EXTRA[haraka]="-I$ROOT/PQClean/common/Haraka"

BACKENDS="turboshake k12 blake3 xoodyak"
[ "$BUILD_HARAKA" = "1" ] && BACKENDS="$BACKENDS haraka"

# ── 12. Build all forked ML-KEM / ML-DSA static libs (parallel) ──────────────
echo "[12/15] Building PQClean static libs (parallel)..."
for tag in $BACKENDS; do
  for v in 512 768 1024; do
    make -j"$NPROC" -C "PQClean/crypto_kem/ml-kem-$v/$tag" EXTRAFLAGS="${EXTRA[$tag]}" &
  done
  for v in 44 65 87; do
    make -j"$NPROC" -C "PQClean/crypto_sign/ml-dsa-$v/$tag" EXTRAFLAGS="${EXTRA[$tag]}" &
  done
done
wait
echo "    Static libs done."

# ── 13. Compile OQS adapter objects ───────────────────────────────────────────
echo "[13/15] Compiling OQS adapter objects..."
for tag in $BACKENDS; do
  HFLAGS=""; [ "$tag" = "haraka" ] && HFLAGS="$HARAKA_CFLAGS"
  gcc $BASE_CFLAGS $HFLAGS -I "$OQS_INC" ${EXTRA[$tag]} \
      -c "pqc_${tag}_kem.c" -o "pqc_${tag}_kem.o"
  gcc $BASE_CFLAGS $HFLAGS -I "$OQS_INC" ${EXTRA[$tag]} \
      -c "pqc_${tag}_dsa.c" -o "pqc_${tag}_dsa.o"
done

# ── 14. Compile bench_shake (FIPS SHAKE baseline via liboqs static) ───────────
echo "[14/15] Compiling and linking benchmark binaries..."

gcc $BASE_CFLAGS -I "$OQS_INC" -c pqc_bench.c -o pqc_bench_shake.o
# Static link against liboqs.a so binary runs without LD_LIBRARY_PATH
gcc $BASE_CFLAGS pqc_bench_shake.o \
    "$OQS_STATIC" -lcrypto -lm -o bench_shake

# ── 15. Compile + link per-backend bench binaries (static) ───────────────────
declare -A KEMTAG=( [turboshake]=turboshake [k12]=k12 [blake3]=blake3 [xoodyak]=xoodyak [haraka]=haraka )
declare -A SIGTAG=( [turboshake]=turbo      [k12]=k12 [blake3]=blake3 [xoodyak]=xoodyak [haraka]=haraka )

for tag in $BACKENDS; do
  UTAG=$(echo "$tag" | tr '[:lower:]' '[:upper:]')
  HFLAGS=""; [ "$tag" = "haraka" ] && HFLAGS="$HARAKA_CFLAGS"

  gcc $BASE_CFLAGS $HFLAGS -DUSE_${UTAG} -I "$OQS_INC" ${EXTRA[$tag]} \
      -c pqc_bench.c -o "pqc_bench_${tag}.o"

  KLIBS=""
  for v in 512 768 1024; do
    KLIBS="$KLIBS PQClean/crypto_kem/ml-kem-$v/$tag/libml-kem-${v}_${KEMTAG[$tag]}.a"
  done
  SLIBS=""
  for v in 44 65 87; do
    SLIBS="$SLIBS PQClean/crypto_sign/ml-dsa-$v/$tag/libml-dsa-${v}_${SIGTAG[$tag]}.a"
  done

  EXTRALIB=""
  case "$tag" in
    turboshake|k12|xoodyak) EXTRALIB="$XKCP_LIB" ;;
    blake3)                 EXTRALIB="$ROOT/PQClean/common/BLAKE3/libblake3.a" ;;
    haraka)                 EXTRALIB="$ROOT/PQClean/common/Haraka/libharaka.a" ;;
  esac

  gcc $BASE_CFLAGS $HFLAGS \
    "pqc_bench_${tag}.o" "pqc_${tag}_kem.o" "pqc_${tag}_dsa.o" \
    $KLIBS $SLIBS \
    PQClean/common/fips202_turbo.o PQClean/common/randombytes_turbo.o \
    $EXTRALIB \
    "$OQS_STATIC" -lcrypto -lm -o "bench_${tag}"
done

echo ""
echo "=== Setup complete ==="
echo "Benchmark binaries:"
for b in bench_shake bench_turboshake bench_k12 bench_blake3 bench_xoodyak; do
  echo "  $b"
done
[ "$BUILD_HARAKA" = "1" ] && echo "  bench_haraka"
echo ""
echo "Run:  bash $REPO/bench.sh"
