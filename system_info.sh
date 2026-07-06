#!/bin/bash
# system_info.sh — Generate detailed CPU/system info file for benchmark context
# Called automatically by bench.sh and kem_k_bench.sh
# Output: system_info.txt in the current directory

OUT="${1:-system_info.txt}"

{
echo "=============================================="
echo " PQC Benchmark — System Information"
echo " Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "=============================================="
echo ""

echo "── CPU ──────────────────────────────────────"
echo "Model          : $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo 'N/A')"
echo "Architecture   : $(uname -m)"
echo "Physical cores : $(grep -c '^processor' /proc/cpuinfo 2>/dev/null || nproc)"
echo "Logical CPUs   : $(nproc)"
THREADS_PER_CORE=$(lscpu 2>/dev/null | grep 'Thread(s) per core' | awk '{print $NF}')
echo "Threads/core   : ${THREADS_PER_CORE:-1}"
if [ "${THREADS_PER_CORE:-1}" -gt 1 ]; then
  echo "Hyperthreading : YES"
else
  echo "Hyperthreading : NO"
fi
echo "Sockets        : $(lscpu 2>/dev/null | grep 'Socket(s)' | awk '{print $NF}' || echo '1')"
echo "Cores/socket   : $(lscpu 2>/dev/null | grep 'Core(s) per socket' | awk '{print $NF}' || echo 'N/A')"
echo ""

echo "── CPU Frequency ────────────────────────────"
if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq ]; then
  CUR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null)
  MIN=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq 2>/dev/null)
  MAX=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq 2>/dev/null)
  echo "Current freq   : $((CUR/1000)) MHz"
  echo "Min freq       : $((MIN/1000)) MHz"
  echo "Max freq       : $((MAX/1000)) MHz"
else
  MHZ=$(grep -m1 'cpu MHz' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs)
  echo "CPU MHz        : ${MHZ:-N/A}"
fi
GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'N/A')
echo "Governor       : $GOV"
echo ""

echo "── CPU Features ─────────────────────────────"
FLAGS=$(grep -m1 'flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2)
echo -n "AES-NI         : "; echo "$FLAGS" | grep -qw aes && echo "YES" || echo "NO"
echo -n "AVX2           : "; echo "$FLAGS" | grep -qw avx2 && echo "YES" || echo "NO"
echo -n "AVX-512        : "; echo "$FLAGS" | grep -qw avx512f && echo "YES" || echo "NO"
echo -n "SSE4.1         : "; echo "$FLAGS" | grep -qw sse4_1 && echo "YES" || echo "NO"
echo -n "SHA-NI         : "; echo "$FLAGS" | grep -qw sha_ni && echo "YES" || echo "NO"
echo -n "NEON (ARM)     : "; echo "$FLAGS" | grep -qw neon && echo "YES" || ([ "$(uname -m)" = "aarch64" ] && echo "YES (implied)" || echo "NO")
echo ""

echo "── Memory ───────────────────────────────────"
echo "Total RAM      : $(free -h 2>/dev/null | awk '/Mem:/{print $2}' || echo 'N/A')"
echo "Available RAM  : $(free -h 2>/dev/null | awk '/Mem:/{print $7}' || echo 'N/A')"
echo ""

echo "── OS / Kernel ──────────────────────────────"
echo "Kernel         : $(uname -r)"
echo "OS             : $(cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME' | cut -d= -f2 | tr -d '"' || uname -o)"
echo "Compiler       : $(gcc --version 2>/dev/null | head -1 || echo 'N/A')"
echo ""

echo "── Compiler Flags (Benchmark Build) ─────────"
echo ""
echo "These are the exact gcc flags used to compile each backend"
echo "during benchmarking (setup.sh / hyper_bench.sh / kem_k_bench.sh)."
echo ""
ARCH_CF="$(uname -m)"
echo "Base CFLAGS    : -O3 -march=native -Wall   (all backends)"
if [ "$ARCH_CF" = "x86_64" ]; then
  echo "Haraka CFLAGS  : -maes -msse4.1   (+ base; AES-NI round fn)"
else
  echo "Haraka CFLAGS  : -march=native    (+ base; ARM Crypto Ext)"
fi
echo "BLAKE3 CFLAGS  : -DBLAKE3_USE_NEON=0 -DBLAKE3_NO_SSE2"
echo "                 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2"
echo "                 -DBLAKE3_NO_AVX512   (portable C, SIMD off)"
echo "liboqs CFLAGS  : -O3 -march=native   (CMAKE_C_FLAGS)"
echo "liboqs cmake   : OQS_DIST_BUILD=OFF, OQS_USE_OPENSSL=OFF,"
if [ "$ARCH_CF" = "x86_64" ]; then
  echo "                 OQS_USE_AVX_INSTRUCTIONS=OFF,"
  echo "                 OQS_USE_AVX2_INSTRUCTIONS=OFF,"
  echo "                 OQS_USE_AVX512_INSTRUCTIONS=OFF"
else
  echo "                 kyber_{512,768,1024}_aarch64=OFF"
fi
echo "Linking        : static (liboqs.a) + libcrypto (OpenSSL) + libm"
echo ""

echo "── Benchmark Threading ──────────────────────"
echo "Execution mode : SINGLE-THREADED (sequential)"
echo "Affinity       : Not pinned (OS scheduler)"
echo "Note           : All PQC operations are single-threaded."
echo "                 No multi-threading or parallelism is used"
echo "                 during timing. Each operation (keygen,"
echo "                 encaps, decaps, sign, verify) runs on"
echo "                 one core at a time."
echo ""

echo "── Process Info ─────────────────────────────"
echo "PID            : $$"
echo "Nice           : $(nice)"
echo "Scheduler      : $(chrt -p $$ 2>/dev/null | tail -1 || echo 'N/A')"
echo ""

echo "── Build Matrix (Implementation Parity) ─────"
echo ""
echo "┌──────────────┬───────────────────┬──────────────────────────────────────┐"
echo "│ Backend      │ Source            │ SIMD / Optimisation                  │"
echo "├──────────────┼───────────────────┼──────────────────────────────────────┤"
echo "│ shake        │ liboqs (scalar)   │ No SIMD (OQS_DIST_BUILD=OFF)        │"
echo "│ turboshake   │ XKCP generic64    │ No SIMD (scalar C Keccak)            │"
echo "│ k12          │ XKCP generic64    │ No SIMD (scalar C Keccak)            │"
echo "│ blake3       │ portable C        │ All SIMD explicitly disabled         │"
echo "│ xoodyak      │ XKCP generic64    │ No SIMD (scalar C Xoodoo)            │"
echo "│ haraka       │ PQClean custom    │ AES-NI/NEON (arch-specific by design)│"
echo "└──────────────┴───────────────────┴──────────────────────────────────────┘"
echo ""
echo "All backends compiled with -O3 -march=native."
echo "liboqs SHAKE Keccak forced to scalar via:"
echo "  OQS_DIST_BUILD=OFF, OQS_USE_OPENSSL=OFF,"
echo "  OQS_USE_AVX_INSTRUCTIONS=OFF, OQS_USE_AVX2_INSTRUCTIONS=OFF,"
echo "  OQS_USE_AVX512_INSTRUCTIONS=OFF"
echo "Baseline x86_64 instructions (SSE2, AES-NI, BMI, POPCNT) kept enabled."
echo "Comparison isolates algorithm properties (round count, permutation)"
echo "from vectorisation tier differences."
echo ""

echo "── Algorithm Capabilities ───────────────────"
echo ""
echo "Compiler flags : -O3 -march=native (all backends)"
echo "Linking        : static (liboqs.a, no shared lib overhead)"
echo "RNG source     : OpenSSL RAND_bytes (via PQClean randombytes.c)"
echo ""
echo "┌──────────────┬──────────────────────────────────────────────────┐"
echo "│ Backend      │ Capabilities / HW features used                 │"
echo "├──────────────┼──────────────────────────────────────────────────┤"
echo "│ shake        │ FIPS SHAKE/SHA-3 (Keccak-f[1600], n_r=24)      │"
echo "│              │ liboqs scalar Keccak (no AVX2 dispatch)         │"
echo "├──────────────┼──────────────────────────────────────────────────┤"
echo "│ turboshake   │ TurboSHAKE (Keccak-p[1600,12], n_r=12)         │"
echo "│              │ via XKCP library; software permutation          │"
echo "├──────────────┼──────────────────────────────────────────────────┤"
echo "│ k12          │ KangarooTwelve (Keccak-p[1600,12] + tree hash)  │"
echo "│              │ via XKCP library; software permutation          │"
echo "├──────────────┼──────────────────────────────────────────────────┤"
echo "│ blake3       │ BLAKE3 XOF (portable C, all SIMD disabled)      │"
echo "│              │ Flags: -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41      │"
echo "│              │        -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512     │"
echo "│              │        -DBLAKE3_USE_NEON=0                      │"
echo "├──────────────┼──────────────────────────────────────────────────┤"
echo "│ xoodyak      │ Xoodyak / Xoodoo[12] (Cyclist mode)             │"
echo "│              │ via XKCP library; software permutation          │"
echo "├──────────────┼──────────────────────────────────────────────────┤"
ARCH_NOW="$(uname -m)"
if [ "$ARCH_NOW" = "x86_64" ]; then
echo "│ haraka       │ Haraka-256/512 v2 (AES round function)          │"
echo "│              │ x86_64: uses AES-NI + SSE4.1 (-maes -msse4.1)  │"
else
echo "│ haraka       │ Haraka-256/512 v2 (AES round function)          │"
echo "│              │ aarch64: uses NEON + ARM Crypto Extensions      │"
fi
echo "└──────────────┴──────────────────────────────────────────────────┘"
echo ""
echo "┌──────────────┬──────────────────────────────────────────────────┐"
echo "│ Algorithm    │ Capabilities / structure                        │"
echo "├──────────────┼──────────────────────────────────────────────────┤"
echo "│ ML-KEM       │ FIPS 203 (Kyber). Lattice-based KEM.            │"
echo "│ (512/768/    │ Operations: keygen, encaps, decaps              │"
echo "│  1024)       │ XOF used for: matrix sampling, noise gen, KDF   │"
echo "├──────────────┼──────────────────────────────────────────────────┤"
echo "│ ML-DSA       │ FIPS 204 (Dilithium). Lattice-based signature.  │"
echo "│ (44/65/87)   │ Operations: keygen, sign, verify               │"
echo "│              │ XOF used for: matrix expand, challenge hash,    │"
echo "│              │   mask generation, hint encoding                │"
echo "└──────────────┴──────────────────────────────────────────────────┘"
echo ""
echo "── Active HW Capabilities (this system) ─────"
HAS_AES="NO"; HAS_AVX2="NO"; HAS_SSE41="NO"; HAS_NEON="NO"; HAS_SHA="NO"
if [ "$ARCH_NOW" = "x86_64" ]; then
  X86_FLAGS=$(grep -m1 'flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2)
  echo "$X86_FLAGS" | grep -qw aes && HAS_AES="YES"
  echo "$X86_FLAGS" | grep -qw avx2 && HAS_AVX2="YES"
  echo "$X86_FLAGS" | grep -qw sse4_1 && HAS_SSE41="YES"
  echo "$X86_FLAGS" | grep -qw sha_ni && HAS_SHA="YES"
  echo "Haraka uses    : AES-NI=$HAS_AES, SSE4.1=$HAS_SSE41"
  echo "BLAKE3 uses    : portable C only (all SIMD disabled)"
  echo "SHAKE uses     : liboqs Keccak (may use AVX2=$HAS_AVX2)"
  echo "TurboSHAKE/K12 : XKCP generic64 (software Keccak)"
  echo "Xoodyak uses   : XKCP generic64 (software Xoodoo)"
elif [ "$ARCH_NOW" = "aarch64" ]; then
  HAS_NEON="YES (always on aarch64)"
  ARM_FEATURES=$(cat /proc/cpuinfo 2>/dev/null | grep -m1 'Features' | cut -d: -f2)
  echo "$ARM_FEATURES" | grep -qw aes && HAS_AES="YES"
  echo "$ARM_FEATURES" | grep -qw sha2 && HAS_SHA="YES"
  echo "Haraka uses    : NEON + ARM Crypto (AES=$HAS_AES)"
  echo "BLAKE3 uses    : portable C only (NEON disabled)"
  echo "SHAKE uses     : liboqs Keccak (HW-accel if available)"
  echo "TurboSHAKE/K12 : XKCP generic64 (software Keccak)"
  echo "Xoodyak uses   : XKCP generic64 (software Xoodoo)"
fi
echo ""

echo "── Algorithm Payloads (bytes) ─────────────────"
echo ""
echo "┌──────────────┬──────────┬──────────┬──────────┬──────────┬───────┐"
echo "│ Algorithm    │ PK (B)   │ SK (B)   │ CT/SIG   │ SS (B)   │ NIST  │"
echo "├──────────────┼──────────┼──────────┼──────────┼──────────┼───────┤"
echo "│ ML-KEM-512   │      800 │    1,632 │      768 │       32 │   1   │"
echo "│ ML-KEM-768   │    1,184 │    2,400 │    1,088 │       32 │   3   │"
echo "│ ML-KEM-1024  │    1,568 │    3,168 │    1,568 │       32 │   5   │"
echo "├──────────────┼──────────┼──────────┼──────────┼──────────┼───────┤"
echo "│ ML-DSA-44    │    1,312 │    2,560 │    2,420 │      n/a │   2   │"
echo "│ ML-DSA-65    │    1,952 │    4,032 │    3,309 │      n/a │   3   │"
echo "│ ML-DSA-87    │    2,592 │    4,896 │    4,627 │      n/a │   5   │"
echo "└──────────────┴──────────┴──────────┴──────────┴──────────┴───────┘"
echo ""
echo "PK = public key, SK = secret key, CT = ciphertext, SIG = signature"
echo "SS = shared secret, NIST = claimed NIST security level"
echo ""
echo "Network note: ML-DSA-87 sig (4,627B) exceeds 1500B MTU → IP fragmentation"
echo "              ML-KEM-1024 ct (1,568B) fits within MTU"
echo ""

echo "=============================================="
} > "$OUT"

echo "[info] System info saved to $OUT"
