#!/bin/bash
# pure_system_info.sh — System info for the pure implementation benchmark
# Output: pure_system_info.txt

OUT="${1:-pure_system_info.txt}"

{
echo "=============================================="
echo " PQC Pure Benchmark — System Information"
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
ARCH_NOW="$(uname -m)"
if [ "$ARCH_NOW" = "x86_64" ]; then
  FLAGS=$(grep -m1 'flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2)
  echo -n "AES-NI         : "; echo "$FLAGS" | grep -qw aes && echo "YES" || echo "NO"
  echo -n "AVX2           : "; echo "$FLAGS" | grep -qw avx2 && echo "YES" || echo "NO"
  echo -n "AVX-512        : "; echo "$FLAGS" | grep -qw avx512f && echo "YES" || echo "NO"
  echo -n "SSE4.1         : "; echo "$FLAGS" | grep -qw sse4_1 && echo "YES" || echo "NO"
  echo -n "SHA-NI         : "; echo "$FLAGS" | grep -qw sha_ni && echo "YES" || echo "NO"
elif [ "$ARCH_NOW" = "aarch64" ]; then
  ARM_FEATURES=$(cat /proc/cpuinfo 2>/dev/null | grep -m1 'Features' | cut -d: -f2)
  echo -n "NEON           : "; echo "YES (always on aarch64)"
  echo -n "AES            : "; echo "$ARM_FEATURES" | grep -qw aes && echo "YES" || echo "NO"
  echo -n "SHA2           : "; echo "$ARM_FEATURES" | grep -qw sha2 && echo "YES" || echo "NO"
fi
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

echo "── Benchmark Configuration ──────────────────"
echo ""
echo "Type           : PURE stock implementation benchmark"
echo "Library        : liboqs (linked statically)"
echo "Hash backend   : liboqs built-in (SHAKE/SHA-3, FIPS 202)"
echo "Modifications  : NONE — algorithms run exactly as liboqs ships them"
echo "Custom backends: NONE — no TurboSHAKE, K12, BLAKE3, Xoodyak, Haraka"
echo ""
echo "┌──────────────┬─────────────────────────────────────────────────┐"
echo "│ Algorithm    │ Description                                     │"
echo "├──────────────┼─────────────────────────────────────────────────┤"
echo "│ ML-KEM-512   │ FIPS 203, k=2, NIST Level 1, pk=800B ct=768B   │"
echo "│ ML-KEM-768   │ FIPS 203, k=3, NIST Level 3, pk=1184B ct=1088B │"
echo "│ ML-KEM-1024  │ FIPS 203, k=4, NIST Level 5, pk=1568B ct=1568B │"
echo "├──────────────┼─────────────────────────────────────────────────┤"
echo "│ ML-DSA-44    │ FIPS 204, NIST Level 2, sig=2420B              │"
echo "│ ML-DSA-65    │ FIPS 204, NIST Level 3, sig=3309B              │"
echo "│ ML-DSA-87    │ FIPS 204, NIST Level 5, sig=4627B              │"
echo "└──────────────┴─────────────────────────────────────────────────┘"
echo ""
echo "Operations     : keygen, encaps/decaps (KEM), sign/verify (DSA)"
echo "Correctness    : Round-trip self-test + tamper detection per algo"
echo "Timing         : wall-clock ns (CLOCK_MONOTONIC)"
echo "Threading      : SINGLE-THREADED (sequential)"
echo "Affinity       : Not pinned (OS scheduler)"
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

echo "── Build Info ─────────────────────────────────"
echo ""
echo "liboqs version : $(cat "$(dirname "$OUT")/../liboqs/.CMake/oqs-config.cmake" 2>/dev/null | grep version | head -1 || echo 'unknown')"
echo "liboqs commit  : $(cd "$(dirname "$OUT")/../liboqs" 2>/dev/null && git rev-parse HEAD 2>/dev/null || echo 'unknown')"
echo "Compiled with  : gcc -O3 -I <liboqs/build/include>"
echo "Linked against : liboqs.a (static), libcrypto (OpenSSL)"
echo ""

echo "=============================================="
} > "$OUT"

echo "[info] Pure system info saved to $OUT"
