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

echo "=============================================="
} > "$OUT"

echo "[info] System info saved to $OUT"
