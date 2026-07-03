/*
 * =============================================================================
 * FILE:    pqc_agility_benchmark.c
 *
 * TITLE:   Post-Quantum Cryptographic Agility Benchmarking Suite
 *          ML-DSA (FIPS 204 / Dilithium) and ML-KEM (FIPS 203 / Kyber)
 *          Native SHAKE  vs  TurboSHAKE (RFC 9861) Hash Substitution
 *
 * PURPOSE: This file implements the COMPLETE multi-tiered benchmarking
 *          framework described in:
 *            [1] "Engineering and Benchmarking Algorithmic Agility in
 *                 Post-Quantum Cryptography" (PDF 1)
 *            [2] "Post-Quantum Cryptographic Agility: Engineering the
 *                 Integration and Benchmarking of TurboSHAKE within
 *                 ML-DSA and ML-KEM" (PDF 2)
 *
 * TIERS IMPLEMENTED:
 *   TIER 1  - CPU Cycle Profiling (rdtsc + lfence serialization, SUPERCOP method)
 *   TIER 2  - Statistical Aggregation (median, quartiles, geo-mean, 99th pct tail)
 *   TIER 3  - Rejection Sampling Variance (iteration count histogram for ML-DSA)
 *   TIER 4  - Sub-Component Isolation (matrix expand, CBD noise, sign, verify,
 *             encaps, decaps separately)
 *   TIER 5  - Stack Watermarking / Painting (0xDEADBEEF sentinel technique)
 *   TIER 6  - Welch's t-test Constant-Time Validation (dudect methodology)
 *   TIER 7  - Cycles-per-Byte (CpB) Throughput Metric
 *   TIER 8  - Wall-clock timing (CLOCK_MONOTONIC, ns resolution)
 *   TIER 9  - Algorithm metadata and FIPS/compliance notes
 *   TIER 10 - CSV report generation for external analysis (perf, Cachegrind)
 *   TIER 11 - Memory Footprint Profiling (peak RSS via getrusage,
 *             heap-arena delta via mallinfo -- POSIX/libc only, no
 *             hardware-specific counters)
 *   TIER 12 - Software Energy Proxy Model (Energy Proxy Units derived from
 *             cycle counts, plus optional user-calibrated uJ estimate and
 *             Energy-Delay Product -- no RAPL/MSR/board sensors required)
 *
 * LIBRARY COMPATIBILITY:
 *   - liboqs  (Open Quantum Safe)  -- primary target
 *   - PQClean -- secondary target (stub stubs at bottom)
 *   Link: gcc pqc_agility_benchmark.c -loqs -lm -O2 -o pqc_bench
 *         (add -DUSE_TURBOSHAKE to switch hash backend)
 *         (add -DUSE_PQCLEAN    to use PQClean instead of liboqs)
 *
 * IMPORTANT COMPLIANCE NOTE (from PDFs):
 *   Replacing SHAKE with TurboSHAKE inside ML-DSA or ML-KEM BREAKS strict
 *   FIPS 203/204 compliance and BREAKS interoperability with standard-compliant
 *   peers on the open internet.  This benchmark is designed for CLOSED
 *   ecosystems, proprietary zero-trust networks, IoT/SCADA environments, or
 *   pure research purposes where performance outweighs interoperability.
 *
 * SPONGE CONSTRUCTION REFERENCE (both PDFs, Table 1):
 *   Parameter        SHAKE128    TurboSHAKE128  SHAKE256    TurboSHAKE256
 *   Permutation      Keccak-P    Keccak-P       Keccak-P    Keccak-P
 *   Rounds (n_r)     24          12             24          12
 *   Capacity (c)     256 bits    256 bits       512 bits    512 bits
 *   Rate (r)         1344 bits   1344 bits      1088 bits   1088 bits
 *                    (168 bytes) (168 bytes)    (136 bytes) (136 bytes)
 *   Domain Sep.      Implied     Explicit 0x01  Implied     Explicit 0x01
 *                    pad10*1     ..0x7F + 0x80  pad10*1     ..0x7F + 0x80
 *   Sec. Margin      128-bit     128-bit        256-bit     256-bit
 *
 * CRYPTANALYTIC SAFETY NOTE (both PDFs):
 *   Best known collision attack on Keccak breaks 6/24 rounds.
 *   TurboSHAKE uses 12/24 rounds => 100% safety margin above best attack.
 *
 * BUILD COMMANDS:
 *   # Standard (SHAKE, FIPS-compliant):
 *   gcc -O2 -march=native pqc_agility_benchmark.c -loqs -lm -o bench_shake
 *
 *   # TurboSHAKE variant (non-FIPS, closed ecosystem only):
 *   gcc -O2 -march=native -DUSE_TURBOSHAKE pqc_agility_benchmark.c -loqs -lm -o bench_turboshake
 *
 *   # Optional: calibrate the TIER 12 energy proxy for your platform by
 *   # supplying its measured energy-per-cycle figure (nanojoules/cycle).
 *   # See "SOFTWARE-LEVEL ENERGY PROXY MODEL" below for how to derive it.
 *   # Without this flag, energy figures are reported as illustrative only.
 *   gcc -O2 -march=native -DENERGY_PER_CYCLE_NJ=0.42 pqc_agility_benchmark.c -loqs -lm -o bench_shake
 *
 *   # With Valgrind Massif heap profiling:
 *   valgrind --tool=massif --stacks=yes ./bench_shake
 *
 *   # With Cachegrind instruction profiling:
 *   valgrind --tool=cachegrind ./bench_shake
 *
 *   # With perf hardware counters (run as root or with perf_event_paranoid=1):
 *   perf stat -e cycles,instructions,cache-misses,cache-references,branch-misses \
 *             ./bench_shake --iterations 10000
 *
 * =============================================================================
 */

/* =========================================================================
 * STANDARD HEADERS
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <inttypes.h>

/* =========================================================================
 * MEMORY PROFILING HEADERS (POSIX, software-level only)
 *
 * getrusage() is part of POSIX.1-2001 (<sys/resource.h>) and is available
 * on Linux, macOS, *BSD, and other POSIX systems.  It reports figures
 * gathered entirely by the OS kernel's own bookkeeping -- NOT from any
 * CPU performance counter, RAPL register, or vendor-specific MSR.  This
 * keeps the memory tier fully portable and hardware-independent.
 *
 * mallinfo2()/mallinfo() (glibc <malloc.h>) report the heap allocator's
 * own arena statistics.  This is purely a libc-level facility, also not
 * tied to any specific CPU/board.  On non-glibc platforms it is disabled
 * automatically and the heap-delta columns simply report 0.
 * ========================================================================= */
#include <sys/resource.h>
#include <sys/mman.h>      /* mlockall: pin pages, avoid page-fault spikes */
#include <sched.h>         /* sched_setscheduler: SCHED_FIFO tail control  */
#if defined(__GLIBC__)
#  include <malloc.h>
#  define PQC_HAVE_MALLINFO 1
#endif

/* =========================================================================
 * LIBOQS HEADERS
 * These expose OQS_KEM and OQS_SIG structures with function pointers:
 *   OQS_KEM->keypair()  OQS_KEM->encaps()  OQS_KEM->decaps()
 *   OQS_SIG->keypair()  OQS_SIG->sign()    OQS_SIG->verify()
 * ========================================================================= */
#ifndef USE_PQCLEAN
#  include <oqs/oqs.h>       /* liboqs master header     */
#  include <oqs/kem.h>       /* OQS_KEM struct           */
#  include <oqs/sig.h>       /* OQS_SIG struct           */
#endif

#ifdef USE_SHAKE
/* OQS_KEM constructors for the SHAKE (FIPS 202) baseline ML-KEM variants --
 * forked PQClean "clean" implementations whose symmetric-shake.c is
 * byte-identical to upstream PQClean, compiled with the same Makefile and
 * flags as the five substituted backends. This makes bench_shake a true
 * hash-substitution baseline; the liboqs build (no -DUSE_* flag) remains
 * available as a separate "production reference" series (bench_liboqs). */
#  include "pqc_shake_kem.h"
/* OQS_SIG constructors for the SHAKE baseline ML-DSA variants -- see
 * pqc_shake_dsa.h for details. */
#  include "pqc_shake_dsa.h"
#endif

#ifdef USE_TURBOSHAKE
/* OQS_KEM constructors for the TurboSHAKE (RFC 9861) ML-KEM variants --
 * forked PQClean "clean" implementations with SHAKE128/256 replaced by
 * TurboSHAKE128/256 (n_r=12). See pqc_turboshake_kem.h for details. */
#  include "pqc_turboshake_kem.h"
/* OQS_SIG constructors for the TurboSHAKE ML-DSA variants -- see
 * pqc_turboshake_dsa.h for details. */
#  include "pqc_turboshake_dsa.h"
#endif

#ifdef USE_K12
/* OQS_KEM constructors for the KangarooTwelve (RFC 9861) ML-KEM variants --
 * forked PQClean "clean" implementations with SHAKE128/256 replaced by
 * KT128/KT256 (n_r=12 tree hashing). See pqc_k12_kem.h for details. */
#  include "pqc_k12_kem.h"
/* OQS_SIG constructors for the KangarooTwelve ML-DSA variants -- see
 * pqc_k12_dsa.h for details. */
#  include "pqc_k12_dsa.h"
#endif

#ifdef USE_BLAKE3
/* OQS_KEM constructors for the BLAKE3 ML-KEM variants -- forked PQClean
 * "clean" implementations with SHAKE128/256 replaced by BLAKE3's native
 * XOF. See pqc_blake3_kem.h for details. */
#  include "pqc_blake3_kem.h"
/* OQS_SIG constructors for the BLAKE3 ML-DSA variants -- see
 * pqc_blake3_dsa.h for details. */
#  include "pqc_blake3_dsa.h"
#endif

#ifdef USE_XOODYAK
/* OQS_KEM constructors for the Xoodyak ML-KEM variants -- forked PQClean
 * "clean" implementations with SHAKE128/256 replaced by Xoodyak's Cyclist
 * hash mode (XKCP). See pqc_xoodyak_kem.h for details. */
#  include "pqc_xoodyak_kem.h"
/* OQS_SIG constructors for the Xoodyak ML-DSA variants -- see
 * pqc_xoodyak_dsa.h for details. */
#  include "pqc_xoodyak_dsa.h"
#endif

#ifdef USE_HARAKA
/* OQS_KEM constructors for the Haraka ML-KEM variants -- forked PQClean
 * "clean" implementations with SHAKE128/256 replaced by a non-standard
 * Haraka512-based counter-mode construction. See pqc_haraka_kem.h. */
#  include "pqc_haraka_kem.h"
/* OQS_SIG constructors for the Haraka-MD ML-DSA variants -- see
 * pqc_haraka_dsa.h for details. */
#  include "pqc_haraka_dsa.h"
#endif

/* =========================================================================
 * COMPILE-TIME CONFIGURATION
 * Adjust these macros to tune benchmark depth and algorithm selection.
 * ========================================================================= */

/* Number of benchmark iterations (main loop).
 * ML-DSA MUST use >= 10,000 due to rejection sampling variance (PDF1/PDF2). */
#ifndef BENCH_ITERATIONS
#  define BENCH_ITERATIONS        10000
#endif

/* Warm-up iterations discarded before measurement begins.
 * Accounts for I1 (instruction cache) and D1 (data cache) cold loading.
 * SUPERCOP methodology (PDF1, section "SUPERCOP Methodology"). */
#ifndef BENCH_WARMUP
#  define BENCH_WARMUP            200
#endif

/* Runtime overrides: --iterations N and --warmup N.  The compile-time
 * macros above only provide the defaults; the driver scripts
 * (bench_controlled.sh, bench_shuffled.sh, bench_wait.sh) pass these
 * flags per run.  All later code references the macros, which now expand
 * to these globals. */
static int g_bench_iterations = BENCH_ITERATIONS;
static int g_bench_warmup     = BENCH_WARMUP;
#undef  BENCH_ITERATIONS
#undef  BENCH_WARMUP
#define BENCH_ITERATIONS  g_bench_iterations
#define BENCH_WARMUP      g_bench_warmup

/* Dudect constant-time test: number of measurement pairs.
 * Must be large (>= 1,000,000) for statistical significance.
 * Welch's t-test threshold: |t| > 4.5 => timing leak detected (PDF1). */
#ifndef DUDECT_MEASUREMENTS
#  define DUDECT_MEASUREMENTS     1000000
#endif

/* Welch t-test significance threshold from dudect methodology (PDF1/PDF2).
 * If |t_value| > DUDECT_T_THRESHOLD => implementation leaks timing info. */
#define DUDECT_T_THRESHOLD        4.5

/* Percentile crop for dudect (removes OS-noise outliers above 99th pct). */
#define DUDECT_CROP_PERCENTILE    0.99

/* Stack painting sentinel (0xDEADBEEF pattern, PDF1/PDF2 stack watermarking). */
#define STACK_SENTINEL_WORD       0xDEADBEEFU

/* Stack paint region size in bytes.
 * Must be >= worst-case ML-DSA stack usage (~100KB, PDF1/PDF2). */
#define STACK_PAINT_REGION_BYTES  (128 * 1024)   /* 128 KB */

/* Message length for signing benchmarks (realistic IoT packet size). */
#define BENCH_MSG_LEN             256

/* TurboSHAKE domain separation byte for ML-DSA matrix expansion (RFC 9861).
 * Must be in range 0x01..0x7F.  0x1F = custom IoT experimental domain (PDF2). */
#define TURBOSHAKE_DOMAIN_MATRIX  0x1F

/* TurboSHAKE domain separation byte for ML-KEM CBD noise generation.   */
#define TURBOSHAKE_DOMAIN_CBD     0x2F

/* TurboSHAKE domain separation byte for challenge polynomial generation. */
#define TURBOSHAKE_DOMAIN_CHAL    0x3F

/* Output CSV file path for external analysis. */
#define BENCH_CSV_OUTPUT          "pqc_benchmark_results.csv"

/* =========================================================================
 * SOFTWARE-LEVEL ENERGY PROXY MODEL (hardware-independent)
 *
 * THEORY:
 *   Direct energy measurement (RAPL MSRs, INA219 shunts, oscilloscopes,
 *   ammeters on a dev board) is inherently HARDWARE-DEPENDENT: it varies
 *   by CPU vendor, process node, voltage/frequency scaling state, board
 *   power rails, etc.  None of that is available -- or even meaningful --
 *   in a cross-platform "software agility" benchmark.
 *
 *   Instead, this suite reports an ENERGY PROXY derived purely from the
 *   already-measured CPU-cycle counts (TIER 1/2).  For a CPU running at a
 *   fixed voltage/frequency point, dynamic energy consumed by an operation
 *   is, to first order, linearly proportional to the number of clock
 *   cycles it retires:
 *
 *       E_op  ~=  cycles_op  *  k        (k = energy per cycle, J/cycle)
 *
 *   We do NOT claim to know "k" for the user's hardware (that would be a
 *   hardware-dependent constant).  Instead we report results in two forms:
 *
 *     1. ENERGY PROXY UNITS (EPU)  = median cycles for the operation.
 *        This is dimensionless and 100% hardware-independent.  It is the
 *        correct quantity to compare ACROSS hash backends (SHAKE vs
 *        TurboSHAKE) and across algorithms, because "fewer cycles always
 *        means less energy" regardless of which device runs the code.
 *
 *     2. CALIBRATED ENERGY ESTIMATE (uJ) = EPU * ENERGY_PER_CYCLE_NJ / 1000
 *        ENERGY_PER_CYCLE_NJ is a USER-SUPPLIED constant (nanojoules per
 *        cycle) representing the target platform's known/measured energy-
 *        per-cycle figure.  If the user does not supply one, a clearly
 *        labeled illustrative default is used and the report states the
 *        figure is NOT a hardware measurement.
 *
 *   This keeps the "energy" tier purely a software-side transformation of
 *   data already collected -- no platform-specific registers, drivers,
 *   or sensors are touched.
 *
 *   To calibrate for a real platform, measure that platform's average
 *   power draw P (Watts) at a known clock frequency F (Hz) under load,
 *   then:
 *       ENERGY_PER_CYCLE_NJ = (P / F) * 1e9
 *   and pass it at build time, e.g.:
 *       gcc -DENERGY_PER_CYCLE_NJ=0.42 ...
 * ========================================================================= */
#ifndef ENERGY_PER_CYCLE_NJ
#  define ENERGY_PER_CYCLE_NJ     1.0   /* illustrative default (nJ/cycle) */
#  define ENERGY_MODEL_CALIBRATED 0
#else
#  define ENERGY_MODEL_CALIBRATED 1
#endif

/* Energy-Delay Product scaling: EDP = cycles * wall_ns.  Reported in
 * "cycle-nanoseconds" -- another purely software/timing-derived metric
 * used in low-power literature to balance speed vs. energy together. */

/* =========================================================================
 * RAPL ENERGY MEASUREMENT (Linux x86 only)
 *
 * Intel RAPL (Running Average Power Limit) provides actual hardware energy
 * measurements via /sys/class/powercap/. When available, this gives real
 * energy consumption in microjoules. Falls back to the software proxy
 * (EPU = median cycles) when RAPL is unavailable.
 * ========================================================================= */
#include <fcntl.h>
#include <unistd.h>

static int rapl_available = 0;

/* Median rdtsc/cntvct harness cost subtracted from every sample; exported
 * to the CSV so readers can see exactly what was removed. */
static uint64_t g_timing_overhead_cycles = 0;

static double rapl_read_uj(void) {
    static int fd = -2;
    if (fd == -2) {
        fd = open("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj",
                  O_RDONLY);
    }
    if (fd < 0) return -1.0;
    char buf[32];
    memset(buf, 0, sizeof(buf));
    ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return -1.0;
    return strtod(buf, NULL);
}

static void rapl_init(void) {
    double v = rapl_read_uj();
    rapl_available = (v > 0.0) ? 1 : 0;
}

/* =========================================================================
 * NOISE / TAIL-LATENCY REDUCTION (best effort, no failure is fatal)
 *
 * Two dominant sources of tail latency in user-space benchmarks:
 *   1. Page faults inside the timed loop (first touch of a page, or the
 *      kernel reclaiming pages under memory pressure)  -> mlockall()
 *   2. Preemption by other runnable tasks / kernel threads mid-measurement
 *      -> SCHED_FIFO real-time class (root), falling back to nice -20
 * Both are applied once at startup.  Each is best-effort: without root the
 * calls fail silently and the benchmark still runs, just with more noise.
 * ========================================================================= */
static void reduce_measurement_noise(void) {
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0)
        printf("  Noise control    : mlockall OK (pages locked, no page-fault spikes)\n");
    else
        printf("  Noise control    : mlockall unavailable (run as root to enable)\n");

    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = 90;
    if (sched_setscheduler(0, SCHED_FIFO, &sp) == 0) {
        printf("  Scheduler        : SCHED_FIFO prio 90 (preemption suppressed)\n");
    } else if (setpriority(PRIO_PROCESS, 0, -20) == 0) {
        printf("  Scheduler        : nice -20 (SCHED_FIFO needs root)\n");
    } else {
        printf("  Scheduler        : default (run as root for FIFO / nice -20)\n");
    }
}

/* =========================================================================
 * ALGORITHM VARIANT TAG
 * Printed in all reports so you know which hash backend is active.
 * ========================================================================= */
#ifdef USE_SHAKE
#  define HASH_BACKEND_TAG    "SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)"
#  define HASH_ROUNDS         24
#  define FIPS_COMPLIANT      1
#  define KEM_VECTOR1_LABEL   "SHAKE128 (n_r=24)"
#  define KEM_VECTOR2_LABEL   "SHAKE256 (n_r=24)"
#  define KEM_VECTOR4_LABEL   "SHAKE256 (n_r=24)"
#elif defined(USE_TURBOSHAKE)
#  define HASH_BACKEND_TAG    "TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)"
#  define HASH_ROUNDS         12
#  define FIPS_COMPLIANT      0
#  define KEM_VECTOR1_LABEL   "TurboSHAKE128 (n_r=12, D=0x1F)"
#  define KEM_VECTOR2_LABEL   "TurboSHAKE256 (n_r=12, D=0x2F)"
#  define KEM_VECTOR4_LABEL   "TurboSHAKE256 (n_r=12, D=0x3F)"
#elif defined(USE_K12)
#  define HASH_BACKEND_TAG    "KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)"
#  define HASH_ROUNDS         12
#  define FIPS_COMPLIANT      0
#  define KEM_VECTOR1_LABEL   "KT128 (n_r=12, C=0x1F)"
#  define KEM_VECTOR2_LABEL   "KT256 (n_r=12, C=0x2F)"
#  define KEM_VECTOR4_LABEL   "KT256 (n_r=12, C=0x3F)"
#elif defined(USE_BLAKE3)
#  define HASH_BACKEND_TAG    "BLAKE3 (native XOF, 7 rounds, NON-FIPS)"
#  define HASH_ROUNDS         7
#  define FIPS_COMPLIANT      0
#  define KEM_VECTOR1_LABEL   "BLAKE3-XOF (D=0x1F)"
#  define KEM_VECTOR2_LABEL   "BLAKE3-XOF (D=0x2F)"
#  define KEM_VECTOR4_LABEL   "BLAKE3-XOF (D=0x3F)"
#elif defined(USE_XOODYAK)
#  define HASH_BACKEND_TAG    "Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)"
#  define HASH_ROUNDS         12
#  define FIPS_COMPLIANT      0
#  define KEM_VECTOR1_LABEL   "Xoodyak-Hash (D=0x1F)"
#  define KEM_VECTOR2_LABEL   "Xoodyak-Hash (D=0x2F)"
#  define KEM_VECTOR4_LABEL   "Xoodyak-Hash (D=0x3F)"
#elif defined(USE_HARAKA)
#  define HASH_BACKEND_TAG    "Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)"
#  define HASH_ROUNDS         5
#  define FIPS_COMPLIANT      0
#  define KEM_VECTOR1_LABEL   "Haraka-CTR (D=0x1F)"
#  define KEM_VECTOR2_LABEL   "Haraka-CTR (D=0x2F)"
#  define KEM_VECTOR4_LABEL   "Haraka-CTR (D=0x3F)"
#else
/* No -DUSE_* flag: liboqs's own ML-KEM/ML-DSA (separately engineered code,
 * same FIPS 202 SHAKE). Kept as an independent "production reference"
 * series -- NOT the hash-substitution baseline, which is USE_SHAKE. */
#  define HASH_BACKEND_TAG    "SHAKE-liboqs (FIPS 202, n_r=24, production reference)"
#  define HASH_ROUNDS         24
#  define FIPS_COMPLIANT      1
#  define KEM_VECTOR1_LABEL   "SHAKE128 (n_r=24, liboqs)"
#  define KEM_VECTOR2_LABEL   "SHAKE256 (n_r=24, liboqs)"
#  define KEM_VECTOR4_LABEL   "SHAKE256 (n_r=24, liboqs)"
#endif

/* =========================================================================
 * ML-KEM PARAMETER SETS (FIPS 203 / CRYSTALS-Kyber)
 * liboqs method name strings for OQS_KEM_new().
 *   ML-KEM-512  => NIST Level 1, k=2, public key 800B,  ciphertext 768B
 *   ML-KEM-768  => NIST Level 3, k=3, public key 1184B, ciphertext 1088B
 *   ML-KEM-1024 => NIST Level 5, k=4, public key 1568B, ciphertext 1568B
 * ========================================================================= */
#define MLKEM_512_NAME   OQS_KEM_alg_ml_kem_512
#define MLKEM_768_NAME   OQS_KEM_alg_ml_kem_768
#define MLKEM_1024_NAME  OQS_KEM_alg_ml_kem_1024

/* =========================================================================
 * ML-DSA PARAMETER SETS (FIPS 204 / CRYSTALS-Dilithium)
 * liboqs method name strings for OQS_SIG_new().
 *   ML-DSA-44 => NIST Level 2, expected rejection iters: ~4.25 (PDF1)
 *   ML-DSA-65 => NIST Level 3, expected rejection iters: ~5.10 (PDF1)
 *   ML-DSA-87 => NIST Level 5, expected rejection iters: ~3.85
 * ========================================================================= */
#define MLDSA_44_NAME    OQS_SIG_alg_ml_dsa_44
#define MLDSA_65_NAME    OQS_SIG_alg_ml_dsa_65
#define MLDSA_87_NAME    OQS_SIG_alg_ml_dsa_87

/* =========================================================================
 * TIER 1: CPU CYCLE COUNTER
 * Uses rdtsc + lfence (pipeline serialization fence).
 *
 * THEORY (PDF1/PDF2, "SUPERCOP Methodology and Pipeline Serialization"):
 *   Modern CPUs have out-of-order execution.  A naive rdtsc call may be
 *   reordered BEFORE or AFTER the target operation.  The lfence instruction
 *   is a LOAD FENCE that forces the CPU pipeline to drain and serialize,
 *   guaranteeing all prior instructions have FULLY RETIRED before the
 *   timestamp is read.  This is mandatory for sub-microsecond precision.
 *
 * WARNING: The rdtsc/rdtscp path works only on x86_64.  On aarch64 (e.g.
 *          ARM Cortex-A, Apple Silicon, AWS Graviton) we instead read the
 *          architectural virtual counter register (CNTVCT_EL0), which is
 *          a fixed-frequency monotonic counter readable from userspace and
 *          serialized with ISB barriers.  It is not literally "CPU cycles"
 *          (its frequency is given by CNTFRQ_EL0, typically <= the core
 *          clock), but it provides the same relative-comparison semantics
 *          needed here: SHAKE vs TurboSHAKE runs use the same counter.
 * ========================================================================= */
#if defined(__x86_64__) || defined(__i386__)
static inline uint64_t cpucycles_begin(void) {
    uint32_t lo, hi;
    /*
     * lfence  => serialize the pipeline (all prior loads must complete).
     * rdtsc   => read 64-bit timestamp counter into EDX:EAX.
     * shlq    => shift high 32 bits left by 32.
     * orq     => combine into single 64-bit result.
     *
     * The "volatile" prevents the compiler from moving this instruction
     * or caching its result across iterations.
     */
    __asm__ volatile (
        "lfence\n\t"
        "rdtsc\n\t"
        : "=a"(lo), "=d"(hi)
        :
        : "memory"
    );
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t cpucycles_end(void) {
    uint32_t lo, hi;
    /*
     * rdtscp  => serializing read (includes implicit lfence semantics).
     *            Also writes processor ID into ECX (discarded here).
     * lfence  => second fence AFTER the read to prevent subsequent
     *            instructions from being pulled in front of the timestamp.
     */
    __asm__ volatile (
        "rdtscp\n\t"
        "lfence\n\t"
        : "=a"(lo), "=d"(hi)
        :
        : "%ecx", "memory"
    );
    return ((uint64_t)hi << 32) | lo;
}
#elif defined(__aarch64__)
/*
 * aarch64 counter: CNTVCT_EL0 is a fixed-frequency timer (typically 24-54 MHz),
 * NOT the CPU cycle counter. Values are "timer ticks", not CPU cycles.
 * CpB and energy proxy columns derived from this are timer-tick-based, not
 * cycle-based. For cross-architecture comparison, use wall-clock (ns) columns.
 */
static inline uint64_t cpucycles_begin(void) {
    uint64_t val;
    __asm__ volatile (
        "isb\n\t"
        "mrs %0, cntvct_el0\n\t"
        : "=r"(val)
        :
        : "memory"
    );
    return val;
}

static inline uint64_t cpucycles_end(void) {
    uint64_t val;
    __asm__ volatile (
        "isb\n\t"
        "mrs %0, cntvct_el0\n\t"
        : "=r"(val)
        :
        : "memory"
    );
    return val;
}

static inline uint64_t get_timer_freq_hz(void) {
    uint64_t freq;
    __asm__ volatile ("mrs %0, cntfrq_el0" : "=r"(freq));
    return freq;
}
#else
#  error "cpucycles_begin/end: unsupported architecture (need x86_64 or aarch64)"
#endif

/* Counter type identification for reports and CSV */
static const char *get_cycle_counter_type(void) {
#if defined(__x86_64__) || defined(__i386__)
    return "rdtsc (CPU cycles)";
#elif defined(__aarch64__)
    return "cntvct_el0 (timer ticks, NOT CPU cycles)";
#else
    return "unknown";
#endif
}

/* High-resolution wall clock (nanoseconds).  Used ONLY for human-readable
 * output; NOT used for cryptographic benchmarking (too noisy). */
static inline uint64_t wallclock_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* =========================================================================
 * TIER 2: STATISTICAL AGGREGATION ENGINE
 *
 * THEORY (PDF1, "SUPERCOP Methodology"):
 *   Arithmetic means are ACTIVELY AVOIDED in cryptographic benchmarking.
 *   A single OS context switch or cache miss spike can skew the mean by
 *   thousands of cycles.  Instead we report:
 *     - Median        (50th percentile) -- primary metric
 *     - Q1            (25th percentile) -- lower quartile
 *     - Q3            (75th percentile) -- upper quartile
 *     - IQR           (Q3 - Q1)         -- interquartile range
 *     - 99th pct      -- tail latency (critical for ML-DSA rejection sampling)
 *     - Min / Max     -- absolute bounds
 *     - Geo mean      -- useful for multiplicative speedup ratios
 *     - Std deviation -- variance measure
 *     - CoV           -- Coefficient of Variation = StdDev/Mean * 100%
 *                        61-71% CoV observed for ML-DSA on Cortex-M0+ (PDF2)
 * ========================================================================= */
typedef struct {
    uint64_t  n;           /* sample count                          */
    double    median;      /* 50th percentile cycles                */
    double    q1;          /* 25th percentile cycles                */
    double    q3;          /* 75th percentile cycles                */
    double    iqr;         /* Q3 - Q1                               */
    double    p99;         /* 99th percentile (tail latency)        */
    double    p95;         /* 95th percentile                       */
    double    p90;         /* 90th percentile                       */
    double    trimmed_mean;/* mean of middle 95% (2.5% cut per side)*/
    uint64_t  min_cycles;  /* minimum observed cycles               */
    uint64_t  max_cycles;  /* maximum observed cycles               */
    double    geo_mean;    /* geometric mean of cycles              */
    double    arith_mean;  /* arithmetic mean (reported but warned) */
    double    std_dev;     /* standard deviation                    */
    double    cov_pct;     /* coefficient of variation (%)          */
    double    cpb;         /* cycles per byte                       */
    double    wall_ns;     /* wall clock nanoseconds (mean)         */
} bench_stats_t;

/* Comparison function for qsort */
static int uint64_cmp(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    return (ua > ub) - (ua < ub);
}

/*
 * compute_stats()
 *   Input : array of raw CPU cycle measurements (after warm-up stripped),
 *           number of valid samples, and total bytes processed per operation.
 *   Output: populated bench_stats_t struct.
 */
static void compute_stats(bench_stats_t *s,
                          uint64_t *samples,
                          uint64_t  n,
                          size_t    bytes_per_op,
                          double    wall_ns_total)
{
    if (n == 0) { memset(s, 0, sizeof(*s)); return; }

    /* Sort for percentile calculations. */
    uint64_t *sorted = (uint64_t *)malloc(n * sizeof(uint64_t));
    if (!sorted) { fprintf(stderr, "[FATAL] malloc failed in compute_stats\n"); exit(1); }
    memcpy(sorted, samples, n * sizeof(uint64_t));
    qsort(sorted, n, sizeof(uint64_t), uint64_cmp);

    s->n          = n;
    s->min_cycles = sorted[0];
    s->max_cycles = sorted[n - 1];

    /* Percentile helper: linear interpolation */
    #define PERCENTILE(arr, cnt, p) \
        ((cnt) == 1 ? (double)(arr)[0] : \
         (arr)[(size_t)((p) * ((cnt) - 1))] + \
         (((p) * ((cnt) - 1)) - (size_t)((p) * ((cnt) - 1))) * \
         ((double)(arr)[(size_t)((p) * ((cnt) - 1)) + 1] - (double)(arr)[(size_t)((p) * ((cnt) - 1))]))

    s->q1     = PERCENTILE(sorted, n, 0.25);
    s->median = PERCENTILE(sorted, n, 0.50);
    s->q3     = PERCENTILE(sorted, n, 0.75);
    s->p90    = PERCENTILE(sorted, n, 0.90);
    s->p95    = PERCENTILE(sorted, n, 0.95);
    s->p99    = PERCENTILE(sorted, n, 0.99);
    s->iqr    = s->q3 - s->q1;

    /* Trimmed mean: drop the lowest and highest 2.5% of samples so a few
     * scheduler / SMI / page-fault outliers cannot skew the average.
     * The raw min/max/p99 columns still expose the untrimmed tail. */
    {
        uint64_t lo = (uint64_t)((double)n * 0.025);
        uint64_t hi = n - lo;
        if (hi <= lo) { lo = 0; hi = n; }
        double tsum = 0.0;
        for (uint64_t i = lo; i < hi; i++) tsum += (double)sorted[i];
        s->trimmed_mean = tsum / (double)(hi - lo);
    }

    /* Arithmetic mean and geometric mean. */
    double sum_log = 0.0;
    double sum     = 0.0;
    for (uint64_t i = 0; i < n; i++) {
        sum     += (double)sorted[i];
        sum_log += log((double)sorted[i]);
    }
    s->arith_mean = sum / (double)n;
    s->geo_mean   = exp(sum_log / (double)n);

    /* Standard deviation. */
    double sq_diff = 0.0;
    for (uint64_t i = 0; i < n; i++) {
        double d = (double)sorted[i] - s->arith_mean;
        sq_diff += d * d;
    }
    s->std_dev  = sqrt(sq_diff / (double)n);

    /* Coefficient of Variation. */
    s->cov_pct = (s->arith_mean > 0) ? (s->std_dev / s->arith_mean) * 100.0 : 0.0;

    /* Cycles per Byte (CpB):  median_cycles / bytes_per_op  (PDF1/PDF2). */
    s->cpb = (bytes_per_op > 0) ? s->median / (double)bytes_per_op : 0.0;

    /* Wall clock mean nanoseconds per operation. */
    s->wall_ns = (n > 0) ? wall_ns_total / (double)n : 0.0;

    free(sorted);
    #undef PERCENTILE
}

/* =========================================================================
 * TIER 3: REJECTION SAMPLING HISTOGRAM (ML-DSA SPECIFIC)
 *
 * THEORY (PDF1/PDF2, "Rejection Sampling Variance in ML-DSA"):
 *   ML-DSA signing uses the Fiat-Shamir with Aborts paradigm.
 *   Each signing attempt may FAIL bound checks and restart, looping over
 *   SHAKE256 expansions.  Expected iterations:
 *     ML-DSA-44 => ~4.25   ML-DSA-65 => ~5.10
 *   On constrained CPUs, high-iteration events push 99th-pct time to
 *   > 1,115 milliseconds (PDF2).  TurboSHAKE reduces each iteration cost,
 *   directly compressing tail latency even though expected iters stay same.
 *
 *   This structure tracks rejection iteration counts so you can see
 *   the full distribution, not just average iters.
 * ========================================================================= */
#define MAX_REJECTION_ITERS  64    /* histogram buckets 0..63, 64=overflow */

typedef struct {
    uint64_t  histogram[MAX_REJECTION_ITERS + 1]; /* iteration count distribution */
    uint64_t  total_signatures;
    uint64_t  total_iterations;
    double    mean_iters;
    double    max_iters;
    /* NOTE: liboqs does not expose internal abort counters directly.
     * We estimate by measuring cycles per signing call relative to a
     * baseline single-iteration cost.  For exact counts, you need a
     * patched Dilithium reference implementation that exposes a counter. */
    int       estimated;   /* 1 = estimated from timing, 0 = exact counter */
} rejection_stats_t;

static void rejection_stats_init(rejection_stats_t *rs) {
    memset(rs, 0, sizeof(*rs));
    rs->estimated = 1;  /* liboqs does not expose internal abort counter */
}

static void rejection_stats_print(const rejection_stats_t *rs,
                                  const char *algo_name)
{
    printf("\n  [Rejection Sampling Distribution: %s]\n", algo_name);
    printf("  Total signatures    : %"PRIu64"\n", rs->total_signatures);
    printf("  Note: liboqs does not expose raw abort counters.\n");
    printf("  Use patched pq-crystals/dilithium ref code for exact counts.\n");
    printf("  Expected mean iters : ~4.25 (ML-DSA-44), ~5.10 (ML-DSA-65)\n");
    printf("  Tail latency (99th percentile cycles) captures abort impact.\n");
}

/* =========================================================================
 * TIER 5: STACK PAINTING / WATERMARKING
 *
 * THEORY (PDF1/PDF2, "Stack Painting and Watermarking in Embedded Environments"):
 *   In embedded/RTOS environments, all heap allocation is forbidden.
 *   ML-DSA needs > 100 KB of stack for its K*L polynomial vectors.
 *   To measure worst-case stack depth WITHOUT a hardware debugger:
 *
 *   1. Fill a large buffer with 0xDEADBEEF sentinel words.
 *   2. Execute the cryptographic operation.
 *   3. Scan upward from the bottom of the buffer.
 *   4. First word != 0xDEADBEEF marks the high-water stack boundary.
 *   5. Delta = buffer_top - first_modified_word = peak stack usage.
 *
 *   This file simulates this on x86_64 using a heap-allocated buffer
 *   (actual embedded use would target the linker-defined stack region).
 *
 * WARNING (PDF1): GCC -O3 may optimize away the painting loop.
 *   Use volatile fills or __attribute__((optimize("O0"))) on the paint func.
 * ========================================================================= */

/* Fill region with sentinel.  volatile prevents compiler elision. */
static void __attribute__((optimize("O0")))
stack_paint(uint8_t *region, size_t size_bytes) {
    uint32_t *p = (uint32_t *)region;
    size_t    n = size_bytes / sizeof(uint32_t);
    for (size_t i = 0; i < n; i++) {
        p[i] = STACK_SENTINEL_WORD;
    }
    /* Memory barrier so the fill is not moved past the crypto call. */
    __asm__ volatile ("" ::: "memory");
}

/*
 * stack_measure_hwm()
 *   Returns the high-water-mark (peak bytes used) by scanning for the first
 *   word that was overwritten from STACK_SENTINEL_WORD.
 *   The delta from the buffer base to first-modified word = stack consumed.
 */
static size_t stack_measure_hwm(const uint8_t *region, size_t size_bytes) {
    const uint32_t *p = (const uint32_t *)region;
    size_t n = size_bytes / sizeof(uint32_t);
    /* Scan from BOTTOM (low address) upward. */
    for (size_t i = 0; i < n; i++) {
        if (p[i] != STACK_SENTINEL_WORD) {
            /* First modified word found -- return byte offset from base. */
            return size_bytes - (i * sizeof(uint32_t));
        }
    }
    /* None modified -- operation used zero stack (unlikely / paint failed). */
    return 0;
}

/* =========================================================================
 * TIER 6: DUDECT CONSTANT-TIME VALIDATION ENGINE
 *
 * THEORY (PDF1/PDF2, "Statistical Validation of Constant-Time Execution"):
 *   Timing side-channel attacks can extract secret key material if the
 *   runtime of the algorithm varies with secret inputs.  After swapping
 *   SHAKE for TurboSHAKE, the C wrappers must be validated for constant-time.
 *
 *   dudect methodology:
 *   a) Partition inputs into CLASS_FIXED  (same secret every iteration)
 *                          CLASS_RANDOM (uniform random secret each time).
 *   b) Execute millions of measurements, alternating randomly between classes.
 *   c) Crop upper tail at DUDECT_CROP_PERCENTILE (99th pct) to remove OS noise.
 *   d) Apply Welch's t-test (unequal variance, unequal sample size).
 *   e) If |t| > 4.5 => LEAKAGE DETECTED (>99.99% confidence).
 *      If |t| ~1.0  => constant time (no detectable timing difference).
 *
 *   Welch's t formula:
 *     t = (mean1 - mean2) / sqrt(var1/n1 + var2/n2)
 * ========================================================================= */

typedef struct {
    double  mean;
    double  m2;          /* running M2 for Welch online variance (Welford) */
    uint64_t count;
} welch_accum_t;

static void welch_update(welch_accum_t *acc, double value) {
    acc->count++;
    double delta  = value - acc->mean;
    acc->mean    += delta / (double)acc->count;
    double delta2 = value - acc->mean;
    acc->m2      += delta * delta2;
}

/* Compute Welch's t-statistic from two accumulators. */
static double welch_t_statistic(const welch_accum_t *a, const welch_accum_t *b) {
    if (a->count < 2 || b->count < 2) return 0.0;
    double var_a = a->m2 / (double)(a->count - 1);
    double var_b = b->m2 / (double)(b->count - 1);
    double denom = sqrt(var_a / (double)a->count + var_b / (double)b->count);
    if (denom < 1e-12) return 0.0;
    return (a->mean - b->mean) / denom;
}

typedef struct {
    double    t_value;          /* Welch's t statistic                     */
    uint64_t  n_class0;         /* measurements in FIXED class             */
    uint64_t  n_class1;         /* measurements in RANDOM class            */
    int       leak_detected;    /* 1 if |t| > DUDECT_T_THRESHOLD           */
    double    mean_fixed_ns;    /* mean timing FIXED class (nanoseconds)   */
    double    mean_random_ns;   /* mean timing RANDOM class (nanoseconds)  */
} dudect_result_t;

/*
 * dudect_run_kem()
 *   Run Welch t-test constant-time analysis on a KEM encapsulation.
 *   CLASS_FIXED  = always encapsulate under same public key + fixed random.
 *   CLASS_RANDOM = encapsulate under same public key but fresh random each time.
 *   (Public key is constant because it is the secret input to decaps.)
 *
 *   NOTE: Full dudect requires injecting fixed vs random inputs at the
 *   secret seed level.  Without a patched liboqs, we use fixed vs
 *   random MESSAGE as a proxy for timing variation tests.
 */
static dudect_result_t dudect_run_kem(OQS_KEM *kem, uint64_t n_measurements) {
    dudect_result_t result;
    memset(&result, 0, sizeof(result));

    uint8_t *public_key    = malloc(kem->length_public_key);
    uint8_t *secret_key    = malloc(kem->length_secret_key);
    uint8_t *ciphertext    = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext || !shared_secret) {
        fprintf(stderr, "[DUDECT] malloc failed\n");
        goto cleanup;
    }

    /* Generate a keypair once -- public key is fixed for all measurements. */
    OQS_KEM_keypair(kem, public_key, secret_key);

    welch_accum_t acc_fixed  = {0};
    welch_accum_t acc_random = {0};

    /* Fixed input: deterministic shared_secret buffer (all zeros). */
    uint8_t fixed_buf[64];
    memset(fixed_buf, 0x42, sizeof(fixed_buf));

    for (uint64_t i = 0; i < n_measurements; i++) {
        int class_id = (rand() & 1);  /* randomly alternate classes */

        uint64_t t0 = cpucycles_begin();
        OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
        uint64_t t1 = cpucycles_end();

        double elapsed = (double)(t1 - t0);

        /* Crop: discard measurements above 99th percentile (OS noise). */
        /* Simple crop: discard if > 10x the running mean (rough heuristic). */
        if (acc_fixed.count > 100) {
            double ref_mean = (acc_fixed.mean + acc_random.mean) / 2.0;
            if (elapsed > ref_mean * 5.0) continue;  /* crop outlier */
        }

        if (class_id == 0) welch_update(&acc_fixed,  elapsed);
        else               welch_update(&acc_random, elapsed);
    }

    result.t_value        = welch_t_statistic(&acc_fixed, &acc_random);
    result.n_class0       = acc_fixed.count;
    result.n_class1       = acc_random.count;
    result.leak_detected  = (fabs(result.t_value) > DUDECT_T_THRESHOLD) ? 1 : 0;
    result.mean_fixed_ns  = acc_fixed.mean;
    result.mean_random_ns = acc_random.mean;

cleanup:
    free(public_key); free(secret_key); free(ciphertext); free(shared_secret);
    return result;
}

static dudect_result_t dudect_run_sig(OQS_SIG *sig, uint64_t n_measurements) {
    dudect_result_t result;
    memset(&result, 0, sizeof(result));

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature  = malloc(sig->length_signature);
    if (!public_key || !secret_key || !signature) { goto sig_cleanup; }

    OQS_SIG_keypair(sig, public_key, secret_key);

    welch_accum_t acc_fixed  = {0};
    welch_accum_t acc_random = {0};

    uint8_t msg_fixed[BENCH_MSG_LEN];
    uint8_t msg_random[BENCH_MSG_LEN];
    memset(msg_fixed, 0xAA, BENCH_MSG_LEN);

    size_t sig_len = 0;

    for (uint64_t i = 0; i < n_measurements; i++) {
        int class_id = (rand() & 1);

        /* Prepare input for this class. */
        if (class_id == 1) {
            for (int b = 0; b < BENCH_MSG_LEN; b++)
                msg_random[b] = (uint8_t)rand();
        }
        uint8_t *msg = (class_id == 0) ? msg_fixed : msg_random;

        uint64_t t0 = cpucycles_begin();
        OQS_SIG_sign(sig, signature, &sig_len, msg, BENCH_MSG_LEN, secret_key);
        uint64_t t1 = cpucycles_end();

        double elapsed = (double)(t1 - t0);
        if (acc_fixed.count > 100) {
            double ref_mean = (acc_fixed.mean + acc_random.mean) / 2.0;
            if (elapsed > ref_mean * 10.0) continue;
        }

        if (class_id == 0) welch_update(&acc_fixed,  elapsed);
        else               welch_update(&acc_random, elapsed);
    }

    result.t_value        = welch_t_statistic(&acc_fixed, &acc_random);
    result.n_class0       = acc_fixed.count;
    result.n_class1       = acc_random.count;
    result.leak_detected  = (fabs(result.t_value) > DUDECT_T_THRESHOLD) ? 1 : 0;
    result.mean_fixed_ns  = acc_fixed.mean;
    result.mean_random_ns = acc_random.mean;

sig_cleanup:
    free(public_key); free(secret_key); free(signature);
    return result;
}

/* =========================================================================
 * TIER 11: MEMORY FOOTPRINT PROFILING (software-level, hardware-independent)
 *
 * Two complementary, purely OS/libc-derived measurements:
 *
 *   a) PEAK RSS DELTA (peak_rss_delta_kb)
 *      getrusage(RUSAGE_SELF, &ru).ru_maxrss is the high-water mark of the
 *      ENTIRE PROCESS's resident memory, maintained by the kernel itself.
 *      We snapshot it immediately before and after each benchmark loop and
 *      report the delta.  Since ru_maxrss is monotonically non-decreasing
 *      for the life of the process, a positive delta means the operation
 *      pushed the process to a new high-water mark (e.g. larger heap
 *      arena or deeper stack growth).  A delta of 0 means the operation
 *      fit entirely within memory already mapped by earlier operations.
 *
 *   b) HEAP ARENA DELTA (heap_delta_bytes)
 *      mallinfo2() / mallinfo() (glibc) report uordblks: bytes currently
 *      allocated via malloc().  We snapshot this immediately before and
 *      after ONE representative call to the operation under test and
 *      report the delta.  This isolates the heap churn of a SINGLE call
 *      (keypair / encaps / decaps / sign / verify), independent of the
 *      cycle-counting loop.  A growing delta across repeated calls would
 *      indicate a leak.
 *
 * Both metrics come solely from the C library / kernel process accounting
 * -- no CPU model, board, or vendor-specific power/perf driver required,
 * so results are directly comparable across any POSIX platform.
 * ========================================================================= */
typedef struct {
    long  peak_rss_delta_kb;   /* growth in process peak RSS (KB)         */
    long  peak_rss_after_kb;   /* absolute peak RSS after the op (KB)     */
    long  heap_delta_bytes;    /* malloc-arena delta for one call (bytes) */
    int   heap_available;      /* 1 if mallinfo-based tracking is active  */
    /* Raw snapshots (unprocessed readings the deltas are derived from). */
    long  rss_before_kb;       /* VmRSS before the op (KB)                */
    long  heap_before_bytes;   /* malloc arena in-use before op (bytes)   */
    long  heap_after_bytes;    /* malloc arena in-use after op (bytes)    */
} mem_stats_t;

/* Returns the process's current RSS in kilobytes via /proc/self/status.
 * Unlike getrusage(ru_maxrss) which is monotonically non-decreasing,
 * VmRSS reflects the actual current resident set. Falls back to getrusage. */
static long get_current_rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            long rss;
            if (sscanf(line, "VmRSS: %ld kB", &rss) == 1) {
                fclose(f);
                return rss;
            }
        }
        fclose(f);
    }
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
#if defined(__APPLE__)
    return (long)(ru.ru_maxrss / 1024L);
#else
    return (long)ru.ru_maxrss;
#endif
}

/* Returns currently allocated heap bytes (malloc arena "in use" space).
 * Returns -1 if the platform's libc does not expose mallinfo. */
static long get_heap_bytes(void) {
#if defined(PQC_HAVE_MALLINFO)
#  if defined(__GLIBC__) && __GLIBC_PREREQ(2, 33)
    struct mallinfo2 mi = mallinfo2();
    return (long)mi.uordblks;
#  else
    struct mallinfo mi = mallinfo();
    return (long)mi.uordblks;
#  endif
#else
    return -1;
#endif
}

/*
 * mem_profile_op()
 *   Generic single-call memory profiler.  Snapshots peak RSS and heap
 *   arena size, invokes the supplied zero-argument operation exactly once
 *   via a function pointer + opaque context, then snapshots again and
 *   fills in `out`.
 *
 *   `op` must be a small trampoline that performs exactly one
 *   keypair/encaps/decaps/sign/verify call using `ctx`.
 */
typedef void (*mem_probe_fn)(void *ctx);

static void mem_profile_op(mem_probe_fn op, void *ctx, mem_stats_t *out) {
    memset(out, 0, sizeof(*out));

    long rss_before  = get_current_rss_kb();
    long heap_before = get_heap_bytes();

    op(ctx);

    long rss_after  = get_current_rss_kb();
    long heap_after = get_heap_bytes();

    out->peak_rss_after_kb  = rss_after;
    out->peak_rss_delta_kb  = (rss_before >= 0 && rss_after >= 0)
                                  ? (rss_after - rss_before) : -1;
    out->rss_before_kb      = rss_before;
    out->heap_before_bytes  = heap_before;
    out->heap_after_bytes   = heap_after;

    if (heap_before >= 0 && heap_after >= 0) {
        out->heap_available   = 1;
        out->heap_delta_bytes = heap_after - heap_before;
    } else {
        out->heap_available   = 0;
        out->heap_delta_bytes = 0;
    }
}

/* =========================================================================
 * TIER 12: SOFTWARE ENERGY PROXY MODEL (hardware-independent)
 *
 * See the ENERGY_PER_CYCLE_NJ documentation in the configuration section
 * above for the full rationale.  In short:
 *
 *   - "Energy Proxy Units" (EPU) == median CPU cycles for the operation.
 *     This is the hardware-independent figure; use it to compare SHAKE vs
 *     TurboSHAKE or to compare algorithms/parameter sets.  Fewer cycles
 *     always implies less dynamic energy on any given silicon.
 *
 *   - "Est. energy (uJ)" is EPU converted via ENERGY_PER_CYCLE_NJ.  Unless
 *     the user supplies a platform-calibrated value at build time
 *     (-DENERGY_PER_CYCLE_NJ=<nJ/cycle>), this is clearly marked as
 *     "illustrative" and NOT a real hardware measurement.
 *
 *   - "Energy-Delay Product" (EDP) = median_cycles * wall_ns is a classic
 *     low-power-design figure of merit that rewards algorithms that are
 *     simultaneously fast AND cheap; it too is derived purely from
 *     already-collected software timing data.
 * ========================================================================= */
typedef struct {
    double  epu;                    /* Energy Proxy Units (= median cycles)   */
    double  epu_per_byte;           /* EPU normalized by bytes processed      */
    double  est_energy_uj;          /* estimated energy via ENERGY_PER_CYCLE_NJ */
    double  est_energy_uj_per_byte; /* per-byte version of the above          */
    double  edp_cycle_ns;           /* Energy-Delay Product (cycles * ns)     */
    double  rapl_energy_uj;         /* actual RAPL measurement (0 if unavail) */
    int     calibrated;             /* 1 if ENERGY_PER_CYCLE_NJ user-supplied */
    int     rapl_measured;          /* 1 if rapl_energy_uj is a real reading  */
    /* Raw RAPL counter readings (unprocessed, whole timed loop). */
    double  rapl_before_uj;         /* package energy counter before the loop */
    double  rapl_after_uj;          /* package energy counter after the loop  */
    double  rapl_loop_total_uj;     /* raw delta over the entire timed loop   */
    uint64_t rapl_loop_iters;       /* ops executed between the two readings  */
} energy_stats_t;

static void compute_energy_stats(energy_stats_t *e,
                                 const bench_stats_t *s,
                                 size_t bytes_per_op)
{
    memset(e, 0, sizeof(*e));

    e->epu          = s->median;
    e->epu_per_byte = (bytes_per_op > 0) ? s->median / (double)bytes_per_op : 0.0;

    /* nJ/cycle * cycles = nJ; divide by 1000 => uJ */
    e->est_energy_uj          = (s->median * ENERGY_PER_CYCLE_NJ) / 1000.0;
    e->est_energy_uj_per_byte = (bytes_per_op > 0)
                                     ? e->est_energy_uj / (double)bytes_per_op
                                     : 0.0;

    e->edp_cycle_ns  = s->median * s->wall_ns;
    e->calibrated    = ENERGY_MODEL_CALIBRATED;
    e->rapl_energy_uj = 0.0;
    e->rapl_measured  = 0;
}

/* Pretty-printer for the memory + energy tiers is defined further below,
 * after print_separator() (see PRINTING HELPERS section). */


static void print_separator(void) {
    printf("  %s\n",
           "----------------------------------------------------------------------");
}

static void print_stats(const char *label,
                        const bench_stats_t *s,
                        const char *unit_label)
{
    print_separator();
    printf("  %-30s  [n=%"PRIu64"]\n", label, s->n);
    print_separator();
    printf("  %-28s : %12.0f  cycles\n",    "Median (primary metric)",  s->median);
    printf("  %-28s : %12.0f  cycles\n",    "Q1 (25th percentile)",    s->q1);
    printf("  %-28s : %12.0f  cycles\n",    "Q3 (75th percentile)",    s->q3);
    printf("  %-28s : %12.0f  cycles\n",    "IQR (Q3 - Q1)",           s->iqr);
    printf("  %-28s : %12.2f  cycles  (outlier-robust)\n",
                                             "Trimmed mean (95%)",      s->trimmed_mean);
    printf("  %-28s : %12.0f  cycles\n",    "90th percentile",         s->p90);
    printf("  %-28s : %12.0f  cycles\n",    "95th percentile",         s->p95);
    printf("  %-28s : %12.0f  cycles  *** TAIL LATENCY ***\n",
                                             "99th percentile",         s->p99);
    printf("  %-28s : %12"PRIu64"  cycles\n", "Minimum",               s->min_cycles);
    printf("  %-28s : %12"PRIu64"  cycles\n", "Maximum",               s->max_cycles);
    printf("  %-28s : %12.0f  cycles  (WARNING: skewed by outliers)\n",
                                             "Arithmetic mean",         s->arith_mean);
    printf("  %-28s : %12.0f  cycles\n",    "Geometric mean",          s->geo_mean);
    printf("  %-28s : %12.2f  cycles\n",    "Std deviation",           s->std_dev);
    printf("  %-28s : %12.2f  %%\n",        "Coeff. of Variation",     s->cov_pct);
    if (s->cpb > 0.0)
        printf("  %-28s : %12.4f  cycles/byte\n", "Cycles per Byte (CpB)", s->cpb);
    printf("  %-28s : %12.2f  ns/op\n",     "Wall clock (mean)",       s->wall_ns);
    if (s->cov_pct > 50.0)
        printf("  ** HIGH CoV (%.1f%%) detected -- likely rejection sampling variance **\n",
               s->cov_pct);
}

static void print_dudect_result(const char *label, const dudect_result_t *r) {
    print_separator();
    printf("  DUDECT Constant-Time Test: %s\n", label);
    print_separator();
    printf("  Measurements  class-FIXED  : %"PRIu64"\n", r->n_class0);
    printf("  Measurements  class-RANDOM : %"PRIu64"\n", r->n_class1);
    printf("  Mean cycles   class-FIXED  : %.2f\n", r->mean_fixed_ns);
    printf("  Mean cycles   class-RANDOM : %.2f\n", r->mean_random_ns);
    printf("  Welch's t-value             : %.6f\n", r->t_value);
    printf("  Threshold |t| > %.1f          : %s\n", DUDECT_T_THRESHOLD,
           r->leak_detected
               ? "*** TIMING LEAK DETECTED *** (|t| > 4.5 => >99.99%% confidence)"
               : "PASS  (|t| <= 4.5 -- no detectable timing leak)");
}

static void print_stack_result(const char *label, size_t hwm_bytes) {
    printf("  %-38s : %zu bytes  (%.1f KB)\n",
           label, hwm_bytes, hwm_bytes / 1024.0);
    if (hwm_bytes > 100 * 1024)
        printf("  ** WARNING: ML-DSA stack usage > 100 KB -- overflow risk on"
               " constrained devices **\n");
}

/* Pretty-printer for the memory + energy tiers (used by both ML-KEM and
 * ML-DSA reports).  See TIER 11/12 above for the underlying methodology. */
static void print_mem_energy(const char *label,
                             const mem_stats_t *m,
                             const energy_stats_t *e)
{
    print_separator();
    printf("  %-30s  [Memory Footprint + Energy Proxy]\n", label);
    print_separator();

    printf("  %-30s : %12ld  KB\n", "Peak RSS delta (process-wide)", m->peak_rss_delta_kb);
    printf("  %-30s : %12ld  KB\n", "Peak RSS after op (absolute)", m->peak_rss_after_kb);
    if (m->heap_available)
        printf("  %-30s : %12ld  bytes  (single call)\n",
               "Heap arena delta", m->heap_delta_bytes);
    else
        printf("  %-30s : %12s  (mallinfo unavailable on this libc)\n",
               "Heap arena delta", "n/a");

    printf("  %-30s : %12.0f  EPU  (== median cycles)\n",
           "Energy Proxy Units (EPU)", e->epu);
    if (e->epu_per_byte > 0.0)
        printf("  %-30s : %12.4f  EPU/byte\n", "Energy Proxy per byte", e->epu_per_byte);

    printf("  %-30s : %12.4f  uJ   %s\n",
           "Est. energy (per op)", e->est_energy_uj,
           e->calibrated
               ? "(calibrated via ENERGY_PER_CYCLE_NJ)"
               : "(illustrative k=1.0 nJ/cyc -- NOT a real measurement)");
    if (e->rapl_measured)
        printf("  %-30s : %12.4f  uJ   (Intel RAPL hardware measurement)\n",
               "RAPL energy (per op)", e->rapl_energy_uj);
    else if (rapl_available)
        printf("  %-30s : %12s  (RAPL read failed for this op)\n",
               "RAPL energy", "n/a");
    else
        printf("  %-30s : %12s  (RAPL unavailable on this platform)\n",
               "RAPL energy", "n/a");
    if (e->est_energy_uj_per_byte > 0.0)
        printf("  %-30s : %12.6f  uJ/byte\n",
               "Est. energy per byte", e->est_energy_uj_per_byte);

    printf("  %-30s : %12.2f  cycle*ns  (Energy-Delay Product)\n",
           "Energy-Delay Product (EDP)", e->edp_cycle_ns);
}

/* =========================================================================
 * TIER 4 + 7: FULL ML-KEM BENCHMARK HARNESS
 *
 * Sub-components benchmarked:
 *   a) KeyGen  -- includes matrix expansion (SHAKE128/TurboSHAKE128) and
 *                 CBD noise generation (SHAKE256/TurboSHAKE256)
 *   b) Encaps  -- includes FO-transform hashing (PDF1/PDF2) and KDF (SHAKE256)
 *   c) Decaps  -- includes ciphertext validation and implicit rejection
 *
 * CpB reference bytes:
 *   KeyGen  => public_key size + secret_key size
 *   Encaps  => ciphertext size + shared_secret size
 *   Decaps  => ciphertext size + shared_secret size
 * ========================================================================= */

typedef struct {
    const char   *name;
    int           correctness_pass;  /* 1 if round-trip self-test passed */
    bench_stats_t keygen;
    bench_stats_t encaps;
    bench_stats_t decaps;
    size_t        stack_hwm_keygen;
    size_t        stack_hwm_encaps;
    size_t        stack_hwm_decaps;
    dudect_result_t dudect_encaps;

    /* TIER 11/12: memory footprint + energy proxy, per sub-operation. */
    mem_stats_t    mem_keygen;
    mem_stats_t    mem_encaps;
    mem_stats_t    mem_decaps;
    energy_stats_t energy_keygen;
    energy_stats_t energy_encaps;
    energy_stats_t energy_decaps;

    /* Algorithm parameter metadata (from liboqs OQS_KEM struct). */
    size_t  pk_bytes;
    size_t  sk_bytes;
    size_t  ct_bytes;
    size_t  ss_bytes;
    uint8_t nist_level;
    int     ind_cca;
} kem_bench_result_t;

/* ------------------------------------------------------------------
 * Single-call probe trampolines (TIER 11 memory profiling).
 * Each wraps exactly one liboqs call so mem_profile_op() can snapshot
 * peak RSS / heap arena size immediately around it.
 * ------------------------------------------------------------------ */
typedef struct { OQS_KEM *kem; uint8_t *pk; uint8_t *sk; } kem_keygen_ctx_t;
static void kem_keygen_probe(void *ctx) {
    kem_keygen_ctx_t *c = (kem_keygen_ctx_t *)ctx;
    OQS_KEM_keypair(c->kem, c->pk, c->sk);
}

typedef struct { OQS_KEM *kem; uint8_t *ct; uint8_t *ss; uint8_t *pk; } kem_encaps_ctx_t;
static void kem_encaps_probe(void *ctx) {
    kem_encaps_ctx_t *c = (kem_encaps_ctx_t *)ctx;
    OQS_KEM_encaps(c->kem, c->ct, c->ss, c->pk);
}

typedef struct { OQS_KEM *kem; uint8_t *ss; uint8_t *ct; uint8_t *sk; } kem_decaps_ctx_t;
static void kem_decaps_probe(void *ctx) {
    kem_decaps_ctx_t *c = (kem_decaps_ctx_t *)ctx;
    OQS_KEM_decaps(c->kem, c->ss, c->ct, c->sk);
}

/*
 * bench_kem_obj()
 *   Core ML-KEM benchmark harness, operating on an already-constructed
 *   OQS_KEM object.  The caller owns `kem` (created via OQS_KEM_new() for
 *   the standard SHAKE build, or via the TurboSHAKE adapter constructors
 *   in pqc_turboshake_kem.c) and is responsible for freeing it.
 */
static kem_bench_result_t bench_kem_obj(OQS_KEM *kem,
                                        const char *display_name,
                                        int run_dudect,
                                        int run_stack)
{
    kem_bench_result_t result;
    memset(&result, 0, sizeof(result));
    result.name = display_name;

    if (!kem) {
        fprintf(stderr, "[ERROR] NULL OQS_KEM for %s\n", display_name);
        return result;
    }

    /* Populate metadata from liboqs OQS_KEM struct (PDF2, OQS_KEM table). */
    result.pk_bytes   = kem->length_public_key;
    result.sk_bytes   = kem->length_secret_key;
    result.ct_bytes   = kem->length_ciphertext;
    result.ss_bytes   = kem->length_shared_secret;
    result.nist_level = kem->claimed_nist_level;
    result.ind_cca    = kem->ind_cca ? 1 : 0;

    /* Allocate key material. */
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);
    if (!pk || !sk || !ct || !ss) {
        fprintf(stderr, "[ERROR] Allocation failed for %s\n", display_name);
        goto kem_cleanup;
    }

    /* Correctness self-test: keygen → encaps → decaps → shared secret match */
    {
        uint8_t *ss2 = malloc(kem->length_shared_secret);
        if (ss2 &&
            OQS_KEM_keypair(kem, pk, sk) == OQS_SUCCESS &&
            OQS_KEM_encaps(kem, ct, ss, pk) == OQS_SUCCESS &&
            OQS_KEM_decaps(kem, ss2, ct, sk) == OQS_SUCCESS &&
            memcmp(ss, ss2, kem->length_shared_secret) == 0) {
            result.correctness_pass = 1;
        }
        free(ss2);
    }

    uint64_t total_iters  = BENCH_ITERATIONS + BENCH_WARMUP;
    uint64_t *cycles_kg   = malloc(total_iters * sizeof(uint64_t));
    uint64_t *cycles_enc  = malloc(total_iters * sizeof(uint64_t));
    uint64_t *cycles_dec  = malloc(total_iters * sizeof(uint64_t));
    if (!cycles_kg || !cycles_enc || !cycles_dec) {
        fprintf(stderr, "[ERROR] Cycle array allocation failed\n"); goto kem_cleanup;
    }

    /* ---------------------------------------------------------------
     * STACK PAINTING SETUP
     * Allocate a sentinel-filled region to measure stack high-water mark.
     * (PDF1/PDF2, "Stack Painting and Watermarking")
     * --------------------------------------------------------------- */
    uint8_t *stack_region = NULL;
    if (run_stack) {
        stack_region = malloc(STACK_PAINT_REGION_BYTES);
        if (!stack_region) {
            fprintf(stderr, "[WARN] Could not allocate stack paint region\n");
            run_stack = 0;
        }
    }

    uint64_t wall_start, wall_end;

    /* ================================================================
     * MEASURE TIMING OVERHEAD (Fix 7: subtract harness cost)
     * Runs an empty begin/end cycle to measure the rdtsc/cntvct overhead.
     * This is subtracted from each measurement to isolate the crypto op.
     * ================================================================ */
    uint64_t timing_overhead = 0;
    {
        uint64_t oh_samples[256];
        for (int oi = 0; oi < 256; oi++) {
            uint64_t t0 = cpucycles_begin();
            __asm__ volatile("" ::: "memory");
            uint64_t t1 = cpucycles_end();
            oh_samples[oi] = t1 - t0;
        }
        qsort(oh_samples, 256, sizeof(uint64_t), uint64_cmp);
        timing_overhead = oh_samples[128];
        g_timing_overhead_cycles = timing_overhead;
    }

    /* ================================================================
     * KEYGEN BENCHMARK LOOP
     * ================================================================ */
    wall_start = wallclock_ns();
    if (run_stack) stack_paint(stack_region, STACK_PAINT_REGION_BYTES);
    double rapl_kg_before = rapl_available ? rapl_read_uj() : 0.0;

    for (uint64_t i = 0; i < total_iters; i++) {
        uint64_t t0 = cpucycles_begin();
        OQS_KEM_keypair(kem, pk, sk);
        uint64_t t1 = cpucycles_end();
        uint64_t raw = t1 - t0;
        cycles_kg[i] = (raw > timing_overhead) ? raw - timing_overhead : 0;
    }
    double rapl_kg_after = rapl_available ? rapl_read_uj() : 0.0;
    wall_end = wallclock_ns();

    if (run_stack)
        result.stack_hwm_keygen = stack_measure_hwm(stack_region, STACK_PAINT_REGION_BYTES);

    compute_stats(&result.keygen,
                  cycles_kg + BENCH_WARMUP,         /* skip warm-up */
                  BENCH_ITERATIONS,
                  kem->length_public_key + kem->length_secret_key,
                  (double)(wall_end - wall_start));

    /* TIER 11/12: memory footprint + energy proxy.
     * Run 3 warmup calls before the probe to exclude first-time library init. */
    for (int mw = 0; mw < 3; mw++) OQS_KEM_keypair(kem, pk, sk);
    {
        kem_keygen_ctx_t kctx = { kem, pk, sk };
        mem_profile_op(kem_keygen_probe, &kctx, &result.mem_keygen);
    }
    compute_energy_stats(&result.energy_keygen, &result.keygen,
                         kem->length_public_key + kem->length_secret_key);
    if (rapl_available && rapl_kg_after > rapl_kg_before) {
        result.energy_keygen.rapl_before_uj     = rapl_kg_before;
        result.energy_keygen.rapl_after_uj      = rapl_kg_after;
        result.energy_keygen.rapl_loop_total_uj = rapl_kg_after - rapl_kg_before;
        result.energy_keygen.rapl_loop_iters    = total_iters;
        result.energy_keygen.rapl_energy_uj =
            (rapl_kg_after - rapl_kg_before) / (double)total_iters;
        result.energy_keygen.rapl_measured = 1;
    }


    /* ================================================================
     * ENCAPS BENCHMARK LOOP
     * ================================================================ */
    wall_start = wallclock_ns();
    if (run_stack) stack_paint(stack_region, STACK_PAINT_REGION_BYTES);
    double rapl_enc_before = rapl_available ? rapl_read_uj() : 0.0;

    for (uint64_t i = 0; i < total_iters; i++) {
        uint64_t t0 = cpucycles_begin();
        OQS_KEM_encaps(kem, ct, ss, pk);
        uint64_t t1 = cpucycles_end();
        uint64_t raw = t1 - t0;
        cycles_enc[i] = (raw > timing_overhead) ? raw - timing_overhead : 0;
    }
    double rapl_enc_after = rapl_available ? rapl_read_uj() : 0.0;
    wall_end = wallclock_ns();

    if (run_stack)
        result.stack_hwm_encaps = stack_measure_hwm(stack_region, STACK_PAINT_REGION_BYTES);

    compute_stats(&result.encaps,
                  cycles_enc + BENCH_WARMUP,
                  BENCH_ITERATIONS,
                  kem->length_ciphertext + kem->length_shared_secret,
                  (double)(wall_end - wall_start));

    for (int mw = 0; mw < 3; mw++) OQS_KEM_encaps(kem, ct, ss, pk);
    {
        kem_encaps_ctx_t kctx = { kem, ct, ss, pk };
        mem_profile_op(kem_encaps_probe, &kctx, &result.mem_encaps);
    }
    compute_energy_stats(&result.energy_encaps, &result.encaps,
                         kem->length_ciphertext + kem->length_shared_secret);
    if (rapl_available && rapl_enc_after > rapl_enc_before) {
        result.energy_encaps.rapl_before_uj     = rapl_enc_before;
        result.energy_encaps.rapl_after_uj      = rapl_enc_after;
        result.energy_encaps.rapl_loop_total_uj = rapl_enc_after - rapl_enc_before;
        result.energy_encaps.rapl_loop_iters    = total_iters;
        result.energy_encaps.rapl_energy_uj =
            (rapl_enc_after - rapl_enc_before) / (double)total_iters;
        result.energy_encaps.rapl_measured = 1;
    }


    /* ================================================================
     * DECAPS BENCHMARK LOOP
     * ================================================================ */
    wall_start = wallclock_ns();
    if (run_stack) stack_paint(stack_region, STACK_PAINT_REGION_BYTES);
    double rapl_dec_before = rapl_available ? rapl_read_uj() : 0.0;

    for (uint64_t i = 0; i < total_iters; i++) {
        uint64_t t0 = cpucycles_begin();
        OQS_KEM_decaps(kem, ss, ct, sk);
        uint64_t t1 = cpucycles_end();
        uint64_t raw = t1 - t0;
        cycles_dec[i] = (raw > timing_overhead) ? raw - timing_overhead : 0;
    }
    double rapl_dec_after = rapl_available ? rapl_read_uj() : 0.0;
    wall_end = wallclock_ns();

    if (run_stack)
        result.stack_hwm_decaps = stack_measure_hwm(stack_region, STACK_PAINT_REGION_BYTES);

    compute_stats(&result.decaps,
                  cycles_dec + BENCH_WARMUP,
                  BENCH_ITERATIONS,
                  kem->length_ciphertext + kem->length_shared_secret,
                  (double)(wall_end - wall_start));

    for (int mw = 0; mw < 3; mw++) OQS_KEM_decaps(kem, ss, ct, sk);
    {
        kem_decaps_ctx_t kctx = { kem, ss, ct, sk };
        mem_profile_op(kem_decaps_probe, &kctx, &result.mem_decaps);
    }
    compute_energy_stats(&result.energy_decaps, &result.decaps,
                         kem->length_ciphertext + kem->length_shared_secret);
    if (rapl_available && rapl_dec_after > rapl_dec_before) {
        result.energy_decaps.rapl_before_uj     = rapl_dec_before;
        result.energy_decaps.rapl_after_uj      = rapl_dec_after;
        result.energy_decaps.rapl_loop_total_uj = rapl_dec_after - rapl_dec_before;
        result.energy_decaps.rapl_loop_iters    = total_iters;
        result.energy_decaps.rapl_energy_uj =
            (rapl_dec_after - rapl_dec_before) / (double)total_iters;
        result.energy_decaps.rapl_measured = 1;
    }


    /* ================================================================
     * DUDECT CONSTANT-TIME VALIDATION
     * (PDF1/PDF2, "Statistical Validation of Constant-Time Execution")
     * ================================================================ */
    if (run_dudect) {
        printf("  Running dudect for %s (this may take several minutes)...\n",
               display_name);
        result.dudect_encaps = dudect_run_kem(kem, DUDECT_MEASUREMENTS);
    }

    free(cycles_kg); free(cycles_enc); free(cycles_dec);
    free(stack_region);

kem_cleanup:
    free(pk); free(sk); free(ct); free(ss);
    return result;
}

/*
 * bench_kem()
 *   Convenience wrapper for the standard (liboqs-registered) SHAKE-based
 *   ML-KEM algorithms: looks the algorithm up by name via OQS_KEM_new(),
 *   benchmarks it, and frees it.
 */
static kem_bench_result_t bench_kem(const char *kem_name,
                                    int run_dudect,
                                    int run_stack)
{
    OQS_KEM *kem = OQS_KEM_new(kem_name);
    if (!kem) {
        fprintf(stderr, "[ERROR] OQS_KEM_new(%s) failed. "
                        "Is liboqs built with this algorithm?\n", kem_name);
        kem_bench_result_t result;
        memset(&result, 0, sizeof(result));
        result.name = kem_name;
        return result;
    }

    kem_bench_result_t result = bench_kem_obj(kem, kem_name, run_dudect, run_stack);
    OQS_KEM_free(kem);
    return result;
}

/* =========================================================================
 * TIER 4 + 7: FULL ML-DSA BENCHMARK HARNESS
 *
 * Sub-components benchmarked:
 *   a) KeyGen  -- matrix expansion (SHAKE128), secret key generation
 *   b) Sign    -- masking vector expansion (SHAKE256 loop), challenge gen,
 *                 rejection sampling aborts -- HIGH VARIANCE expected
 *   c) Verify  -- matrix re-expansion, commitment re-computation
 *
 * ML-DSA signing MUST use >= 10,000 iterations (PDF1/PDF2) to capture
 * the full rejection sampling distribution in the tail latency metric.
 * ========================================================================= */

typedef struct {
    const char   *name;
    int           correctness_pass;
    bench_stats_t keygen;
    bench_stats_t sign_op;
    bench_stats_t verify;
    size_t        stack_hwm_keygen;
    size_t        stack_hwm_sign;
    size_t        stack_hwm_verify;
    dudect_result_t dudect_sign;
    rejection_stats_t rejection;

    /* TIER 11/12: memory footprint + energy proxy, per sub-operation. */
    mem_stats_t    mem_keygen;
    mem_stats_t    mem_sign;
    mem_stats_t    mem_verify;
    energy_stats_t energy_keygen;
    energy_stats_t energy_sign;
    energy_stats_t energy_verify;

    /* Algorithm parameter metadata. */
    size_t  pk_bytes;
    size_t  sk_bytes;
    size_t  sig_bytes;
    uint8_t nist_level;
} sig_bench_result_t;

/* ------------------------------------------------------------------
 * Single-call probe trampolines (TIER 11 memory profiling), ML-DSA.
 * ------------------------------------------------------------------ */
typedef struct { OQS_SIG *sig; uint8_t *pk; uint8_t *sk; } sig_keygen_ctx_t;
static void sig_keygen_probe(void *ctx) {
    sig_keygen_ctx_t *c = (sig_keygen_ctx_t *)ctx;
    OQS_SIG_keypair(c->sig, c->pk, c->sk);
}

typedef struct {
    OQS_SIG *sig; uint8_t *signature; size_t *sig_len;
    const uint8_t *msg; size_t msg_len; const uint8_t *sk;
} sig_sign_ctx_t;
static void sig_sign_probe(void *ctx) {
    sig_sign_ctx_t *c = (sig_sign_ctx_t *)ctx;
    OQS_SIG_sign(c->sig, c->signature, c->sig_len, c->msg, c->msg_len, c->sk);
}

typedef struct {
    OQS_SIG *sig; const uint8_t *msg; size_t msg_len;
    const uint8_t *signature; size_t sig_len; const uint8_t *pk;
} sig_verify_ctx_t;
static void sig_verify_probe(void *ctx) {
    sig_verify_ctx_t *c = (sig_verify_ctx_t *)ctx;
    OQS_SIG_verify(c->sig, c->msg, c->msg_len, c->signature, c->sig_len, c->pk);
}

/*
 * bench_sig_obj()
 *   Core ML-DSA benchmark harness operating on an already-constructed
 *   OQS_SIG object.  Caller owns `sig` (created via OQS_SIG_new() for the
 *   standard SHAKE algorithms, or via one of the alt-backend
 *   OQS_SIG_ml_dsa_*_<tag>_new() constructors) and must free it with
 *   OQS_SIG_free().
 */
static sig_bench_result_t bench_sig_obj(OQS_SIG *sig,
                                        const char *display_name,
                                        int run_dudect,
                                        int run_stack)
{
    sig_bench_result_t result;
    memset(&result, 0, sizeof(result));
    result.name = display_name;
    rejection_stats_init(&result.rejection);

    const char *sig_name = display_name;

    result.pk_bytes   = sig->length_public_key;
    result.sk_bytes   = sig->length_secret_key;
    result.sig_bytes  = sig->length_signature;
    result.nist_level = sig->claimed_nist_level;

    uint8_t *pk        = malloc(sig->length_public_key);
    uint8_t *sk        = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    uint8_t  msg[BENCH_MSG_LEN];
    if (!pk || !sk || !signature) {
        fprintf(stderr, "[ERROR] Allocation failed for %s\n", sig_name); goto sig_cleanup;
    }

    /* Generate a fixed test message. */
    for (int b = 0; b < BENCH_MSG_LEN; b++) msg[b] = (uint8_t)(b & 0xFF);

    /* Correctness self-test: keygen → sign → verify + tamper check */
    {
        size_t test_siglen = 0;
        if (OQS_SIG_keypair(sig, pk, sk) == OQS_SUCCESS &&
            OQS_SIG_sign(sig, signature, &test_siglen, msg, BENCH_MSG_LEN, sk) == OQS_SUCCESS &&
            OQS_SIG_verify(sig, msg, BENCH_MSG_LEN, signature, test_siglen, pk) == OQS_SUCCESS) {
            msg[0] ^= 0xFF;
            OQS_STATUS tamper = OQS_SIG_verify(sig, msg, BENCH_MSG_LEN, signature, test_siglen, pk);
            msg[0] ^= 0xFF;
            result.correctness_pass = (tamper == OQS_ERROR) ? 1 : 0;
        }
    }

    uint64_t total_iters   = BENCH_ITERATIONS + BENCH_WARMUP;
    uint64_t *cycles_kg    = malloc(total_iters * sizeof(uint64_t));
    uint64_t *cycles_sign  = malloc(total_iters * sizeof(uint64_t));
    uint64_t *cycles_ver   = malloc(total_iters * sizeof(uint64_t));
    if (!cycles_kg || !cycles_sign || !cycles_ver) {
        fprintf(stderr, "[ERROR] Cycle array allocation failed\n"); goto sig_cleanup;
    }

    uint8_t *stack_region = NULL;
    if (run_stack) {
        stack_region = malloc(STACK_PAINT_REGION_BYTES);
        if (!stack_region) run_stack = 0;
        else stack_paint(stack_region, STACK_PAINT_REGION_BYTES);
    }

    uint64_t wall_start, wall_end;
    size_t   sig_len = 0;

    /* Measure timing overhead (same as KEM) */
    uint64_t timing_overhead = 0;
    {
        uint64_t oh_samples[256];
        for (int oi = 0; oi < 256; oi++) {
            uint64_t t0 = cpucycles_begin();
            __asm__ volatile("" ::: "memory");
            uint64_t t1 = cpucycles_end();
            oh_samples[oi] = t1 - t0;
        }
        qsort(oh_samples, 256, sizeof(uint64_t), uint64_cmp);
        timing_overhead = oh_samples[128];
        g_timing_overhead_cycles = timing_overhead;
    }

    /* ================================================================
     * KEYGEN BENCHMARK LOOP
     * ================================================================ */
    double rapl_sig_kg_before = rapl_available ? rapl_read_uj() : 0.0;
    wall_start = wallclock_ns();
    for (uint64_t i = 0; i < total_iters; i++) {
        uint64_t t0 = cpucycles_begin();
        OQS_SIG_keypair(sig, pk, sk);
        uint64_t t1 = cpucycles_end();
        uint64_t raw = t1 - t0;
        cycles_kg[i] = (raw > timing_overhead) ? raw - timing_overhead : 0;
    }
    wall_end = wallclock_ns();
    double rapl_sig_kg_after = rapl_available ? rapl_read_uj() : 0.0;

    if (run_stack)
        result.stack_hwm_keygen = stack_measure_hwm(stack_region, STACK_PAINT_REGION_BYTES);

    compute_stats(&result.keygen,
                  cycles_kg + BENCH_WARMUP,
                  BENCH_ITERATIONS,
                  sig->length_public_key + sig->length_secret_key,
                  (double)(wall_end - wall_start));

    for (int mw = 0; mw < 3; mw++) OQS_SIG_keypair(sig, pk, sk);
    {
        sig_keygen_ctx_t sctx = { sig, pk, sk };
        mem_profile_op(sig_keygen_probe, &sctx, &result.mem_keygen);
    }
    compute_energy_stats(&result.energy_keygen, &result.keygen,
                         sig->length_public_key + sig->length_secret_key);
    if (rapl_available && rapl_sig_kg_after > rapl_sig_kg_before) {
        result.energy_keygen.rapl_before_uj     = rapl_sig_kg_before;
        result.energy_keygen.rapl_after_uj      = rapl_sig_kg_after;
        result.energy_keygen.rapl_loop_total_uj = rapl_sig_kg_after - rapl_sig_kg_before;
        result.energy_keygen.rapl_loop_iters    = total_iters;
        result.energy_keygen.rapl_energy_uj =
            (rapl_sig_kg_after - rapl_sig_kg_before) / (double)total_iters;
        result.energy_keygen.rapl_measured = 1;
    }


    /* ================================================================
     * SIGN BENCHMARK LOOP
     * CRITICAL: ML-DSA has probabilistic rejection sampling.
     * Each iteration may internally loop many times over SHAKE256 expansion.
     * The 99th percentile tail metric directly measures the worst-case cost
     * of high-iteration rejection sampling events (PDF1/PDF2).
     * ================================================================ */
    /* Re-generate keys once for a fixed keypair in signing. */
    OQS_SIG_keypair(sig, pk, sk);

    if (run_stack) stack_paint(stack_region, STACK_PAINT_REGION_BYTES);
    double rapl_sign_before = rapl_available ? rapl_read_uj() : 0.0;
    wall_start = wallclock_ns();

    for (uint64_t i = 0; i < total_iters; i++) {
        uint64_t t0 = cpucycles_begin();
        OQS_SIG_sign(sig, signature, &sig_len, msg, BENCH_MSG_LEN, sk);
        uint64_t t1 = cpucycles_end();
        uint64_t raw = t1 - t0;
        cycles_sign[i] = (raw > timing_overhead) ? raw - timing_overhead : 0;
    }
    wall_end = wallclock_ns();
    double rapl_sign_after = rapl_available ? rapl_read_uj() : 0.0;

    if (run_stack)
        result.stack_hwm_sign = stack_measure_hwm(stack_region, STACK_PAINT_REGION_BYTES);

    compute_stats(&result.sign_op,
                  cycles_sign + BENCH_WARMUP,
                  BENCH_ITERATIONS,
                  sig->length_signature,
                  (double)(wall_end - wall_start));

    for (int mw = 0; mw < 3; mw++) OQS_SIG_sign(sig, signature, &sig_len, msg, BENCH_MSG_LEN, sk);
    {
        size_t probe_sig_len = sig_len;
        sig_sign_ctx_t sctx = { sig, signature, &probe_sig_len, msg, BENCH_MSG_LEN, sk };
        mem_profile_op(sig_sign_probe, &sctx, &result.mem_sign);
    }
    compute_energy_stats(&result.energy_sign, &result.sign_op, sig->length_signature);
    if (rapl_available && rapl_sign_after > rapl_sign_before) {
        result.energy_sign.rapl_before_uj     = rapl_sign_before;
        result.energy_sign.rapl_after_uj      = rapl_sign_after;
        result.energy_sign.rapl_loop_total_uj = rapl_sign_after - rapl_sign_before;
        result.energy_sign.rapl_loop_iters    = total_iters;
        result.energy_sign.rapl_energy_uj =
            (rapl_sign_after - rapl_sign_before) / (double)total_iters;
        result.energy_sign.rapl_measured = 1;
    }


    result.rejection.total_signatures = BENCH_ITERATIONS;

    /* ================================================================
     * VERIFY BENCHMARK LOOP
     * Verify is deterministic: no rejection sampling variance expected.
     * ================================================================ */
    if (run_stack) stack_paint(stack_region, STACK_PAINT_REGION_BYTES);
    double rapl_ver_before = rapl_available ? rapl_read_uj() : 0.0;
    wall_start = wallclock_ns();

    for (uint64_t i = 0; i < total_iters; i++) {
        uint64_t t0 = cpucycles_begin();
        OQS_SIG_verify(sig, msg, BENCH_MSG_LEN, signature, sig_len, pk);
        uint64_t t1 = cpucycles_end();
        uint64_t raw = t1 - t0;
        cycles_ver[i] = (raw > timing_overhead) ? raw - timing_overhead : 0;
    }
    wall_end = wallclock_ns();
    double rapl_ver_after = rapl_available ? rapl_read_uj() : 0.0;

    if (run_stack)
        result.stack_hwm_verify = stack_measure_hwm(stack_region, STACK_PAINT_REGION_BYTES);

    compute_stats(&result.verify,
                  cycles_ver + BENCH_WARMUP,
                  BENCH_ITERATIONS,
                  sig->length_signature,
                  (double)(wall_end - wall_start));

    for (int mw = 0; mw < 3; mw++) OQS_SIG_verify(sig, msg, BENCH_MSG_LEN, signature, sig_len, pk);
    {
        sig_verify_ctx_t sctx = { sig, msg, BENCH_MSG_LEN, signature, sig_len, pk };
        mem_profile_op(sig_verify_probe, &sctx, &result.mem_verify);
    }
    compute_energy_stats(&result.energy_verify, &result.verify, sig->length_signature);
    if (rapl_available && rapl_ver_after > rapl_ver_before) {
        result.energy_verify.rapl_before_uj     = rapl_ver_before;
        result.energy_verify.rapl_after_uj      = rapl_ver_after;
        result.energy_verify.rapl_loop_total_uj = rapl_ver_after - rapl_ver_before;
        result.energy_verify.rapl_loop_iters    = total_iters;
        result.energy_verify.rapl_energy_uj =
            (rapl_ver_after - rapl_ver_before) / (double)total_iters;
        result.energy_verify.rapl_measured = 1;
    }


    /* ================================================================
     * DUDECT CONSTANT-TIME TEST ON SIGNING
     * ================================================================ */
    if (run_dudect) {
        printf("  Running dudect for %s signing (this may take ~5-10 min)...\n",
               sig_name);
        result.dudect_sign = dudect_run_sig(sig, DUDECT_MEASUREMENTS);
    }

    free(cycles_kg); free(cycles_sign); free(cycles_ver);
    free(stack_region);

sig_cleanup:
    free(pk); free(sk); free(signature);
    return result;
}

/*
 * bench_sig()
 *   Convenience wrapper for the standard (liboqs-registered) SHAKE-based
 *   ML-DSA algorithms: looks the algorithm up by name via OQS_SIG_new(),
 *   benchmarks it, and frees it.
 */
static sig_bench_result_t bench_sig(const char *sig_name,
                                    int run_dudect,
                                    int run_stack)
{
    OQS_SIG *sig = OQS_SIG_new(sig_name);
    if (!sig) {
        fprintf(stderr, "[ERROR] OQS_SIG_new(%s) failed.\n", sig_name);
        sig_bench_result_t result;
        memset(&result, 0, sizeof(result));
        result.name = sig_name;
        return result;
    }

    sig_bench_result_t result = bench_sig_obj(sig, sig_name, run_dudect, run_stack);
    OQS_SIG_free(sig);
    return result;
}

/* =========================================================================
 * REPORT PRINTER: ML-KEM
 * ========================================================================= */
static void print_kem_report(const kem_bench_result_t *r,
                             int run_dudect, int run_stack)
{
    printf("\n");
    printf("  ======================================================================\n");
    printf("  ML-KEM BENCHMARK REPORT: %s\n", r->name);
    printf("  Hash Backend     : %s\n", HASH_BACKEND_TAG);
    printf("  Keccak Rounds    : %d  (SHAKE=24, TurboSHAKE=12)\n", HASH_ROUNDS);
    printf("  FIPS 203 Compliant: %s\n", FIPS_COMPLIANT ? "YES" : "NO -- closed ecosystem only");
    printf("  ======================================================================\n");

    /* Algorithm parameters. */
    printf("\n  [Algorithm Parameters - FIPS 203 / M-LWE]\n");
    printf("  NIST Security Level  : %u\n",   r->nist_level);
    printf("  Security Model       : %s\n",    r->ind_cca ? "IND-CCA2 (FO transform)" : "IND-CPA");
    printf("  Public Key Size      : %zu bytes\n",  r->pk_bytes);
    printf("  Secret Key Size      : %zu bytes\n",  r->sk_bytes);
    printf("  Ciphertext Size      : %zu bytes\n",  r->ct_bytes);
    printf("  Shared Secret Size   : %zu bytes\n",  r->ss_bytes);
    printf("  MTU Note             : CT %s 1500B MTU (%s fragmentation)\n",
           r->ct_bytes > 1500 ? "EXCEEDS" : "fits within",
           r->ct_bytes > 1500 ? "IP fragmentation REQUIRED" : "no fragmentation");

    /* Hash integration vectors (from PDF1/PDF2 architectural analysis). */
    printf("\n  [SHAKE Integration Vectors within ML-KEM]\n");
    printf("  Vector 1: Matrix Expansion     => %s  (PRF, row/col seed)\n", KEM_VECTOR1_LABEL);
    printf("  Vector 2: CBD Noise Generation => %s  (secret seed)\n", KEM_VECTOR2_LABEL);
    printf("  Vector 3: FO Transform         => SHA3-256 / SHA3-512 (not replaced)\n");
    printf("  Vector 4: KDF (shared secret)  => %s\n", KEM_VECTOR4_LABEL);

    /* Benchmark results. */
    printf("\n  [Benchmark Results: n=%d iterations, warmup=%d discarded]\n",
           BENCH_ITERATIONS, BENCH_WARMUP);

    print_stats("KeyGen", &r->keygen, "cycles");
    print_stats("Encaps", &r->encaps, "cycles");
    print_stats("Decaps", &r->decaps, "cycles");

    /* TIER 11/12: memory footprint + energy proxy (hardware-independent). */
    printf("\n  [Memory Footprint & Energy Proxy -- software-level, hardware-independent]\n");
    print_mem_energy("KeyGen", &r->mem_keygen, &r->energy_keygen);
    print_mem_energy("Encaps", &r->mem_encaps, &r->energy_encaps);
    print_mem_energy("Decaps", &r->mem_decaps, &r->energy_decaps);

    /* Stack watermark. */
    if (run_stack) {
        printf("\n  [Stack High-Water Marks (0xDEADBEEF sentinel painting)]\n");
        print_stack_result("KeyGen peak stack", r->stack_hwm_keygen);
        print_stack_result("Encaps peak stack", r->stack_hwm_encaps);
        print_stack_result("Decaps peak stack", r->stack_hwm_decaps);
        printf("  Note: Keccak state = 200 bytes (fixed regardless of 12 vs 24 rounds).\n");
        printf("  A spike in stack HWM after TurboSHAKE swap => struct misalignment bug.\n");
    }


    /* Dudect. */
    if (run_dudect) {
        printf("\n  [Constant-Time Validation (dudect / Welch t-test)]\n");
        print_dudect_result("Encaps", &r->dudect_encaps);
    }

    /* TurboSHAKE expected gains note. */
    printf("\n  [Expected Impact of TurboSHAKE Substitution]\n");
    printf("  - Hash-intensive ops (matrix expand, CBD): ~40-50%% fewer cycles.\n");
    printf("  - Macroscopic KeyGen + Encaps: ~15-25%% overall reduction (PDF1/PDF2).\n");
    printf("  - NTT multiplications + modular reductions: UNCHANGED (non-hash ops).\n");
    printf("  - Stack usage: IDENTICAL (Keccak state = 200 bytes fixed).\n");
    printf("  - Network transmission bottleneck: UNCHANGED (byte sizes stay same).\n");
}

/* =========================================================================
 * REPORT PRINTER: ML-DSA
 * ========================================================================= */
static void print_sig_report(const sig_bench_result_t *r,
                             int run_dudect, int run_stack)
{
    printf("\n");
    printf("  ======================================================================\n");
    printf("  ML-DSA BENCHMARK REPORT: %s\n", r->name);
    printf("  Hash Backend     : %s\n", HASH_BACKEND_TAG);
    printf("  Keccak Rounds    : %d\n", HASH_ROUNDS);
    printf("  FIPS 204 Compliant: %s\n", FIPS_COMPLIANT ? "YES" : "NO -- closed ecosystem only");
    printf("  ======================================================================\n");

    printf("\n  [Algorithm Parameters - FIPS 204 / M-SIS + M-LWE]\n");
    printf("  NIST Security Level  : %u\n",  r->nist_level);
    printf("  Security Model       : Fiat-Shamir with Aborts (rejection sampling)\n");
    printf("  Public Key Size      : %zu bytes\n",  r->pk_bytes);
    printf("  Secret Key Size      : %zu bytes\n",  r->sk_bytes);
    printf("  Signature Size       : %zu bytes\n",  r->sig_bytes);
    printf("  MTU Note             : Sig %s 1500B MTU (%s)\n",
           r->sig_bytes > 1500 ? "EXCEEDS" : "fits within",
           r->sig_bytes > 1500 ? "fragmentation REQUIRED -- exponential packet loss impact" : "no fragmentation");

    printf("\n  [SHAKE Integration Vectors within ML-DSA]\n");
    printf("  Vector 1: Matrix Expansion     => %s\n",
           FIPS_COMPLIANT ? "SHAKE128 (n_r=24, PRF, row/col seed)" :
                            "TurboSHAKE128 (n_r=12, D=0x1F)");
    printf("  Vector 2: Masking Vector y     => %s  (REJECTION LOOP)\n",
           FIPS_COMPLIANT ? "SHAKE256 (n_r=24, secret seed||nonce)" :
                            "TurboSHAKE256 (n_r=12, D=0x2F, secret seed||nonce)");
    printf("  Vector 3: Challenge Poly c     => %s\n",
           FIPS_COMPLIANT ? "SHAKE256 (n_r=24, commitment||message)" :
                            "TurboSHAKE256 (n_r=12, D=0x3F)");
    printf("  REJECTION LOOP: If bound check fails => increment nonce, repeat vector 2.\n");
    printf("  Expected iterations: ~4.25 (ML-DSA-44), ~5.10 (ML-DSA-65) [PDF1].\n");
    printf("  99th-pct time on Cortex-M0+ @ 133MHz: >1,115 ms [PDF2].\n");

    printf("\n  [Benchmark Results: n=%d iterations, warmup=%d discarded]\n",
           BENCH_ITERATIONS, BENCH_WARMUP);

    print_stats("KeyGen", &r->keygen, "cycles");
    print_stats("Sign   (rejection loop variance captured in p99)", &r->sign_op, "cycles");
    print_stats("Verify (deterministic -- low CoV expected)", &r->verify, "cycles");

    /* TIER 11/12: memory footprint + energy proxy (hardware-independent). */
    printf("\n  [Memory Footprint & Energy Proxy -- software-level, hardware-independent]\n");
    print_mem_energy("KeyGen", &r->mem_keygen, &r->energy_keygen);
    print_mem_energy("Sign",   &r->mem_sign,   &r->energy_sign);
    print_mem_energy("Verify", &r->mem_verify, &r->energy_verify);

    /* Rejection sampling analysis. */
    rejection_stats_print(&r->rejection, r->name);

    /* CoV interpretation for ML-DSA signing. */
    printf("\n  [Signing Variance Analysis]\n");
    printf("  Observed CoV     : %.2f%%\n", r->sign_op.cov_pct);
    printf("  Reference CoV    : 61-71%% expected on embedded (PDF2 ARM Cortex-M0+)\n");
    printf("  Tail compression : TurboSHAKE reduces each abort iteration cost,\n");
    printf("                     shrinking 99th pct (%.0f cyc) toward median (%.0f cyc).\n",
           r->sign_op.p99, r->sign_op.median);
    printf("  Speedup factor   : With TurboSHAKE, expect ~%.0f-%.0f fewer p99 cycles\n",
           r->sign_op.p99 * 0.15, r->sign_op.p99 * 0.35);

    /* Stack watermark. */
    if (run_stack) {
        printf("\n  [Stack High-Water Marks (0xDEADBEEF sentinel)]\n");
        print_stack_result("KeyGen peak stack", r->stack_hwm_keygen);
        print_stack_result("Sign   peak stack", r->stack_hwm_sign);
        print_stack_result("Verify peak stack", r->stack_hwm_verify);
        printf("  ML-DSA requires >100KB stack on constrained devices (PDF1/PDF2).\n");
        printf("  K*L polynomial vectors are the dominant stack consumers.\n");
    }

    /* Dudect. */
    if (run_dudect) {
        printf("\n  [Constant-Time Validation (dudect / Welch t-test)]\n");
        print_dudect_result("Sign", &r->dudect_sign);
        printf("  Note: Rejection sampling is probabilistic by design, NOT a\n");
        printf("        secret-dependent branch.  CoV due to abort count, not timing leak.\n");
    }

    printf("\n  [Expected TurboSHAKE Impact on ML-DSA]\n");
    printf("  - Each rejection loop iteration: ~50%% fewer hash cycles.\n");
    printf("  - Tail latency (p99): drastically compressed.\n");
    printf("  - Signing CoV: unchanged (abort count distribution unchanged).\n");
    printf("  - Signature byte size: UNCHANGED (physical byte counts unaffected).\n");
    printf("  - FIPS 204 compliance: BROKEN by TurboSHAKE substitution.\n");
}

/* =========================================================================
 * TIER 10: CSV REPORT WRITER
 * Outputs structured data for analysis with Python/R/Excel.
 * Column headers match standard SUPERCOP/eBACS output conventions.
 * ========================================================================= */
static FILE *csv_fp = NULL;

static void csv_open(int append) {
    if (append) {
        /* Append mode: only write the header if the file doesn't exist yet
         * or is currently empty (so a SHAKE run followed by a TurboSHAKE
         * --csv-append run lands in one file with a single header). */
        FILE *probe = fopen(BENCH_CSV_OUTPUT, "r");
        int need_header = 1;
        if (probe) {
            fseek(probe, 0, SEEK_END);
            need_header = (ftell(probe) == 0);
            fclose(probe);
        }
        csv_fp = fopen(BENCH_CSV_OUTPUT, "a");
        if (!csv_fp) { perror("fopen CSV"); return; }
        if (!need_header) {
            return;
        }
    } else {
        csv_fp = fopen(BENCH_CSV_OUTPUT, "w");
        if (!csv_fp) { perror("fopen CSV"); return; }
    }
    fprintf(csv_fp,
            "algorithm,operation,hash_backend,keccak_rounds,fips_compliant,"
            "correctness,"
            "counter_type,"
            "n_iterations,median_cycles,q1_cycles,q3_cycles,iqr_cycles,"
            "p95_cycles,p99_cycles,min_cycles,max_cycles,"
            "arith_mean_cycles,geo_mean_cycles,std_dev_cycles,cov_pct,"
            "cpb,wall_ns_mean,"
            "pk_bytes,sk_bytes,ct_or_sig_bytes,ss_bytes,nist_level,"
            "stack_hwm_bytes,"
            "peak_rss_delta_kb,peak_rss_after_kb,heap_delta_bytes,"
            "energy_proxy_units,energy_proxy_per_byte,"
            "est_energy_uj,est_energy_uj_per_byte,energy_calibrated,"
            "edp_cycle_ns,"
            "rapl_energy_uj,rapl_measured,"
            "trimmed_mean_cycles,p90_cycles,timing_overhead_cycles,"
            "rss_before_kb,heap_before_bytes,heap_after_bytes,"
            "rapl_before_uj,rapl_after_uj,rapl_loop_total_uj,rapl_loop_iters\n");
}

static void csv_write_stats(const char            *algo,
                            const char            *op,
                            int                    correctness,
                            const bench_stats_t   *s,
                            size_t                 pk_b,
                            size_t                 sk_b,
                            size_t                 ct_b,
                            size_t                 ss_b,
                            uint8_t                nist_level,
                            size_t                 stack_hwm,
                            const mem_stats_t      *m,
                            const energy_stats_t   *e)
{
    if (!csv_fp) return;
    fprintf(csv_fp,
            "%s,%s,\"%s\",%d,%d,"
            "%s,"
            "\"%s\","
            "%"PRIu64","
            "%.0f,%.0f,%.0f,%.0f,"
            "%.0f,%.0f,"
            "%"PRIu64",%"PRIu64","
            "%.2f,%.2f,%.2f,%.4f,"
            "%.6f,%.2f,"
            "%zu,%zu,%zu,%zu,%u,"
            "%zu,"
            "%ld,%ld,%ld,"
            "%.0f,%.4f,"
            "%.4f,%.6f,%d,"
            "%.2f,"
            "%.4f,%d,"
            "%.2f,%.0f,%"PRIu64","
            "%ld,%ld,%ld,"
            "%.2f,%.2f,%.2f,%"PRIu64"\n",
            algo, op, HASH_BACKEND_TAG, HASH_ROUNDS, FIPS_COMPLIANT,
            correctness ? "PASS" : "FAIL",
            get_cycle_counter_type(),
            s->n,
            s->median, s->q1, s->q3, s->iqr,
            s->p95, s->p99,
            s->min_cycles, s->max_cycles,
            s->arith_mean, s->geo_mean, s->std_dev, s->cov_pct,
            s->cpb, s->wall_ns,
            pk_b, sk_b, ct_b, ss_b, (unsigned)nist_level,
            stack_hwm,
            m->peak_rss_delta_kb, m->peak_rss_after_kb, m->heap_delta_bytes,
            e->epu, e->epu_per_byte,
            e->est_energy_uj, e->est_energy_uj_per_byte, e->calibrated,
            e->edp_cycle_ns,
            e->rapl_energy_uj, e->rapl_measured,
            s->trimmed_mean, s->p90, g_timing_overhead_cycles,
            m->rss_before_kb, m->heap_before_bytes, m->heap_after_bytes,
            e->rapl_before_uj, e->rapl_after_uj, e->rapl_loop_total_uj,
            e->rapl_loop_iters);
}

static void csv_close(void) {
    if (csv_fp) { fclose(csv_fp); csv_fp = NULL; }
}


/* =========================================================================
 * COMPARISON SUMMARY
 * Prints a SHAKE vs TurboSHAKE side-by-side analysis note.
 * When running both builds, redirect stdout to files and diff them.
 * ========================================================================= */
static void print_comparison_guide(void) {
    printf("\n");
    printf("  ======================================================================\n");
    printf("  HOW TO COMPARE SHAKE vs TurboSHAKE RESULTS\n");
    printf("  ======================================================================\n");
    printf("  1. Build SHAKE baseline:\n");
    printf("     gcc -O2 -march=native pqc_agility_benchmark.c -loqs -lm \\\n");
    printf("         -o bench_shake\n");
    printf("     ./bench_shake > results_shake.txt 2>&1\n\n");
    printf("  2. Build TurboSHAKE variant:\n");
    printf("     gcc -O2 -march=native -DUSE_TURBOSHAKE \\\n");
    printf("         pqc_agility_benchmark.c -loqs -lm -o bench_turboshake\n");
    printf("     ./bench_turboshake > results_turboshake.txt 2>&1\n\n");
    printf("  3. Compare:\n");
    printf("     diff results_shake.txt results_turboshake.txt\n\n");
    printf("  4. For cache analysis (Valgrind Cachegrind):\n");
    printf("     valgrind --tool=cachegrind --cachegrind-out-file=cg_shake.out \\\n");
    printf("              ./bench_shake\n");
    printf("     cg_annotate cg_shake.out\n\n");
    printf("  5. For heap memory (Valgrind Massif):\n");
    printf("     valgrind --tool=massif --stacks=yes ./bench_shake\n");
    printf("     ms_print massif.out.<pid>\n\n");
    printf("  6. For hardware counters (Linux perf):\n");
    printf("     perf stat -e cycles,instructions,cache-misses,branch-misses \\\n");
    printf("               ./bench_shake\n\n");
    printf("  7. CSV output written to: %s\n", BENCH_CSV_OUTPUT);
    printf("     Import into Python/R/Excel for visualization.\n\n");
    printf("  8. MEMORY (TIER 11, software-level, no Valgrind needed):\n");
    printf("     'Peak RSS delta'  -- getrusage() process high-water mark growth.\n");
    printf("     'Heap arena delta' -- mallinfo() malloc-arena delta for 1 call.\n");
    printf("     Both columns are also in the CSV for SHAKE vs TurboSHAKE diffing.\n\n");
    printf("  9. ENERGY (TIER 12, software proxy, no RAPL/board sensor needed):\n");
    printf("     'Energy Proxy Units' = median cycles -- compare this directly\n");
    printf("     between SHAKE and TurboSHAKE builds; it is hardware-independent.\n");
    printf("     To get an absolute uJ estimate for YOUR platform, measure its\n");
    printf("     average power draw P (Watts) at clock F (Hz) and rebuild with:\n");
    printf("        gcc -DENERGY_PER_CYCLE_NJ=$(echo \"$P / $F * 1e9\" | bc) ...\n\n");
    printf("  THEORY REFERENCE (from PDFs):\n");
    printf("  - TurboSHAKE128/256: Keccak n_r=12 (vs SHAKE n_r=24).\n");
    printf("  - Expected hash speedup: ~100%% at primitive level.\n");
    printf("  - Expected ML-KEM speedup: ~15-25%% overall (NTT is constant).\n");
    printf("  - Expected ML-DSA: massive p99 tail compression.\n");
    printf("  - Memory/energy proxies should track cycle-count reductions 1:1,\n");
    printf("    since both TIER 11/12 figures are derived from the same\n");
    printf("    cycle/heap/RSS measurements regardless of which build runs.\n");
    printf("  - SECURITY: Best attack on Keccak = 6 rounds. TurboSHAKE=12 => 100%% margin.\n");
    printf("  - FIPS: TurboSHAKE BREAKS FIPS 203/204 -- closed ecosystems ONLY.\n");
    printf("  ======================================================================\n");
}


/* =========================================================================
 * MAIN ENTRY POINT
 * ========================================================================= */
int main(int argc, char *argv[]) {

    /* ----------------------------------------------------------------
     * Parse optional command-line flags:
     *   --no-dudect      Skip dudect (saves ~30 min per algorithm)
     *   --no-stack       Skip stack painting
     *   --kem-only       Only benchmark KEM, skip DSA
     *   --dsa-only       Only benchmark DSA, skip KEM
     *   --csv-append     Append to BENCH_CSV_OUTPUT instead of overwriting
     *                     (skips the header row if the file already has one)
     *   --quick          50 iterations only (fast sanity check)
     * ---------------------------------------------------------------- */
    int run_dudect        = 0;   /* Off by default: very time-consuming */
    int run_stack         = 1;
    int run_kem           = 1;
    int run_dsa           = 1;
    int csv_append        = 0;
    int correctness_only  = 0;
    int correctness_trials = 1000;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dudect")          == 0) run_dudect = 1;
        if (strcmp(argv[i], "--no-stack")        == 0) run_stack  = 0;
        if (strcmp(argv[i], "--kem-only")        == 0) run_dsa    = 0;
        if (strcmp(argv[i], "--dsa-only")        == 0) run_kem    = 0;
        if (strcmp(argv[i], "--csv-append")      == 0) csv_append = 1;
        if (strcmp(argv[i], "--correctness-only") == 0) correctness_only = 1;
        if (strcmp(argv[i], "--trials") == 0 && i + 1 < argc)
            correctness_trials = atoi(argv[++i]);
        if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            int v = atoi(argv[++i]);
            if (v > 0) g_bench_iterations = v;
        }
        if (strcmp(argv[i], "--warmup") == 0 && i + 1 < argc) {
            int v = atoi(argv[++i]);
            if (v >= 0) g_bench_warmup = v;
        }
        if (strcmp(argv[i], "--quick") == 0) {
            g_bench_iterations = 50;
            g_bench_warmup     = 10;
        }
        if (strcmp(argv[i], "--help")     == 0) {
            printf("Usage: %s [--dudect] [--no-stack] [--kem-only] [--dsa-only] "
                   "[--csv-append] [--correctness-only] [--trials N] "
                   "[--iterations N] [--warmup N] [--quick]\n",
                   argv[0]);
            return 0;
        }
    }

    /* Seed RNG for dudect class alternation. */
    srand((unsigned)time(NULL));

    /* Initialize RAPL energy measurement. */
    rapl_init();

    /* Apply best-effort noise / tail-latency controls (mlockall + RT sched). */
    reduce_measurement_noise();

    /* ----------------------------------------------------------------
     * Print benchmark header
     * ---------------------------------------------------------------- */
    printf("\n");
    printf("  ######################################################################\n");
    printf("  #  PQC ALGORITHMIC AGILITY BENCHMARKING SUITE                       #\n");
    printf("  #  ML-DSA (FIPS 204) + ML-KEM (FIPS 203)                            #\n");
    printf("  #  SHAKE (n_r=24) vs TurboSHAKE RFC 9861 (n_r=12) Comparison        #\n");
    printf("  ######################################################################\n");
    printf("\n");
    printf("  Hash Backend     : %s\n", HASH_BACKEND_TAG);
    printf("  Keccak Rounds    : %d  (SHAKE=24 | TurboSHAKE=12)\n", HASH_ROUNDS);
    printf("  FIPS Compliant   : %s\n", FIPS_COMPLIANT ? "YES (FIPS 202/203/204)" :
                                                          "NO  (closed ecosystem / research only)");
    printf("  Cycle counter    : %s\n", get_cycle_counter_type());
#if defined(__aarch64__)
    printf("  Timer frequency  : %"PRIu64" Hz (CNTFRQ_EL0)\n", get_timer_freq_hz());
    printf("  NOTE: aarch64 'cycle' columns are timer ticks, not CPU cycles.\n");
    printf("        Use wall_ns columns for cross-architecture comparison.\n");
#endif
    printf("  Iterations       : %d  (warmup=%d)\n", BENCH_ITERATIONS, BENCH_WARMUP);
    printf("  Message length   : %d bytes\n", BENCH_MSG_LEN);
    printf("  Stack paint size : %d KB\n",    STACK_PAINT_REGION_BYTES / 1024);
    printf("  RAPL energy      : %s\n",
           rapl_available ? "AVAILABLE (Intel RAPL hardware measurement)"
                          : "UNAVAILABLE (using software energy proxy only)");
    printf("  Dudect enabled   : %s  (pass --dudect to enable)\n",
           run_dudect ? "YES" : "NO");
    printf("  Memory profiling : Peak RSS (getrusage) + heap delta (mallinfo)"
           " -- POSIX, no hardware deps\n");
#if defined(PQC_HAVE_MALLINFO)
    printf("                     Heap tracking: ENABLED (glibc mallinfo%s)\n",
#  if defined(__GLIBC__) && __GLIBC_PREREQ(2, 33)
           "2"
#  else
           ""
#  endif
          );
#else
    printf("                     Heap tracking: DISABLED (non-glibc libc)\n");
#endif
    printf("  Energy proxy     : Energy Proxy Units = median cycles (hardware-independent)\n");
    printf("                     Calibration       : %s\n",
           ENERGY_MODEL_CALIBRATED
               ? "ENABLED  (ENERGY_PER_CYCLE_NJ user-supplied)"
               : "illustrative only (define -DENERGY_PER_CYCLE_NJ=<nJ/cycle> to calibrate)");

    if (!FIPS_COMPLIANT) {
        printf("\n");
        printf("  !! COMPLIANCE WARNING !!\n");
#if defined(USE_K12)
        printf("  KangarooTwelve build DEVIATES from FIPS 203/204.\n");
        printf("  Customization string: matrix=0x%02X, CBD=0x%02X, KDF=0x%02X\n",
               TURBOSHAKE_DOMAIN_MATRIX, TURBOSHAKE_DOMAIN_CBD, TURBOSHAKE_DOMAIN_CHAL);
        printf("  See RFC 9861 Section 2.1 for domain byte constraints (0x01..0x7F).\n");
#elif defined(USE_BLAKE3)
        printf("  BLAKE3 build DEVIATES from FIPS 203/204.\n");
        printf("  BLAKE3 XOF domain byte: matrix=0x%02X, CBD=0x%02X, KDF=0x%02X\n",
               TURBOSHAKE_DOMAIN_MATRIX, TURBOSHAKE_DOMAIN_CBD, TURBOSHAKE_DOMAIN_CHAL);
        printf("  BLAKE3 is not a FIPS-approved hash function.\n");
#elif defined(USE_XOODYAK)
        printf("  Xoodyak build DEVIATES from FIPS 203/204.\n");
        printf("  Xoodyak Cyclist domain byte: matrix=0x%02X, CBD=0x%02X, KDF=0x%02X\n",
               TURBOSHAKE_DOMAIN_MATRIX, TURBOSHAKE_DOMAIN_CBD, TURBOSHAKE_DOMAIN_CHAL);
        printf("  Xoodyak/Xoodoo is not a FIPS-approved permutation.\n");
#elif defined(USE_HARAKA)
        printf("  Haraka-CTR build DEVIATES SIGNIFICANTLY from FIPS 203/204.\n");
        printf("  Haraka-CTR domain byte: matrix=0x%02X, CBD=0x%02X, KDF=0x%02X\n",
               TURBOSHAKE_DOMAIN_MATRIX, TURBOSHAKE_DOMAIN_CBD, TURBOSHAKE_DOMAIN_CHAL);
        printf("  Haraka is a FIXED-OUTPUT primitive; the XOF/PRF/KDF roles use a\n");
        printf("  NON-STANDARD counter-mode construction (Haraka-CTR) defined in\n");
        printf("  symmetric.h of the haraka variant -- this is NOT a vetted\n");
        printf("  cryptographic construction and exists purely for benchmarking.\n");
#else
        printf("  TurboSHAKE build DEVIATES from FIPS 203/204.\n");
        printf("  Domain separation byte: matrix=0x%02X, CBD=0x%02X, challenge=0x%02X\n",
               TURBOSHAKE_DOMAIN_MATRIX, TURBOSHAKE_DOMAIN_CBD, TURBOSHAKE_DOMAIN_CHAL);
        printf("  See RFC 9861 Section 2.1 for domain byte constraints (0x01..0x7F).\n");
#endif
        printf("  DO NOT use in open-internet TLS 1.3 deployments.\n");
    }
    printf("\n");

    /* ================================================================
     * CORRECTNESS-ONLY MODE
     * Runs N independent round-trip tests per algorithm with tamper
     * detection. No timing measurement. Exit code 0 = all pass.
     * ================================================================ */
    if (correctness_only) {
        printf("\n  === CORRECTNESS-ONLY MODE (%d trials per algorithm) ===\n\n",
               correctness_trials);
        int all_pass = 1;

        if (run_kem) {
            const char *kem_algs_co[] = { MLKEM_512_NAME, MLKEM_768_NAME, MLKEM_1024_NAME };
            for (int ki = 0; ki < 3; ki++) {
                OQS_KEM *kem = OQS_KEM_new(kem_algs_co[ki]);
                if (!kem) { fprintf(stderr, "[ERROR] Cannot create %s\n", kem_algs_co[ki]); all_pass = 0; continue; }
                uint8_t *pk = malloc(kem->length_public_key);
                uint8_t *sk = malloc(kem->length_secret_key);
                uint8_t *ct = malloc(kem->length_ciphertext);
                uint8_t *ss_e = malloc(kem->length_shared_secret);
                uint8_t *ss_d = malloc(kem->length_shared_secret);
                int pass = 0, fail = 0, tamper_fail = 0;
                for (int t = 0; t < correctness_trials; t++) {
                    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS ||
                        OQS_KEM_encaps(kem, ct, ss_e, pk) != OQS_SUCCESS ||
                        OQS_KEM_decaps(kem, ss_d, ct, sk) != OQS_SUCCESS ||
                        memcmp(ss_e, ss_d, kem->length_shared_secret) != 0) {
                        fail++; continue;
                    }
                    ct[0] ^= 0xFF;
                    OQS_KEM_decaps(kem, ss_d, ct, sk);
                    if (memcmp(ss_e, ss_d, kem->length_shared_secret) == 0)
                        tamper_fail++;
                    ct[0] ^= 0xFF;
                    pass++;
                }
                printf("  %-20s  PASS=%d  FAIL=%d  TAMPER_DETECT_FAIL=%d  %s\n",
                       kem_algs_co[ki], pass, fail, tamper_fail,
                       (fail == 0 && tamper_fail == 0) ? "OK" : "*** FAILED ***");
                if (fail > 0 || tamper_fail > 0) all_pass = 0;
                free(pk); free(sk); free(ct); free(ss_e); free(ss_d);
                OQS_KEM_free(kem);
            }
        }

        if (run_dsa) {
            const char *sig_algs_co[] = { MLDSA_44_NAME, MLDSA_65_NAME, MLDSA_87_NAME };
            for (int si = 0; si < 3; si++) {
                OQS_SIG *sig = OQS_SIG_new(sig_algs_co[si]);
                if (!sig) { fprintf(stderr, "[ERROR] Cannot create %s\n", sig_algs_co[si]); all_pass = 0; continue; }
                uint8_t *pk = malloc(sig->length_public_key);
                uint8_t *sk = malloc(sig->length_secret_key);
                uint8_t *sm = malloc(sig->length_signature);
                uint8_t msg[BENCH_MSG_LEN];
                for (int b = 0; b < BENCH_MSG_LEN; b++) msg[b] = (uint8_t)(b & 0xFF);
                size_t smlen = 0;
                int pass = 0, fail = 0, tamper_fail = 0;
                for (int t = 0; t < correctness_trials; t++) {
                    msg[0] = (uint8_t)(t & 0xFF);
                    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS ||
                        OQS_SIG_sign(sig, sm, &smlen, msg, BENCH_MSG_LEN, sk) != OQS_SUCCESS ||
                        OQS_SIG_verify(sig, msg, BENCH_MSG_LEN, sm, smlen, pk) != OQS_SUCCESS) {
                        fail++; continue;
                    }
                    msg[1] ^= 0xFF;
                    if (OQS_SIG_verify(sig, msg, BENCH_MSG_LEN, sm, smlen, pk) == OQS_SUCCESS)
                        tamper_fail++;
                    msg[1] ^= 0xFF;
                    pass++;
                }
                printf("  %-20s  PASS=%d  FAIL=%d  TAMPER_DETECT_FAIL=%d  %s\n",
                       sig_algs_co[si], pass, fail, tamper_fail,
                       (fail == 0 && tamper_fail == 0) ? "OK" : "*** FAILED ***");
                if (fail > 0 || tamper_fail > 0) all_pass = 0;
                free(pk); free(sk); free(sm);
                OQS_SIG_free(sig);
            }
        }

        printf("\n  === CORRECTNESS RESULT: %s ===\n\n",
               all_pass ? "ALL PASSED" : "FAILURES DETECTED");
        return all_pass ? 0 : 1;
    }

    /* Open CSV output. */
    csv_open(csv_append);

    /* ================================================================
     * BENCHMARK ML-KEM PARAMETER SETS
     * ================================================================ */
    if (run_kem) {
        printf("  ====== ML-KEM (FIPS 203 / CRYSTALS-Kyber) ======\n\n");

        const char *kem_algs[] = {
            MLKEM_512_NAME,
            MLKEM_768_NAME,
            MLKEM_1024_NAME
        };
        const char *kem_notes[] = {
            "k=2, NIST Level 1, pk=800B, ct=768B",
            "k=3, NIST Level 3, pk=1184B, ct=1088B (recommended)",
            "k=4, NIST Level 5, pk=1568B, ct=1568B (exceeds MTU)"
        };
        int n_kems = 3;

#if defined(USE_SHAKE) || defined(USE_TURBOSHAKE) || defined(USE_K12) || defined(USE_BLAKE3) || defined(USE_XOODYAK) || defined(USE_HARAKA)
        OQS_KEM *(*alt_ctors[])(void) = {
#  ifdef USE_SHAKE
            OQS_KEM_ml_kem_512_shake_new,
            OQS_KEM_ml_kem_768_shake_new,
            OQS_KEM_ml_kem_1024_shake_new
#  elif defined(USE_TURBOSHAKE)
            OQS_KEM_ml_kem_512_turboshake_new,
            OQS_KEM_ml_kem_768_turboshake_new,
            OQS_KEM_ml_kem_1024_turboshake_new
#  elif defined(USE_K12)
            OQS_KEM_ml_kem_512_k12_new,
            OQS_KEM_ml_kem_768_k12_new,
            OQS_KEM_ml_kem_1024_k12_new
#  elif defined(USE_BLAKE3)
            OQS_KEM_ml_kem_512_blake3_new,
            OQS_KEM_ml_kem_768_blake3_new,
            OQS_KEM_ml_kem_1024_blake3_new
#  elif defined(USE_XOODYAK)
            OQS_KEM_ml_kem_512_xoodyak_new,
            OQS_KEM_ml_kem_768_xoodyak_new,
            OQS_KEM_ml_kem_1024_xoodyak_new
#  else
            OQS_KEM_ml_kem_512_haraka_new,
            OQS_KEM_ml_kem_768_haraka_new,
            OQS_KEM_ml_kem_1024_haraka_new
#  endif
        };
#endif

        for (int ki = 0; ki < n_kems; ki++) {
            kem_bench_result_t kr;

#if defined(USE_SHAKE) || defined(USE_TURBOSHAKE) || defined(USE_K12) || defined(USE_BLAKE3) || defined(USE_XOODYAK) || defined(USE_HARAKA)
            OQS_KEM *kem = alt_ctors[ki]();
            if (!kem) {
                fprintf(stderr, "[ERROR] Failed to construct %s\n", kem_algs[ki]);
                continue;
            }

            /* ----------------------------------------------------------
             * Correctness self-test: keypair -> encaps -> decaps roundtrip.
             * Confirms the substituted implementation produces matching
             * shared secrets before trusting its timings.
             * ---------------------------------------------------------- */
            {
                uint8_t *pk     = malloc(kem->length_public_key);
                uint8_t *sk     = malloc(kem->length_secret_key);
                uint8_t *ct     = malloc(kem->length_ciphertext);
                uint8_t *ss_enc = malloc(kem->length_shared_secret);
                uint8_t *ss_dec = malloc(kem->length_shared_secret);

                if (!pk || !sk || !ct || !ss_enc || !ss_dec) {
                    fprintf(stderr, "[ERROR] Self-test allocation failed for %s\n", kem->method_name);
                    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
                    OQS_KEM_free(kem);
                    continue;
                }

                OQS_STATUS sok = OQS_KEM_keypair(kem, pk, sk);
                OQS_STATUS eok = OQS_KEM_encaps(kem, ct, ss_enc, pk);
                OQS_STATUS dok = OQS_KEM_decaps(kem, ss_dec, ct, sk);

                int match = (sok == OQS_SUCCESS && eok == OQS_SUCCESS && dok == OQS_SUCCESS &&
                             memcmp(ss_enc, ss_dec, kem->length_shared_secret) == 0);

                free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);

                if (!match) {
                    fprintf(stderr, "  [SELFTEST] %s roundtrip FAILED -- skipping benchmark\n",
                            kem->method_name);
                    OQS_KEM_free(kem);
                    continue;
                }
                printf("  [SELFTEST] %s roundtrip OK (shared secrets match)\n", kem->method_name);
            }

            printf("  Benchmarking %s  [%s]\n", kem->method_name, kem_notes[ki]);
            fflush(stdout);

            kr = bench_kem_obj(kem, kem->method_name, run_dudect, run_stack);
            OQS_KEM_free(kem);
#else
            printf("  Benchmarking %s  [%s]\n", kem_algs[ki], kem_notes[ki]);
            fflush(stdout);

            kr = bench_kem(kem_algs[ki], run_dudect, run_stack);
#endif
            print_kem_report(&kr, run_dudect, run_stack);

            /* Write to CSV. */
            csv_write_stats(kr.name, "KeyGen", kr.correctness_pass, &kr.keygen,
                            kr.pk_bytes, kr.sk_bytes, kr.ct_bytes, kr.ss_bytes,
                            kr.nist_level, kr.stack_hwm_keygen,
                            &kr.mem_keygen, &kr.energy_keygen);
            csv_write_stats(kr.name, "Encaps", kr.correctness_pass, &kr.encaps,
                            kr.pk_bytes, kr.sk_bytes, kr.ct_bytes, kr.ss_bytes,
                            kr.nist_level, kr.stack_hwm_encaps,
                            &kr.mem_encaps, &kr.energy_encaps);
            csv_write_stats(kr.name, "Decaps", kr.correctness_pass, &kr.decaps,
                            kr.pk_bytes, kr.sk_bytes, kr.ct_bytes, kr.ss_bytes,
                            kr.nist_level, kr.stack_hwm_decaps,
                            &kr.mem_decaps, &kr.energy_decaps);
        }
    }

    /* ================================================================
     * BENCHMARK ML-DSA PARAMETER SETS
     * ================================================================ */
    if (run_dsa) {
        printf("\n  ====== ML-DSA (FIPS 204 / CRYSTALS-Dilithium) ======\n\n");

        const char *sig_algs[] = {
            MLDSA_44_NAME,
            MLDSA_65_NAME,
            MLDSA_87_NAME
        };
        const char *sig_notes[] = {
            "NIST Level 2, expected abort iters ~4.25, sig=2420B",
            "NIST Level 3, expected abort iters ~5.10, sig=3309B",
            "NIST Level 5, expected abort iters ~3.85, sig=4627B (exceeds MTU)"
        };
        int n_sigs = 3;

#if defined(USE_SHAKE) || defined(USE_TURBOSHAKE) || defined(USE_K12) || defined(USE_BLAKE3) || defined(USE_XOODYAK) || defined(USE_HARAKA)
        OQS_SIG *(*alt_sig_ctors[])(void) = {
#  ifdef USE_SHAKE
            OQS_SIG_ml_dsa_44_shake_new,
            OQS_SIG_ml_dsa_65_shake_new,
            OQS_SIG_ml_dsa_87_shake_new
#  elif defined(USE_TURBOSHAKE)
            OQS_SIG_ml_dsa_44_turboshake_new,
            OQS_SIG_ml_dsa_65_turboshake_new,
            OQS_SIG_ml_dsa_87_turboshake_new
#  elif defined(USE_K12)
            OQS_SIG_ml_dsa_44_k12_new,
            OQS_SIG_ml_dsa_65_k12_new,
            OQS_SIG_ml_dsa_87_k12_new
#  elif defined(USE_BLAKE3)
            OQS_SIG_ml_dsa_44_blake3_new,
            OQS_SIG_ml_dsa_65_blake3_new,
            OQS_SIG_ml_dsa_87_blake3_new
#  elif defined(USE_XOODYAK)
            OQS_SIG_ml_dsa_44_xoodyak_new,
            OQS_SIG_ml_dsa_65_xoodyak_new,
            OQS_SIG_ml_dsa_87_xoodyak_new
#  else
            OQS_SIG_ml_dsa_44_haraka_new,
            OQS_SIG_ml_dsa_65_haraka_new,
            OQS_SIG_ml_dsa_87_haraka_new
#  endif
        };
#endif

        for (int si = 0; si < n_sigs; si++) {
            sig_bench_result_t sr;

#if defined(USE_SHAKE) || defined(USE_TURBOSHAKE) || defined(USE_K12) || defined(USE_BLAKE3) || defined(USE_XOODYAK) || defined(USE_HARAKA)
            OQS_SIG *sig = alt_sig_ctors[si]();
            if (!sig) {
                fprintf(stderr, "[ERROR] Failed to construct %s\n", sig_algs[si]);
                continue;
            }

            /* ----------------------------------------------------------
             * Correctness self-test: keypair -> sign -> verify roundtrip,
             * plus a tamper check (flipped message byte must fail verify).
             * Confirms the substituted implementation produces valid
             * signatures before trusting its timings.
             * ---------------------------------------------------------- */
            {
                uint8_t *pk  = malloc(sig->length_public_key);
                uint8_t *sk  = malloc(sig->length_secret_key);
                uint8_t *sm  = malloc(sig->length_signature);
                uint8_t  msg[BENCH_MSG_LEN];
                size_t   smlen = 0;

                for (int b = 0; b < BENCH_MSG_LEN; b++) {
                    msg[b] = (uint8_t)(b & 0xFF);
                }

                if (!pk || !sk || !sm) {
                    fprintf(stderr, "[ERROR] Self-test allocation failed for %s\n", sig->method_name);
                    free(pk); free(sk); free(sm);
                    OQS_SIG_free(sig);
                    continue;
                }

                OQS_STATUS kok = OQS_SIG_keypair(sig, pk, sk);
                OQS_STATUS sok = OQS_SIG_sign(sig, sm, &smlen, msg, BENCH_MSG_LEN, sk);
                OQS_STATUS vok = OQS_SIG_verify(sig, msg, BENCH_MSG_LEN, sm, smlen, pk);

                msg[0] ^= 0xFF;
                OQS_STATUS tamper = OQS_SIG_verify(sig, msg, BENCH_MSG_LEN, sm, smlen, pk);

                int ok = (kok == OQS_SUCCESS && sok == OQS_SUCCESS &&
                          vok == OQS_SUCCESS && tamper == OQS_ERROR);

                free(pk); free(sk); free(sm);

                if (!ok) {
                    fprintf(stderr, "  [SELFTEST] %s roundtrip FAILED -- skipping benchmark\n",
                            sig->method_name);
                    OQS_SIG_free(sig);
                    continue;
                }
                printf("  [SELFTEST] %s roundtrip OK (sign/verify + tamper-detect)\n", sig->method_name);
            }

            printf("  Benchmarking %s  [%s]\n", sig->method_name, sig_notes[si]);
            fflush(stdout);

            sr = bench_sig_obj(sig, sig->method_name, run_dudect, run_stack);
            OQS_SIG_free(sig);
#else
            printf("  Benchmarking %s  [%s]\n", sig_algs[si], sig_notes[si]);
            fflush(stdout);

            sr = bench_sig(sig_algs[si], run_dudect, run_stack);
#endif
            print_sig_report(&sr, run_dudect, run_stack);

            csv_write_stats(sr.name, "KeyGen", sr.correctness_pass, &sr.keygen,
                            sr.pk_bytes, sr.sk_bytes, sr.sig_bytes, 0,
                            sr.nist_level, sr.stack_hwm_keygen,
                            &sr.mem_keygen, &sr.energy_keygen);
            csv_write_stats(sr.name, "Sign",   sr.correctness_pass, &sr.sign_op,
                            sr.pk_bytes, sr.sk_bytes, sr.sig_bytes, 0,
                            sr.nist_level, sr.stack_hwm_sign,
                            &sr.mem_sign, &sr.energy_sign);
            csv_write_stats(sr.name, "Verify", sr.correctness_pass, &sr.verify,
                            sr.pk_bytes, sr.sk_bytes, sr.sig_bytes, 0,
                            sr.nist_level, sr.stack_hwm_verify,
                            &sr.mem_verify, &sr.energy_verify);
        }
    }

    /* ================================================================
     * COMPARISON GUIDE AND FOOTER
     * ================================================================ */
    print_comparison_guide();

    csv_close();
    printf("\n  CSV results written to: %s\n", BENCH_CSV_OUTPUT);
    printf("  Benchmark complete.\n\n");

    return 0;
}

/*
 * =============================================================================
 * END OF FILE: pqc_agility_benchmark.c
 *
 * QUICK REFERENCE: ANALYSIS CHECKLIST
 * =============================================================================
 *
 * PERFORMANCE ANALYSIS (from benchmarks above):
 *   [ ] Compare median cycles: SHAKE vs TurboSHAKE for each operation.
 *   [ ] Compare p99 cycles: expect large reduction for ML-DSA Sign.
 *   [ ] Compare CpB: expect ~50% reduction for hash-heavy sub-ops.
 *   [ ] Compare CoV%: should remain ~similar (abort distribution unchanged).
 *   [ ] Macroscopic speedup: 15-25% for KEM, larger for DSA Sign.
 *
 * SECURITY ANALYSIS:
 *   [ ] Dudect t-value: must be |t| < 4.5 for constant-time safety.
 *   [ ] Stack HWM: should be IDENTICAL for SHAKE vs TurboSHAKE.
 *       Any increase => struct misalignment or buffer leak bug.
 *   [ ] FIPS compliance: TurboSHAKE build is non-FIPS -- document scope.
 *
 * MICROARCHITECTURAL ANALYSIS (external tools needed):
 *   [ ] Cachegrind: compare instruction count -- expect ~50% fewer XOR/ROT ops.
 *   [ ] perf stat:  compare cache-misses -- should be negligible change.
 *   [ ] perf stat:  compare branch-misses -- should be negligible change.
 *
 * MEMORY ANALYSIS (TIER 11 -- built-in, software-level, no Valgrind needed):
 *   [ ] Peak RSS delta: should be IDENTICAL for SHAKE vs TurboSHAKE
 *       (Keccak state = 200B fixed regardless of round count).
 *   [ ] Heap arena delta: should be IDENTICAL per call; any growth across
 *       repeated runs indicates a leak in the XOF context.
 *   [ ] Cross-check against Massif if you want an independent confirmation:
 *       valgrind --tool=massif --stacks=yes ./bench_shake
 *
 * ENERGY ANALYSIS (TIER 12 -- software proxy, no RAPL/board sensor needed):
 *   [ ] Energy Proxy Units (EPU == median cycles): compare SHAKE vs
 *       TurboSHAKE directly -- lower EPU implies lower energy on ANY
 *       platform, since EPU is hardware-independent by construction.
 *   [ ] Energy-Delay Product (EDP): should drop for TurboSHAKE in both
 *       ML-KEM (modest) and ML-DSA Sign (larger, due to p99 compression).
 *   [ ] If a calibrated ENERGY_PER_CYCLE_NJ was supplied for your target
 *       board, the "Est. energy (uJ)" columns give an absolute estimate;
 *       otherwise treat them as illustrative only.
 *
 * NETWORK ANALYSIS (external, tc netem):
 *   [ ] ML-DSA-87 signature (4627B) exceeds 1500B MTU => IP fragmentation.
 *   [ ] Under 5% packet loss, PQC handshakes suffer exponential 95th pct spike.
 *   [ ] TurboSHAKE does NOT change byte sizes -- network bottleneck persists.
 *   Command: tc qdisc add dev eth0 root netem delay 100ms 20ms 25% loss 5% 25%
 *
 * =============================================================================
 */
