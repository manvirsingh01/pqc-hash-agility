/*
 * full_bench.c  —  Comprehensive correctness + performance test for all
 *                  PQC algorithms × all hash backends.
 *
 * Backends:
 *   shake      PQClean fork     (FIPS SHAKE / SHA3, symmetric-shake.c —
 *                                hash-substitution BASELINE, compiled
 *                                identically to the five backends below)
 *   turboshake PQClean fork     (TurboSHAKE128/256, n_r=12)
 *   k12        PQClean fork     (KangarooTwelve)
 *   blake3     PQClean fork     (BLAKE3 XOF)
 *   xoodyak    PQClean fork     (Xoodyak / Xoodoo[12])
 *   haraka     PQClean fork     (Haraka-256/512 AES)
 *   liboqs-ref liboqs built-in  (separately engineered ML-KEM/ML-DSA —
 *                                "production reference" series, not part
 *                                of the hash-substitution comparison)
 *
 * Algorithms:
 *   ML-KEM-512 / 768 / 1024   (KEM: keygen, encaps, decaps)
 *   ML-DSA-44  / 65  / 87     (SIG: keygen, sign, verify)
 *
 * Output:  full_benchmark_results.csv
 *
 * Build:   see Makefile in the same directory.
 * Usage:   ./full_bench [--iters N] [--csv PATH] [--no-haraka]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include <oqs/oqs.h>

#include "pqc_shake_kem.h"
#include "pqc_shake_dsa.h"
#include "pqc_turboshake_kem.h"
#include "pqc_turboshake_dsa.h"
#include "pqc_k12_kem.h"
#include "pqc_k12_dsa.h"
#include "pqc_blake3_kem.h"
#include "pqc_blake3_dsa.h"
#include "pqc_xoodyak_kem.h"
#include "pqc_xoodyak_dsa.h"
#include "pqc_haraka_kem.h"
#include "pqc_haraka_dsa.h"

/* ------------------------------------------------------------------ */
/* Timing                                                               */
/* ------------------------------------------------------------------ */

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
    uint64_t mean_ns;
    uint64_t median_ns;
    uint64_t min_ns;
    uint64_t max_ns;
    uint64_t stddev_ns;
    uint64_t p95_ns;
    uint64_t p99_ns;
    uint64_t trimmed_mean_ns;   /* mean of middle 95% — outlier-robust */
    double   ops_per_sec;
    int      n;
} Stats;

static Stats compute_stats(uint64_t *samples, int n) {
    Stats s = {0};
    s.n = n;
    qsort(samples, (size_t)n, sizeof(uint64_t), cmp_u64);
    s.min_ns    = samples[0];
    s.max_ns    = samples[n - 1];
    s.median_ns = (n & 1) ? samples[n / 2] : (samples[n/2 - 1] + samples[n/2]) / 2;
    s.p95_ns    = samples[(int)((n - 1) * 0.95)];
    s.p99_ns    = samples[(int)((n - 1) * 0.99)];

    double sum = 0.0, sum2 = 0.0;
    for (int i = 0; i < n; i++) { double v = (double)samples[i]; sum += v; sum2 += v * v; }
    s.mean_ns    = (uint64_t)(sum / n);
    double var   = sum2 / n - (sum / n) * (sum / n);
    s.stddev_ns  = (uint64_t)sqrt(var < 0 ? 0 : var);
    s.ops_per_sec = (s.mean_ns > 0) ? 1e9 / (double)s.mean_ns : 0.0;

    /* Trimmed mean: drop lowest/highest 2.5% so a few scheduler or SMI
     * outliers cannot skew the average (raw max/p99 still show the tail). */
    {
        int lo = (int)(n * 0.025), hi = n - lo;
        if (hi <= lo) { lo = 0; hi = n; }
        double tsum = 0.0;
        for (int i = lo; i < hi; i++) tsum += (double)samples[i];
        s.trimmed_mean_ns = (uint64_t)(tsum / (double)(hi - lo));
    }
    return s;
}

/* ------------------------------------------------------------------ */
/* Raw memory (RSS/heap via /proc) + energy (Intel RAPL) probes         */
/* ------------------------------------------------------------------ */

static long rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[128]; long v = -1;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "VmRSS: %ld kB", &v) == 1) break;
    fclose(f);
    return v;
}

static double rapl_uj(void) {
    static int fd = -2;
    if (fd == -2)
        fd = open("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj",
                  O_RDONLY);
    if (fd < 0) return -1.0;
    char buf[32];
    memset(buf, 0, sizeof(buf));
    ssize_t r = pread(fd, buf, sizeof(buf) - 1, 0);
    if (r <= 0) return -1.0;
    return strtod(buf, NULL);
}

typedef struct {
    long   rss_before_kb, rss_after_kb;
    double rapl_before_uj, rapl_after_uj;
    double rapl_total_uj, rapl_per_op_uj;
    int    rapl_measured;
} Probe;

/* Call rss_kb()/rapl_uj() right before the timed loop, then this right
 * after it, to capture raw before/after counters plus derived per-op uJ. */
static Probe probe_finish(long rss_b, double rapl_b, int iters) {
    Probe p;
    memset(&p, 0, sizeof(p));
    p.rss_before_kb  = rss_b;
    p.rss_after_kb   = rss_kb();
    p.rapl_before_uj = rapl_b;
    p.rapl_after_uj  = rapl_uj();
    if (rapl_b >= 0.0 && p.rapl_after_uj > rapl_b && iters > 0) {
        p.rapl_total_uj  = p.rapl_after_uj - rapl_b;
        p.rapl_per_op_uj = p.rapl_total_uj / (double)iters;
        p.rapl_measured  = 1;
    }
    return p;
}

/* ------------------------------------------------------------------ */
/* Per-iteration raw sample dump                                        */
/* When PQC_RAW_DIR is set, every timed sample is appended to           */
/* $PQC_RAW_DIR/<PQC_RAW_TAG|full_bench>_raw.csv (one row per           */
/* iteration) before compute_stats() sorts the array.                   */
/* ------------------------------------------------------------------ */

static FILE *g_raw = NULL;

static void raw_init(void) {
    const char *dir = getenv("PQC_RAW_DIR");
    if (!dir || !*dir) return;
    const char *tag = getenv("PQC_RAW_TAG");
    if (!tag || !*tag) tag = "full_bench";
    char path[768];
    snprintf(path, sizeof(path), "%s/%s_raw.csv", dir, tag);
    FILE *probe = fopen(path, "r");
    int fresh = (probe == NULL);
    if (probe) fclose(probe);
    g_raw = fopen(path, "a");
    if (!g_raw) { perror(path); return; }
    if (fresh)
        fprintf(g_raw, "backend,algorithm,operation,iteration,sample,unit\n");
    printf("Raw samples: %s (per-iteration)\n", path);
}

static void raw_dump(const char *backend, const char *algo, const char *op,
                     const uint64_t *samples, int n) {
    if (!g_raw) return;
    for (int i = 0; i < n; i++)
        fprintf(g_raw, "%s,%s,%s,%d,%" PRIu64 ",ns\n",
                backend, algo, op, i + 1, samples[i]);
    fflush(g_raw);
}

static void raw_close(void) { if (g_raw) { fclose(g_raw); g_raw = NULL; } }

/* ------------------------------------------------------------------ */
/* CSV output                                                           */
/* ------------------------------------------------------------------ */

static FILE *g_csv = NULL;

static void csv_header(void) {
    fprintf(g_csv,
        "backend,algorithm,operation,"
        "correctness,"
        "iterations,"
        "mean_ns,median_ns,min_ns,max_ns,stddev_ns,"
        "p95_ns,p99_ns,trimmed_mean_ns,"
        "ops_per_sec,"
        "pk_bytes,sk_bytes,ct_or_sig_bytes,ss_bytes,"
        "nist_level,"
        "rss_before_kb,rss_after_kb,"
        "rapl_before_uj,rapl_after_uj,rapl_total_uj,"
        "rapl_energy_per_op_uj,rapl_measured\n");
}

static void csv_row(const char *backend, const char *algo, const char *op,
                    const char *correct, Stats st, Probe pr,
                    size_t pk, size_t sk, size_t ct_sig, size_t ss,
                    int nist) {
    fprintf(g_csv,
        "%s,%s,%s,"
        "%s,"
        "%d,"
        "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64","
        "%"PRIu64",%"PRIu64",%"PRIu64","
        "%.2f,"
        "%zu,%zu,%zu,%zu,"
        "%d,"
        "%ld,%ld,"
        "%.2f,%.2f,%.2f,"
        "%.4f,%d\n",
        backend, algo, op,
        correct,
        st.n,
        st.mean_ns, st.median_ns, st.min_ns, st.max_ns, st.stddev_ns,
        st.p95_ns, st.p99_ns, st.trimmed_mean_ns,
        st.ops_per_sec,
        pk, sk, ct_sig, ss,
        nist,
        pr.rss_before_kb, pr.rss_after_kb,
        pr.rapl_before_uj, pr.rapl_after_uj, pr.rapl_total_uj,
        pr.rapl_per_op_uj, pr.rapl_measured);
    fflush(g_csv);
}

/* ------------------------------------------------------------------ */
/* KEM: correctness + benchmark                                         */
/* ------------------------------------------------------------------ */

static void bench_kem(OQS_KEM *kem, const char *backend, int iters,
                      int warmup, const char *algo_name) {
    if (!kem) {
        fprintf(stderr, "  [SKIP] %s / %s  (kem constructor returned NULL)\n",
                backend, algo_name);
        return;
    }

    uint8_t *pk  = OQS_MEM_malloc(kem->length_public_key);
    uint8_t *sk  = OQS_MEM_malloc(kem->length_secret_key);
    uint8_t *ct  = OQS_MEM_malloc(kem->length_ciphertext);
    uint8_t *ss1 = OQS_MEM_malloc(kem->length_shared_secret);
    uint8_t *ss2 = OQS_MEM_malloc(kem->length_shared_secret);
    uint64_t *ts = OQS_MEM_malloc(sizeof(uint64_t) * (size_t)iters);

    if (!pk || !sk || !ct || !ss1 || !ss2 || !ts) {
        fprintf(stderr, "malloc failed for %s/%s\n", backend, algo_name);
        goto cleanup;
    }

    /* --- correctness test --- */
    const char *correct = "FAIL";
    if (OQS_KEM_keypair(kem, pk, sk) == OQS_SUCCESS &&
        OQS_KEM_encaps(kem, ct, ss1, pk) == OQS_SUCCESS &&
        OQS_KEM_decaps(kem, ss2, ct, sk) == OQS_SUCCESS &&
        memcmp(ss1, ss2, kem->length_shared_secret) == 0) {
        correct = "PASS";
    }
    printf("  %-12s %-14s correctness: %s\n", backend, algo_name, correct);

    size_t pk_b  = kem->length_public_key;
    size_t sk_b  = kem->length_secret_key;
    size_t ct_b  = kem->length_ciphertext;
    size_t ss_b  = kem->length_shared_secret;
    int    nist  = kem->claimed_nist_level;

    /* --- warmup --- */
    for (int i = 0; i < warmup; i++) {
        OQS_KEM_keypair(kem, pk, sk);
        OQS_KEM_encaps(kem, ct, ss1, pk);
        OQS_KEM_decaps(kem, ss2, ct, sk);
    }

    long   rss_b;
    double rapl_b;

    /* keygen */
    rss_b = rss_kb(); rapl_b = rapl_uj();
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        OQS_KEM_keypair(kem, pk, sk);
        ts[i] = now_ns() - t0;
    }
    raw_dump(backend, algo_name, "keygen", ts, iters);
    csv_row(backend, algo_name, "keygen", correct,
            compute_stats(ts, iters), probe_finish(rss_b, rapl_b, iters),
            pk_b, sk_b, ct_b, ss_b, nist);

    /* encaps */
    OQS_KEM_keypair(kem, pk, sk);
    rss_b = rss_kb(); rapl_b = rapl_uj();
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        OQS_KEM_encaps(kem, ct, ss1, pk);
        ts[i] = now_ns() - t0;
    }
    raw_dump(backend, algo_name, "encaps", ts, iters);
    csv_row(backend, algo_name, "encaps", correct,
            compute_stats(ts, iters), probe_finish(rss_b, rapl_b, iters),
            pk_b, sk_b, ct_b, ss_b, nist);

    /* decaps */
    OQS_KEM_encaps(kem, ct, ss1, pk);
    rss_b = rss_kb(); rapl_b = rapl_uj();
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        OQS_KEM_decaps(kem, ss2, ct, sk);
        ts[i] = now_ns() - t0;
    }
    raw_dump(backend, algo_name, "decaps", ts, iters);
    csv_row(backend, algo_name, "decaps", correct,
            compute_stats(ts, iters), probe_finish(rss_b, rapl_b, iters),
            pk_b, sk_b, ct_b, ss_b, nist);

cleanup:
    OQS_MEM_insecure_free(pk);
    OQS_MEM_insecure_free(sk);
    OQS_MEM_insecure_free(ct);
    OQS_MEM_insecure_free(ss1);
    OQS_MEM_insecure_free(ss2);
    OQS_MEM_insecure_free(ts);
    OQS_KEM_free(kem);
}

/* ------------------------------------------------------------------ */
/* SIG: correctness + benchmark                                         */
/* ------------------------------------------------------------------ */

#define MSG_LEN 32

static void bench_sig(OQS_SIG *sig, const char *backend, int iters,
                      int warmup, const char *algo_name) {
    if (!sig) {
        fprintf(stderr, "  [SKIP] %s / %s  (sig constructor returned NULL)\n",
                backend, algo_name);
        return;
    }

    uint8_t *pk      = OQS_MEM_malloc(sig->length_public_key);
    uint8_t *sk      = OQS_MEM_malloc(sig->length_secret_key);
    uint8_t *sigbuf  = OQS_MEM_malloc(sig->length_signature);
    uint8_t  msg[MSG_LEN];
    uint64_t *ts     = OQS_MEM_malloc(sizeof(uint64_t) * (size_t)iters);
    size_t   siglen  = 0;

    if (!pk || !sk || !sigbuf || !ts) {
        fprintf(stderr, "malloc failed for %s/%s\n", backend, algo_name);
        goto cleanup;
    }
    OQS_randombytes(msg, MSG_LEN);

    /* --- correctness test --- */
    const char *correct = "FAIL";
    if (OQS_SIG_keypair(sig, pk, sk) == OQS_SUCCESS &&
        OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk) == OQS_SUCCESS &&
        OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk) == OQS_SUCCESS) {
        correct = "PASS";
    }
    printf("  %-12s %-14s correctness: %s\n", backend, algo_name, correct);

    size_t pk_b  = sig->length_public_key;
    size_t sk_b  = sig->length_secret_key;
    size_t sg_b  = sig->length_signature;
    int    nist  = sig->claimed_nist_level;

    /* --- warmup --- */
    for (int i = 0; i < warmup; i++) {
        OQS_SIG_keypair(sig, pk, sk);
        OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk);
        OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk);
    }

    long   rss_b;
    double rapl_b;

    /* keygen */
    rss_b = rss_kb(); rapl_b = rapl_uj();
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        OQS_SIG_keypair(sig, pk, sk);
        ts[i] = now_ns() - t0;
    }
    raw_dump(backend, algo_name, "keygen", ts, iters);
    csv_row(backend, algo_name, "keygen", correct,
            compute_stats(ts, iters), probe_finish(rss_b, rapl_b, iters),
            pk_b, sk_b, sg_b, 0, nist);

    /* sign */
    OQS_SIG_keypair(sig, pk, sk);
    rss_b = rss_kb(); rapl_b = rapl_uj();
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk);
        ts[i] = now_ns() - t0;
    }
    raw_dump(backend, algo_name, "sign", ts, iters);
    csv_row(backend, algo_name, "sign", correct,
            compute_stats(ts, iters), probe_finish(rss_b, rapl_b, iters),
            pk_b, sk_b, sg_b, 0, nist);

    /* verify */
    OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk);
    rss_b = rss_kb(); rapl_b = rapl_uj();
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk);
        ts[i] = now_ns() - t0;
    }
    raw_dump(backend, algo_name, "verify", ts, iters);
    csv_row(backend, algo_name, "verify", correct,
            compute_stats(ts, iters), probe_finish(rss_b, rapl_b, iters),
            pk_b, sk_b, sg_b, 0, nist);

cleanup:
    OQS_MEM_insecure_free(pk);
    OQS_MEM_insecure_free(sk);
    OQS_MEM_insecure_free(sigbuf);
    OQS_MEM_insecure_free(ts);
    OQS_SIG_free(sig);
}

/* ------------------------------------------------------------------ */
/* Main                                                                 */
/* ------------------------------------------------------------------ */

static void usage(const char *prog) {
    printf("Usage: %s [--iters N] [--warmup N] [--csv PATH] [--no-haraka]\n", prog);
    printf("  --iters   N       benchmark iterations per operation (default 1000)\n");
    printf("  --warmup  N       warmup iterations before timing (default 50)\n");
    printf("  --csv     PATH    output CSV file (default full_benchmark_results.csv)\n");
    printf("  --no-haraka       skip Haraka backend\n");
}

int main(int argc, char **argv) {
    int         iters       = 1000;
    int         warmup      = 50;
    const char *csv_path    = "full_benchmark_results.csv";
    int         skip_haraka = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iters")    && i+1 < argc) { iters       = atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--warmup")   && i+1 < argc) { warmup      = atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--csv")      && i+1 < argc) { csv_path    = argv[++i]; }
        else if (!strcmp(argv[i], "--no-haraka"))              { skip_haraka = 1; }
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "Unknown arg: %s\n", argv[i]); usage(argv[0]); return 1; }
    }

    OQS_init();

    g_csv = fopen(csv_path, "w");
    if (!g_csv) { perror(csv_path); return 1; }
    csv_header();
    raw_init();

    printf("=== PQC Full Benchmark ===\n");
    printf("Iterations: %d   Warmup: %d   CSV: %s\n\n", iters, warmup, csv_path);

    /* ----------------------------------------------------------------
     * SHAKE baseline — PQClean fork, symmetric-shake.c compiled
     * identically to the five substituted backends. Comparing the
     * backends below against this row isolates the hash function.
     * --------------------------------------------------------------- */
    printf("[Backend: shake  — PQClean fork baseline]\n");
    bench_kem(OQS_KEM_ml_kem_512_shake_new(),   "shake", iters, warmup, "ML-KEM-512");
    bench_kem(OQS_KEM_ml_kem_768_shake_new(),   "shake", iters, warmup, "ML-KEM-768");
    bench_kem(OQS_KEM_ml_kem_1024_shake_new(),  "shake", iters, warmup, "ML-KEM-1024");
    bench_sig(OQS_SIG_ml_dsa_44_shake_new(),    "shake", iters, warmup, "ML-DSA-44");
    bench_sig(OQS_SIG_ml_dsa_65_shake_new(),    "shake", iters, warmup, "ML-DSA-65");
    bench_sig(OQS_SIG_ml_dsa_87_shake_new(),    "shake", iters, warmup, "ML-DSA-87");

    /* ----------------------------------------------------------------
     * TurboSHAKE
     * --------------------------------------------------------------- */
    printf("\n[Backend: turboshake]\n");
    bench_kem(OQS_KEM_ml_kem_512_turboshake_new(),   "turboshake", iters, warmup, "ML-KEM-512");
    bench_kem(OQS_KEM_ml_kem_768_turboshake_new(),   "turboshake", iters, warmup, "ML-KEM-768");
    bench_kem(OQS_KEM_ml_kem_1024_turboshake_new(),  "turboshake", iters, warmup, "ML-KEM-1024");
    bench_sig(OQS_SIG_ml_dsa_44_turboshake_new(),    "turboshake", iters, warmup, "ML-DSA-44");
    bench_sig(OQS_SIG_ml_dsa_65_turboshake_new(),    "turboshake", iters, warmup, "ML-DSA-65");
    bench_sig(OQS_SIG_ml_dsa_87_turboshake_new(),    "turboshake", iters, warmup, "ML-DSA-87");

    /* ----------------------------------------------------------------
     * KangarooTwelve (K12)
     * --------------------------------------------------------------- */
    printf("\n[Backend: k12]\n");
    bench_kem(OQS_KEM_ml_kem_512_k12_new(),          "k12", iters, warmup, "ML-KEM-512");
    bench_kem(OQS_KEM_ml_kem_768_k12_new(),          "k12", iters, warmup, "ML-KEM-768");
    bench_kem(OQS_KEM_ml_kem_1024_k12_new(),         "k12", iters, warmup, "ML-KEM-1024");
    bench_sig(OQS_SIG_ml_dsa_44_k12_new(),           "k12", iters, warmup, "ML-DSA-44");
    bench_sig(OQS_SIG_ml_dsa_65_k12_new(),           "k12", iters, warmup, "ML-DSA-65");
    bench_sig(OQS_SIG_ml_dsa_87_k12_new(),           "k12", iters, warmup, "ML-DSA-87");

    /* ----------------------------------------------------------------
     * BLAKE3
     * --------------------------------------------------------------- */
    printf("\n[Backend: blake3]\n");
    bench_kem(OQS_KEM_ml_kem_512_blake3_new(),       "blake3", iters, warmup, "ML-KEM-512");
    bench_kem(OQS_KEM_ml_kem_768_blake3_new(),       "blake3", iters, warmup, "ML-KEM-768");
    bench_kem(OQS_KEM_ml_kem_1024_blake3_new(),      "blake3", iters, warmup, "ML-KEM-1024");
    bench_sig(OQS_SIG_ml_dsa_44_blake3_new(),        "blake3", iters, warmup, "ML-DSA-44");
    bench_sig(OQS_SIG_ml_dsa_65_blake3_new(),        "blake3", iters, warmup, "ML-DSA-65");
    bench_sig(OQS_SIG_ml_dsa_87_blake3_new(),        "blake3", iters, warmup, "ML-DSA-87");

    /* ----------------------------------------------------------------
     * Xoodyak
     * --------------------------------------------------------------- */
    printf("\n[Backend: xoodyak]\n");
    bench_kem(OQS_KEM_ml_kem_512_xoodyak_new(),      "xoodyak", iters, warmup, "ML-KEM-512");
    bench_kem(OQS_KEM_ml_kem_768_xoodyak_new(),      "xoodyak", iters, warmup, "ML-KEM-768");
    bench_kem(OQS_KEM_ml_kem_1024_xoodyak_new(),     "xoodyak", iters, warmup, "ML-KEM-1024");
    bench_sig(OQS_SIG_ml_dsa_44_xoodyak_new(),       "xoodyak", iters, warmup, "ML-DSA-44");
    bench_sig(OQS_SIG_ml_dsa_65_xoodyak_new(),       "xoodyak", iters, warmup, "ML-DSA-65");
    bench_sig(OQS_SIG_ml_dsa_87_xoodyak_new(),       "xoodyak", iters, warmup, "ML-DSA-87");

    /* ----------------------------------------------------------------
     * Haraka  (AES-based; skip if --no-haraka)
     * --------------------------------------------------------------- */
    if (!skip_haraka) {
        printf("\n[Backend: haraka]\n");
        bench_kem(OQS_KEM_ml_kem_512_haraka_new(),   "haraka", iters, warmup, "ML-KEM-512");
        bench_kem(OQS_KEM_ml_kem_768_haraka_new(),   "haraka", iters, warmup, "ML-KEM-768");
        bench_kem(OQS_KEM_ml_kem_1024_haraka_new(),  "haraka", iters, warmup, "ML-KEM-1024");
        bench_sig(OQS_SIG_ml_dsa_44_haraka_new(),    "haraka", iters, warmup, "ML-DSA-44");
        bench_sig(OQS_SIG_ml_dsa_65_haraka_new(),    "haraka", iters, warmup, "ML-DSA-65");
        bench_sig(OQS_SIG_ml_dsa_87_haraka_new(),    "haraka", iters, warmup, "ML-DSA-87");
    } else {
        printf("\n[Backend: haraka  — SKIPPED (--no-haraka)]\n");
    }

    /* ----------------------------------------------------------------
     * liboqs production reference — liboqs's own ML-KEM/ML-DSA (same
     * FIPS SHAKE, different engineering). Separate series; NOT the
     * hash-substitution baseline.
     * --------------------------------------------------------------- */
    printf("\n[Backend: liboqs-ref  — liboqs built-in, production reference]\n");
    bench_kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_512),  "liboqs-ref", iters, warmup, "ML-KEM-512");
    bench_kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_768),  "liboqs-ref", iters, warmup, "ML-KEM-768");
    bench_kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_1024), "liboqs-ref", iters, warmup, "ML-KEM-1024");
    bench_sig(OQS_SIG_new(OQS_SIG_alg_ml_dsa_44),   "liboqs-ref", iters, warmup, "ML-DSA-44");
    bench_sig(OQS_SIG_new(OQS_SIG_alg_ml_dsa_65),   "liboqs-ref", iters, warmup, "ML-DSA-65");
    bench_sig(OQS_SIG_new(OQS_SIG_alg_ml_dsa_87),   "liboqs-ref", iters, warmup, "ML-DSA-87");

    fclose(g_csv);
    raw_close();
    OQS_destroy();

    printf("\n=== Done. Results written to: %s ===\n", csv_path);
    return 0;
}
