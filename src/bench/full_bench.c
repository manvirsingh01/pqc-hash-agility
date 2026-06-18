/*
 * full_bench.c  —  Comprehensive correctness + performance test for all
 *                  PQC algorithms × all hash backends.
 *
 * Backends:
 *   shake      liboqs built-in  (standard FIPS SHAKE / SHA3)
 *   turboshake PQClean fork     (TurboSHAKE128/256, n_r=12)
 *   k12        PQClean fork     (KangarooTwelve)
 *   blake3     PQClean fork     (BLAKE3 XOF)
 *   xoodyak    PQClean fork     (Xoodyak / Xoodoo[12])
 *   haraka     PQClean fork     (Haraka-256/512 AES)
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

#include <oqs/oqs.h>

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

    double sum = 0.0, sum2 = 0.0;
    for (int i = 0; i < n; i++) { double v = (double)samples[i]; sum += v; sum2 += v * v; }
    s.mean_ns    = (uint64_t)(sum / n);
    double var   = sum2 / n - (sum / n) * (sum / n);
    s.stddev_ns  = (uint64_t)sqrt(var < 0 ? 0 : var);
    s.ops_per_sec = (s.mean_ns > 0) ? 1e9 / (double)s.mean_ns : 0.0;
    return s;
}

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
        "ops_per_sec,"
        "pk_bytes,sk_bytes,ct_or_sig_bytes,ss_bytes,"
        "nist_level\n");
}

static void csv_row(const char *backend, const char *algo, const char *op,
                    const char *correct, Stats st,
                    size_t pk, size_t sk, size_t ct_sig, size_t ss,
                    int nist) {
    fprintf(g_csv,
        "%s,%s,%s,"
        "%s,"
        "%d,"
        "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64","
        "%.2f,"
        "%zu,%zu,%zu,%zu,"
        "%d\n",
        backend, algo, op,
        correct,
        st.n,
        st.mean_ns, st.median_ns, st.min_ns, st.max_ns, st.stddev_ns,
        st.ops_per_sec,
        pk, sk, ct_sig, ss,
        nist);
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

    /* keygen */
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        OQS_KEM_keypair(kem, pk, sk);
        ts[i] = now_ns() - t0;
    }
    csv_row(backend, algo_name, "keygen", correct,
            compute_stats(ts, iters), pk_b, sk_b, ct_b, ss_b, nist);

    /* encaps */
    OQS_KEM_keypair(kem, pk, sk);
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        OQS_KEM_encaps(kem, ct, ss1, pk);
        ts[i] = now_ns() - t0;
    }
    csv_row(backend, algo_name, "encaps", correct,
            compute_stats(ts, iters), pk_b, sk_b, ct_b, ss_b, nist);

    /* decaps */
    OQS_KEM_encaps(kem, ct, ss1, pk);
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        OQS_KEM_decaps(kem, ss2, ct, sk);
        ts[i] = now_ns() - t0;
    }
    csv_row(backend, algo_name, "decaps", correct,
            compute_stats(ts, iters), pk_b, sk_b, ct_b, ss_b, nist);

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

    /* keygen */
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        OQS_SIG_keypair(sig, pk, sk);
        ts[i] = now_ns() - t0;
    }
    csv_row(backend, algo_name, "keygen", correct,
            compute_stats(ts, iters), pk_b, sk_b, sg_b, 0, nist);

    /* sign */
    OQS_SIG_keypair(sig, pk, sk);
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk);
        ts[i] = now_ns() - t0;
    }
    csv_row(backend, algo_name, "sign", correct,
            compute_stats(ts, iters), pk_b, sk_b, sg_b, 0, nist);

    /* verify */
    OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk);
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk);
        ts[i] = now_ns() - t0;
    }
    csv_row(backend, algo_name, "verify", correct,
            compute_stats(ts, iters), pk_b, sk_b, sg_b, 0, nist);

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

    printf("=== PQC Full Benchmark ===\n");
    printf("Iterations: %d   Warmup: %d   CSV: %s\n\n", iters, warmup, csv_path);

    /* ----------------------------------------------------------------
     * SHAKE baseline — liboqs built-in implementations
     * --------------------------------------------------------------- */
    printf("[Backend: shake  — liboqs built-in]\n");
    bench_kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_512),  "shake", iters, warmup, "ML-KEM-512");
    bench_kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_768),  "shake", iters, warmup, "ML-KEM-768");
    bench_kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_1024), "shake", iters, warmup, "ML-KEM-1024");
    bench_sig(OQS_SIG_new(OQS_SIG_alg_ml_dsa_44),   "shake", iters, warmup, "ML-DSA-44");
    bench_sig(OQS_SIG_new(OQS_SIG_alg_ml_dsa_65),   "shake", iters, warmup, "ML-DSA-65");
    bench_sig(OQS_SIG_new(OQS_SIG_alg_ml_dsa_87),   "shake", iters, warmup, "ML-DSA-87");

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

    fclose(g_csv);
    OQS_destroy();

    printf("\n=== Done. Results written to: %s ===\n", csv_path);
    return 0;
}
