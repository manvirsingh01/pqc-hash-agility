/*
 * pure_backends_bench.c — Pure-style benchmark of the six hash backends
 * inside ML-KEM and ML-DSA.
 *
 * Measures the project's six hash-substituted PQClean forks (shake baseline,
 * turboshake, k12, blake3, xoodyak, haraka) with the SAME simple methodology
 * as pure_bench.c: plain CLOCK_MONOTONIC wall-clock timing, one warmup pass,
 * one timed loop. No cycle counters, no mlockall, no RT scheduling inside the
 * binary, no timing-overhead subtraction — the raw measurement of the
 * implementations exactly as they were built. Nothing about the algorithms,
 * their parameters, or the library build flags is changed here.
 *
 * One binary is built per backend (like bench_<tag>):
 *   gcc -O3 -march=native -DUSE_<TAG> -I <oqs-include> -I <build-root> \
 *       -c pure_backends_bench.c
 * then linked against the SAME pre-built objects and static libs that
 * bench_<tag> uses (pqc_<tag>_kem.o, pqc_<tag>_dsa.o, the forked PQClean
 * libs, fips202_turbo.o, randombytes_turbo.o, the backend hash lib, liboqs).
 *
 * Algorithms (per backend):
 *   ML-KEM-512, ML-KEM-768, ML-KEM-1024          (FIPS 203)
 *   ML-DSA-44, ML-DSA-65, ML-DSA-87              (FIPS 204)
 *
 * Each algorithm gets:
 *   - Correctness self-test (round-trip + tamper detection)
 *   - Timing: keygen, encaps/sign, decaps/verify
 *   - CSV output with all statistics (appended, so the six per-backend
 *     binaries share one combined CSV)
 *   - Per-iteration raw samples via PQC_RAW_DIR / PQC_RAW_TAG
 *
 * Usage:
 *   ./pure_bench_<tag> [--iters N] [--warmup N] [--csv PATH]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <time.h>

#include <oqs/oqs.h>

#if defined(USE_SHAKE)
#  define BACKEND_SHORT "shake"
#  include "pqc_shake_kem.h"
#  include "pqc_shake_dsa.h"
#  define KEM_512_NEW  OQS_KEM_ml_kem_512_shake_new
#  define KEM_768_NEW  OQS_KEM_ml_kem_768_shake_new
#  define KEM_1024_NEW OQS_KEM_ml_kem_1024_shake_new
#  define SIG_44_NEW   OQS_SIG_ml_dsa_44_shake_new
#  define SIG_65_NEW   OQS_SIG_ml_dsa_65_shake_new
#  define SIG_87_NEW   OQS_SIG_ml_dsa_87_shake_new
#elif defined(USE_TURBOSHAKE)
#  define BACKEND_SHORT "turboshake"
#  include "pqc_turboshake_kem.h"
#  include "pqc_turboshake_dsa.h"
#  define KEM_512_NEW  OQS_KEM_ml_kem_512_turboshake_new
#  define KEM_768_NEW  OQS_KEM_ml_kem_768_turboshake_new
#  define KEM_1024_NEW OQS_KEM_ml_kem_1024_turboshake_new
#  define SIG_44_NEW   OQS_SIG_ml_dsa_44_turboshake_new
#  define SIG_65_NEW   OQS_SIG_ml_dsa_65_turboshake_new
#  define SIG_87_NEW   OQS_SIG_ml_dsa_87_turboshake_new
#elif defined(USE_K12)
#  define BACKEND_SHORT "k12"
#  include "pqc_k12_kem.h"
#  include "pqc_k12_dsa.h"
#  define KEM_512_NEW  OQS_KEM_ml_kem_512_k12_new
#  define KEM_768_NEW  OQS_KEM_ml_kem_768_k12_new
#  define KEM_1024_NEW OQS_KEM_ml_kem_1024_k12_new
#  define SIG_44_NEW   OQS_SIG_ml_dsa_44_k12_new
#  define SIG_65_NEW   OQS_SIG_ml_dsa_65_k12_new
#  define SIG_87_NEW   OQS_SIG_ml_dsa_87_k12_new
#elif defined(USE_BLAKE3)
#  define BACKEND_SHORT "blake3"
#  include "pqc_blake3_kem.h"
#  include "pqc_blake3_dsa.h"
#  define KEM_512_NEW  OQS_KEM_ml_kem_512_blake3_new
#  define KEM_768_NEW  OQS_KEM_ml_kem_768_blake3_new
#  define KEM_1024_NEW OQS_KEM_ml_kem_1024_blake3_new
#  define SIG_44_NEW   OQS_SIG_ml_dsa_44_blake3_new
#  define SIG_65_NEW   OQS_SIG_ml_dsa_65_blake3_new
#  define SIG_87_NEW   OQS_SIG_ml_dsa_87_blake3_new
#elif defined(USE_XOODYAK)
#  define BACKEND_SHORT "xoodyak"
#  include "pqc_xoodyak_kem.h"
#  include "pqc_xoodyak_dsa.h"
#  define KEM_512_NEW  OQS_KEM_ml_kem_512_xoodyak_new
#  define KEM_768_NEW  OQS_KEM_ml_kem_768_xoodyak_new
#  define KEM_1024_NEW OQS_KEM_ml_kem_1024_xoodyak_new
#  define SIG_44_NEW   OQS_SIG_ml_dsa_44_xoodyak_new
#  define SIG_65_NEW   OQS_SIG_ml_dsa_65_xoodyak_new
#  define SIG_87_NEW   OQS_SIG_ml_dsa_87_xoodyak_new
#elif defined(USE_HARAKA)
#  define BACKEND_SHORT "haraka"
#  include "pqc_haraka_kem.h"
#  include "pqc_haraka_dsa.h"
#  define KEM_512_NEW  OQS_KEM_ml_kem_512_haraka_new
#  define KEM_768_NEW  OQS_KEM_ml_kem_768_haraka_new
#  define KEM_1024_NEW OQS_KEM_ml_kem_1024_haraka_new
#  define SIG_44_NEW   OQS_SIG_ml_dsa_44_haraka_new
#  define SIG_65_NEW   OQS_SIG_ml_dsa_65_haraka_new
#  define SIG_87_NEW   OQS_SIG_ml_dsa_87_haraka_new
#else
#  error "Build with -DUSE_<BACKEND> (SHAKE, TURBOSHAKE, K12, BLAKE3, XOODYAK or HARAKA)"
#endif

#define MSG_LEN 256

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
    uint64_t mean_ns, median_ns, min_ns, max_ns, stddev_ns, p95_ns, p99_ns;
    double   ops_per_sec;
    int      n;
} Stats;

static Stats compute_stats(uint64_t *s, int n) {
    Stats r = {0};
    r.n = n;
    qsort(s, (size_t)n, sizeof(uint64_t), cmp_u64);
    r.min_ns    = s[0];
    r.max_ns    = s[n - 1];
    r.median_ns = (n & 1) ? s[n/2] : (s[n/2 - 1] + s[n/2]) / 2;
    r.p95_ns    = s[(int)(n * 0.95)];
    r.p99_ns    = s[(int)(n * 0.99)];
    double sum = 0, sum2 = 0;
    for (int i = 0; i < n; i++) { double v = (double)s[i]; sum += v; sum2 += v * v; }
    r.mean_ns   = (uint64_t)(sum / n);
    double var  = sum2 / n - (sum / n) * (sum / n);
    r.stddev_ns = (uint64_t)sqrt(var < 0 ? 0 : var);
    r.ops_per_sec = r.mean_ns > 0 ? 1e9 / (double)r.mean_ns : 0.0;
    return r;
}

/* Per-iteration raw sample dump: when PQC_RAW_DIR is set, every timed
 * sample is appended to $PQC_RAW_DIR/<PQC_RAW_TAG|pure_backends>_raw.csv
 * (one row per iteration) before compute_stats() sorts the array. */
static FILE *g_raw;

static void raw_init(void) {
    const char *dir = getenv("PQC_RAW_DIR");
    if (!dir || !*dir) return;
    const char *tag = getenv("PQC_RAW_TAG");
    if (!tag || !*tag) tag = "pure_backends";
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

static void raw_dump(const char *algo, const char *op,
                     const uint64_t *samples, int n) {
    if (!g_raw) return;
    for (int i = 0; i < n; i++)
        fprintf(g_raw, "%s,%s,%s,%d,%" PRIu64 ",ns\n",
                BACKEND_SHORT, algo, op, i + 1, samples[i]);
    fflush(g_raw);
}

static void raw_close(void) { if (g_raw) { fclose(g_raw); g_raw = NULL; } }

/* Combined CSV shared by the six per-backend binaries: open in append
 * mode, write the header only when the file is new. */
static FILE *g_csv;

static void csv_open(const char *path) {
    FILE *probe = fopen(path, "r");
    int fresh = (probe == NULL);
    if (probe) fclose(probe);
    g_csv = fopen(path, "a");
    if (!g_csv) { perror(path); exit(1); }
    if (fresh)
        fprintf(g_csv,
            "backend,algorithm,type,operation,"
            "correctness,iterations,"
            "mean_ns,median_ns,min_ns,max_ns,stddev_ns,p95_ns,p99_ns,"
            "ops_per_sec,"
            "pk_bytes,sk_bytes,ct_or_sig_bytes,ss_bytes,"
            "nist_level\n");
}

static void csv_row(const char *algo, const char *type, const char *op,
                    const char *correct, Stats st,
                    size_t pk, size_t sk, size_t ct_sig, size_t ss, int nist) {
    fprintf(g_csv,
        "%s,%s,%s,%s,"
        "%s,%d,"
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%.2f,"
        "%zu,%zu,%zu,%zu,"
        "%d\n",
        BACKEND_SHORT, algo, type, op,
        correct, st.n,
        st.mean_ns, st.median_ns, st.min_ns, st.max_ns,
        st.stddev_ns, st.p95_ns, st.p99_ns,
        st.ops_per_sec,
        pk, sk, ct_sig, ss,
        nist);
    fflush(g_csv);
}

static void bench_kem(OQS_KEM *kem, const char *algo, int iters, int warmup) {
    if (!kem) {
        fprintf(stderr, "  [SKIP] %s (constructor failed)\n", algo);
        return;
    }

    uint8_t *pk  = malloc(kem->length_public_key);
    uint8_t *sk  = malloc(kem->length_secret_key);
    uint8_t *ct  = malloc(kem->length_ciphertext);
    uint8_t *ss1 = malloc(kem->length_shared_secret);
    uint8_t *ss2 = malloc(kem->length_shared_secret);
    uint64_t *ts = malloc(sizeof(uint64_t) * (size_t)iters);

    if (!pk || !sk || !ct || !ss1 || !ss2 || !ts) {
        fprintf(stderr, "  [ERROR] malloc failed for %s\n", algo);
        goto cleanup;
    }

    const char *correct = "FAIL";
    if (OQS_KEM_keypair(kem, pk, sk)     == OQS_SUCCESS &&
        OQS_KEM_encaps(kem, ct, ss1, pk) == OQS_SUCCESS &&
        OQS_KEM_decaps(kem, ss2, ct, sk) == OQS_SUCCESS &&
        memcmp(ss1, ss2, kem->length_shared_secret) == 0) {
        ct[0] ^= 0xFF;
        OQS_KEM_decaps(kem, ss2, ct, sk);
        if (memcmp(ss1, ss2, kem->length_shared_secret) != 0)
            correct = "PASS";
        ct[0] ^= 0xFF;
    }

    printf("  %-14s %-12s  %s  (pk=%zu sk=%zu ct=%zu ss=%zu)\n",
           algo, "[" BACKEND_SHORT "]", correct,
           kem->length_public_key, kem->length_secret_key,
           kem->length_ciphertext, kem->length_shared_secret);

    size_t pk_b = kem->length_public_key,  sk_b = kem->length_secret_key;
    size_t ct_b = kem->length_ciphertext,  ss_b = kem->length_shared_secret;
    int    nist = kem->claimed_nist_level;

    for (int i = 0; i < warmup; i++) {
        OQS_KEM_keypair(kem, pk, sk);
        OQS_KEM_encaps(kem, ct, ss1, pk);
        OQS_KEM_decaps(kem, ss2, ct, sk);
    }

    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns(); OQS_KEM_keypair(kem, pk, sk); ts[i] = now_ns() - t;
    }
    raw_dump(algo, "keygen", ts, iters);
    csv_row(algo, "KEM", "keygen", correct, compute_stats(ts, iters), pk_b, sk_b, ct_b, ss_b, nist);

    OQS_KEM_keypair(kem, pk, sk);
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns(); OQS_KEM_encaps(kem, ct, ss1, pk); ts[i] = now_ns() - t;
    }
    raw_dump(algo, "encaps", ts, iters);
    csv_row(algo, "KEM", "encaps", correct, compute_stats(ts, iters), pk_b, sk_b, ct_b, ss_b, nist);

    OQS_KEM_encaps(kem, ct, ss1, pk);
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns(); OQS_KEM_decaps(kem, ss2, ct, sk); ts[i] = now_ns() - t;
    }
    raw_dump(algo, "decaps", ts, iters);
    csv_row(algo, "KEM", "decaps", correct, compute_stats(ts, iters), pk_b, sk_b, ct_b, ss_b, nist);

cleanup:
    free(pk); free(sk); free(ct); free(ss1); free(ss2); free(ts);
    OQS_KEM_free(kem);
}

static void bench_sig(OQS_SIG *sig, const char *algo, int iters, int warmup) {
    if (!sig) {
        fprintf(stderr, "  [SKIP] %s (constructor failed)\n", algo);
        return;
    }

    uint8_t *pk     = malloc(sig->length_public_key);
    uint8_t *sk     = malloc(sig->length_secret_key);
    uint8_t *sigbuf = malloc(sig->length_signature);
    uint8_t  msg[MSG_LEN];
    uint64_t *ts    = malloc(sizeof(uint64_t) * (size_t)iters);
    size_t   siglen = 0;

    if (!pk || !sk || !sigbuf || !ts) {
        fprintf(stderr, "  [ERROR] malloc failed for %s\n", algo);
        goto cleanup;
    }
    for (int b = 0; b < MSG_LEN; b++) msg[b] = (uint8_t)(b & 0xFF);

    const char *correct = "FAIL";
    if (OQS_SIG_keypair(sig, pk, sk)                               == OQS_SUCCESS &&
        OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk)       == OQS_SUCCESS &&
        OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk)      == OQS_SUCCESS) {
        msg[0] ^= 0xFF;
        OQS_STATUS tamper = OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk);
        msg[0] ^= 0xFF;
        if (tamper == OQS_ERROR)
            correct = "PASS";
    }

    printf("  %-14s %-12s  %s  (pk=%zu sk=%zu sig=%zu)\n",
           algo, "[" BACKEND_SHORT "]", correct,
           sig->length_public_key, sig->length_secret_key,
           sig->length_signature);

    size_t pk_b = sig->length_public_key,  sk_b = sig->length_secret_key;
    size_t sg_b = sig->length_signature;
    int    nist = sig->claimed_nist_level;

    for (int i = 0; i < warmup; i++) {
        OQS_SIG_keypair(sig, pk, sk);
        OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk);
        OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk);
    }

    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns(); OQS_SIG_keypair(sig, pk, sk); ts[i] = now_ns() - t;
    }
    raw_dump(algo, "keygen", ts, iters);
    csv_row(algo, "SIG", "keygen", correct, compute_stats(ts, iters), pk_b, sk_b, sg_b, 0, nist);

    OQS_SIG_keypair(sig, pk, sk);
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns(); OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk); ts[i] = now_ns() - t;
    }
    raw_dump(algo, "sign", ts, iters);
    csv_row(algo, "SIG", "sign", correct, compute_stats(ts, iters), pk_b, sk_b, sg_b, 0, nist);

    OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk);
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns(); OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk); ts[i] = now_ns() - t;
    }
    raw_dump(algo, "verify", ts, iters);
    csv_row(algo, "SIG", "verify", correct, compute_stats(ts, iters), pk_b, sk_b, sg_b, 0, nist);

cleanup:
    free(pk); free(sk); free(sigbuf); free(ts);
    OQS_SIG_free(sig);
}

int main(int argc, char **argv) {
    int         iters    = 200;
    int         warmup   = 20;
    const char *csv_path = "pure_backends_benchmark.csv";

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--iters")  && i + 1 < argc) iters    = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--warmup") && i + 1 < argc) warmup   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--csv")    && i + 1 < argc) csv_path = argv[++i];
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            printf("Usage: %s [--iters N] [--warmup N] [--csv PATH]\n", argv[0]);
            return 0;
        }
    }

    OQS_init();

    csv_open(csv_path);
    raw_init();

    printf("=========================================================\n");
    printf(" PQC Pure Backend Benchmark — hash backend: %s\n", BACKEND_SHORT);
    printf(" Same simple wall-clock methodology as pure_bench.\n");
    printf(" No algorithm, compiler-flag or hardware changes.\n");
    printf(" Iterations : %d\n", iters);
    printf(" Warmup     : %d\n", warmup);
    printf(" CSV        : %s\n", csv_path);
    printf("=========================================================\n\n");

    printf("── ML-KEM (FIPS 203) — %s backend ──────────────────────\n\n", BACKEND_SHORT);
    bench_kem(KEM_512_NEW(),  "ML-KEM-512",  iters, warmup);
    bench_kem(KEM_768_NEW(),  "ML-KEM-768",  iters, warmup);
    bench_kem(KEM_1024_NEW(), "ML-KEM-1024", iters, warmup);
    printf("\n");

    printf("── ML-DSA (FIPS 204) — %s backend ──────────────────────\n\n", BACKEND_SHORT);
    bench_sig(SIG_44_NEW(), "ML-DSA-44", iters, warmup);
    bench_sig(SIG_65_NEW(), "ML-DSA-65", iters, warmup);
    bench_sig(SIG_87_NEW(), "ML-DSA-87", iters, warmup);
    printf("\n");

    fclose(g_csv);
    raw_close();
    OQS_destroy();

    printf("=========================================================\n");
    printf(" DONE — %s\n", csv_path);
    printf("=========================================================\n");
    return 0;
}
