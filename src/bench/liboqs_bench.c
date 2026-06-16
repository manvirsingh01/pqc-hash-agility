/*
 * liboqs_bench.c — Default library benchmark
 *
 * Iterates over every KEM and SIG algorithm built into liboqs, runs a
 * correctness check (keygen→encaps→decaps, keygen→sign→verify), then
 * times each operation with clock_gettime(CLOCK_MONOTONIC).
 *
 * Output: library_default_benchmark.csv
 *
 * Usage: ./liboqs_bench [--iters N] [--warmup N] [--csv PATH]
 *
 * Build: see src/bench/Makefile
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <time.h>

#include <oqs/oqs.h>

/* ── timing ─────────────────────────────────────────────────────────── */

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
    r.max_ns    = s[n-1];
    r.median_ns = (n & 1) ? s[n/2] : (s[n/2-1] + s[n/2]) / 2;
    r.p95_ns    = s[(int)(n * 0.95)];
    r.p99_ns    = s[(int)(n * 0.99)];
    double sum = 0, sum2 = 0;
    for (int i = 0; i < n; i++) { double v = (double)s[i]; sum += v; sum2 += v*v; }
    r.mean_ns   = (uint64_t)(sum / n);
    double var  = sum2/n - (sum/n)*(sum/n);
    r.stddev_ns = (uint64_t)sqrt(var < 0 ? 0 : var);
    r.ops_per_sec = r.mean_ns > 0 ? 1e9 / (double)r.mean_ns : 0.0;
    return r;
}

/* ── CSV ─────────────────────────────────────────────────────────────── */

static FILE *g_csv;

static void csv_header(void) {
    fprintf(g_csv,
        "library,algorithm,type,operation,"
        "correctness,iterations,"
        "mean_ns,median_ns,min_ns,max_ns,stddev_ns,p95_ns,p99_ns,"
        "ops_per_sec,"
        "pk_bytes,sk_bytes,ct_or_sig_bytes,ss_bytes,"
        "nist_level\n");
}

static void csv_row(const char *lib, const char *algo, const char *type,
                    const char *op, const char *correct,
                    Stats st,
                    size_t pk, size_t sk, size_t ct_sig, size_t ss,
                    int nist) {
    fprintf(g_csv,
        "%s,%s,%s,%s,"
        "%s,%d,"
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%.2f,"
        "%zu,%zu,%zu,%zu,"
        "%d\n",
        lib, algo, type, op,
        correct, st.n,
        st.mean_ns, st.median_ns, st.min_ns, st.max_ns,
        st.stddev_ns, st.p95_ns, st.p99_ns,
        st.ops_per_sec,
        pk, sk, ct_sig, ss,
        nist);
    fflush(g_csv);
}

/* ── KEM benchmark ───────────────────────────────────────────────────── */

static void bench_kem(const char *alg_name, const char *lib,
                      int iters, int warmup) {
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) {
        fprintf(stderr, "  [SKIP] %s (not enabled in this build)\n", alg_name);
        return;
    }

    uint8_t *pk  = OQS_MEM_malloc(kem->length_public_key);
    uint8_t *sk  = OQS_MEM_malloc(kem->length_secret_key);
    uint8_t *ct  = OQS_MEM_malloc(kem->length_ciphertext);
    uint8_t *ss1 = OQS_MEM_malloc(kem->length_shared_secret);
    uint8_t *ss2 = OQS_MEM_malloc(kem->length_shared_secret);
    uint64_t *ts = OQS_MEM_malloc(sizeof(uint64_t) * (size_t)iters);

    if (!pk || !sk || !ct || !ss1 || !ss2 || !ts) {
        fprintf(stderr, "  malloc failed for %s\n", alg_name);
        goto cleanup;
    }

    /* correctness check */
    const char *correct = "FAIL";
    if (OQS_KEM_keypair(kem, pk, sk)     == OQS_SUCCESS &&
        OQS_KEM_encaps(kem, ct, ss1, pk) == OQS_SUCCESS &&
        OQS_KEM_decaps(kem, ss2, ct, sk) == OQS_SUCCESS &&
        memcmp(ss1, ss2, kem->length_shared_secret) == 0)
        correct = "PASS";
    printf("  %-40s  %s\n", alg_name, correct);

    size_t pk_b = kem->length_public_key,   sk_b = kem->length_secret_key;
    size_t ct_b = kem->length_ciphertext,   ss_b = kem->length_shared_secret;
    int    nist = kem->claimed_nist_level;

    /* warmup */
    for (int i = 0; i < warmup; i++) {
        OQS_KEM_keypair(kem, pk, sk);
        OQS_KEM_encaps(kem, ct, ss1, pk);
        OQS_KEM_decaps(kem, ss2, ct, sk);
    }

    /* keygen */
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns();
        OQS_KEM_keypair(kem, pk, sk);
        ts[i] = now_ns() - t;
    }
    csv_row(lib, alg_name, "KEM", "keygen", correct,
            compute_stats(ts, iters), pk_b, sk_b, ct_b, ss_b, nist);

    /* encaps */
    OQS_KEM_keypair(kem, pk, sk);
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns();
        OQS_KEM_encaps(kem, ct, ss1, pk);
        ts[i] = now_ns() - t;
    }
    csv_row(lib, alg_name, "KEM", "encaps", correct,
            compute_stats(ts, iters), pk_b, sk_b, ct_b, ss_b, nist);

    /* decaps */
    OQS_KEM_encaps(kem, ct, ss1, pk);
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns();
        OQS_KEM_decaps(kem, ss2, ct, sk);
        ts[i] = now_ns() - t;
    }
    csv_row(lib, alg_name, "KEM", "decaps", correct,
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

/* ── SIG benchmark ───────────────────────────────────────────────────── */

#define MSG_LEN 32

static void bench_sig(const char *alg_name, const char *lib,
                      int iters, int warmup) {
    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (!sig) {
        fprintf(stderr, "  [SKIP] %s (not enabled in this build)\n", alg_name);
        return;
    }

    uint8_t *pk     = OQS_MEM_malloc(sig->length_public_key);
    uint8_t *sk     = OQS_MEM_malloc(sig->length_secret_key);
    uint8_t *sigbuf = OQS_MEM_malloc(sig->length_signature);
    uint8_t  msg[MSG_LEN];
    uint64_t *ts    = OQS_MEM_malloc(sizeof(uint64_t) * (size_t)iters);
    size_t   siglen = 0;

    if (!pk || !sk || !sigbuf || !ts) {
        fprintf(stderr, "  malloc failed for %s\n", alg_name);
        goto cleanup;
    }
    OQS_randombytes(msg, MSG_LEN);

    /* correctness check */
    const char *correct = "FAIL";
    if (OQS_SIG_keypair(sig, pk, sk)                              == OQS_SUCCESS &&
        OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk)      == OQS_SUCCESS &&
        OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk)      == OQS_SUCCESS)
        correct = "PASS";
    printf("  %-40s  %s\n", alg_name, correct);

    size_t pk_b = sig->length_public_key,   sk_b = sig->length_secret_key;
    size_t sg_b = sig->length_signature;
    int    nist = sig->claimed_nist_level;

    /* warmup */
    for (int i = 0; i < warmup; i++) {
        OQS_SIG_keypair(sig, pk, sk);
        OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk);
        OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk);
    }

    /* keygen */
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns();
        OQS_SIG_keypair(sig, pk, sk);
        ts[i] = now_ns() - t;
    }
    csv_row(lib, alg_name, "SIG", "keygen", correct,
            compute_stats(ts, iters), pk_b, sk_b, sg_b, 0, nist);

    /* sign */
    OQS_SIG_keypair(sig, pk, sk);
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns();
        OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk);
        ts[i] = now_ns() - t;
    }
    csv_row(lib, alg_name, "SIG", "sign", correct,
            compute_stats(ts, iters), pk_b, sk_b, sg_b, 0, nist);

    /* verify */
    OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk);
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns();
        OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk);
        ts[i] = now_ns() - t;
    }
    csv_row(lib, alg_name, "SIG", "verify", correct,
            compute_stats(ts, iters), pk_b, sk_b, sg_b, 0, nist);

cleanup:
    OQS_MEM_insecure_free(pk);
    OQS_MEM_insecure_free(sk);
    OQS_MEM_insecure_free(sigbuf);
    OQS_MEM_insecure_free(ts);
    OQS_SIG_free(sig);
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    int         iters    = 200;
    int         warmup   = 20;
    const char *csv_path = "library_default_benchmark.csv";

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--iters")  && i+1 < argc) iters    = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--warmup") && i+1 < argc) warmup   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--csv")    && i+1 < argc) csv_path = argv[++i];
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            printf("Usage: %s [--iters N] [--warmup N] [--csv PATH]\n", argv[0]);
            return 0;
        }
    }

    OQS_init();

    /* build lib version string */
    char lib[64];
    snprintf(lib, sizeof(lib), "liboqs-%s", OQS_VERSION_TEXT);

    g_csv = fopen(csv_path, "w");
    if (!g_csv) { perror(csv_path); return 1; }
    csv_header();

    printf("=== liboqs Default Library Benchmark ===\n");
    printf("Library   : %s\n", lib);
    printf("Iterations: %d   Warmup: %d   CSV: %s\n\n", iters, warmup, csv_path);

    /* ── KEM algorithms (all enabled in this build) ─────────────────── */
    int n_kem = OQS_KEM_alg_count();
    printf("--- KEM algorithms (%d total) ---\n", n_kem);
    for (int i = 0; i < n_kem; i++) {
        const char *name = OQS_KEM_alg_identifier((size_t)i);
        if (!OQS_KEM_alg_is_enabled(name)) {
            printf("  %-40s  [disabled]\n", name);
            continue;
        }
        bench_kem(name, lib, iters, warmup);
    }

    /* ── SIG algorithms (all enabled in this build) ──────────────────── */
    int n_sig = OQS_SIG_alg_count();
    printf("\n--- SIG algorithms (%d total) ---\n", n_sig);
    for (int i = 0; i < n_sig; i++) {
        const char *name = OQS_SIG_alg_identifier((size_t)i);
        if (!OQS_SIG_alg_is_enabled(name)) {
            printf("  %-40s  [disabled]\n", name);
            continue;
        }
        bench_sig(name, lib, iters, warmup);
    }

    fclose(g_csv);
    OQS_destroy();

    printf("\n=== Done. Results: %s ===\n", csv_path);
    return 0;
}
