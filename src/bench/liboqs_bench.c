/*
 * liboqs_bench.c — Benchmark all 6 custom backends via the OQS_KEM/OQS_SIG API
 *
 * Tests ML-KEM-512/768/1024 and ML-DSA-44/65/87 for each of the six hash
 * backends (shake, turboshake, k12, blake3, xoodyak, haraka) using the
 * same liboqs OQS_KEM / OQS_SIG adapter interface used by the library itself.
 *
 * Output: library_default_benchmark.csv
 *
 * Usage: ./liboqs_bench [--iters N] [--warmup N] [--csv PATH]
 *
 * Build: see src/bench/Makefile  (links all custom static libs + liboqs.a)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <time.h>

#include <oqs/oqs.h>

/* adapter headers for our 5 custom backends (shake uses OQS_KEM_new directly) */
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
    uint64_t trimmed_mean_ns;   /* mean of middle 95% — outlier-robust */
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
    r.p95_ns    = s[(int)((n - 1) * 0.95)];
    r.p99_ns    = s[(int)((n - 1) * 0.99)];
    double sum = 0, sum2 = 0;
    for (int i = 0; i < n; i++) { double v = (double)s[i]; sum += v; sum2 += v*v; }
    r.mean_ns   = (uint64_t)(sum / n);
    double var  = sum2/n - (sum/n)*(sum/n);
    r.stddev_ns = (uint64_t)sqrt(var < 0 ? 0 : var);
    r.ops_per_sec = r.mean_ns > 0 ? 1e9 / (double)r.mean_ns : 0.0;

    /* Trimmed mean: drop lowest/highest 2.5% so a few scheduler or SMI
     * outliers cannot skew the average (raw max/p99 still show the tail). */
    {
        int lo = (int)(n * 0.025), hi = n - lo;
        if (hi <= lo) { lo = 0; hi = n; }
        double tsum = 0.0;
        for (int i = lo; i < hi; i++) tsum += (double)s[i];
        r.trimmed_mean_ns = (uint64_t)(tsum / (double)(hi - lo));
    }
    return r;
}

/* ── raw memory (RSS via /proc) + energy (Intel RAPL) probes ─────────── */

#include <fcntl.h>
#include <unistd.h>

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

/* Snapshot rss_kb()/rapl_uj() right before the timed loop, then call this
 * right after it: raw before/after counters plus derived per-op uJ. */
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

/* ── CSV ─────────────────────────────────────────────────────────────── */

static FILE *g_csv;

static void csv_header(void) {
    fprintf(g_csv,
        "backend,algorithm,type,operation,"
        "correctness,iterations,"
        "mean_ns,median_ns,min_ns,max_ns,stddev_ns,p95_ns,p99_ns,"
        "trimmed_mean_ns,"
        "ops_per_sec,"
        "pk_bytes,sk_bytes,ct_or_sig_bytes,ss_bytes,"
        "nist_level,"
        "rss_before_kb,rss_after_kb,"
        "rapl_before_uj,rapl_after_uj,rapl_total_uj,"
        "rapl_energy_per_op_uj,rapl_measured\n");
}

static void csv_row(const char *backend, const char *algo, const char *type,
                    const char *op, const char *correct,
                    Stats st, Probe pr,
                    size_t pk, size_t sk, size_t ct_sig, size_t ss,
                    int nist) {
    fprintf(g_csv,
        "%s,%s,%s,%s,"
        "%s,%d,"
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ","
        "%.2f,"
        "%zu,%zu,%zu,%zu,"
        "%d,"
        "%ld,%ld,"
        "%.2f,%.2f,%.2f,"
        "%.4f,%d\n",
        backend, algo, type, op,
        correct, st.n,
        st.mean_ns, st.median_ns, st.min_ns, st.max_ns,
        st.stddev_ns, st.p95_ns, st.p99_ns,
        st.trimmed_mean_ns,
        st.ops_per_sec,
        pk, sk, ct_sig, ss,
        nist,
        pr.rss_before_kb, pr.rss_after_kb,
        pr.rapl_before_uj, pr.rapl_after_uj, pr.rapl_total_uj,
        pr.rapl_per_op_uj, pr.rapl_measured);
    fflush(g_csv);
}

/* ── KEM benchmark ───────────────────────────────────────────────────── */

static void bench_kem(OQS_KEM *kem, const char *alg_name,
                      const char *backend, int iters, int warmup) {
    if (!kem) {
        fprintf(stderr, "  [SKIP] %s/%s (constructor returned NULL)\n",
                backend, alg_name);
        return;
    }

    uint8_t *pk  = OQS_MEM_malloc(kem->length_public_key);
    uint8_t *sk  = OQS_MEM_malloc(kem->length_secret_key);
    uint8_t *ct  = OQS_MEM_malloc(kem->length_ciphertext);
    uint8_t *ss1 = OQS_MEM_malloc(kem->length_shared_secret);
    uint8_t *ss2 = OQS_MEM_malloc(kem->length_shared_secret);
    uint64_t *ts = OQS_MEM_malloc(sizeof(uint64_t) * (size_t)iters);

    if (!pk || !sk || !ct || !ss1 || !ss2 || !ts) {
        fprintf(stderr, "  malloc failed for %s/%s\n", backend, alg_name);
        goto cleanup;
    }

    /* correctness check */
    const char *correct = "FAIL";
    if (OQS_KEM_keypair(kem, pk, sk)     == OQS_SUCCESS &&
        OQS_KEM_encaps(kem, ct, ss1, pk) == OQS_SUCCESS &&
        OQS_KEM_decaps(kem, ss2, ct, sk) == OQS_SUCCESS &&
        memcmp(ss1, ss2, kem->length_shared_secret) == 0)
        correct = "PASS";
    printf("  %-12s  %-20s  %s\n", backend, alg_name, correct);

    size_t pk_b = kem->length_public_key,   sk_b = kem->length_secret_key;
    size_t ct_b = kem->length_ciphertext,   ss_b = kem->length_shared_secret;
    int    nist = kem->claimed_nist_level;

    /* warmup */
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
        uint64_t t = now_ns();
        OQS_KEM_keypair(kem, pk, sk);
        ts[i] = now_ns() - t;
    }
    csv_row(backend, alg_name, "KEM", "keygen", correct,
            compute_stats(ts, iters), probe_finish(rss_b, rapl_b, iters),
            pk_b, sk_b, ct_b, ss_b, nist);

    /* encaps */
    OQS_KEM_keypair(kem, pk, sk);
    rss_b = rss_kb(); rapl_b = rapl_uj();
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns();
        OQS_KEM_encaps(kem, ct, ss1, pk);
        ts[i] = now_ns() - t;
    }
    csv_row(backend, alg_name, "KEM", "encaps", correct,
            compute_stats(ts, iters), probe_finish(rss_b, rapl_b, iters),
            pk_b, sk_b, ct_b, ss_b, nist);

    /* decaps */
    OQS_KEM_encaps(kem, ct, ss1, pk);
    rss_b = rss_kb(); rapl_b = rapl_uj();
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns();
        OQS_KEM_decaps(kem, ss2, ct, sk);
        ts[i] = now_ns() - t;
    }
    csv_row(backend, alg_name, "KEM", "decaps", correct,
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

/* ── SIG benchmark ───────────────────────────────────────────────────── */

#define MSG_LEN 32

static void bench_sig(OQS_SIG *sig, const char *alg_name,
                      const char *backend, int iters, int warmup) {
    if (!sig) {
        fprintf(stderr, "  [SKIP] %s/%s (constructor returned NULL)\n",
                backend, alg_name);
        return;
    }

    uint8_t *pk     = OQS_MEM_malloc(sig->length_public_key);
    uint8_t *sk     = OQS_MEM_malloc(sig->length_secret_key);
    uint8_t *sigbuf = OQS_MEM_malloc(sig->length_signature);
    uint8_t  msg[MSG_LEN];
    uint64_t *ts    = OQS_MEM_malloc(sizeof(uint64_t) * (size_t)iters);
    size_t   siglen = 0;

    if (!pk || !sk || !sigbuf || !ts) {
        fprintf(stderr, "  malloc failed for %s/%s\n", backend, alg_name);
        goto cleanup;
    }
    OQS_randombytes(msg, MSG_LEN);

    /* correctness check */
    const char *correct = "FAIL";
    if (OQS_SIG_keypair(sig, pk, sk)                             == OQS_SUCCESS &&
        OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk)     == OQS_SUCCESS &&
        OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk)    == OQS_SUCCESS)
        correct = "PASS";
    printf("  %-12s  %-20s  %s\n", backend, alg_name, correct);

    size_t pk_b = sig->length_public_key,   sk_b = sig->length_secret_key;
    size_t sg_b = sig->length_signature;
    int    nist = sig->claimed_nist_level;

    /* warmup */
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
        uint64_t t = now_ns();
        OQS_SIG_keypair(sig, pk, sk);
        ts[i] = now_ns() - t;
    }
    csv_row(backend, alg_name, "SIG", "keygen", correct,
            compute_stats(ts, iters), probe_finish(rss_b, rapl_b, iters),
            pk_b, sk_b, sg_b, 0, nist);

    /* sign */
    OQS_SIG_keypair(sig, pk, sk);
    rss_b = rss_kb(); rapl_b = rapl_uj();
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns();
        OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk);
        ts[i] = now_ns() - t;
    }
    csv_row(backend, alg_name, "SIG", "sign", correct,
            compute_stats(ts, iters), probe_finish(rss_b, rapl_b, iters),
            pk_b, sk_b, sg_b, 0, nist);

    /* verify */
    OQS_SIG_sign(sig, sigbuf, &siglen, msg, MSG_LEN, sk);
    rss_b = rss_kb(); rapl_b = rapl_uj();
    for (int i = 0; i < iters; i++) {
        uint64_t t = now_ns();
        OQS_SIG_verify(sig, msg, MSG_LEN, sigbuf, siglen, pk);
        ts[i] = now_ns() - t;
    }
    csv_row(backend, alg_name, "SIG", "verify", correct,
            compute_stats(ts, iters), probe_finish(rss_b, rapl_b, iters),
            pk_b, sk_b, sg_b, 0, nist);

cleanup:
    OQS_MEM_insecure_free(pk);
    OQS_MEM_insecure_free(sk);
    OQS_MEM_insecure_free(sigbuf);
    OQS_MEM_insecure_free(ts);
    OQS_SIG_free(sig);
}

/* ── backend tables ──────────────────────────────────────────────────── */

typedef OQS_KEM *(*kem_ctor)(void);
typedef OQS_SIG *(*sig_ctor)(void);

typedef struct {
    const char *name;
    kem_ctor    kem[3];   /* 512, 768, 1024 */
    sig_ctor    sig[3];   /* 44,  65,  87   */
} Backend;

/* shake uses liboqs OQS_KEM_new / OQS_SIG_new — wrap with thin helpers */
static OQS_KEM *shake_kem_512_new(void)  { return OQS_KEM_new(OQS_KEM_alg_ml_kem_512);  }
static OQS_KEM *shake_kem_768_new(void)  { return OQS_KEM_new(OQS_KEM_alg_ml_kem_768);  }
static OQS_KEM *shake_kem_1024_new(void) { return OQS_KEM_new(OQS_KEM_alg_ml_kem_1024); }
static OQS_SIG *shake_sig_44_new(void)   { return OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);   }
static OQS_SIG *shake_sig_65_new(void)   { return OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);   }
static OQS_SIG *shake_sig_87_new(void)   { return OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);   }

static const Backend backends[] = {
    { "shake",
      { shake_kem_512_new,                   shake_kem_768_new,                   shake_kem_1024_new                   },
      { shake_sig_44_new,                    shake_sig_65_new,                    shake_sig_87_new                     } },
    { "turboshake",
      { OQS_KEM_ml_kem_512_turboshake_new,   OQS_KEM_ml_kem_768_turboshake_new,   OQS_KEM_ml_kem_1024_turboshake_new   },
      { OQS_SIG_ml_dsa_44_turboshake_new,    OQS_SIG_ml_dsa_65_turboshake_new,    OQS_SIG_ml_dsa_87_turboshake_new     } },
    { "k12",
      { OQS_KEM_ml_kem_512_k12_new,          OQS_KEM_ml_kem_768_k12_new,          OQS_KEM_ml_kem_1024_k12_new          },
      { OQS_SIG_ml_dsa_44_k12_new,           OQS_SIG_ml_dsa_65_k12_new,           OQS_SIG_ml_dsa_87_k12_new            } },
    { "blake3",
      { OQS_KEM_ml_kem_512_blake3_new,       OQS_KEM_ml_kem_768_blake3_new,       OQS_KEM_ml_kem_1024_blake3_new       },
      { OQS_SIG_ml_dsa_44_blake3_new,        OQS_SIG_ml_dsa_65_blake3_new,        OQS_SIG_ml_dsa_87_blake3_new         } },
    { "xoodyak",
      { OQS_KEM_ml_kem_512_xoodyak_new,      OQS_KEM_ml_kem_768_xoodyak_new,      OQS_KEM_ml_kem_1024_xoodyak_new      },
      { OQS_SIG_ml_dsa_44_xoodyak_new,       OQS_SIG_ml_dsa_65_xoodyak_new,       OQS_SIG_ml_dsa_87_xoodyak_new        } },
    { "haraka",
      { OQS_KEM_ml_kem_512_haraka_new,       OQS_KEM_ml_kem_768_haraka_new,       OQS_KEM_ml_kem_1024_haraka_new       },
      { OQS_SIG_ml_dsa_44_haraka_new,        OQS_SIG_ml_dsa_65_haraka_new,        OQS_SIG_ml_dsa_87_haraka_new         } },
};
#define N_BACKENDS (int)(sizeof(backends)/sizeof(backends[0]))

static const char *kem_algs[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
static const char *sig_algs[] = { "ML-DSA-44",  "ML-DSA-65",  "ML-DSA-87"  };

/* ── main ────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    int         iters    = 1000;
    int         warmup   = 100;
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

    g_csv = fopen(csv_path, "w");
    if (!g_csv) { perror(csv_path); return 1; }
    csv_header();

    printf("=== Default Library Benchmark — All 6 Backends via OQS API ===\n");
    printf("Backends  : shake, turboshake, k12, blake3, xoodyak, haraka\n");
    printf("Algorithms: ML-KEM-512/768/1024  +  ML-DSA-44/65/87\n");
    printf("Iterations: %d   Warmup: %d   CSV: %s\n\n", iters, warmup, csv_path);

    for (int b = 0; b < N_BACKENDS; b++) {
        const Backend *bk = &backends[b];

        printf("━━━ [%d/6] %s ━━━\n", b+1, bk->name);

        printf("  KEM:\n");
        for (int k = 0; k < 3; k++)
            bench_kem(bk->kem[k](), kem_algs[k], bk->name, iters, warmup);

        printf("  SIG:\n");
        for (int s = 0; s < 3; s++)
            bench_sig(bk->sig[s](), sig_algs[s], bk->name, iters, warmup);

        printf("\n");
    }

    fclose(g_csv);
    OQS_destroy();

    printf("=== Done. Results: %s ===\n", csv_path);
    return 0;
}
