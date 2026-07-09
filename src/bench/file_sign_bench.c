/* =============================================================================
 * file_sign_bench.c — Hash + sign a user-supplied payload file with one of
 * the six hash backends (shake / turboshake / k12 / blake3 / xoodyak /
 * haraka) and benchmark it.
 *
 * For the selected backend (chosen at compile time with -DUSE_<TAG>) this
 * program:
 *
 *   1. Reads the payload file into memory and records payload information
 *      (name, size, reference SHA-256).
 *   2. Hashes the payload with the backend's hash function — the exact
 *      "H/CRH role" construction the backend substitutes into ML-DSA
 *      (domain byte 0x3F, 32-byte output) — and benchmarks it.
 *   3. Signs the payload with ML-DSA-44 / 65 / 87 built on that backend
 *      (via the pre-built adapter objects + static libs from setup.sh,
 *      linked exactly as they are) and benchmarks sign + verify.
 *
 * Timing follows the same simple raw methodology as pure_bench.c — plain
 * CLOCK_MONOTONIC wall-clock ns, one warmup pass, one timed loop — plus a
 * per-iteration cycle-counter reading (rdtsc on x86_64, CNTVCT_EL0 timer
 * ticks on aarch64) recorded alongside every wall-clock sample, as in the
 * controlled benchmark's raw CSVs. No algorithm settings, compiler flags
 * of the pre-built libraries, or hardware settings are changed.
 *
 * Output (all opened in append mode so the six per-backend binaries share
 * the same files; the driver script starts them fresh):
 *
 *   --csv FILE       aggregate stats: one row per backend × operation
 *                    (hash, and sign/verify per ML-DSA variant), with
 *                    rounds, ns stats, cycle stats and payload info
 *   --hashcsv FILE   hash/signature detail: digest hex codes, signature
 *                    sizes + SHA-256 fingerprints, constructions, payload
 *                    information, verification results
 *   $PQC_RAW_DIR/<PQC_RAW_TAG|file_sign>_raw.csv
 *                    per-iteration raw rows: ns AND cycles per round
 *
 * Usage:
 *   ./file_sign_<tag> --file PAYLOAD [--iters N] [--warmup N]
 *                     [--csv out.csv] [--hashcsv hashes.csv]
 * ========================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <time.h>
#include <libgen.h>

#include <oqs/oqs.h>
#include <openssl/sha.h>

/* =========================================================================
 * Backend selection (-DUSE_<TAG>)
 * Each backend exposes its ML-DSA implementations through the OQS-style
 * adapter constructors in pqc_<tag>_dsa.h, and its payload hash through
 * backend_hash(): the same H/CRH-role construction (domain 0x3F, 32-byte
 * output) documented in the fork's symmetric.h.
 * ========================================================================= */
#define HASH_OUT_BYTES 32
#define HASH_DOMAIN    0x3F  /* the forks' "H/CRH role" domain byte */

#if defined(USE_SHAKE)
#  define BACKEND_SHORT "shake"
#  define HASH_NAME "SHAKE256"
#  define HASH_CONSTRUCTION "SHAKE256 XOF (FIPS 202); 32-byte output; baseline - no domain byte"
#  include "pqc_shake_dsa.h"
#  include "fips202.h"
#  define SIG_44_NEW OQS_SIG_ml_dsa_44_shake_new
#  define SIG_65_NEW OQS_SIG_ml_dsa_65_shake_new
#  define SIG_87_NEW OQS_SIG_ml_dsa_87_shake_new
static void backend_hash(uint8_t out[HASH_OUT_BYTES], const uint8_t *in, size_t inlen) {
    shake256(out, HASH_OUT_BYTES, in, inlen);
}

#elif defined(USE_TURBOSHAKE)
#  define BACKEND_SHORT "turboshake"
#  define HASH_NAME "TurboSHAKE256"
#  define HASH_CONSTRUCTION "TurboSHAKE256 (RFC 9861; capacity 512); domain byte 0x3F (fork H/CRH role); 32-byte output"
#  include "pqc_turboshake_dsa.h"
#  include "TurboSHAKE.h"
#  define SIG_44_NEW OQS_SIG_ml_dsa_44_turboshake_new
#  define SIG_65_NEW OQS_SIG_ml_dsa_65_turboshake_new
#  define SIG_87_NEW OQS_SIG_ml_dsa_87_turboshake_new
static void backend_hash(uint8_t out[HASH_OUT_BYTES], const uint8_t *in, size_t inlen) {
    TurboSHAKE(512, in, inlen, HASH_DOMAIN, out, HASH_OUT_BYTES);
}

#elif defined(USE_K12)
#  define BACKEND_SHORT "k12"
#  define HASH_NAME "KT256"
#  define HASH_CONSTRUCTION "KT256 / KangarooTwelve (RFC 9861); customization string C = 0x3F (fork H/CRH role); 32-byte output"
#  include "pqc_k12_dsa.h"
#  include "KangarooTwelve.h"
#  define SIG_44_NEW OQS_SIG_ml_dsa_44_k12_new
#  define SIG_65_NEW OQS_SIG_ml_dsa_65_k12_new
#  define SIG_87_NEW OQS_SIG_ml_dsa_87_k12_new
static void backend_hash(uint8_t out[HASH_OUT_BYTES], const uint8_t *in, size_t inlen) {
    const unsigned char dom = HASH_DOMAIN;
    KT256(in, inlen, out, HASH_OUT_BYTES, &dom, 1);
}

#elif defined(USE_BLAKE3)
#  define BACKEND_SHORT "blake3"
#  define HASH_NAME "BLAKE3"
#  define HASH_CONSTRUCTION "BLAKE3 XOF; domain byte 0x3F appended to input (fork H/CRH role); 32-byte output"
#  include "pqc_blake3_dsa.h"
#  include "blake3.h"
#  define SIG_44_NEW OQS_SIG_ml_dsa_44_blake3_new
#  define SIG_65_NEW OQS_SIG_ml_dsa_65_blake3_new
#  define SIG_87_NEW OQS_SIG_ml_dsa_87_blake3_new
static void backend_hash(uint8_t out[HASH_OUT_BYTES], const uint8_t *in, size_t inlen) {
    blake3_hasher h;
    uint8_t dom = HASH_DOMAIN;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, in, inlen);
    blake3_hasher_update(&h, &dom, 1);
    blake3_hasher_finalize(&h, out, HASH_OUT_BYTES);
}

#elif defined(USE_XOODYAK)
#  define BACKEND_SHORT "xoodyak"
#  define HASH_NAME "Xoodyak"
#  define HASH_CONSTRUCTION "Xoodyak Cyclist hash mode (unkeyed); domain byte 0x3F appended to input (fork H/CRH role); 32-byte output"
#  include "pqc_xoodyak_dsa.h"
#  include "Xoodyak.h"
#  define SIG_44_NEW OQS_SIG_ml_dsa_44_xoodyak_new
#  define SIG_65_NEW OQS_SIG_ml_dsa_65_xoodyak_new
#  define SIG_87_NEW OQS_SIG_ml_dsa_87_xoodyak_new
static void backend_hash(uint8_t out[HASH_OUT_BYTES], const uint8_t *in, size_t inlen) {
    Xoodyak_Instance x;
    uint8_t dom = HASH_DOMAIN;
    Xoodyak_Initialize(&x, NULL, 0, NULL, 0, NULL, 0);
    Xoodyak_Absorb(&x, in, inlen);
    Xoodyak_Absorb(&x, &dom, 1);
    Xoodyak_Squeeze(&x, out, HASH_OUT_BYTES);
}

#elif defined(USE_HARAKA)
#  define BACKEND_SHORT "haraka"
#  define HASH_NAME "Haraka-MD"
#  define HASH_CONSTRUCTION "Haraka-MD (Merkle-Damgard over haraka512; cv=haraka512(cv||block); pad domain 0x3F; squeeze haraka512(cv||LE64(i)||0^24)); 32-byte output; fork H/CRH role"
#  include "pqc_haraka_dsa.h"
#  include "haraka.h"
#  define SIG_44_NEW OQS_SIG_ml_dsa_44_haraka_new
#  define SIG_65_NEW OQS_SIG_ml_dsa_65_haraka_new
#  define SIG_87_NEW OQS_SIG_ml_dsa_87_haraka_new
/* Same Haraka-MD construction as the fork's symmetric.h: 32-byte chaining
 * value (IV = 0^256), 32-byte blocks compressed via cv = haraka512(cv||block),
 * finalize pads the tail with the domain byte then zeros, output block 0 is
 * haraka512(cv || LE64(0) || 0^24) truncated to 32 bytes. */
static void backend_hash(uint8_t out[HASH_OUT_BYTES], const uint8_t *in, size_t inlen) {
    uint8_t cv[32] = {0}, blk[64], tail[32] = {0};
    while (inlen >= 32) {
        memcpy(blk, cv, 32);
        memcpy(blk + 32, in, 32);
        haraka512(cv, blk);
        in += 32; inlen -= 32;
    }
    memcpy(tail, in, inlen);
    tail[inlen] = HASH_DOMAIN;
    memcpy(blk, cv, 32);
    memcpy(blk + 32, tail, 32);
    haraka512(cv, blk);
    memcpy(blk, cv, 32);
    memset(blk + 32, 0, 32);   /* LE64(0) || 0^24 */
    haraka512(out, blk);
}

#else
#  error "Define one of USE_SHAKE, USE_TURBOSHAKE, USE_K12, USE_BLAKE3, USE_XOODYAK, USE_HARAKA"
#endif

/* =========================================================================
 * Wall clock (ns) — same as pure_bench.c
 * ========================================================================= */
static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* =========================================================================
 * Cycle counter — same readings as the controlled benchmark's raw CSVs:
 * rdtsc/rdtscp (+lfence) on x86_64, ISB-serialized CNTVCT_EL0 on aarch64
 * (a fixed-frequency timer, so values are "timer ticks", not core cycles).
 * ========================================================================= */
#if defined(__x86_64__) || defined(__i386__)
#  define CYCLE_UNIT "rdtsc_cycles"
static inline uint64_t cycles_begin(void) {
    uint32_t lo, hi;
    __asm__ volatile ("lfence\n\trdtsc\n\t" : "=a"(lo), "=d"(hi) : : "memory");
    return ((uint64_t)hi << 32) | lo;
}
static inline uint64_t cycles_end(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtscp\n\tlfence\n\t" : "=a"(lo), "=d"(hi) : : "%ecx", "memory");
    return ((uint64_t)hi << 32) | lo;
}
#elif defined(__aarch64__)
#  define CYCLE_UNIT "cntvct_ticks"
static inline uint64_t cycles_begin(void) {
    uint64_t v;
    __asm__ volatile ("isb\n\tmrs %0, cntvct_el0\n\t" : "=r"(v) : : "memory");
    return v;
}
static inline uint64_t cycles_end(void) {
    uint64_t v;
    __asm__ volatile ("isb\n\tmrs %0, cntvct_el0\n\t" : "=r"(v) : : "memory");
    return v;
}
#else
#  define CYCLE_UNIT "unavailable"
static inline uint64_t cycles_begin(void) { return 0; }
static inline uint64_t cycles_end(void)   { return 0; }
#endif

/* =========================================================================
 * Statistics — identical to pure_bench.c (sorts samples in place)
 * ========================================================================= */
typedef struct {
    double mean, median, min, max, stddev, p95, p99;
} Stats;

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void compute_stats(uint64_t *samples, int n, Stats *st) {
    qsort(samples, (size_t)n, sizeof(uint64_t), cmp_u64);
    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += (double)samples[i];
    st->mean   = sum / n;
    st->median = (n % 2) ? (double)samples[n / 2]
                         : ((double)samples[n / 2 - 1] + (double)samples[n / 2]) / 2.0;
    st->min = (double)samples[0];
    st->max = (double)samples[n - 1];
    double var = 0.0;
    for (int i = 0; i < n; i++) {
        double d = (double)samples[i] - st->mean;
        var += d * d;
    }
    st->stddev = (n > 1) ? sqrt(var / (n - 1)) : 0.0;
    int i95 = (int)(0.95 * n); if (i95 >= n) i95 = n - 1;
    int i99 = (int)(0.99 * n); if (i99 >= n) i99 = n - 1;
    st->p95 = (double)samples[i95];
    st->p99 = (double)samples[i99];
}

/* =========================================================================
 * Per-iteration raw dump — one row per round with BOTH the wall-clock ns
 * sample and the cycle-counter sample. Enabled via PQC_RAW_DIR.
 * ========================================================================= */
static FILE *g_raw = NULL;

static void raw_init(void) {
    const char *dir = getenv("PQC_RAW_DIR");
    if (!dir || !dir[0]) return;
    const char *tag = getenv("PQC_RAW_TAG");
    if (!tag || !tag[0]) tag = "file_sign";
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s_raw.csv", dir, tag);
    FILE *probe = fopen(path, "r");
    int fresh = (probe == NULL);
    if (probe) fclose(probe);
    g_raw = fopen(path, "a");
    if (g_raw && fresh)
        fprintf(g_raw, "backend,algorithm,operation,iteration,ns,cycles,cycle_unit\n");
}

static void raw_dump(const char *algo, const char *op,
                     const uint64_t *ns, const uint64_t *cyc, int n) {
    if (!g_raw) return;
    for (int i = 0; i < n; i++)
        fprintf(g_raw, "%s,%s,%s,%d,%" PRIu64 ",%" PRIu64 ",%s\n",
                BACKEND_SHORT, algo, op, i + 1, ns[i], cyc[i], CYCLE_UNIT);
    fflush(g_raw);
}

static void raw_close(void) {
    if (g_raw) { fclose(g_raw); g_raw = NULL; }
}

/* =========================================================================
 * Payload + CSV helpers
 * ========================================================================= */
static const char *g_payload_name = "?";
static size_t      g_payload_len  = 0;
static char        g_payload_sha256[65] = "?";

static void hex_encode(char *dst, const uint8_t *src, size_t n) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        dst[2 * i]     = h[src[i] >> 4];
        dst[2 * i + 1] = h[src[i] & 0xF];
    }
    dst[2 * n] = '\0';
}

/* Open a shared CSV in append mode, writing the header only if new. */
static FILE *csv_open(const char *path, const char *header) {
    FILE *probe = fopen(path, "r");
    int fresh = (probe == NULL);
    if (probe) fclose(probe);
    FILE *f = fopen(path, "a");
    if (!f) { fprintf(stderr, "ERROR: cannot open %s\n", path); exit(1); }
    if (fresh) fprintf(f, "%s\n", header);
    return f;
}

#define AGG_HEADER \
    "backend,algorithm,operation,payload_file,payload_bytes,correctness,rounds," \
    "mean_ns,median_ns,min_ns,max_ns,stddev_ns,p95_ns,p99_ns,ops_per_sec," \
    "mean_cycles,median_cycles,cycle_unit,payload_mb_per_sec,out_bytes,nist_level"

#define HASH_HEADER \
    "backend,record,algorithm,construction,payload_file,payload_bytes," \
    "payload_sha256,rounds,output_bytes,output_hex,verify"

static void agg_row(FILE *f, const char *algo, const char *op, const char *ok,
                    int rounds, const Stats *ns, const Stats *cy,
                    size_t out_bytes, int nist_level) {
    double ops = (ns->median > 0.0) ? 1e9 / ns->median : 0.0;
    double mbps = (ns->median > 0.0)
                ? ((double)g_payload_len / (ns->median / 1e9)) / 1e6 : 0.0;
    fprintf(f,
        "%s,%s,%s,%s,%zu,%s,%d,"
        "%.1f,%.1f,%.0f,%.0f,%.1f,%.0f,%.0f,%.2f,"
        "%.1f,%.1f,%s,%.3f,%zu,%d\n",
        BACKEND_SHORT, algo, op, g_payload_name, g_payload_len, ok, rounds,
        ns->mean, ns->median, ns->min, ns->max, ns->stddev, ns->p95, ns->p99, ops,
        cy->mean, cy->median, CYCLE_UNIT, mbps, out_bytes, nist_level);
    fflush(f);
}

static void hash_row(FILE *f, const char *record, const char *algo,
                     const char *construction, int rounds,
                     size_t out_bytes, const char *out_hex, const char *verify) {
    fprintf(f, "%s,%s,%s,%s,%s,%zu,%s,%d,%zu,%s,%s\n",
            BACKEND_SHORT, record, algo, construction,
            g_payload_name, g_payload_len, g_payload_sha256,
            rounds, out_bytes, out_hex, verify);
    fflush(f);
}

/* =========================================================================
 * Benchmarks
 * ========================================================================= */
static int bench_hash(FILE *agg, FILE *hcsv, const uint8_t *payload,
                      int iters, int warmup) {
    uint8_t digest[HASH_OUT_BYTES], check[HASH_OUT_BYTES];
    char digest_hex[2 * HASH_OUT_BYTES + 1];

    /* correctness: the hash must be deterministic over the payload */
    backend_hash(digest, payload, g_payload_len);
    backend_hash(check,  payload, g_payload_len);
    const char *ok = (memcmp(digest, check, HASH_OUT_BYTES) == 0) ? "PASS" : "FAIL";
    hex_encode(digest_hex, digest, HASH_OUT_BYTES);

    uint64_t *ns  = malloc((size_t)iters * sizeof(uint64_t));
    uint64_t *cyc = malloc((size_t)iters * sizeof(uint64_t));
    if (!ns || !cyc) { fprintf(stderr, "ERROR: out of memory\n"); exit(1); }

    for (int i = 0; i < warmup; i++)
        backend_hash(check, payload, g_payload_len);
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns(), c0 = cycles_begin();
        backend_hash(check, payload, g_payload_len);
        uint64_t c1 = cycles_end(), t1 = now_ns();
        ns[i]  = t1 - t0;
        cyc[i] = c1 - c0;
    }
    raw_dump(HASH_NAME, "hash", ns, cyc, iters);

    Stats sn, sc;
    compute_stats(ns, iters, &sn);
    compute_stats(cyc, iters, &sc);
    agg_row(agg, HASH_NAME, "hash", ok, iters, &sn, &sc, HASH_OUT_BYTES, 0);
    hash_row(hcsv, "hash", HASH_NAME, HASH_CONSTRUCTION, iters,
             HASH_OUT_BYTES, digest_hex, ok);

    printf("  %-14s hash    %s  median %10.0f ns  %10.0f %s  digest %s\n",
           HASH_NAME, ok, sn.median, sc.median, CYCLE_UNIT, digest_hex);
    free(ns); free(cyc);
    return strcmp(ok, "PASS") == 0;
}

static int bench_sign(FILE *agg, FILE *hcsv, OQS_SIG *sig, const char *algo,
                      int nist_level, const uint8_t *payload,
                      int iters, int warmup) {
    if (!sig) { fprintf(stderr, "ERROR: %s constructor returned NULL\n", algo); return 0; }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *sm = malloc(sig->length_signature);
    size_t smlen = 0;
    if (!pk || !sk || !sm) { fprintf(stderr, "ERROR: out of memory\n"); exit(1); }

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: %s keypair failed\n", algo);
        return 0;
    }

    /* correctness: sign/verify roundtrip over the payload + tamper check */
    const char *ok = "PASS";
    if (OQS_SIG_sign(sig, sm, &smlen, payload, g_payload_len, sk) != OQS_SUCCESS ||
        OQS_SIG_verify(sig, payload, g_payload_len, sm, smlen, pk) != OQS_SUCCESS)
        ok = "FAIL";
    else {
        sm[0] ^= 0x01;   /* tampered signature must NOT verify */
        if (OQS_SIG_verify(sig, payload, g_payload_len, sm, smlen, pk) == OQS_SUCCESS)
            ok = "FAIL";
        sm[0] ^= 0x01;
    }

    uint64_t *ns  = malloc((size_t)iters * sizeof(uint64_t));
    uint64_t *cyc = malloc((size_t)iters * sizeof(uint64_t));
    if (!ns || !cyc) { fprintf(stderr, "ERROR: out of memory\n"); exit(1); }
    Stats sn, sc;

    /* ── sign ── */
    for (int i = 0; i < warmup; i++)
        OQS_SIG_sign(sig, sm, &smlen, payload, g_payload_len, sk);
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns(), c0 = cycles_begin();
        OQS_SIG_sign(sig, sm, &smlen, payload, g_payload_len, sk);
        uint64_t c1 = cycles_end(), t1 = now_ns();
        ns[i]  = t1 - t0;
        cyc[i] = c1 - c0;
    }
    raw_dump(algo, "sign", ns, cyc, iters);
    compute_stats(ns, iters, &sn);
    compute_stats(cyc, iters, &sc);
    agg_row(agg, algo, "sign", ok, iters, &sn, &sc, smlen, nist_level);
    printf("  %-14s sign    %s  median %10.0f ns  %10.0f %s  sig %zu bytes\n",
           algo, ok, sn.median, sc.median, CYCLE_UNIT, smlen);

    /* signature detail row: size + SHA-256 fingerprint of the signature
     * produced by the LAST timed round (ML-DSA signing is hedged/randomized,
     * so signatures differ between rounds; the fingerprint identifies the
     * recorded one). */
    {
        uint8_t fp[32];
        char fp_hex[65];
        SHA256(sm, smlen, fp);
        hex_encode(fp_hex, fp, 32);
        char constr[256];
        snprintf(constr, sizeof(constr),
                 "%s signature over full payload; message hashing via %s (sha256 fingerprint of last-round signature)",
                 algo, HASH_NAME);
        hash_row(hcsv, "signature", algo, constr, iters, smlen, fp_hex, ok);
    }

    /* ── verify ── */
    for (int i = 0; i < warmup; i++)
        OQS_SIG_verify(sig, payload, g_payload_len, sm, smlen, pk);
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns(), c0 = cycles_begin();
        OQS_SIG_verify(sig, payload, g_payload_len, sm, smlen, pk);
        uint64_t c1 = cycles_end(), t1 = now_ns();
        ns[i]  = t1 - t0;
        cyc[i] = c1 - c0;
    }
    raw_dump(algo, "verify", ns, cyc, iters);
    compute_stats(ns, iters, &sn);
    compute_stats(cyc, iters, &sc);
    agg_row(agg, algo, "verify", ok, iters, &sn, &sc, smlen, nist_level);
    printf("  %-14s verify  %s  median %10.0f ns  %10.0f %s\n",
           algo, ok, sn.median, sc.median, CYCLE_UNIT);

    int pass = strcmp(ok, "PASS") == 0;
    free(pk); free(sk); free(sm); free(ns); free(cyc);
    OQS_SIG_free(sig);
    return pass;
}

/* =========================================================================
 * main
 * ========================================================================= */
int main(int argc, char **argv) {
    const char *file_path = NULL;
    const char *csv_path  = "file_sign_benchmark.csv";
    const char *hash_path = "file_sign_hashes.csv";
    int iters = 200, warmup = 20;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--file")    && i + 1 < argc) file_path = argv[++i];
        else if (!strcmp(argv[i], "--iters")   && i + 1 < argc) iters  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--warmup")  && i + 1 < argc) warmup = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--csv")     && i + 1 < argc) csv_path  = argv[++i];
        else if (!strcmp(argv[i], "--hashcsv") && i + 1 < argc) hash_path = argv[++i];
    }
    if (!file_path || iters < 1 || warmup < 0) {
        fprintf(stderr, "usage: %s --file PAYLOAD [--iters N] [--warmup N] "
                        "[--csv out.csv] [--hashcsv hashes.csv]\n", argv[0]);
        return 1;
    }

    /* ── load payload ── */
    FILE *pf = fopen(file_path, "rb");
    if (!pf) { fprintf(stderr, "ERROR: cannot open payload %s\n", file_path); return 1; }
    fseek(pf, 0, SEEK_END);
    long len = ftell(pf);
    fseek(pf, 0, SEEK_SET);
    if (len <= 0) { fprintf(stderr, "ERROR: payload %s is empty\n", file_path); return 1; }
    uint8_t *payload = malloc((size_t)len);
    if (!payload || fread(payload, 1, (size_t)len, pf) != (size_t)len) {
        fprintf(stderr, "ERROR: cannot read payload %s\n", file_path);
        return 1;
    }
    fclose(pf);
    g_payload_len = (size_t)len;

    static char base[512];
    strncpy(base, file_path, sizeof(base) - 1);
    g_payload_name = basename(base);

    uint8_t psha[32];
    SHA256(payload, g_payload_len, psha);
    hex_encode(g_payload_sha256, psha, 32);

    OQS_init();
    raw_init();
    FILE *agg  = csv_open(csv_path,  AGG_HEADER);
    FILE *hcsv = csv_open(hash_path, HASH_HEADER);

    printf("Backend %s — payload %s (%zu bytes, sha256 %.16s…), %d rounds (+%d warmup)\n",
           BACKEND_SHORT, g_payload_name, g_payload_len, g_payload_sha256,
           iters, warmup);

    int all = 1;
    all &= bench_hash(agg, hcsv, payload, iters, warmup);
    all &= bench_sign(agg, hcsv, SIG_44_NEW(), "ML-DSA-44", 2, payload, iters, warmup);
    all &= bench_sign(agg, hcsv, SIG_65_NEW(), "ML-DSA-65", 3, payload, iters, warmup);
    all &= bench_sign(agg, hcsv, SIG_87_NEW(), "ML-DSA-87", 5, payload, iters, warmup);

    fclose(agg);
    fclose(hcsv);
    raw_close();
    free(payload);
    printf("Backend %s: %s\n", BACKEND_SHORT, all ? "ALL PASS" : "FAILURES PRESENT");
    return all ? 0 : 2;
}
