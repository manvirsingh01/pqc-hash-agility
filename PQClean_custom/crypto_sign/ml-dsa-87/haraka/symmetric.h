#ifndef PQCLEAN_MLDSA87_HARAKA_SYMMETRIC_H
#define PQCLEAN_MLDSA87_HARAKA_SYMMETRIC_H
#include "params.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Haraka-MD: a custom Merkle-Damgard-style hash/XOF built on top of
 * haraka512 (512-bit input / 256-bit output AES-round permutation,
 * Davies-Meyer), substituting for the SHAKE128/SHAKE256 uses inside
 * ML-DSA, per the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (stream128, poly_uniform)            -> Haraka-MD XOF, domain 0x1F
 *   Vector 2: Eta/mask noise sampling (stream256, poly_uniform_eta/
 *             poly_uniform_gamma1)                                   -> Haraka-MD XOF, domain 0x2F
 *   Vector 3: "H/CRH" role (tr=H(pk), mu=CRH(tr,msg), rhoprime=H(K,
 *             rnd,mu), c~=H(mu,w1))                                  -> Haraka-MD XOF, domain 0x3F
 *   Vector 4: Challenge polynomial sampling (poly_challenge)         -> Haraka-MD XOF, domain 0x4F
 *
 * Construction (NOT a FIPS-approved mode -- a benchmarking substitution
 * only):
 *   - 32-byte chaining value cv, initialized to all-zero (IV = 0^256).
 *   - Absorb: input is buffered into 32-byte blocks; each full block is
 *     compressed via cv = haraka512(cv || block)[0:32].
 *   - Finalize: the (possibly empty, 0-31 byte) remaining buffer is
 *     padded with a single domain-separation byte followed by zeros to
 *     32 bytes, then compressed into cv exactly like an absorb block.
 *     This also resets the output block counter to 0.
 *   - Squeeze: output block i = haraka512(cv || LE64(i) || 0^24)[0:32],
 *     for i = 0, 1, 2, ... -- i.e. the 64-byte compression input is the
 *     chaining value concatenated with an 8-byte little-endian counter
 *     and 24 zero bytes. Output is the concatenation of these 32-byte
 *     blocks, truncated to the requested length.
 *
 * All four vectors and both stream128/stream256 use the same 32-byte
 * block size, so a single xof_state type and block size serve all uses.
 */
#define XOF_DOMAIN_MATRIX    0x1F
#define XOF_DOMAIN_NOISE     0x2F
#define XOF_DOMAIN_HASH      0x3F
#define XOF_DOMAIN_CHALLENGE 0x4F

#define STREAM128_BLOCKBYTES 32
#define STREAM256_BLOCKBYTES 32
#define XOF_BLOCKBYTES       32

typedef struct {
    uint8_t cv[32];
    uint8_t buf[32];
    size_t buflen;
    uint64_t counter;
} xof_state;
typedef xof_state stream128_state;
typedef xof_state stream256_state;

void PQCLEAN_MLDSA87_HARAKA_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce);
void PQCLEAN_MLDSA87_HARAKA_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce);
void PQCLEAN_MLDSA87_HARAKA_dilithium_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state);

void PQCLEAN_MLDSA87_HARAKA_xof_init(xof_state *state);
void PQCLEAN_MLDSA87_HARAKA_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen);
void PQCLEAN_MLDSA87_HARAKA_xof_finalize(xof_state *state, uint8_t domain);
void PQCLEAN_MLDSA87_HARAKA_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state);

#define stream128_init(STATE, SEED, NONCE) PQCLEAN_MLDSA87_HARAKA_dilithium_stream128_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA87_HARAKA_dilithium_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream128_release(STATE) ((void)(STATE))

#define stream256_init(STATE, SEED, NONCE) PQCLEAN_MLDSA87_HARAKA_dilithium_stream256_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA87_HARAKA_dilithium_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_release(STATE) ((void)(STATE))

#define xof_init(STATE) PQCLEAN_MLDSA87_HARAKA_xof_init(STATE)
#define xof_absorb(STATE, IN, INLEN) PQCLEAN_MLDSA87_HARAKA_xof_absorb(STATE, IN, INLEN)
#define xof_finalize(STATE, DOMAIN) PQCLEAN_MLDSA87_HARAKA_xof_finalize(STATE, DOMAIN)
#define xof_squeeze(OUT, OUTLEN, STATE) PQCLEAN_MLDSA87_HARAKA_xof_squeeze(OUT, OUTLEN, STATE)
#define xof_release(STATE) ((void)(STATE))

#endif
