#include "fips202.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void set_counter(uint8_t block[64], uint64_t counter) {
    int i;
    for (i = 0; i < 8; i++) {
        block[56 + i] = (uint8_t)(counter >> (8 * i));
    }
}

/*
 * PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_absorb
 *   Haraka-CTR replacement for the SHAKE128 matrix expansion XOF.
 *   Domain byte 0x1F (HARAKA_CUSTOM_MATRIX).  See symmetric.h for the
 *   non-standard counter-mode construction.
 */
void PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_absorb(xof_state *state,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y) {
    memset(state->block, 0, sizeof(state->block));
    memcpy(state->block, seed, KYBER_SYMBYTES);
    state->block[KYBER_SYMBYTES + 0] = x;
    state->block[KYBER_SYMBYTES + 1] = y;
    state->block[KYBER_SYMBYTES + 2] = HARAKA_CUSTOM_MATRIX;
    state->counter = 0;
}

void PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    size_t i;
    for (i = 0; i < nblocks; i++) {
        set_counter(state->block, state->counter);
        haraka512(out + i * XOF_BLOCKBYTES, state->block);
        state->counter++;
    }
}

void PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_ctx_release(xof_state *state) {
    (void)state;
}

/*
 * PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_prf
 *   Haraka-CTR replacement for the SHAKE256 PRF used in CBD noise
 *   generation.  Domain byte 0x2F (HARAKA_CUSTOM_CBD).
 */
void PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t block[64];
    uint8_t tmp[XOF_BLOCKBYTES];
    uint64_t counter = 0;
    size_t produced = 0;
    size_t chunk;

    memset(block, 0, sizeof(block));
    memcpy(block, key, KYBER_SYMBYTES);
    block[KYBER_SYMBYTES + 0] = nonce;
    block[KYBER_SYMBYTES + 1] = HARAKA_CUSTOM_CBD;

    while (produced < outlen) {
        set_counter(block, counter++);
        haraka512(tmp, block);
        chunk = (outlen - produced < XOF_BLOCKBYTES) ? (outlen - produced) : XOF_BLOCKBYTES;
        memcpy(out + produced, tmp, chunk);
        produced += chunk;
    }
}

/*
 * PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_rkprf
 *   Haraka-CTR/MD replacement for the SHAKE256 "J" function used to
 *   derive the implicit-rejection shared secret.  Domain byte 0x3F
 *   (HARAKA_CUSTOM_KDF).  Chains Haraka512 as a Merkle-Damgard
 *   compression function over key || ciphertext (whose length is always
 *   a multiple of 32 bytes for ML-KEM).
 */
void PQCLEAN_MLKEM1024_HARAKA_kyber_haraka_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]) {
    uint8_t cv[32];
    uint8_t block[64];
    size_t i;

    memcpy(cv, key, sizeof(cv));

    for (i = 0; i < KYBER_CIPHERTEXTBYTES; i += 32) {
        memcpy(block, cv, 32);
        memcpy(block + 32, input + i, 32);
        haraka512(cv, block);
    }

    memset(block, 0, sizeof(block));
    memcpy(block, cv, 32);
    block[32] = HARAKA_CUSTOM_KDF;
    haraka512(out, block);
}
