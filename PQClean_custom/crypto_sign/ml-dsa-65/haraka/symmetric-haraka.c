#include "haraka.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * compress: Davies-Meyer-style chaining step cv <- haraka512(cv || block).
 */
static void compress(uint8_t cv[32], const uint8_t block[32]) {
    uint8_t in[64];
    memcpy(in, cv, 32);
    memcpy(in + 32, block, 32);
    haraka512(cv, in);
}

void PQCLEAN_MLDSA65_HARAKA_xof_init(xof_state *state) {
    memset(state->cv, 0, sizeof state->cv);
    state->buflen = 0;
    state->counter = 0;
}

void PQCLEAN_MLDSA65_HARAKA_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen) {
    size_t take;
    while (inlen > 0) {
        take = 32 - state->buflen;
        if (take > inlen) {
            take = inlen;
        }
        memcpy(state->buf + state->buflen, in, take);
        state->buflen += take;
        in += take;
        inlen -= take;
        if (state->buflen == 32) {
            compress(state->cv, state->buf);
            state->buflen = 0;
        }
    }
}

void PQCLEAN_MLDSA65_HARAKA_xof_finalize(xof_state *state, uint8_t domain) {
    state->buf[state->buflen++] = domain;
    while (state->buflen < 32) {
        state->buf[state->buflen++] = 0;
    }
    compress(state->cv, state->buf);
    state->buflen = 0;
    state->counter = 0;
}

void PQCLEAN_MLDSA65_HARAKA_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state) {
    uint8_t in[64];
    uint8_t block[32];
    size_t i, take;

    memcpy(in, state->cv, 32);
    while (outlen > 0) {
        memset(in + 32, 0, 32);
        for (i = 0; i < 8; ++i) {
            in[32 + i] = (uint8_t)(state->counter >> (8 * i));
        }
        haraka512(block, in);
        state->counter++;

        take = (outlen < 32) ? outlen : 32;
        memcpy(out, block, take);
        out += take;
        outlen -= take;
    }
}

/*
 * PQCLEAN_MLDSA65_HARAKA_dilithium_stream128_init / stream256_init
 *   Haraka-MD replacements for the SHAKE128/256 "stream" XOFs used for
 *   matrix expansion (poly_uniform) and eta/mask sampling
 *   (poly_uniform_eta, poly_uniform_gamma1).  The 2-byte nonce is absorbed
 *   little-endian, followed by xof_finalize with the matching domain byte
 *   (XOF_DOMAIN_MATRIX / XOF_DOMAIN_NOISE).
 */
void PQCLEAN_MLDSA65_HARAKA_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    PQCLEAN_MLDSA65_HARAKA_xof_init(state);
    PQCLEAN_MLDSA65_HARAKA_xof_absorb(state, seed, SEEDBYTES);
    PQCLEAN_MLDSA65_HARAKA_xof_absorb(state, t, 2);
    PQCLEAN_MLDSA65_HARAKA_xof_finalize(state, XOF_DOMAIN_MATRIX);
}

void PQCLEAN_MLDSA65_HARAKA_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    PQCLEAN_MLDSA65_HARAKA_xof_init(state);
    PQCLEAN_MLDSA65_HARAKA_xof_absorb(state, seed, CRHBYTES);
    PQCLEAN_MLDSA65_HARAKA_xof_absorb(state, t, 2);
    PQCLEAN_MLDSA65_HARAKA_xof_finalize(state, XOF_DOMAIN_NOISE);
}

void PQCLEAN_MLDSA65_HARAKA_dilithium_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    PQCLEAN_MLDSA65_HARAKA_xof_squeeze(out, nblocks * XOF_BLOCKBYTES, state);
}
