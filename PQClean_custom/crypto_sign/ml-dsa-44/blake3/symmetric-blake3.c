#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>

/*
 * PQCLEAN_MLDSA44_BLAKE3_dilithium_stream128_init / stream256_init
 *   BLAKE3-XOF replacements for the SHAKE128/256 "stream" XOFs used for
 *   matrix expansion (poly_uniform) and eta/mask sampling
 *   (poly_uniform_eta, poly_uniform_gamma1).  The 2-byte nonce is
 *   absorbed little-endian, followed by a 1-byte domain-separation value
 *   (XOF_DOMAIN_MATRIX / XOF_DOMAIN_NOISE) before squeezing begins.
 */
void PQCLEAN_MLDSA44_BLAKE3_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    blake3_hasher_init(&state->hasher);
    blake3_hasher_update(&state->hasher, seed, SEEDBYTES);
    blake3_hasher_update(&state->hasher, t, 2);
    {
        const uint8_t domain = XOF_DOMAIN_MATRIX;
        blake3_hasher_update(&state->hasher, &domain, 1);
    }
    state->squeezed = 0;
}

void PQCLEAN_MLDSA44_BLAKE3_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    blake3_hasher_init(&state->hasher);
    blake3_hasher_update(&state->hasher, seed, CRHBYTES);
    blake3_hasher_update(&state->hasher, t, 2);
    {
        const uint8_t domain = XOF_DOMAIN_NOISE;
        blake3_hasher_update(&state->hasher, &domain, 1);
    }
    state->squeezed = 0;
}

void PQCLEAN_MLDSA44_BLAKE3_dilithium_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    size_t outlen = nblocks * XOF_BLOCKBYTES;
    blake3_hasher_finalize_seek(&state->hasher, state->squeezed, out, outlen);
    state->squeezed += outlen;
}

/*
 * PQCLEAN_MLDSA44_BLAKE3_xof_*
 *   Generic incremental BLAKE3 XOF used for the "H/CRH" role (tr, mu,
 *   rhoprime, c~ -- domain XOF_DOMAIN_HASH) and for poly_challenge
 *   (domain XOF_DOMAIN_CHALLENGE).  xof_absorb may be called any number
 *   of times before xof_finalize (blake3_hasher_update); xof_finalize
 *   appends the 1-byte domain and resets the squeeze cursor;
 *   xof_squeeze may be called any number of times afterwards
 *   (blake3_hasher_finalize_seek at increasing offsets).
 */
void PQCLEAN_MLDSA44_BLAKE3_xof_init(xof_state *state) {
    blake3_hasher_init(&state->hasher);
    state->squeezed = 0;
}

void PQCLEAN_MLDSA44_BLAKE3_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen) {
    if (inlen) {
        blake3_hasher_update(&state->hasher, in, inlen);
    }
}

void PQCLEAN_MLDSA44_BLAKE3_xof_finalize(xof_state *state, uint8_t domain) {
    blake3_hasher_update(&state->hasher, &domain, 1);
    state->squeezed = 0;
}

void PQCLEAN_MLDSA44_BLAKE3_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state) {
    blake3_hasher_finalize_seek(&state->hasher, state->squeezed, out, outlen);
    state->squeezed += outlen;
}
