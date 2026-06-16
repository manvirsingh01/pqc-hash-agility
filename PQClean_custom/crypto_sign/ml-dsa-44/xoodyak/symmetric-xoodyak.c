#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>

/*
 * PQCLEAN_MLDSA44_XOODYAK_dilithium_stream128_init / stream256_init
 *   Xoodyak (Cyclist hash mode) replacements for the SHAKE128/256 "stream"
 *   XOFs used for matrix expansion (poly_uniform) and eta/mask sampling
 *   (poly_uniform_eta, poly_uniform_gamma1).  The 2-byte nonce is absorbed
 *   little-endian, followed by a 1-byte domain-separation value
 *   (XOF_DOMAIN_MATRIX / XOF_DOMAIN_NOISE) before squeezing begins.
 */
void PQCLEAN_MLDSA44_XOODYAK_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
    uint8_t t[2];
    const uint8_t domain = XOF_DOMAIN_MATRIX;
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    Xoodyak_Initialize(state, NULL, 0, NULL, 0, NULL, 0);
    Xoodyak_Absorb(state, seed, SEEDBYTES);
    Xoodyak_Absorb(state, t, 2);
    Xoodyak_Absorb(state, &domain, 1);
}

void PQCLEAN_MLDSA44_XOODYAK_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    uint8_t t[2];
    const uint8_t domain = XOF_DOMAIN_NOISE;
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    Xoodyak_Initialize(state, NULL, 0, NULL, 0, NULL, 0);
    Xoodyak_Absorb(state, seed, CRHBYTES);
    Xoodyak_Absorb(state, t, 2);
    Xoodyak_Absorb(state, &domain, 1);
}

void PQCLEAN_MLDSA44_XOODYAK_dilithium_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    Xoodyak_Squeeze(state, out, nblocks * XOF_BLOCKBYTES);
}

/*
 * PQCLEAN_MLDSA44_XOODYAK_xof_*
 *   Generic incremental Xoodyak (Cyclist hash mode) XOF used for the
 *   "H/CRH" role (tr, mu, rhoprime, c~ -- domain XOF_DOMAIN_HASH) and for
 *   poly_challenge (domain XOF_DOMAIN_CHALLENGE).  xof_absorb may be
 *   called any number of times before xof_finalize (Xoodyak_Absorb);
 *   xof_finalize absorbs the 1-byte domain; xof_squeeze may be called any
 *   number of times afterwards (Xoodyak_Squeeze).
 */
void PQCLEAN_MLDSA44_XOODYAK_xof_init(xof_state *state) {
    Xoodyak_Initialize(state, NULL, 0, NULL, 0, NULL, 0);
}

void PQCLEAN_MLDSA44_XOODYAK_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen) {
    if (inlen) {
        Xoodyak_Absorb(state, in, inlen);
    }
}

void PQCLEAN_MLDSA44_XOODYAK_xof_finalize(xof_state *state, uint8_t domain) {
    Xoodyak_Absorb(state, &domain, 1);
}

void PQCLEAN_MLDSA44_XOODYAK_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state) {
    Xoodyak_Squeeze(state, out, outlen);
}
