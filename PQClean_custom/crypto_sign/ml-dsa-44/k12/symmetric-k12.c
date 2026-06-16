#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>

/*
 * PQCLEAN_MLDSA44_K12_dilithium_stream128_init / stream256_init
 *   KT128/KT256 (KangarooTwelve, RFC 9861) replacements for the
 *   SHAKE128/256 "stream" XOFs used for matrix expansion (poly_uniform)
 *   and eta/mask sampling (poly_uniform_eta, poly_uniform_gamma1).  The
 *   2-byte nonce is absorbed little-endian, then KangarooTwelve_Final()
 *   is called with a 1-byte customization string (XOF_DOMAIN_MATRIX /
 *   XOF_DOMAIN_NOISE) and unbounded output (0), so squeezeblocks can
 *   later draw as many blocks as the rejection-sampling loop needs.
 */
void PQCLEAN_MLDSA44_K12_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
    uint8_t t[2];
    const uint8_t custom = XOF_DOMAIN_MATRIX;
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    KangarooTwelve_Initialize(state, 128, 0);
    KangarooTwelve_Update(state, seed, SEEDBYTES);
    KangarooTwelve_Update(state, t, 2);
    KangarooTwelve_Final(state, NULL, &custom, 1);
}

void PQCLEAN_MLDSA44_K12_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    uint8_t t[2];
    const uint8_t custom = XOF_DOMAIN_NOISE;
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    KangarooTwelve_Initialize(state, 256, 0);
    KangarooTwelve_Update(state, seed, CRHBYTES);
    KangarooTwelve_Update(state, t, 2);
    KangarooTwelve_Final(state, NULL, &custom, 1);
}

void PQCLEAN_MLDSA44_K12_dilithium_squeezeblocks128(uint8_t *out, size_t nblocks, stream128_state *state) {
    KangarooTwelve_Squeeze(state, out, nblocks * STREAM128_BLOCKBYTES);
}

void PQCLEAN_MLDSA44_K12_dilithium_squeezeblocks256(uint8_t *out, size_t nblocks, stream256_state *state) {
    KangarooTwelve_Squeeze(state, out, nblocks * STREAM256_BLOCKBYTES);
}

/*
 * PQCLEAN_MLDSA44_K12_xof_*
 *   Generic incremental KT256 XOF used for the "H/CRH" role (tr, mu,
 *   rhoprime, c~ -- domain XOF_DOMAIN_HASH) and for poly_challenge
 *   (domain XOF_DOMAIN_CHALLENGE).  xof_absorb may be called any number
 *   of times before xof_finalize (KangarooTwelve_Update); xof_finalize
 *   calls KangarooTwelve_Final() with the 1-byte domain as the
 *   customization string and unbounded output, after which xof_squeeze
 *   may be called any number of times (KangarooTwelve_Squeeze).
 */
void PQCLEAN_MLDSA44_K12_xof_init(xof_state *state) {
    KangarooTwelve_Initialize(state, 256, 0);
}

void PQCLEAN_MLDSA44_K12_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen) {
    if (inlen) {
        KangarooTwelve_Update(state, in, inlen);
    }
}

void PQCLEAN_MLDSA44_K12_xof_finalize(xof_state *state, uint8_t domain) {
    KangarooTwelve_Final(state, NULL, &domain, 1);
}

void PQCLEAN_MLDSA44_K12_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state) {
    KangarooTwelve_Squeeze(state, out, outlen);
}
