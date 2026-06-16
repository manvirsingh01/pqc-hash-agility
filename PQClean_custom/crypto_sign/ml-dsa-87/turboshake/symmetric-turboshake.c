#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>

/*
 * PQCLEAN_MLDSA87_TURBO_dilithium_stream128_init / stream256_init
 *   TurboSHAKE128/256 (n_r=12, RFC 9861) replacements for the SHAKE128/256
 *   "stream" XOFs used for matrix expansion (poly_uniform) and eta/mask
 *   sampling (poly_uniform_eta, poly_uniform_gamma1).  The 2-byte nonce is
 *   absorbed little-endian, followed by a domain-separation byte
 *   (XOF_DOMAIN_MATRIX / XOF_DOMAIN_NOISE).
 */
void PQCLEAN_MLDSA87_TURBO_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    TurboSHAKE128_Initialize(state);
    TurboSHAKE_Absorb(state, seed, SEEDBYTES);
    TurboSHAKE_Absorb(state, t, 2);
    TurboSHAKE_AbsorbDomainSeparationByte(state, XOF_DOMAIN_MATRIX);
}

void PQCLEAN_MLDSA87_TURBO_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    TurboSHAKE256_Initialize(state);
    TurboSHAKE_Absorb(state, seed, CRHBYTES);
    TurboSHAKE_Absorb(state, t, 2);
    TurboSHAKE_AbsorbDomainSeparationByte(state, XOF_DOMAIN_NOISE);
}

void PQCLEAN_MLDSA87_TURBO_dilithium_squeezeblocks128(uint8_t *out, size_t nblocks, stream128_state *state) {
    TurboSHAKE_Squeeze(state, out, nblocks * STREAM128_BLOCKBYTES);
}

void PQCLEAN_MLDSA87_TURBO_dilithium_squeezeblocks256(uint8_t *out, size_t nblocks, stream256_state *state) {
    TurboSHAKE_Squeeze(state, out, nblocks * STREAM256_BLOCKBYTES);
}

/*
 * PQCLEAN_MLDSA87_TURBO_xof_*
 *   Generic incremental TurboSHAKE256 XOF used for the "H/CRH" role
 *   (tr, mu, rhoprime, c~ -- domain XOF_DOMAIN_HASH) and for
 *   poly_challenge (domain XOF_DOMAIN_CHALLENGE).  xof_absorb may be
 *   called any number of times before xof_finalize; xof_squeeze may be
 *   called any number of times afterwards (TurboSHAKE_Squeeze supports
 *   arbitrary-length, repeated squeeze calls).
 */
void PQCLEAN_MLDSA87_TURBO_xof_init(xof_state *state) {
    TurboSHAKE256_Initialize(state);
}

void PQCLEAN_MLDSA87_TURBO_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen) {
    if (inlen) {
        TurboSHAKE_Absorb(state, in, inlen);
    }
}

void PQCLEAN_MLDSA87_TURBO_xof_finalize(xof_state *state, uint8_t domain) {
    TurboSHAKE_AbsorbDomainSeparationByte(state, domain);
}

void PQCLEAN_MLDSA87_TURBO_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state) {
    TurboSHAKE_Squeeze(state, out, outlen);
}
