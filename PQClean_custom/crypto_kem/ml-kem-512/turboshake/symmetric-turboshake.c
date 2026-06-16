#include "fips202.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * PQCLEAN_MLKEM512_TURBO_kyber_turboshake128_absorb
 *   TurboSHAKE128 (n_r=12, RFC 9861) replacement for the SHAKE128 matrix
 *   expansion XOF.  Domain separation byte 0x1F (TURBOSHAKE_DOMAIN_MATRIX).
 */
void PQCLEAN_MLKEM512_TURBO_kyber_turboshake128_absorb(xof_state *state,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y) {
    uint8_t extseed[KYBER_SYMBYTES + 2];

    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;

    TurboSHAKE128_Initialize(state);
    TurboSHAKE_Absorb(state, extseed, sizeof(extseed));
    TurboSHAKE_AbsorbDomainSeparationByte(state, TURBOSHAKE_DOMAIN_MATRIX);
}

void PQCLEAN_MLKEM512_TURBO_kyber_turboshake_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    TurboSHAKE_Squeeze(state, out, nblocks * XOF_BLOCKBYTES);
}

void PQCLEAN_MLKEM512_TURBO_kyber_turboshake_ctx_release(xof_state *state) {
    (void)state;
}

/*
 * PQCLEAN_MLKEM512_TURBO_kyber_turboshake256_prf
 *   TurboSHAKE256 (n_r=12, RFC 9861) replacement for the SHAKE256 PRF used
 *   in CBD noise generation.  Domain separation byte 0x2F (TURBOSHAKE_DOMAIN_CBD).
 */
void PQCLEAN_MLKEM512_TURBO_kyber_turboshake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t extkey[KYBER_SYMBYTES + 1];
    TurboSHAKE_Instance state;

    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = nonce;

    TurboSHAKE256_Initialize(&state);
    TurboSHAKE_Absorb(&state, extkey, sizeof(extkey));
    TurboSHAKE_AbsorbDomainSeparationByte(&state, TURBOSHAKE_DOMAIN_CBD);
    TurboSHAKE_Squeeze(&state, out, outlen);
}

/*
 * PQCLEAN_MLKEM512_TURBO_kyber_turboshake256_rkprf
 *   TurboSHAKE256 (n_r=12, RFC 9861) replacement for the SHAKE256 "J" function
 *   used to derive the implicit-rejection shared secret.  Domain separation
 *   byte 0x3F (TURBOSHAKE_DOMAIN_KDF).
 */
void PQCLEAN_MLKEM512_TURBO_kyber_turboshake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]) {
    TurboSHAKE_Instance state;

    TurboSHAKE256_Initialize(&state);
    TurboSHAKE_Absorb(&state, key, KYBER_SYMBYTES);
    TurboSHAKE_Absorb(&state, input, KYBER_CIPHERTEXTBYTES);
    TurboSHAKE_AbsorbDomainSeparationByte(&state, TURBOSHAKE_DOMAIN_KDF);
    TurboSHAKE_Squeeze(&state, out, KYBER_SSBYTES);
}
