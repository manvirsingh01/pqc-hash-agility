#include "fips202.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * PQCLEAN_MLKEM768_XOODYAK_kyber_xoodyak_absorb
 *   Xoodyak (Cyclist hash mode) replacement for the SHAKE128 matrix
 *   expansion XOF.  Domain byte 0x1F (XOODYAK_CUSTOM_MATRIX) is appended
 *   after the seed and the (x, y) matrix-position bytes.
 */
void PQCLEAN_MLKEM768_XOODYAK_kyber_xoodyak_absorb(xof_state *state,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y) {
    uint8_t extseed[KYBER_SYMBYTES + 3];

    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;
    extseed[KYBER_SYMBYTES + 2] = XOODYAK_CUSTOM_MATRIX;

    Xoodyak_Initialize(state, NULL, 0, NULL, 0, NULL, 0);
    Xoodyak_Absorb(state, extseed, sizeof(extseed));
}

void PQCLEAN_MLKEM768_XOODYAK_kyber_xoodyak_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    Xoodyak_Squeeze(state, out, nblocks * XOF_BLOCKBYTES);
}

void PQCLEAN_MLKEM768_XOODYAK_kyber_xoodyak_ctx_release(xof_state *state) {
    (void)state;
}

/*
 * PQCLEAN_MLKEM768_XOODYAK_kyber_xoodyak_prf
 *   Xoodyak (Cyclist hash mode) replacement for the SHAKE256 PRF used in
 *   CBD noise generation.  Domain byte 0x2F (XOODYAK_CUSTOM_CBD).
 */
void PQCLEAN_MLKEM768_XOODYAK_kyber_xoodyak_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t extkey[KYBER_SYMBYTES + 2];
    xof_state state;

    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES + 0] = nonce;
    extkey[KYBER_SYMBYTES + 1] = XOODYAK_CUSTOM_CBD;

    Xoodyak_Initialize(&state, NULL, 0, NULL, 0, NULL, 0);
    Xoodyak_Absorb(&state, extkey, sizeof(extkey));
    Xoodyak_Squeeze(&state, out, outlen);
}

/*
 * PQCLEAN_MLKEM768_XOODYAK_kyber_xoodyak_rkprf
 *   Xoodyak (Cyclist hash mode) replacement for the SHAKE256 "J" function
 *   used to derive the implicit-rejection shared secret.  Domain byte
 *   0x3F (XOODYAK_CUSTOM_KDF).
 */
void PQCLEAN_MLKEM768_XOODYAK_kyber_xoodyak_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]) {
    xof_state state;
    const uint8_t custom = XOODYAK_CUSTOM_KDF;

    Xoodyak_Initialize(&state, NULL, 0, NULL, 0, NULL, 0);
    Xoodyak_Absorb(&state, key, KYBER_SYMBYTES);
    Xoodyak_Absorb(&state, input, KYBER_CIPHERTEXTBYTES);
    Xoodyak_Absorb(&state, &custom, 1);
    Xoodyak_Squeeze(&state, out, KYBER_SSBYTES);
}
