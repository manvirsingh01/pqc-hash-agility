#include "fips202.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_absorb
 *   BLAKE3 XOF replacement for the SHAKE128 matrix expansion XOF.
 *   Domain byte 0x1F (BLAKE3_CUSTOM_MATRIX) is appended after the seed
 *   and the (x, y) matrix-position bytes.
 */
void PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_absorb(xof_state *state,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y) {
    uint8_t extseed[KYBER_SYMBYTES + 3];

    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;
    extseed[KYBER_SYMBYTES + 2] = BLAKE3_CUSTOM_MATRIX;

    blake3_hasher_init(&state->hasher);
    blake3_hasher_update(&state->hasher, extseed, sizeof(extseed));
    state->squeezed = 0;
}

void PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    size_t outlen = nblocks * XOF_BLOCKBYTES;
    blake3_hasher_finalize_seek(&state->hasher, state->squeezed, out, outlen);
    state->squeezed += outlen;
}

void PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_ctx_release(xof_state *state) {
    (void)state;
}

/*
 * PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_prf
 *   BLAKE3 XOF replacement for the SHAKE256 PRF used in CBD noise
 *   generation.  Domain byte 0x2F (BLAKE3_CUSTOM_CBD).
 */
void PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t extkey[KYBER_SYMBYTES + 2];
    blake3_hasher hasher;

    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES + 0] = nonce;
    extkey[KYBER_SYMBYTES + 1] = BLAKE3_CUSTOM_CBD;

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, extkey, sizeof(extkey));
    blake3_hasher_finalize_seek(&hasher, 0, out, outlen);
}

/*
 * PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_rkprf
 *   BLAKE3 XOF replacement for the SHAKE256 "J" function used to derive
 *   the implicit-rejection shared secret.  Domain byte 0x3F
 *   (BLAKE3_CUSTOM_KDF).
 */
void PQCLEAN_MLKEM1024_BLAKE3_kyber_blake3_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]) {
    blake3_hasher hasher;
    const uint8_t custom = BLAKE3_CUSTOM_KDF;

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, key, KYBER_SYMBYTES);
    blake3_hasher_update(&hasher, input, KYBER_CIPHERTEXTBYTES);
    blake3_hasher_update(&hasher, &custom, 1);
    blake3_hasher_finalize_seek(&hasher, 0, out, KYBER_SSBYTES);
}
