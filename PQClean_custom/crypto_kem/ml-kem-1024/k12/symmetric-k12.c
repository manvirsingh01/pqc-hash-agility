#include "fips202.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * PQCLEAN_MLKEM1024_K12_kyber_k12_absorb
 *   KT128 (KangarooTwelve, RFC 9861) replacement for the SHAKE128 matrix
 *   expansion XOF.  Customization string 0x1F (K12_CUSTOM_MATRIX).
 *   Output length is left open (0) so xof_squeezeblocks can squeeze
 *   as many XOF_BLOCKBYTES blocks as the rejection-sampling loop needs.
 */
void PQCLEAN_MLKEM1024_K12_kyber_k12_absorb(xof_state *state,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y) {
    uint8_t extseed[KYBER_SYMBYTES + 2];
    const uint8_t custom = K12_CUSTOM_MATRIX;

    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;

    KangarooTwelve_Initialize(state, 128, 0);
    KangarooTwelve_Update(state, extseed, sizeof(extseed));
    KangarooTwelve_Final(state, NULL, &custom, 1);
}

void PQCLEAN_MLKEM1024_K12_kyber_k12_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    KangarooTwelve_Squeeze(state, out, nblocks * XOF_BLOCKBYTES);
}

void PQCLEAN_MLKEM1024_K12_kyber_k12_ctx_release(xof_state *state) {
    (void)state;
}

/*
 * PQCLEAN_MLKEM1024_K12_kyber_k12_prf
 *   KT256 (KangarooTwelve, RFC 9861) replacement for the SHAKE256 PRF used
 *   in CBD noise generation.  Customization string 0x2F (K12_CUSTOM_CBD).
 */
void PQCLEAN_MLKEM1024_K12_kyber_k12_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t extkey[KYBER_SYMBYTES + 1];
    const uint8_t custom = K12_CUSTOM_CBD;

    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = nonce;

    KT256(extkey, sizeof(extkey), out, outlen, &custom, 1);
}

/*
 * PQCLEAN_MLKEM1024_K12_kyber_k12_rkprf
 *   KT256 (KangarooTwelve, RFC 9861) replacement for the SHAKE256 "J"
 *   function used to derive the implicit-rejection shared secret.
 *   Customization string 0x3F (K12_CUSTOM_KDF).
 */
void PQCLEAN_MLKEM1024_K12_kyber_k12_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]) {
    xof_state state;
    const uint8_t custom = K12_CUSTOM_KDF;

    KangarooTwelve_Initialize(&state, 256, KYBER_SSBYTES);
    KangarooTwelve_Update(&state, key, KYBER_SYMBYTES);
    KangarooTwelve_Update(&state, input, KYBER_CIPHERTEXTBYTES);
    KangarooTwelve_Final(&state, out, &custom, 1);
}
