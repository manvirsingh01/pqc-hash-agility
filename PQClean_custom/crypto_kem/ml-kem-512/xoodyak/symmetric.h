#ifndef PQCLEAN_MLKEM512_XOODYAK_SYMMETRIC_H
#define PQCLEAN_MLKEM512_XOODYAK_SYMMETRIC_H
#include "Xoodyak.h"
#include "fips202.h"
#include "params.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Xoodyak (NIST LWC finalist, sponge over the 384-bit Xoodoo permutation,
 * via XKCP's Cyclist construction) substitution for the SHAKE128/SHAKE256
 * uses inside ML-KEM, per the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (XOF)         -> Xoodyak hash mode, domain 0x1F
 *   Vector 2: CBD noise generation (PRF)      -> Xoodyak hash mode, domain 0x2F
 *   Vector 4: Implicit-rejection KDF (rkprf)  -> Xoodyak hash mode, domain 0x3F
 * Vector 3 (hash_h/hash_g, the FO transform) is intentionally left as
 * SHA3-256/SHA3-512 -- it is NOT part of the SHAKE/Xoodyak swap.
 *
 * Xoodyak's Cyclist mode is used as a plain sponge: Initialize() with no
 * key selects Cyclist_ModeHash (absorb/squeeze rate = Xoodyak_Rhash = 16
 * bytes). The single-byte domain values are appended to the absorbed
 * input, mirroring the customization-string convention used by the
 * K12/TurboSHAKE/BLAKE3 variants.
 */
#define XOODYAK_CUSTOM_MATRIX 0x1F
#define XOODYAK_CUSTOM_CBD    0x2F
#define XOODYAK_CUSTOM_KDF    0x3F

typedef Xoodyak_Instance xof_state;

void PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_absorb(xof_state *s,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y);

void PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *s);

void PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_ctx_release(xof_state *s);

void PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

void PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

/* Xoodyak's hash-mode squeeze rate (Xoodyak_Rhash). Cyclist_Squeeze()
 * handles arbitrary lengths internally, so this just matches the native
 * rate for efficiency in the rejection-sampling squeeze loop. */
#define XOF_BLOCKBYTES 16

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_rkprf(OUT, KEY, INPUT)

#endif
