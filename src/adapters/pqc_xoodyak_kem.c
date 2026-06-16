/*
 * pqc_xoodyak_kem.c
 *
 * See pqc_xoodyak_kem.h.  Thin OQS_KEM-shaped wrappers around the
 * Xoodyak-substituted PQClean ML-KEM implementations.
 */
#include "pqc_xoodyak_kem.h"

#include <stdlib.h>
#include <string.h>

#include "/root/PQClean/crypto_kem/ml-kem-512/xoodyak/api.h"
#include "/root/PQClean/crypto_kem/ml-kem-768/xoodyak/api.h"
#include "/root/PQClean/crypto_kem/ml-kem-1024/xoodyak/api.h"

/* ---------------------------------------------------------------- */
/* ML-KEM-512-XOODYAK                                                    */
/* ---------------------------------------------------------------- */
static OQS_STATUS xoodyak_512_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM512_XOODYAK_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS xoodyak_512_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM512_XOODYAK_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS xoodyak_512_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM512_XOODYAK_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-KEM-768-XOODYAK                                                    */
/* ---------------------------------------------------------------- */
static OQS_STATUS xoodyak_768_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM768_XOODYAK_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS xoodyak_768_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM768_XOODYAK_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS xoodyak_768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM768_XOODYAK_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-KEM-1024-XOODYAK                                                   */
/* ---------------------------------------------------------------- */
static OQS_STATUS xoodyak_1024_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM1024_XOODYAK_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS xoodyak_1024_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM1024_XOODYAK_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS xoodyak_1024_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM1024_XOODYAK_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* Constructors                                                      */
/* ---------------------------------------------------------------- */
static OQS_KEM *xoodyak_kem_alloc(const char *method_name,
                               uint8_t nist_level,
                               size_t pk_len, size_t sk_len, size_t ct_len, size_t ss_len,
                               OQS_STATUS (*keypair)(uint8_t *, uint8_t *),
                               OQS_STATUS (*encaps)(uint8_t *, uint8_t *, const uint8_t *),
                               OQS_STATUS (*decaps)(uint8_t *, const uint8_t *, const uint8_t *)) {
	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (!kem) {
		return NULL;
	}
	memset(kem, 0, sizeof(OQS_KEM));

	kem->method_name        = method_name;
	kem->alg_version        = "Xoodyak (Cyclist hash mode, XKCP) substitution -- NON-FIPS";
	kem->claimed_nist_level = nist_level;
	kem->ind_cca            = true;
	kem->length_public_key  = pk_len;
	kem->length_secret_key  = sk_len;
	kem->length_ciphertext  = ct_len;
	kem->length_shared_secret = ss_len;
	kem->length_keypair_seed  = 0;  /* derand keypair not implemented for this variant */
	kem->length_encaps_seed   = 0;  /* derand encaps not implemented for this variant  */

	kem->keypair_derand = NULL;
	kem->keypair        = keypair;
	kem->encaps_derand  = NULL;
	kem->encaps         = encaps;
	kem->decaps         = decaps;

	return kem;
}

OQS_KEM *OQS_KEM_ml_kem_512_xoodyak_new(void) {
	return xoodyak_kem_alloc("ML-KEM-512-XOODYAK", 1,
	                      PQCLEAN_MLKEM512_XOODYAK_CRYPTO_PUBLICKEYBYTES,
	                      PQCLEAN_MLKEM512_XOODYAK_CRYPTO_SECRETKEYBYTES,
	                      PQCLEAN_MLKEM512_XOODYAK_CRYPTO_CIPHERTEXTBYTES,
	                      PQCLEAN_MLKEM512_XOODYAK_CRYPTO_BYTES,
	                      xoodyak_512_keypair, xoodyak_512_encaps, xoodyak_512_decaps);
}

OQS_KEM *OQS_KEM_ml_kem_768_xoodyak_new(void) {
	return xoodyak_kem_alloc("ML-KEM-768-XOODYAK", 3,
	                      PQCLEAN_MLKEM768_XOODYAK_CRYPTO_PUBLICKEYBYTES,
	                      PQCLEAN_MLKEM768_XOODYAK_CRYPTO_SECRETKEYBYTES,
	                      PQCLEAN_MLKEM768_XOODYAK_CRYPTO_CIPHERTEXTBYTES,
	                      PQCLEAN_MLKEM768_XOODYAK_CRYPTO_BYTES,
	                      xoodyak_768_keypair, xoodyak_768_encaps, xoodyak_768_decaps);
}

OQS_KEM *OQS_KEM_ml_kem_1024_xoodyak_new(void) {
	return xoodyak_kem_alloc("ML-KEM-1024-XOODYAK", 5,
	                      PQCLEAN_MLKEM1024_XOODYAK_CRYPTO_PUBLICKEYBYTES,
	                      PQCLEAN_MLKEM1024_XOODYAK_CRYPTO_SECRETKEYBYTES,
	                      PQCLEAN_MLKEM1024_XOODYAK_CRYPTO_CIPHERTEXTBYTES,
	                      PQCLEAN_MLKEM1024_XOODYAK_CRYPTO_BYTES,
	                      xoodyak_1024_keypair, xoodyak_1024_encaps, xoodyak_1024_decaps);
}
