/*
 * pqc_turboshake_kem.c
 *
 * See pqc_turboshake_kem.h.  Thin OQS_KEM-shaped wrappers around the
 * TurboSHAKE-substituted PQClean ML-KEM implementations.
 */
#include "pqc_turboshake_kem.h"

#include <stdlib.h>
#include <string.h>

#include "/root/PQClean/crypto_kem/ml-kem-512/turboshake/api.h"
#include "/root/PQClean/crypto_kem/ml-kem-768/turboshake/api.h"
#include "/root/PQClean/crypto_kem/ml-kem-1024/turboshake/api.h"

/* ---------------------------------------------------------------- */
/* ML-KEM-512-TurboSHAKE                                             */
/* ---------------------------------------------------------------- */
static OQS_STATUS turbo_512_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM512_TURBO_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS turbo_512_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM512_TURBO_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS turbo_512_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM512_TURBO_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-KEM-768-TurboSHAKE                                             */
/* ---------------------------------------------------------------- */
static OQS_STATUS turbo_768_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM768_TURBO_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS turbo_768_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM768_TURBO_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS turbo_768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM768_TURBO_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-KEM-1024-TurboSHAKE                                            */
/* ---------------------------------------------------------------- */
static OQS_STATUS turbo_1024_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM1024_TURBO_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS turbo_1024_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM1024_TURBO_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS turbo_1024_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM1024_TURBO_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* Constructors                                                      */
/* ---------------------------------------------------------------- */
static OQS_KEM *turbo_kem_alloc(const char *method_name,
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
	kem->alg_version        = "TurboSHAKE (RFC 9861, n_r=12) substitution -- NON-FIPS";
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

OQS_KEM *OQS_KEM_ml_kem_512_turboshake_new(void) {
	return turbo_kem_alloc("ML-KEM-512-TurboSHAKE", 1,
	                        PQCLEAN_MLKEM512_TURBO_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLKEM512_TURBO_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLKEM512_TURBO_CRYPTO_CIPHERTEXTBYTES,
	                        PQCLEAN_MLKEM512_TURBO_CRYPTO_BYTES,
	                        turbo_512_keypair, turbo_512_encaps, turbo_512_decaps);
}

OQS_KEM *OQS_KEM_ml_kem_768_turboshake_new(void) {
	return turbo_kem_alloc("ML-KEM-768-TurboSHAKE", 3,
	                        PQCLEAN_MLKEM768_TURBO_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLKEM768_TURBO_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLKEM768_TURBO_CRYPTO_CIPHERTEXTBYTES,
	                        PQCLEAN_MLKEM768_TURBO_CRYPTO_BYTES,
	                        turbo_768_keypair, turbo_768_encaps, turbo_768_decaps);
}

OQS_KEM *OQS_KEM_ml_kem_1024_turboshake_new(void) {
	return turbo_kem_alloc("ML-KEM-1024-TurboSHAKE", 5,
	                        PQCLEAN_MLKEM1024_TURBO_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLKEM1024_TURBO_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLKEM1024_TURBO_CRYPTO_CIPHERTEXTBYTES,
	                        PQCLEAN_MLKEM1024_TURBO_CRYPTO_BYTES,
	                        turbo_1024_keypair, turbo_1024_encaps, turbo_1024_decaps);
}
