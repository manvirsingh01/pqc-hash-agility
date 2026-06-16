/*
 * pqc_blake3_dsa.c
 *
 * See pqc_blake3_dsa.h.  Thin OQS_SIG-shaped wrappers around the
 * BLAKE3 ML-DSA implementations.
 */
#include "pqc_blake3_dsa.h"

#include <stdlib.h>
#include <string.h>

#include "/root/PQClean/crypto_sign/ml-dsa-44/blake3/api.h"
#include "/root/PQClean/crypto_sign/ml-dsa-65/blake3/api.h"
#include "/root/PQClean/crypto_sign/ml-dsa-87/blake3/api.h"

/* ---------------------------------------------------------------- */
/* ML-DSA-44-BLAKE3                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS blake3_44_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA44_BLAKE3_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS blake3_44_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA44_BLAKE3_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS blake3_44_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA44_BLAKE3_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-DSA-65-BLAKE3                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS blake3_65_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA65_BLAKE3_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS blake3_65_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA65_BLAKE3_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS blake3_65_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA65_BLAKE3_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-DSA-87-BLAKE3                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS blake3_87_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA87_BLAKE3_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS blake3_87_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA87_BLAKE3_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS blake3_87_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA87_BLAKE3_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}


/* ---------------------------------------------------------------- */
/* Constructors                                                      */
/* ---------------------------------------------------------------- */
static OQS_SIG *blake3_sig_alloc(const char *method_name,
                                 uint8_t nist_level,
                                 size_t pk_len, size_t sk_len, size_t sig_len,
                                 OQS_STATUS (*keypair)(uint8_t *, uint8_t *),
                                 OQS_STATUS (*sign)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *),
                                 OQS_STATUS (*verify)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) {
	OQS_SIG *sig = malloc(sizeof(OQS_SIG));
	if (!sig) {
		return NULL;
	}
	memset(sig, 0, sizeof(OQS_SIG));

	sig->method_name        = method_name;
	sig->alg_version        = "BLAKE3 (native XOF) substitution -- NON-FIPS";
	sig->claimed_nist_level = nist_level;
	sig->euf_cma            = true;
	sig->suf_cma            = false;
	sig->sig_with_ctx_support = false;
	sig->length_public_key  = pk_len;
	sig->length_secret_key  = sk_len;
	sig->length_signature   = sig_len;

	sig->keypair             = keypair;
	sig->sign                = sign;
	sig->sign_with_ctx_str   = NULL;
	sig->verify              = verify;
	sig->verify_with_ctx_str = NULL;

	return sig;
}

OQS_SIG *OQS_SIG_ml_dsa_44_blake3_new(void) {
	return blake3_sig_alloc("ML-DSA-44-BLAKE3", 2,
	                        PQCLEAN_MLDSA44_BLAKE3_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA44_BLAKE3_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA44_BLAKE3_CRYPTO_BYTES,
	                        blake3_44_keypair, blake3_44_sign, blake3_44_verify);
}

OQS_SIG *OQS_SIG_ml_dsa_65_blake3_new(void) {
	return blake3_sig_alloc("ML-DSA-65-BLAKE3", 3,
	                        PQCLEAN_MLDSA65_BLAKE3_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA65_BLAKE3_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA65_BLAKE3_CRYPTO_BYTES,
	                        blake3_65_keypair, blake3_65_sign, blake3_65_verify);
}

OQS_SIG *OQS_SIG_ml_dsa_87_blake3_new(void) {
	return blake3_sig_alloc("ML-DSA-87-BLAKE3", 5,
	                        PQCLEAN_MLDSA87_BLAKE3_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA87_BLAKE3_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA87_BLAKE3_CRYPTO_BYTES,
	                        blake3_87_keypair, blake3_87_sign, blake3_87_verify);
}
