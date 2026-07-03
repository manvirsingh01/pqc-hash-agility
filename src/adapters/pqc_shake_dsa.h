/*
 * pqc_shake_dsa.h
 *
 * OQS_SIG constructors for the SHAKE (FIPS 202) baseline variants of
 * ML-DSA-44/65/87.  These are NOT the liboqs built-ins -- they wrap the
 * forked PQClean "clean" implementations living under
 * /root/PQClean/crypto_sign/ml-dsa-{44,65,87}/shake, whose
 * symmetric-shake.c is byte-identical to upstream PQClean and is compiled
 * with the exact same Makefile and flags as the five substituted backends
 * (turboshake/k12/blake3/xoodyak/haraka).
 *
 * This makes bench_shake a true hash-substitution baseline; liboqs's
 * separately engineered ML-DSA remains available as an independent
 * "production reference" series (bench_liboqs).
 *
 * Returned objects are heap-allocated and must be freed with OQS_SIG_free().
 */
#ifndef PQC_SHAKE_DSA_H
#define PQC_SHAKE_DSA_H

#include <oqs/sig.h>

OQS_SIG *OQS_SIG_ml_dsa_44_shake_new(void);
OQS_SIG *OQS_SIG_ml_dsa_65_shake_new(void);
OQS_SIG *OQS_SIG_ml_dsa_87_shake_new(void);

#endif /* PQC_SHAKE_DSA_H */
