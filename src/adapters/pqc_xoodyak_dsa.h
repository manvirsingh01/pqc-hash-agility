/*
 * pqc_xoodyak_dsa.h
 *
 * OQS_SIG constructors for the Xoodyak variants of
 * ML-DSA-44/65/87.  These are NOT part of liboqs -- they wrap the forked
 * PQClean "clean" implementations living under
 * /root/PQClean/crypto_sign/ml-dsa-{44,65,87}/xoodyak, in which all
 * SHAKE128/SHAKE256 uses (matrix expansion, eta/mask sampling, the H/CRH
 * hash role in sign.c, and poly_challenge) have been replaced by Xoodyak
 * with the domain separation bytes documented in pqc_bench.c
 * (0x1F matrix, 0x2F noise, 0x3F hash, 0x4F challenge).
 *
 * Returned objects are heap-allocated and must be freed with OQS_SIG_free().
 */
#ifndef PQC_XOODYAK_DSA_H
#define PQC_XOODYAK_DSA_H

#include <oqs/sig.h>

OQS_SIG *OQS_SIG_ml_dsa_44_xoodyak_new(void);
OQS_SIG *OQS_SIG_ml_dsa_65_xoodyak_new(void);
OQS_SIG *OQS_SIG_ml_dsa_87_xoodyak_new(void);

#endif /* PQC_XOODYAK_DSA_H */
