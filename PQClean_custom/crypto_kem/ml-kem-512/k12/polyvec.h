#ifndef PQCLEAN_MLKEM512_K12_POLYVEC_H
#define PQCLEAN_MLKEM512_K12_POLYVEC_H
#include "params.h"
#include "poly.h"
#include <stdint.h>

typedef struct {
    poly vec[KYBER_K];
} polyvec;

void PQCLEAN_MLKEM512_K12_polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a);
void PQCLEAN_MLKEM512_K12_polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

void PQCLEAN_MLKEM512_K12_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a);
void PQCLEAN_MLKEM512_K12_polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

void PQCLEAN_MLKEM512_K12_polyvec_ntt(polyvec *r);
void PQCLEAN_MLKEM512_K12_polyvec_invntt_tomont(polyvec *r);

void PQCLEAN_MLKEM512_K12_polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);

void PQCLEAN_MLKEM512_K12_polyvec_reduce(polyvec *r);

void PQCLEAN_MLKEM512_K12_polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif
