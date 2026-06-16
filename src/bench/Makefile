# Makefile for full_bench — single binary covering all 6 backends.
# Run from the BUILD ROOT (where setup.sh was executed):
#   make -f /path/to/repo/src/bench/Makefile REPO=/path/to/repo
#
# Or just use bench.sh which calls this automatically.

REPO   ?= $(shell git -C $(dir $(abspath $(lastword $(MAKEFILE_LIST)))) rev-parse --show-toplevel)
ROOT   := $(shell pwd)

OQS_INC     := $(ROOT)/liboqs/build/include
OQS_STATIC  := $(ROOT)/liboqs/build/lib/liboqs.a
XKCP_LIB    := $(ROOT)/XKCP/bin/generic64/libXKCP.a
XKCP_HDRS   := $(ROOT)/XKCP/bin/generic64/libXKCP.a.headers
BLAKE3_DIR  := $(ROOT)/PQClean/common/BLAKE3
HARAKA_DIR  := $(ROOT)/PQClean/common/Haraka

BLAKE3_FLAGS := -DBLAKE3_USE_NEON=0 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 \
                -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
  HARAKA_FLAGS := -maes -msse4.1
else
  HARAKA_FLAGS := -march=native
endif

CFLAGS := -O3 -march=native -Wall \
           -I$(OQS_INC) -I$(XKCP_HDRS) \
           -I$(BLAKE3_DIR) -I$(HARAKA_DIR) \
           -I$(ROOT) \
           $(BLAKE3_FLAGS) $(HARAKA_FLAGS)

ADAPTER_OBJS := \
  pqc_turboshake_kem.o pqc_turboshake_dsa.o \
  pqc_k12_kem.o        pqc_k12_dsa.o        \
  pqc_blake3_kem.o     pqc_blake3_dsa.o     \
  pqc_xoodyak_kem.o    pqc_xoodyak_dsa.o   \
  pqc_haraka_kem.o     pqc_haraka_dsa.o

KEM_LIBS := $(foreach v,512 768 1024,\
  $(foreach t,turboshake k12 blake3 xoodyak haraka,\
    $(ROOT)/PQClean/crypto_kem/ml-kem-$(v)/$(t)/libml-kem-$(v)_$(t).a))

DSA_LIBS := \
  $(foreach v,44 65 87,\
    $(ROOT)/PQClean/crypto_sign/ml-dsa-$(v)/turboshake/libml-dsa-$(v)_turbo.a \
    $(ROOT)/PQClean/crypto_sign/ml-dsa-$(v)/k12/libml-dsa-$(v)_k12.a \
    $(ROOT)/PQClean/crypto_sign/ml-dsa-$(v)/blake3/libml-dsa-$(v)_blake3.a \
    $(ROOT)/PQClean/crypto_sign/ml-dsa-$(v)/xoodyak/libml-dsa-$(v)_xoodyak.a \
    $(ROOT)/PQClean/crypto_sign/ml-dsa-$(v)/haraka/libml-dsa-$(v)_haraka.a)

COMMON_OBJS := \
  $(ROOT)/PQClean/common/fips202_turbo.o \
  $(ROOT)/PQClean/common/randombytes_turbo.o

EXTRA_LIBS := $(BLAKE3_DIR)/libblake3.a $(HARAKA_DIR)/libharaka.a $(XKCP_LIB)

all: full_bench liboqs_bench

pqc_%_kem.o: $(ROOT)/pqc_%_kem.c
	$(CC) $(CFLAGS) -c -o $@ $<

pqc_%_dsa.o: $(ROOT)/pqc_%_dsa.c
	$(CC) $(CFLAGS) -c -o $@ $<

full_bench: $(REPO)/src/bench/full_bench.c $(ADAPTER_OBJS)
	$(CC) $(CFLAGS) -o $@ $< \
	  $(ADAPTER_OBJS) $(KEM_LIBS) $(DSA_LIBS) \
	  $(COMMON_OBJS) $(EXTRA_LIBS) \
	  $(OQS_STATIC) -lcrypto -lm

liboqs_bench: $(REPO)/src/bench/liboqs_bench.c
	$(CC) $(CFLAGS) -o $@ $< \
	  $(OQS_STATIC) -lcrypto -lm

clean:
	rm -f full_bench liboqs_bench $(ADAPTER_OBJS) \
	      custom_benchmark.csv library_default_benchmark.csv \
	      full_benchmark_results.csv

.PHONY: all clean
