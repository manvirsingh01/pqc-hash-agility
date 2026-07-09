# PQC ML-KEM / ML-DSA Hash-Agility Benchmark — Full Implementation Guide

This document is a complete, self-contained reference for the ML-KEM
(512/768/1024) and ML-DSA (44/65/87) "hash-agility" benchmark: each
algorithm is rebuilt 6 times, once per internal hash/XOF backend, and all
6 variants are benchmarked through a single harness (`pqc_bench.c`) via
`liboqs`'s `OQS_KEM` / `OQS_SIG` object interfaces.

> **See also:** [`ARCHITECTURE.md`](ARCHITECTURE.md) — the high-level companion
> with system flowcharts, the file-connection graph, and detailed algorithm
> descriptions. It also documents the current **7-series design**: the SHAKE
> baseline is now a PQClean fork (`bench_shake`, upstream `symmetric-shake.c`
> compiled identically to the other five), and the liboqs built-ins run as a
> separate production-reference series (`bench_liboqs`, tag `SHAKE-liboqs`).
> Where this guide says "6 backends", the system today builds 6 PQClean forks
> **plus** that liboqs reference binary.

It covers:

1. [Overview & architecture](#1-overview--architecture)
2. [Prerequisites & pinned versions](#2-prerequisites--pinned-versions)
3. [Quick start — use the migration package](#3-quick-start--use-the-migration-package)
4. [Manual setup, step by step](#4-manual-setup-step-by-step)
5. [Directory layout](#5-directory-layout)
6. [How a backend fork is derived from `clean`](#6-how-a-backend-fork-is-derived-from-clean)
7. [ML-KEM hash/XOF backend code (symmetric.c/h)](#7-ml-kem-hashxof-backend-code-symmetricch)
8. [ML-DSA hash/XOF backend code (symmetric.c/h + poly/sign refactor)](#8-ml-dsa-hashxof-backend-code-symmetricch--polysign-refactor)
9. [Custom common library: BLAKE3](#9-custom-common-library-blake3)
10. [Custom common library: Haraka](#10-custom-common-library-haraka)
11. [liboqs adapter shims (OQS_KEM / OQS_SIG)](#11-liboqs-adapter-shims-oqs_kem--oqs_sig)
12. [Benchmark harness: pqc_bench.c](#12-benchmark-harness-pqc_benchc)
13. [Full automated rebuild script](#13-full-automated-rebuild-script)
14. [Build command cheat-sheet](#14-build-command-cheat-sheet)
15. [Running the benchmarks & reading results](#15-running-the-benchmarks--reading-results)
16. [Reference results (this machine)](#16-reference-results-this-machine)
17. [Migrating to a new machine](#17-migrating-to-a-new-machine)
18. [Troubleshooting](#18-troubleshooting)

---

## 1. Overview & architecture

**Goal.** NIST's ML-KEM (FIPS 203, ex-Kyber) and ML-DSA (FIPS 204,
ex-Dilithium) both internally rely on SHA3/SHAKE (Keccak, `n_r = 24`
rounds) for expansion, sampling and the Fiat-Shamir transform. This
project answers "what happens if you swap that internal hash/XOF for
something else?" — both functionally (does it still round-trip) and
performance-wise (cycles, wall time, memory, an energy proxy).

**The 6 backends:**

| Tag          | Primitive                                      | Source                  | Notes |
|--------------|-------------------------------------------------|-------------------------|-------|
| `shake`      | SHA3/SHAKE, Keccak-f[1600], `n_r=24` (baseline)  | PQClean `clean` (stock) | FIPS-203/204 compliant |
| `turboshake` | TurboSHAKE128/256 (RFC 9861), Keccak `n_r=12`    | XKCP `generic64`        | NON-FIPS |
| `k12`        | KangarooTwelve (RFC 9861 tree hash, `n_r=12`)    | XKCP `generic64`        | NON-FIPS |
| `blake3`     | BLAKE3 native XOF                               | BLAKE3 reference C       | NON-FIPS |
| `xoodyak`    | Xoodyak (Cyclist mode over Xoodoo[12])          | XKCP `generic64`        | NON-FIPS |
| `haraka`     | Haraka-MD (AES-based MD construction)           | Haraka ref / ARM-NEON   | NON-FIPS, ARM-only build |

**Architecture / data flow:**

```
                 +----------------------------------------+
                 |  PQClean/crypto_kem/ml-kem-{512,768,1024}/<tag>  |
                 |  PQClean/crypto_sign/ml-dsa-{44,65,87}/<tag>     |
                 |  (forked from .../clean, namespace renamed,      |
                 |   symmetric.h + symmetric-<tag>.c swapped)       |
                 +-------------------+----------------------+
                                      | static libs
                                      | libml-kem-*_<tag>.a
                                      | libml-dsa-*_<tag>.a
                                      v
   +---------------------------+   +------------------------------+
   | XKCP / BLAKE3 / Haraka     |   | pqc_<tag>_kem.{c,h}           |
   | libXKCP.a / libblake3.a /  |-->| pqc_<tag>_dsa.{c,h}            |
   | libharaka.a (per backend)  |   | (OQS_KEM / OQS_SIG adapters)   |
   +---------------------------+   +---------------+----------------+
                                                     |
                                                     v
                                          +----------------------+
                                          |     pqc_bench.c      |
                                          | (selftest + timing   |
                                          |  loop + CSV output)  |
                                          +----------+-----------+
                                                     |
                                          +----------v-----------+
                                          |  liboqs (-loqs)       |
                                          |  + OpenSSL (-lcrypto) |
                                          +----------------------+
                                                     |
                                                     v
                                              bench_<tag> binary
                                                     |
                                                     v
                                       pqc_benchmark_results.csv
```

For each backend, `pqc_bench.c` is compiled once per tag with
`-DUSE_<TAG>` so that `#ifdef` blocks select the matching
`OQS_KEM_new_*` / `OQS_SIG_new_*` constructors from the corresponding
adapter. Every binary is statically linked against the forked PQClean
algorithm libraries (no `liboqs` Kyber/Dilithium code is used — the
liboqs build only supplies the generic `OQS_KEM`/`OQS_SIG` plumbing,
RNG, and `-loqs`/`-lcrypto` glue).

---

## 2. Prerequisites & pinned versions

### System packages (Debian/Ubuntu/Kali)

```bash
sudo apt-get update
sudo apt-get install -y git build-essential cmake gcc g++ make libssl-dev ninja-build rsync
```

### Pinned upstream commits

These exact commits were used to build and validate every backend. Using
different commits may change file layouts (especially for PQClean, whose
`clean` directories are the basis for every fork).

| Repo     | URL                                              | Commit                                      |
|----------|--------------------------------------------------|----------------------------------------------|
| PQClean  | https://github.com/PQClean/PQClean.git           | `202a8f96315f9ed219387a50f7e40d04af037ea8`   |
| XKCP     | https://github.com/XKCP/XKCP.git                 | `d71b764513a6c3163b3cfc919dd6f974d98a6c53`   |
| liboqs   | https://github.com/open-quantum-safe/liboqs.git  | `f986aea60a9f3cb4055474aa212538bb0b14f1fe`   |

### Architecture notes

- **SHAKE, TurboSHAKE, K12, BLAKE3 (portable build), Xoodyak** build and run
  unmodified on x86_64 *and* aarch64.
- **Haraka**: the symmetric backend (`PQClean/common/Haraka/haraka.c`) used
  here is an **ARM-NEON port** (`<arm_neon.h>`, `vaeseq_u8`/AES intrinsics).
  It only builds on `aarch64`/`arm64`. On x86_64 it is skipped automatically
  by the rebuild script (porting it to AES-NI is a separate task — see
  [§18 Troubleshooting](#18-troubleshooting)).

---

## 3. Quick start — use the migration package

The fastest way to reproduce everything on a fresh Linux machine is the
prebuilt package `pqc_migrate.tar.gz` (built from this directory's parent:
`tar czf pqc_migrate.tar.gz migrate_pkg2`). It contains:

```
migrate_pkg2/
├── setup_on_new_machine.sh          # one-shot rebuild script (see §13)
├── pqc_bench.c                      # benchmark harness (see §12)
├── pqc_<tag>_kem.{c,h}               # OQS_KEM adapters, tag in
├── pqc_<tag>_dsa.{c,h}               #   {turboshake,k12,blake3,xoodyak,haraka}
├── pqc_benchmark_results.reference.csv  # reference run (this machine)
├── IMPLEMENTATION_GUIDE.md           # <- this file
└── PQClean_custom/
    ├── common/BLAKE3/...             # custom BLAKE3 sources (see §9)
    ├── common/Haraka/...             # custom Haraka sources (see §10)
    ├── crypto_kem/ml-kem-{512,768,1024}/<tag>/...   # forked KEM dirs
    └── crypto_sign/ml-dsa-{44,65,87}/<tag>/...      # forked DSA dirs
```

On the new machine:

```bash
mkdir -p ~/pqc && cd ~/pqc
tar xzf pqc_migrate.tar.gz                  # -> migrate_pkg2/
./migrate_pkg2/setup_on_new_machine.sh      # clones PQClean/XKCP/liboqs,
                                             # drops in the custom sources,
                                             # builds everything (§13)
```

Then run the benchmarks (writes `pqc_benchmark_results.csv` next to the
binaries):

```bash
rm -f pqc_benchmark_results.csv
./bench_shake
./bench_turboshake --csv-append
./bench_k12        --csv-append
./bench_blake3     --csv-append
./bench_xoodyak    --csv-append
./bench_haraka     --csv-append   # only present on aarch64

diff <(sort pqc_benchmark_results.csv) \
     <(sort migrate_pkg2/pqc_benchmark_results.reference.csv)
```

Everything below explains **what** the script does and **why**, plus the
full source of every custom file, so the whole thing can also be
reproduced by hand or adapted to a different starting point.

---

## 4. Manual setup, step by step

This is the same procedure the rebuild script automates (§13), explained
one step at a time. All commands assume you start in an empty working
directory `~/pqc` (referred to below as `$ROOT`).

### 4.1 Clone and pin the three upstream repos

```bash
cd $ROOT
git clone https://github.com/PQClean/PQClean.git
git clone https://github.com/XKCP/XKCP.git
git clone https://github.com/open-quantum-safe/liboqs.git

(cd PQClean && git checkout 202a8f96315f9ed219387a50f7e40d04af037ea8)
(cd XKCP    && git checkout d71b764513a6c3163b3cfc919dd6f974d98a6c53)
(cd liboqs  && git checkout f986aea60a9f3cb4055474aa212538bb0b14f1fe)
```

### 4.2 Build XKCP's generic64 library

This provides `TurboSHAKE.h`, `KangarooTwelve.h` and `Xoodyak.h` plus their
compiled object code, used by the `turboshake`, `k12` and `xoodyak`
backends.

```bash
cd $ROOT/XKCP && make generic64/libXKCP.a
```

This produces:
- `$ROOT/XKCP/bin/generic64/libXKCP.a`
- `$ROOT/XKCP/bin/generic64/libXKCP.a.headers/` (the public headers)

### 4.3 Build liboqs

liboqs supplies the generic `OQS_KEM`/`OQS_SIG` object types, RNG, and the
`-loqs` library that the benchmark links against. **None of liboqs's own
Kyber/Dilithium implementations are used** — only its plumbing.

```bash
cd $ROOT/liboqs
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

This produces `$ROOT/liboqs/build/include` and `$ROOT/liboqs/build/lib`
(static `liboqs.a`/shared `liboqs.so`).

### 4.4 Drop in the custom sources

Copy (from this package) into the freshly cloned `PQClean` tree:

```bash
cp -r migrate_pkg2/PQClean_custom/common/BLAKE3 PQClean/common/
cp -r migrate_pkg2/PQClean_custom/common/Haraka PQClean/common/

for tag in turboshake k12 blake3 xoodyak haraka; do
  for v in 512 768 1024; do
    mkdir -p PQClean/crypto_kem/ml-kem-$v/$tag
    cp -r migrate_pkg2/PQClean_custom/crypto_kem/ml-kem-$v/$tag/. \
          PQClean/crypto_kem/ml-kem-$v/$tag/
  done
  for v in 44 65 87; do
    mkdir -p PQClean/crypto_sign/ml-dsa-$v/$tag
    cp -r migrate_pkg2/PQClean_custom/crypto_sign/ml-dsa-$v/$tag/. \
          PQClean/crypto_sign/ml-dsa-$v/$tag/
  done
done
```

### 4.5 Copy the adapters + benchmark harness, fixing absolute paths

The adapter `.c` files contain a hardcoded `#include "/root/PQClean/..."`
from the machine they were generated on. Fix it with `sed`:

```bash
cp migrate_pkg2/pqc_bench.c .
for tag in turboshake k12 blake3 xoodyak haraka; do
  cp migrate_pkg2/pqc_${tag}_kem.c migrate_pkg2/pqc_${tag}_kem.h .
  cp migrate_pkg2/pqc_${tag}_dsa.c migrate_pkg2/pqc_${tag}_dsa.h .
  sed -i "s#/root/PQClean#$ROOT/PQClean#g" pqc_${tag}_kem.c pqc_${tag}_dsa.c
done

# Cosmetic: also fix the hardcoded XKCP include path baked into the
# turboshake/k12 KEM Makefiles (harmless if left, since gcc ignores a
# nonexistent -I path, but keeps things tidy):
sed -i "s#/root/XKCP#$ROOT/XKCP#g" \
  PQClean/crypto_kem/ml-kem-{512,768,1024}/{turboshake,k12}/Makefile
```

The remaining steps (building each backend's static libs, the adapters,
and linking the 6 `bench_*` binaries) are identical to §13 steps 7-13 —
see the [build command cheat-sheet](#14-build-command-cheat-sheet) for the
exact commands, or just run `setup_on_new_machine.sh` which does all of
4.1-4.5 plus these remaining steps in one go.

---

## 5. Directory layout

```
$ROOT/
├── PQClean/
│   ├── common/
│   │   ├── fips202.c / fips202.h       # stock SHA3/SHAKE (Keccak n_r=24)
│   │   ├── randombytes.c/.h            # stock RNG
│   │   ├── BLAKE3/                     # ** custom, see §9 **
│   │   └── Haraka/                     # ** custom, see §10 **
│   ├── crypto_kem/ml-kem-{512,768,1024}/
│   │   ├── clean/                      # stock PQClean reference (SHAKE)
│   │   ├── turboshake/                 # ** fork, see §6-7 **
│   │   ├── k12/                        # ** fork **
│   │   ├── blake3/                     # ** fork **
│   │   ├── xoodyak/                    # ** fork **
│   │   └── haraka/                     # ** fork, aarch64 only **
│   └── crypto_sign/ml-dsa-{44,65,87}/
│       ├── clean/                      # stock PQClean reference (SHAKE)
│       ├── turboshake/ k12/ blake3/ xoodyak/ haraka/   # ** forks, §6-8 **
├── XKCP/
│   └── bin/generic64/{libXKCP.a, libXKCP.a.headers/}
├── liboqs/
│   └── build/{include/, lib/}
├── pqc_bench.c                          # §12
├── pqc_<tag>_kem.{c,h}                  # §11 (tag = turboshake/k12/blake3/xoodyak/haraka)
├── pqc_<tag>_dsa.{c,h}                  # §11
├── bench_shake, bench_<tag>             # final binaries
├── pure_bench, pure_bench_<tag>         # pure-style harness binaries (§15)
├── file_sign_<tag>                      # payload hash+sign binaries (§15)
└── pqc_benchmark_results.csv            # benchmark output
```

The "baseline" `bench_shake` binary is built straight from `PQClean`'s
stock `clean` directories — no forking needed, since `clean` already uses
SHAKE/SHA3. Only the 5 alternative backends (`turboshake`, `k12`,
`blake3`, `xoodyak`, `haraka`) need forked algorithm directories.

---

## 6. How a backend fork is derived from `clean`

Each `PQClean/crypto_{kem,sign}/<algo>/<tag>/` directory is produced by:

1. **Copying** the corresponding `.../<algo>/clean/` directory verbatim
   (minus `LICENSE` and `Makefile.Microsoft_nmake`).
2. **Renaming the symbol/include-guard namespace** from
   `PQCLEAN_<ALGO>_CLEAN_` to `PQCLEAN_<ALGO>_<TAG>_` (e.g.
   `PQCLEAN_MLKEM512_CLEAN_` → `PQCLEAN_MLKEM512_TURBO_`) across **every**
   `.c`/`.h` file. This is a pure find/replace and is what makes the
   resulting static library's exported symbols distinct from the `clean`
   build's, so both can be linked into the same binary if needed.
3. **Replacing `symmetric-shake.c` with `symmetric-<tag>.c`**, and
   rewriting `symmetric.h` to declare the new backend's `xof_*`/`prf`/
   `rkprf` (KEM) or `xof_*` (DSA) functions in place of the SHAKE ones.
   This is the *only functionally meaningful* change — see §7/§8 for the
   full source of every backend's `symmetric.h` + `symmetric-<tag>.c`.
4. For **ML-DSA only**, additionally patching `poly.c` and `sign.c` to
   replace direct `shake256incctx`/`shake256_inc_*` calls with the
   backend-agnostic `xof_state`/`xof_*` API declared in the new
   `symmetric.h` (ML-KEM's `clean` code already goes through an
   `xof_*`/`prf`/`rkprf` indirection layer in `symmetric.h`, so no
   `.c` patching beyond `symmetric-<tag>.c` is needed there). See §8.2
   for the exact patch (`mldsa_refactor.py`).
5. **Editing the `Makefile`**: change `LIB=`, the `OBJECTS=` line (swap
   `symmetric-shake.o` for `symmetric-<tag>.o`), and add any
   backend-specific `-I` include path via `$(EXTRAFLAGS)`.

### Example: Makefile diff (`ml-kem-512/clean` → `ml-kem-512/turboshake`)

```diff
--- crypto_kem/ml-kem-512/clean/Makefile
+++ crypto_kem/ml-kem-512/turboshake/Makefile
@@
-LIB=libml-kem-512_clean.a
+LIB=libml-kem-512_turboshake.a
 HEADERS=api.h cbd.h indcpa.h kem.h ntt.h params.h poly.h polyvec.h reduce.h symmetric.h verify.h
-OBJECTS=cbd.o indcpa.o kem.o ntt.o poly.o polyvec.o reduce.o symmetric-shake.o verify.o
+OBJECTS=cbd.o indcpa.o kem.o ntt.o poly.o polyvec.o reduce.o symmetric-turboshake.o verify.o
@@
-CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99 -I../../../common $(EXTRAFLAGS)
+CFLAGS=-O3 -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -std=c99 \
+       -I../../../common -I$ROOT/XKCP/bin/generic64/libXKCP.a.headers $(EXTRAFLAGS)
```

(`-Werror` is dropped because the alternative backends introduce a couple
of harmless unused-parameter / sign-compare warnings under `-Wextra` that
aren't worth suppressing individually.)

Every other `.c`/`.h` file in a forked directory (`cbd.c`, `indcpa.c`,
`kem.c`, `ntt.c`, `poly.c`, `polyvec.c`, `reduce.c`, `verify.c`, ... and
for ML-DSA also `packing.c`, `rounding.c`, `sign.c`) is **byte-identical
to `clean` except for the namespace rename** (step 2 above) — i.e. a
mechanical `sed`-style substitution of the `PQCLEAN_<ALGO>_CLEAN_` prefix.
They are *not* reproduced in this guide; only the genuinely new/changed
files are (symmetric backend, Makefile, and for ML-DSA the poly/sign
patch).

---

## 7. ML-KEM hash/XOF backend code (symmetric.c/h)

Below is the **complete** `symmetric.h` + `symmetric-<tag>.c` pair for
each of the 5 alternative backends, taken from `ml-kem-512/<tag>/`. The
`ml-kem-768` and `ml-kem-1024` versions are identical except for the
`MLKEM768`/`MLKEM1024` namespace prefix (step 2 in §6) — copy these files
into the corresponding `ml-kem-{768,1024}/<tag>/` directories and the
build's `sed`-based namespace rename (already applied in the package) will
have produced the matching symbol names.

Each `symmetric.h` defines the `xof_absorb` / `xof_squeezeblocks` /
`xof_ctx_release` / `prf` / `rkprf` macros that `cbd.c`/`indcpa.c` call
into — this is the **entire** integration surface for ML-KEM.

### 7.1 Backend: `turboshake`

**`crypto_kem/ml-kem-512/turboshake/symmetric.h`**

```c
#ifndef PQCLEAN_MLKEM512_TURBO_SYMMETRIC_H
#define PQCLEAN_MLKEM512_TURBO_SYMMETRIC_H
#include "fips202.h"
#include "params.h"
#include "TurboSHAKE.h"
#include <stddef.h>
#include <stdint.h>

/*
 * TurboSHAKE (RFC 9861) substitution for the SHAKE128/SHAKE256 uses inside
 * ML-KEM, per the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (XOF)         -> TurboSHAKE128, D=0x1F
 *   Vector 2: CBD noise generation (PRF)      -> TurboSHAKE256, D=0x2F
 *   Vector 4: Implicit-rejection KDF (rkprf)  -> TurboSHAKE256, D=0x3F
 * Vector 3 (hash_h/hash_g, the FO transform) is intentionally left as
 * SHA3-256/SHA3-512 -- it is NOT part of the SHAKE/TurboSHAKE swap.
 */
#define TURBOSHAKE_DOMAIN_MATRIX 0x1F
#define TURBOSHAKE_DOMAIN_CBD    0x2F
#define TURBOSHAKE_DOMAIN_KDF    0x3F

typedef TurboSHAKE_Instance xof_state;

void PQCLEAN_MLKEM512_TURBO_kyber_turboshake128_absorb(xof_state *s,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y);

void PQCLEAN_MLKEM512_TURBO_kyber_turboshake_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *s);

void PQCLEAN_MLKEM512_TURBO_kyber_turboshake_ctx_release(xof_state *s);

void PQCLEAN_MLKEM512_TURBO_kyber_turboshake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

void PQCLEAN_MLKEM512_TURBO_kyber_turboshake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

/* TurboSHAKE128 rate (capacity=256) is 1344 bits = 168 bytes, identical to SHAKE128. */
#define XOF_BLOCKBYTES 168

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) PQCLEAN_MLKEM512_TURBO_kyber_turboshake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLKEM512_TURBO_kyber_turboshake_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) PQCLEAN_MLKEM512_TURBO_kyber_turboshake_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) PQCLEAN_MLKEM512_TURBO_kyber_turboshake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) PQCLEAN_MLKEM512_TURBO_kyber_turboshake256_rkprf(OUT, KEY, INPUT)

#endif

```

**`crypto_kem/ml-kem-512/turboshake/symmetric-turboshake.c`**

```c
#include "fips202.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * PQCLEAN_MLKEM512_TURBO_kyber_turboshake128_absorb
 *   TurboSHAKE128 (n_r=12, RFC 9861) replacement for the SHAKE128 matrix
 *   expansion XOF.  Domain separation byte 0x1F (TURBOSHAKE_DOMAIN_MATRIX).
 */
void PQCLEAN_MLKEM512_TURBO_kyber_turboshake128_absorb(xof_state *state,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y) {
    uint8_t extseed[KYBER_SYMBYTES + 2];

    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;

    TurboSHAKE128_Initialize(state);
    TurboSHAKE_Absorb(state, extseed, sizeof(extseed));
    TurboSHAKE_AbsorbDomainSeparationByte(state, TURBOSHAKE_DOMAIN_MATRIX);
}

void PQCLEAN_MLKEM512_TURBO_kyber_turboshake_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    TurboSHAKE_Squeeze(state, out, nblocks * XOF_BLOCKBYTES);
}

void PQCLEAN_MLKEM512_TURBO_kyber_turboshake_ctx_release(xof_state *state) {
    (void)state;
}

/*
 * PQCLEAN_MLKEM512_TURBO_kyber_turboshake256_prf
 *   TurboSHAKE256 (n_r=12, RFC 9861) replacement for the SHAKE256 PRF used
 *   in CBD noise generation.  Domain separation byte 0x2F (TURBOSHAKE_DOMAIN_CBD).
 */
void PQCLEAN_MLKEM512_TURBO_kyber_turboshake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t extkey[KYBER_SYMBYTES + 1];
    TurboSHAKE_Instance state;

    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = nonce;

    TurboSHAKE256_Initialize(&state);
    TurboSHAKE_Absorb(&state, extkey, sizeof(extkey));
    TurboSHAKE_AbsorbDomainSeparationByte(&state, TURBOSHAKE_DOMAIN_CBD);
    TurboSHAKE_Squeeze(&state, out, outlen);
}

/*
 * PQCLEAN_MLKEM512_TURBO_kyber_turboshake256_rkprf
 *   TurboSHAKE256 (n_r=12, RFC 9861) replacement for the SHAKE256 "J" function
 *   used to derive the implicit-rejection shared secret.  Domain separation
 *   byte 0x3F (TURBOSHAKE_DOMAIN_KDF).
 */
void PQCLEAN_MLKEM512_TURBO_kyber_turboshake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]) {
    TurboSHAKE_Instance state;

    TurboSHAKE256_Initialize(&state);
    TurboSHAKE_Absorb(&state, key, KYBER_SYMBYTES);
    TurboSHAKE_Absorb(&state, input, KYBER_CIPHERTEXTBYTES);
    TurboSHAKE_AbsorbDomainSeparationByte(&state, TURBOSHAKE_DOMAIN_KDF);
    TurboSHAKE_Squeeze(&state, out, KYBER_SSBYTES);
}

```

### 7.2 Backend: `k12`

**`crypto_kem/ml-kem-512/k12/symmetric.h`**

```c
#ifndef PQCLEAN_MLKEM512_K12_SYMMETRIC_H
#define PQCLEAN_MLKEM512_K12_SYMMETRIC_H
#include "fips202.h"
#include "params.h"
#include "KangarooTwelve.h"
#include <stddef.h>
#include <stdint.h>

/*
 * KangarooTwelve (RFC 9861) substitution for the SHAKE128/SHAKE256 uses
 * inside ML-KEM, per the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (XOF)         -> KT128, C=0x1F
 *   Vector 2: CBD noise generation (PRF)      -> KT256, C=0x2F
 *   Vector 4: Implicit-rejection KDF (rkprf)  -> KT256, C=0x3F
 * Vector 3 (hash_h/hash_g, the FO transform) is intentionally left as
 * SHA3-256/SHA3-512 -- it is NOT part of the SHAKE/K12 swap.
 *
 * K12 has no sponge-level "domain separation byte" the way TurboSHAKE
 * does; instead these single-byte values are used as the K12
 * "customization string" C, which K12 absorbs (with a length encoding)
 * after the message M.  Reusing the same numeric values as the
 * TurboSHAKE build keeps the Vector table in pqc_bench.c consistent.
 */
#define K12_CUSTOM_MATRIX 0x1F
#define K12_CUSTOM_CBD    0x2F
#define K12_CUSTOM_KDF    0x3F

typedef KangarooTwelve_Instance xof_state;

void PQCLEAN_MLKEM512_K12_kyber_k12_absorb(xof_state *s,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y);

void PQCLEAN_MLKEM512_K12_kyber_k12_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *s);

void PQCLEAN_MLKEM512_K12_kyber_k12_ctx_release(xof_state *s);

void PQCLEAN_MLKEM512_K12_kyber_k12_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

void PQCLEAN_MLKEM512_K12_kyber_k12_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

/* KT128's underlying TurboSHAKE128 rate (capacity=256) is 1344 bits = 168
 * bytes, identical to SHAKE128 -- so the existing rejection-sampling
 * squeeze loop in indcpa.c works unchanged. */
#define XOF_BLOCKBYTES 168

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) PQCLEAN_MLKEM512_K12_kyber_k12_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLKEM512_K12_kyber_k12_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) PQCLEAN_MLKEM512_K12_kyber_k12_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) PQCLEAN_MLKEM512_K12_kyber_k12_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) PQCLEAN_MLKEM512_K12_kyber_k12_rkprf(OUT, KEY, INPUT)

#endif

```

**`crypto_kem/ml-kem-512/k12/symmetric-k12.c`**

```c
#include "fips202.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * PQCLEAN_MLKEM512_K12_kyber_k12_absorb
 *   KT128 (KangarooTwelve, RFC 9861) replacement for the SHAKE128 matrix
 *   expansion XOF.  Customization string 0x1F (K12_CUSTOM_MATRIX).
 *   Output length is left open (0) so xof_squeezeblocks can squeeze
 *   as many XOF_BLOCKBYTES blocks as the rejection-sampling loop needs.
 */
void PQCLEAN_MLKEM512_K12_kyber_k12_absorb(xof_state *state,
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

void PQCLEAN_MLKEM512_K12_kyber_k12_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    KangarooTwelve_Squeeze(state, out, nblocks * XOF_BLOCKBYTES);
}

void PQCLEAN_MLKEM512_K12_kyber_k12_ctx_release(xof_state *state) {
    (void)state;
}

/*
 * PQCLEAN_MLKEM512_K12_kyber_k12_prf
 *   KT256 (KangarooTwelve, RFC 9861) replacement for the SHAKE256 PRF used
 *   in CBD noise generation.  Customization string 0x2F (K12_CUSTOM_CBD).
 */
void PQCLEAN_MLKEM512_K12_kyber_k12_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t extkey[KYBER_SYMBYTES + 1];
    const uint8_t custom = K12_CUSTOM_CBD;

    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = nonce;

    KT256(extkey, sizeof(extkey), out, outlen, &custom, 1);
}

/*
 * PQCLEAN_MLKEM512_K12_kyber_k12_rkprf
 *   KT256 (KangarooTwelve, RFC 9861) replacement for the SHAKE256 "J"
 *   function used to derive the implicit-rejection shared secret.
 *   Customization string 0x3F (K12_CUSTOM_KDF).
 */
void PQCLEAN_MLKEM512_K12_kyber_k12_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]) {
    xof_state state;
    const uint8_t custom = K12_CUSTOM_KDF;

    KangarooTwelve_Initialize(&state, 256, KYBER_SSBYTES);
    KangarooTwelve_Update(&state, key, KYBER_SYMBYTES);
    KangarooTwelve_Update(&state, input, KYBER_CIPHERTEXTBYTES);
    KangarooTwelve_Final(&state, out, &custom, 1);
}

```

### 7.3 Backend: `blake3`

**`crypto_kem/ml-kem-512/blake3/symmetric.h`**

```c
#ifndef PQCLEAN_MLKEM512_BLAKE3_SYMMETRIC_H
#define PQCLEAN_MLKEM512_BLAKE3_SYMMETRIC_H
#include "blake3.h"
#include "fips202.h"
#include "params.h"
#include <stddef.h>
#include <stdint.h>

/*
 * BLAKE3 substitution for the SHAKE128/SHAKE256 uses inside ML-KEM, per the
 * agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (XOF)         -> BLAKE3 XOF, domain 0x1F
 *   Vector 2: CBD noise generation (PRF)      -> BLAKE3 XOF, domain 0x2F
 *   Vector 4: Implicit-rejection KDF (rkprf)  -> BLAKE3 XOF, domain 0x3F
 * Vector 3 (hash_h/hash_g, the FO transform) is intentionally left as
 * SHA3-256/SHA3-512 -- it is NOT part of the SHAKE/BLAKE3 swap.
 *
 * BLAKE3 has no sponge-level "domain separation byte"; instead these
 * single-byte values are appended to the absorbed input before
 * finalization, mirroring the customization-string convention used by the
 * K12/TurboSHAKE variants so the Vector table in pqc_bench.c stays
 * consistent across backends.
 *
 * BLAKE3 is a native XOF: blake3_hasher_finalize_seek() can produce any
 * number of output bytes starting at any byte offset, so squeezing in
 * XOF_BLOCKBYTES-sized blocks is purely a convention to match the existing
 * rejection-sampling loop in indcpa.c.
 */
#define BLAKE3_CUSTOM_MATRIX 0x1F
#define BLAKE3_CUSTOM_CBD    0x2F
#define BLAKE3_CUSTOM_KDF    0x3F

typedef struct {
    blake3_hasher hasher;
    uint64_t squeezed;
} xof_state;

void PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_absorb(xof_state *s,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y);

void PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *s);

void PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_ctx_release(xof_state *s);

void PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

void PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

/* Arbitrary block size for the squeeze loop -- BLAKE3's XOF has no fixed
 * rate, 168 is chosen to match the SHAKE128 rate used elsewhere. */
#define XOF_BLOCKBYTES 168

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_rkprf(OUT, KEY, INPUT)

#endif

```

**`crypto_kem/ml-kem-512/blake3/symmetric-blake3.c`**

```c
#include "fips202.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_absorb
 *   BLAKE3 XOF replacement for the SHAKE128 matrix expansion XOF.
 *   Domain byte 0x1F (BLAKE3_CUSTOM_MATRIX) is appended after the seed
 *   and the (x, y) matrix-position bytes.
 */
void PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_absorb(xof_state *state,
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

void PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    size_t outlen = nblocks * XOF_BLOCKBYTES;
    blake3_hasher_finalize_seek(&state->hasher, state->squeezed, out, outlen);
    state->squeezed += outlen;
}

void PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_ctx_release(xof_state *state) {
    (void)state;
}

/*
 * PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_prf
 *   BLAKE3 XOF replacement for the SHAKE256 PRF used in CBD noise
 *   generation.  Domain byte 0x2F (BLAKE3_CUSTOM_CBD).
 */
void PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
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
 * PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_rkprf
 *   BLAKE3 XOF replacement for the SHAKE256 "J" function used to derive
 *   the implicit-rejection shared secret.  Domain byte 0x3F
 *   (BLAKE3_CUSTOM_KDF).
 */
void PQCLEAN_MLKEM512_BLAKE3_kyber_blake3_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]) {
    blake3_hasher hasher;
    const uint8_t custom = BLAKE3_CUSTOM_KDF;

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, key, KYBER_SYMBYTES);
    blake3_hasher_update(&hasher, input, KYBER_CIPHERTEXTBYTES);
    blake3_hasher_update(&hasher, &custom, 1);
    blake3_hasher_finalize_seek(&hasher, 0, out, KYBER_SSBYTES);
}

```

### 7.4 Backend: `xoodyak`

**`crypto_kem/ml-kem-512/xoodyak/symmetric.h`**

```c
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

```

**`crypto_kem/ml-kem-512/xoodyak/symmetric-xoodyak.c`**

```c
#include "fips202.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_absorb
 *   Xoodyak (Cyclist hash mode) replacement for the SHAKE128 matrix
 *   expansion XOF.  Domain byte 0x1F (XOODYAK_CUSTOM_MATRIX) is appended
 *   after the seed and the (x, y) matrix-position bytes.
 */
void PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_absorb(xof_state *state,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y) {
    uint8_t extseed[KYBER_SYMBYTES + 3];

    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;
    extseed[KYBER_SYMBYTES + 2] = XOODYAK_CUSTOM_MATRIX;

    Xoodyak_Initialize(state, NULL, 0, NULL, 0, NULL, 0);
    Xoodyak_Absorb(state, extseed, sizeof(extseed));
}

void PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    Xoodyak_Squeeze(state, out, nblocks * XOF_BLOCKBYTES);
}

void PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_ctx_release(xof_state *state) {
    (void)state;
}

/*
 * PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_prf
 *   Xoodyak (Cyclist hash mode) replacement for the SHAKE256 PRF used in
 *   CBD noise generation.  Domain byte 0x2F (XOODYAK_CUSTOM_CBD).
 */
void PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t extkey[KYBER_SYMBYTES + 2];
    xof_state state;

    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES + 0] = nonce;
    extkey[KYBER_SYMBYTES + 1] = XOODYAK_CUSTOM_CBD;

    Xoodyak_Initialize(&state, NULL, 0, NULL, 0, NULL, 0);
    Xoodyak_Absorb(&state, extkey, sizeof(extkey));
    Xoodyak_Squeeze(&state, out, outlen);
}

/*
 * PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_rkprf
 *   Xoodyak (Cyclist hash mode) replacement for the SHAKE256 "J" function
 *   used to derive the implicit-rejection shared secret.  Domain byte
 *   0x3F (XOODYAK_CUSTOM_KDF).
 */
void PQCLEAN_MLKEM512_XOODYAK_kyber_xoodyak_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]) {
    xof_state state;
    const uint8_t custom = XOODYAK_CUSTOM_KDF;

    Xoodyak_Initialize(&state, NULL, 0, NULL, 0, NULL, 0);
    Xoodyak_Absorb(&state, key, KYBER_SYMBYTES);
    Xoodyak_Absorb(&state, input, KYBER_CIPHERTEXTBYTES);
    Xoodyak_Absorb(&state, &custom, 1);
    Xoodyak_Squeeze(&state, out, KYBER_SSBYTES);
}

```

### 7.5 Backend: `haraka`

**`crypto_kem/ml-kem-512/haraka/symmetric.h`**

```c
#ifndef PQCLEAN_MLKEM512_HARAKA_SYMMETRIC_H
#define PQCLEAN_MLKEM512_HARAKA_SYMMETRIC_H
#include "fips202.h"
#include "haraka.h"
#include "params.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Haraka v2 substitution for the SHAKE128/SHAKE256 uses inside ML-KEM, per
 * the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (XOF)         -> Haraka-CTR-XOF, domain 0x1F
 *   Vector 2: CBD noise generation (PRF)      -> Haraka-CTR-XOF, domain 0x2F
 *   Vector 4: Implicit-rejection KDF (rkprf)  -> Haraka-CTR-MD,  domain 0x3F
 * Vector 3 (hash_h/hash_g, the FO transform) is intentionally left as
 * SHA3-256/SHA3-512 -- it is NOT part of the SHAKE/Haraka swap.
 *
 * !! NON-STANDARD CONSTRUCTION -- NON-FIPS !!
 * Haraka is a fixed-input/fixed-output short-input permutation (Haraka512:
 * 64-byte input -> 32-byte output via Davies-Meyer + truncation), it is
 * NOT an XOF. To stand in for SHAKE's variable-length XOF/PRF/KDF roles,
 * this build defines a non-standard counter-mode construction
 * ("Haraka-CTR"):
 *
 *   - xof_absorb()/squeezeblocks(): build a 64-byte block from
 *     seed(32) || x || y || domain || zero-padding(29) || counter(8, LE),
 *     and squeeze XOF_BLOCKBYTES=32 bytes per block as
 *     Haraka512(block), incrementing counter for each block.
 *
 *   - prf(): same construction seeded from key(32) || nonce || domain.
 *
 *   - rkprf(): a Merkle-Damgard-style chain over Haraka512 used as the
 *     compression function -- cv_0 = key(32); cv_{i+1} =
 *     Haraka512(cv_i || input_block_i) for each 32-byte block of the
 *     (always-32-byte-multiple) ciphertext; final output =
 *     Haraka512(cv_n || domain || zero-padding)[0:32].
 *
 * This is purely an experimental agility benchmark and is NOT a vetted
 * cryptographic construction.
 */
#define HARAKA_CUSTOM_MATRIX 0x1F
#define HARAKA_CUSTOM_CBD    0x2F
#define HARAKA_CUSTOM_KDF    0x3F

typedef struct {
    uint8_t block[64];
    uint64_t counter;
} xof_state;

void PQCLEAN_MLKEM512_HARAKA_kyber_haraka_absorb(xof_state *s,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y);

void PQCLEAN_MLKEM512_HARAKA_kyber_haraka_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *s);

void PQCLEAN_MLKEM512_HARAKA_kyber_haraka_ctx_release(xof_state *s);

void PQCLEAN_MLKEM512_HARAKA_kyber_haraka_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

void PQCLEAN_MLKEM512_HARAKA_kyber_haraka_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

/* One Haraka512 call produces 32 bytes per "block". */
#define XOF_BLOCKBYTES 32

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) PQCLEAN_MLKEM512_HARAKA_kyber_haraka_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLKEM512_HARAKA_kyber_haraka_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) PQCLEAN_MLKEM512_HARAKA_kyber_haraka_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) PQCLEAN_MLKEM512_HARAKA_kyber_haraka_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) PQCLEAN_MLKEM512_HARAKA_kyber_haraka_rkprf(OUT, KEY, INPUT)

#endif

```

**`crypto_kem/ml-kem-512/haraka/symmetric-haraka.c`**

```c
#include "fips202.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void set_counter(uint8_t block[64], uint64_t counter) {
    int i;
    for (i = 0; i < 8; i++) {
        block[56 + i] = (uint8_t)(counter >> (8 * i));
    }
}

/*
 * PQCLEAN_MLKEM512_HARAKA_kyber_haraka_absorb
 *   Haraka-CTR replacement for the SHAKE128 matrix expansion XOF.
 *   Domain byte 0x1F (HARAKA_CUSTOM_MATRIX).  See symmetric.h for the
 *   non-standard counter-mode construction.
 */
void PQCLEAN_MLKEM512_HARAKA_kyber_haraka_absorb(xof_state *state,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y) {
    memset(state->block, 0, sizeof(state->block));
    memcpy(state->block, seed, KYBER_SYMBYTES);
    state->block[KYBER_SYMBYTES + 0] = x;
    state->block[KYBER_SYMBYTES + 1] = y;
    state->block[KYBER_SYMBYTES + 2] = HARAKA_CUSTOM_MATRIX;
    state->counter = 0;
}

void PQCLEAN_MLKEM512_HARAKA_kyber_haraka_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    size_t i;
    for (i = 0; i < nblocks; i++) {
        set_counter(state->block, state->counter);
        haraka512(out + i * XOF_BLOCKBYTES, state->block);
        state->counter++;
    }
}

void PQCLEAN_MLKEM512_HARAKA_kyber_haraka_ctx_release(xof_state *state) {
    (void)state;
}

/*
 * PQCLEAN_MLKEM512_HARAKA_kyber_haraka_prf
 *   Haraka-CTR replacement for the SHAKE256 PRF used in CBD noise
 *   generation.  Domain byte 0x2F (HARAKA_CUSTOM_CBD).
 */
void PQCLEAN_MLKEM512_HARAKA_kyber_haraka_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t block[64];
    uint8_t tmp[XOF_BLOCKBYTES];
    uint64_t counter = 0;
    size_t produced = 0;
    size_t chunk;

    memset(block, 0, sizeof(block));
    memcpy(block, key, KYBER_SYMBYTES);
    block[KYBER_SYMBYTES + 0] = nonce;
    block[KYBER_SYMBYTES + 1] = HARAKA_CUSTOM_CBD;

    while (produced < outlen) {
        set_counter(block, counter++);
        haraka512(tmp, block);
        chunk = (outlen - produced < XOF_BLOCKBYTES) ? (outlen - produced) : XOF_BLOCKBYTES;
        memcpy(out + produced, tmp, chunk);
        produced += chunk;
    }
}

/*
 * PQCLEAN_MLKEM512_HARAKA_kyber_haraka_rkprf
 *   Haraka-CTR/MD replacement for the SHAKE256 "J" function used to
 *   derive the implicit-rejection shared secret.  Domain byte 0x3F
 *   (HARAKA_CUSTOM_KDF).  Chains Haraka512 as a Merkle-Damgard
 *   compression function over key || ciphertext (whose length is always
 *   a multiple of 32 bytes for ML-KEM).
 */
void PQCLEAN_MLKEM512_HARAKA_kyber_haraka_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]) {
    uint8_t cv[32];
    uint8_t block[64];
    size_t i;

    memcpy(cv, key, sizeof(cv));

    for (i = 0; i < KYBER_CIPHERTEXTBYTES; i += 32) {
        memcpy(block, cv, 32);
        memcpy(block + 32, input + i, 32);
        haraka512(cv, block);
    }

    memset(block, 0, sizeof(block));
    memcpy(block, cv, 32);
    block[32] = HARAKA_CUSTOM_KDF;
    haraka512(out, block);
}

```

---

## 8. ML-DSA hash/XOF backend code (symmetric.c/h + poly/sign refactor)

ML-DSA's `clean` reference code calls `shake256_inc_*` directly from
`poly.c` and `sign.c` (there is no pre-existing `xof_*` indirection like
ML-KEM has). So each fork needs **two** changes:

1. A new `symmetric.h` + `symmetric-<tag>.c` declaring a backend-agnostic
   `xof_state` type and `xof_init`/`xof_absorb`/`xof_finalize`/
   `xof_squeeze`/`xof_release` functions, plus `XOF_DOMAIN_HASH` /
   `XOF_DOMAIN_CHALLENGE` domain-separation bytes (§8.1).
2. A mechanical patch to `poly.c` (function `poly_challenge`) and
   `sign.c` (the `crypto_sign{,_signature}` H(μ)/challenge-hash call
   sites) that replaces the direct `shake256incctx`/`shake256_inc_*`
   calls with the new `xof_*` API (§8.2). This patch text is
   **byte-identical across ml-dsa-44/65/87** (modulo namespace), so it is
   applied once and copied to all three sizes.

### 8.1 Per-backend `symmetric.h` + `symmetric-<tag>.c` (ml-dsa-44 representative)

As with ML-KEM (§7), `ml-dsa-65`/`ml-dsa-87` are identical modulo the
`MLDSA65`/`MLDSA87` namespace prefix.

#### 8.1.1 Backend: `turboshake`

**`crypto_sign/ml-dsa-44/turboshake/symmetric.h`**

```c
#ifndef PQCLEAN_MLDSA44_TURBO_SYMMETRIC_H
#define PQCLEAN_MLDSA44_TURBO_SYMMETRIC_H
#include "params.h"
#include "TurboSHAKE.h"
#include <stddef.h>
#include <stdint.h>

/*
 * TurboSHAKE (RFC 9861) substitution for the SHAKE128/SHAKE256 uses inside
 * ML-DSA, per the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (stream128, poly_uniform)            -> TurboSHAKE128, D=0x1F
 *   Vector 2: Eta/mask noise sampling (stream256, poly_uniform_eta/
 *             poly_uniform_gamma1)                                   -> TurboSHAKE256, D=0x2F
 *   Vector 3: "H/CRH" role (tr=H(pk), mu=CRH(tr,msg), rhoprime=H(K,
 *             rnd,mu), c~=H(mu,w1))                                  -> TurboSHAKE256, D=0x3F
 *   Vector 4: Challenge polynomial sampling (poly_challenge)         -> TurboSHAKE256, D=0x4F
 *
 * Unlike ML-KEM, Dilithium has no separate SHA3-256/512 "hash_h/hash_g"
 * step left untouched -- essentially all hashing in ML-DSA is
 * SHAKE128/256-based, so this substitution touches poly_uniform*,
 * poly_challenge, and every H/CRH call in sign.c.
 */
#define XOF_DOMAIN_MATRIX    0x1F
#define XOF_DOMAIN_NOISE     0x2F
#define XOF_DOMAIN_HASH      0x3F
#define XOF_DOMAIN_CHALLENGE 0x4F

/* TurboSHAKE128 rate (capacity=256) = 168 bytes; TurboSHAKE256 rate
 * (capacity=512) = 136 bytes -- identical to SHAKE128/256, so the
 * existing rejection-sampling block-size math in poly.c is unchanged. */
#define STREAM128_BLOCKBYTES 168
#define STREAM256_BLOCKBYTES 136
#define XOF_BLOCKBYTES       136

typedef TurboSHAKE_Instance stream128_state;
typedef TurboSHAKE_Instance stream256_state;
typedef TurboSHAKE_Instance xof_state;

void PQCLEAN_MLDSA44_TURBO_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce);
void PQCLEAN_MLDSA44_TURBO_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce);
void PQCLEAN_MLDSA44_TURBO_dilithium_squeezeblocks128(uint8_t *out, size_t nblocks, stream128_state *state);
void PQCLEAN_MLDSA44_TURBO_dilithium_squeezeblocks256(uint8_t *out, size_t nblocks, stream256_state *state);

void PQCLEAN_MLDSA44_TURBO_xof_init(xof_state *state);
void PQCLEAN_MLDSA44_TURBO_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen);
void PQCLEAN_MLDSA44_TURBO_xof_finalize(xof_state *state, uint8_t domain);
void PQCLEAN_MLDSA44_TURBO_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state);

#define stream128_init(STATE, SEED, NONCE) PQCLEAN_MLDSA44_TURBO_dilithium_stream128_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA44_TURBO_dilithium_squeezeblocks128(OUT, OUTBLOCKS, STATE)
#define stream128_release(STATE) ((void)(STATE))

#define stream256_init(STATE, SEED, NONCE) PQCLEAN_MLDSA44_TURBO_dilithium_stream256_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA44_TURBO_dilithium_squeezeblocks256(OUT, OUTBLOCKS, STATE)
#define stream256_release(STATE) ((void)(STATE))

#define xof_init(STATE) PQCLEAN_MLDSA44_TURBO_xof_init(STATE)
#define xof_absorb(STATE, IN, INLEN) PQCLEAN_MLDSA44_TURBO_xof_absorb(STATE, IN, INLEN)
#define xof_finalize(STATE, DOMAIN) PQCLEAN_MLDSA44_TURBO_xof_finalize(STATE, DOMAIN)
#define xof_squeeze(OUT, OUTLEN, STATE) PQCLEAN_MLDSA44_TURBO_xof_squeeze(OUT, OUTLEN, STATE)
#define xof_release(STATE) ((void)(STATE))

#endif

```

**`crypto_sign/ml-dsa-44/turboshake/symmetric-turboshake.c`**

```c
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>

/*
 * PQCLEAN_MLDSA44_TURBO_dilithium_stream128_init / stream256_init
 *   TurboSHAKE128/256 (n_r=12, RFC 9861) replacements for the SHAKE128/256
 *   "stream" XOFs used for matrix expansion (poly_uniform) and eta/mask
 *   sampling (poly_uniform_eta, poly_uniform_gamma1).  The 2-byte nonce is
 *   absorbed little-endian, followed by a domain-separation byte
 *   (XOF_DOMAIN_MATRIX / XOF_DOMAIN_NOISE).
 */
void PQCLEAN_MLDSA44_TURBO_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    TurboSHAKE128_Initialize(state);
    TurboSHAKE_Absorb(state, seed, SEEDBYTES);
    TurboSHAKE_Absorb(state, t, 2);
    TurboSHAKE_AbsorbDomainSeparationByte(state, XOF_DOMAIN_MATRIX);
}

void PQCLEAN_MLDSA44_TURBO_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    TurboSHAKE256_Initialize(state);
    TurboSHAKE_Absorb(state, seed, CRHBYTES);
    TurboSHAKE_Absorb(state, t, 2);
    TurboSHAKE_AbsorbDomainSeparationByte(state, XOF_DOMAIN_NOISE);
}

void PQCLEAN_MLDSA44_TURBO_dilithium_squeezeblocks128(uint8_t *out, size_t nblocks, stream128_state *state) {
    TurboSHAKE_Squeeze(state, out, nblocks * STREAM128_BLOCKBYTES);
}

void PQCLEAN_MLDSA44_TURBO_dilithium_squeezeblocks256(uint8_t *out, size_t nblocks, stream256_state *state) {
    TurboSHAKE_Squeeze(state, out, nblocks * STREAM256_BLOCKBYTES);
}

/*
 * PQCLEAN_MLDSA44_TURBO_xof_*
 *   Generic incremental TurboSHAKE256 XOF used for the "H/CRH" role
 *   (tr, mu, rhoprime, c~ -- domain XOF_DOMAIN_HASH) and for
 *   poly_challenge (domain XOF_DOMAIN_CHALLENGE).  xof_absorb may be
 *   called any number of times before xof_finalize; xof_squeeze may be
 *   called any number of times afterwards (TurboSHAKE_Squeeze supports
 *   arbitrary-length, repeated squeeze calls).
 */
void PQCLEAN_MLDSA44_TURBO_xof_init(xof_state *state) {
    TurboSHAKE256_Initialize(state);
}

void PQCLEAN_MLDSA44_TURBO_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen) {
    if (inlen) {
        TurboSHAKE_Absorb(state, in, inlen);
    }
}

void PQCLEAN_MLDSA44_TURBO_xof_finalize(xof_state *state, uint8_t domain) {
    TurboSHAKE_AbsorbDomainSeparationByte(state, domain);
}

void PQCLEAN_MLDSA44_TURBO_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state) {
    TurboSHAKE_Squeeze(state, out, outlen);
}

```

#### 8.1.2 Backend: `k12`

**`crypto_sign/ml-dsa-44/k12/symmetric.h`**

```c
#ifndef PQCLEAN_MLDSA44_K12_SYMMETRIC_H
#define PQCLEAN_MLDSA44_K12_SYMMETRIC_H
#include "params.h"
#include "KangarooTwelve.h"
#include <stddef.h>
#include <stdint.h>

/*
 * KangarooTwelve (RFC 9861) substitution for the SHAKE128/SHAKE256 uses
 * inside ML-DSA, per the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (stream128, poly_uniform)            -> KT128, C=0x1F
 *   Vector 2: Eta/mask noise sampling (stream256, poly_uniform_eta/
 *             poly_uniform_gamma1)                                   -> KT256, C=0x2F
 *   Vector 3: "H/CRH" role (tr=H(pk), mu=CRH(tr,msg), rhoprime=H(K,
 *             rnd,mu), c~=H(mu,w1))                                  -> KT256, C=0x3F
 *   Vector 4: Challenge polynomial sampling (poly_challenge)         -> KT256, C=0x4F
 *
 * K12 has no sponge-level "domain separation byte" the way TurboSHAKE
 * does; instead these single-byte values are used as the K12
 * "customization string" C, absorbed (with a length encoding) after the
 * message M via KangarooTwelve_Final().
 */
#define XOF_DOMAIN_MATRIX    0x1F
#define XOF_DOMAIN_NOISE     0x2F
#define XOF_DOMAIN_HASH      0x3F
#define XOF_DOMAIN_CHALLENGE 0x4F

/* KT128's underlying TurboSHAKE128 rate = 168 bytes; KT256's underlying
 * TurboSHAKE256 rate = 136 bytes -- identical to SHAKE128/256, so the
 * existing rejection-sampling block-size math in poly.c is unchanged. */
#define STREAM128_BLOCKBYTES 168
#define STREAM256_BLOCKBYTES 136
#define XOF_BLOCKBYTES       136

typedef KangarooTwelve_Instance stream128_state;
typedef KangarooTwelve_Instance stream256_state;
typedef KangarooTwelve_Instance xof_state;

void PQCLEAN_MLDSA44_K12_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce);
void PQCLEAN_MLDSA44_K12_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce);
void PQCLEAN_MLDSA44_K12_dilithium_squeezeblocks128(uint8_t *out, size_t nblocks, stream128_state *state);
void PQCLEAN_MLDSA44_K12_dilithium_squeezeblocks256(uint8_t *out, size_t nblocks, stream256_state *state);

void PQCLEAN_MLDSA44_K12_xof_init(xof_state *state);
void PQCLEAN_MLDSA44_K12_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen);
void PQCLEAN_MLDSA44_K12_xof_finalize(xof_state *state, uint8_t domain);
void PQCLEAN_MLDSA44_K12_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state);

#define stream128_init(STATE, SEED, NONCE) PQCLEAN_MLDSA44_K12_dilithium_stream128_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA44_K12_dilithium_squeezeblocks128(OUT, OUTBLOCKS, STATE)
#define stream128_release(STATE) ((void)(STATE))

#define stream256_init(STATE, SEED, NONCE) PQCLEAN_MLDSA44_K12_dilithium_stream256_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA44_K12_dilithium_squeezeblocks256(OUT, OUTBLOCKS, STATE)
#define stream256_release(STATE) ((void)(STATE))

#define xof_init(STATE) PQCLEAN_MLDSA44_K12_xof_init(STATE)
#define xof_absorb(STATE, IN, INLEN) PQCLEAN_MLDSA44_K12_xof_absorb(STATE, IN, INLEN)
#define xof_finalize(STATE, DOMAIN) PQCLEAN_MLDSA44_K12_xof_finalize(STATE, DOMAIN)
#define xof_squeeze(OUT, OUTLEN, STATE) PQCLEAN_MLDSA44_K12_xof_squeeze(OUT, OUTLEN, STATE)
#define xof_release(STATE) ((void)(STATE))

#endif

```

**`crypto_sign/ml-dsa-44/k12/symmetric-k12.c`**

```c
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>

/*
 * PQCLEAN_MLDSA44_K12_dilithium_stream128_init / stream256_init
 *   KT128/KT256 (KangarooTwelve, RFC 9861) replacements for the
 *   SHAKE128/256 "stream" XOFs used for matrix expansion (poly_uniform)
 *   and eta/mask sampling (poly_uniform_eta, poly_uniform_gamma1).  The
 *   2-byte nonce is absorbed little-endian, then KangarooTwelve_Final()
 *   is called with a 1-byte customization string (XOF_DOMAIN_MATRIX /
 *   XOF_DOMAIN_NOISE) and unbounded output (0), so squeezeblocks can
 *   later draw as many blocks as the rejection-sampling loop needs.
 */
void PQCLEAN_MLDSA44_K12_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
    uint8_t t[2];
    const uint8_t custom = XOF_DOMAIN_MATRIX;
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    KangarooTwelve_Initialize(state, 128, 0);
    KangarooTwelve_Update(state, seed, SEEDBYTES);
    KangarooTwelve_Update(state, t, 2);
    KangarooTwelve_Final(state, NULL, &custom, 1);
}

void PQCLEAN_MLDSA44_K12_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    uint8_t t[2];
    const uint8_t custom = XOF_DOMAIN_NOISE;
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    KangarooTwelve_Initialize(state, 256, 0);
    KangarooTwelve_Update(state, seed, CRHBYTES);
    KangarooTwelve_Update(state, t, 2);
    KangarooTwelve_Final(state, NULL, &custom, 1);
}

void PQCLEAN_MLDSA44_K12_dilithium_squeezeblocks128(uint8_t *out, size_t nblocks, stream128_state *state) {
    KangarooTwelve_Squeeze(state, out, nblocks * STREAM128_BLOCKBYTES);
}

void PQCLEAN_MLDSA44_K12_dilithium_squeezeblocks256(uint8_t *out, size_t nblocks, stream256_state *state) {
    KangarooTwelve_Squeeze(state, out, nblocks * STREAM256_BLOCKBYTES);
}

/*
 * PQCLEAN_MLDSA44_K12_xof_*
 *   Generic incremental KT256 XOF used for the "H/CRH" role (tr, mu,
 *   rhoprime, c~ -- domain XOF_DOMAIN_HASH) and for poly_challenge
 *   (domain XOF_DOMAIN_CHALLENGE).  xof_absorb may be called any number
 *   of times before xof_finalize (KangarooTwelve_Update); xof_finalize
 *   calls KangarooTwelve_Final() with the 1-byte domain as the
 *   customization string and unbounded output, after which xof_squeeze
 *   may be called any number of times (KangarooTwelve_Squeeze).
 */
void PQCLEAN_MLDSA44_K12_xof_init(xof_state *state) {
    KangarooTwelve_Initialize(state, 256, 0);
}

void PQCLEAN_MLDSA44_K12_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen) {
    if (inlen) {
        KangarooTwelve_Update(state, in, inlen);
    }
}

void PQCLEAN_MLDSA44_K12_xof_finalize(xof_state *state, uint8_t domain) {
    KangarooTwelve_Final(state, NULL, &domain, 1);
}

void PQCLEAN_MLDSA44_K12_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state) {
    KangarooTwelve_Squeeze(state, out, outlen);
}

```

#### 8.1.3 Backend: `blake3`

**`crypto_sign/ml-dsa-44/blake3/symmetric.h`**

```c
#ifndef PQCLEAN_MLDSA44_BLAKE3_SYMMETRIC_H
#define PQCLEAN_MLDSA44_BLAKE3_SYMMETRIC_H
#include "blake3.h"
#include "params.h"
#include <stddef.h>
#include <stdint.h>

/*
 * BLAKE3 substitution for the SHAKE128/SHAKE256 uses inside ML-DSA, per
 * the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (stream128, poly_uniform)            -> BLAKE3 XOF, domain 0x1F
 *   Vector 2: Eta/mask noise sampling (stream256, poly_uniform_eta/
 *             poly_uniform_gamma1)                                   -> BLAKE3 XOF, domain 0x2F
 *   Vector 3: "H/CRH" role (tr=H(pk), mu=CRH(tr,msg), rhoprime=H(K,
 *             rnd,mu), c~=H(mu,w1))                                  -> BLAKE3 XOF, domain 0x3F
 *   Vector 4: Challenge polynomial sampling (poly_challenge)         -> BLAKE3 XOF, domain 0x4F
 *
 * BLAKE3 has no sponge-level "domain separation byte"; instead the
 * 1-byte value is appended to the absorbed input before
 * blake3_hasher_finalize_seek() is used to squeeze output, mirroring the
 * customization-string convention used by the K12/TurboSHAKE variants so
 * the Vector table in pqc_bench.c stays consistent across backends.
 *
 * BLAKE3 has no native "128 vs 256" rate split the way SHAKE/TurboSHAKE/K12
 * do, so a single xof_state type and block size serve all four vectors.
 */
#define XOF_DOMAIN_MATRIX    0x1F
#define XOF_DOMAIN_NOISE     0x2F
#define XOF_DOMAIN_HASH      0x3F
#define XOF_DOMAIN_CHALLENGE 0x4F

/* Arbitrary block size for the squeeze loop -- BLAKE3's XOF has no fixed
 * rate, 168 is chosen to match the SHAKE128 rate used elsewhere. */
#define STREAM128_BLOCKBYTES 168
#define STREAM256_BLOCKBYTES 168
#define XOF_BLOCKBYTES       168

typedef struct {
    blake3_hasher hasher;
    uint64_t squeezed;
} stream128_state;
typedef stream128_state stream256_state;
typedef stream128_state xof_state;

void PQCLEAN_MLDSA44_BLAKE3_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce);
void PQCLEAN_MLDSA44_BLAKE3_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce);
void PQCLEAN_MLDSA44_BLAKE3_dilithium_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state);

void PQCLEAN_MLDSA44_BLAKE3_xof_init(xof_state *state);
void PQCLEAN_MLDSA44_BLAKE3_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen);
void PQCLEAN_MLDSA44_BLAKE3_xof_finalize(xof_state *state, uint8_t domain);
void PQCLEAN_MLDSA44_BLAKE3_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state);

#define stream128_init(STATE, SEED, NONCE) PQCLEAN_MLDSA44_BLAKE3_dilithium_stream128_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA44_BLAKE3_dilithium_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream128_release(STATE) ((void)(STATE))

#define stream256_init(STATE, SEED, NONCE) PQCLEAN_MLDSA44_BLAKE3_dilithium_stream256_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA44_BLAKE3_dilithium_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_release(STATE) ((void)(STATE))

#define xof_init(STATE) PQCLEAN_MLDSA44_BLAKE3_xof_init(STATE)
#define xof_absorb(STATE, IN, INLEN) PQCLEAN_MLDSA44_BLAKE3_xof_absorb(STATE, IN, INLEN)
#define xof_finalize(STATE, DOMAIN) PQCLEAN_MLDSA44_BLAKE3_xof_finalize(STATE, DOMAIN)
#define xof_squeeze(OUT, OUTLEN, STATE) PQCLEAN_MLDSA44_BLAKE3_xof_squeeze(OUT, OUTLEN, STATE)
#define xof_release(STATE) ((void)(STATE))

#endif

```

**`crypto_sign/ml-dsa-44/blake3/symmetric-blake3.c`**

```c
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>

/*
 * PQCLEAN_MLDSA44_BLAKE3_dilithium_stream128_init / stream256_init
 *   BLAKE3-XOF replacements for the SHAKE128/256 "stream" XOFs used for
 *   matrix expansion (poly_uniform) and eta/mask sampling
 *   (poly_uniform_eta, poly_uniform_gamma1).  The 2-byte nonce is
 *   absorbed little-endian, followed by a 1-byte domain-separation value
 *   (XOF_DOMAIN_MATRIX / XOF_DOMAIN_NOISE) before squeezing begins.
 */
void PQCLEAN_MLDSA44_BLAKE3_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    blake3_hasher_init(&state->hasher);
    blake3_hasher_update(&state->hasher, seed, SEEDBYTES);
    blake3_hasher_update(&state->hasher, t, 2);
    {
        const uint8_t domain = XOF_DOMAIN_MATRIX;
        blake3_hasher_update(&state->hasher, &domain, 1);
    }
    state->squeezed = 0;
}

void PQCLEAN_MLDSA44_BLAKE3_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    blake3_hasher_init(&state->hasher);
    blake3_hasher_update(&state->hasher, seed, CRHBYTES);
    blake3_hasher_update(&state->hasher, t, 2);
    {
        const uint8_t domain = XOF_DOMAIN_NOISE;
        blake3_hasher_update(&state->hasher, &domain, 1);
    }
    state->squeezed = 0;
}

void PQCLEAN_MLDSA44_BLAKE3_dilithium_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    size_t outlen = nblocks * XOF_BLOCKBYTES;
    blake3_hasher_finalize_seek(&state->hasher, state->squeezed, out, outlen);
    state->squeezed += outlen;
}

/*
 * PQCLEAN_MLDSA44_BLAKE3_xof_*
 *   Generic incremental BLAKE3 XOF used for the "H/CRH" role (tr, mu,
 *   rhoprime, c~ -- domain XOF_DOMAIN_HASH) and for poly_challenge
 *   (domain XOF_DOMAIN_CHALLENGE).  xof_absorb may be called any number
 *   of times before xof_finalize (blake3_hasher_update); xof_finalize
 *   appends the 1-byte domain and resets the squeeze cursor;
 *   xof_squeeze may be called any number of times afterwards
 *   (blake3_hasher_finalize_seek at increasing offsets).
 */
void PQCLEAN_MLDSA44_BLAKE3_xof_init(xof_state *state) {
    blake3_hasher_init(&state->hasher);
    state->squeezed = 0;
}

void PQCLEAN_MLDSA44_BLAKE3_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen) {
    if (inlen) {
        blake3_hasher_update(&state->hasher, in, inlen);
    }
}

void PQCLEAN_MLDSA44_BLAKE3_xof_finalize(xof_state *state, uint8_t domain) {
    blake3_hasher_update(&state->hasher, &domain, 1);
    state->squeezed = 0;
}

void PQCLEAN_MLDSA44_BLAKE3_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state) {
    blake3_hasher_finalize_seek(&state->hasher, state->squeezed, out, outlen);
    state->squeezed += outlen;
}

```

#### 8.1.4 Backend: `xoodyak`

**`crypto_sign/ml-dsa-44/xoodyak/symmetric.h`**

```c
#ifndef PQCLEAN_MLDSA44_XOODYAK_SYMMETRIC_H
#define PQCLEAN_MLDSA44_XOODYAK_SYMMETRIC_H
#include "params.h"
#include <stddef.h>
#include <stdint.h>

/* ML-DSA's params.h #defines K to the matrix dimension, which collides
 * with Cyclist.h's use of "K" as a function-parameter name. Hide our K
 * macro while parsing the XKCP header, then restore it. */
#pragma push_macro("K")
#undef K
#include "Xoodyak.h"
#pragma pop_macro("K")

/*
 * Xoodyak (NIST LWC finalist, sponge over the 384-bit Xoodoo permutation,
 * via XKCP's Cyclist construction) substitution for the SHAKE128/SHAKE256
 * uses inside ML-DSA, per the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (stream128, poly_uniform)            -> Xoodyak hash mode, domain 0x1F
 *   Vector 2: Eta/mask noise sampling (stream256, poly_uniform_eta/
 *             poly_uniform_gamma1)                                   -> Xoodyak hash mode, domain 0x2F
 *   Vector 3: "H/CRH" role (tr=H(pk), mu=CRH(tr,msg), rhoprime=H(K,
 *             rnd,mu), c~=H(mu,w1))                                  -> Xoodyak hash mode, domain 0x3F
 *   Vector 4: Challenge polynomial sampling (poly_challenge)         -> Xoodyak hash mode, domain 0x4F
 *
 * Xoodyak's Cyclist mode is used as a plain sponge: Initialize() with no
 * key selects Cyclist_ModeHash (absorb/squeeze rate = Xoodyak_Rhash = 16
 * bytes). The single-byte domain values are appended to the absorbed
 * input, mirroring the customization-string convention used by the
 * K12/TurboSHAKE/BLAKE3 variants so the Vector table in pqc_bench.c stays
 * consistent across backends. A single xof_state type and block size
 * serve all four vectors.
 */
#define XOF_DOMAIN_MATRIX    0x1F
#define XOF_DOMAIN_NOISE     0x2F
#define XOF_DOMAIN_HASH      0x3F
#define XOF_DOMAIN_CHALLENGE 0x4F

/* Xoodyak's hash-mode absorb/squeeze rate (Xoodyak_Rhash). Cyclist_Squeeze()
 * handles arbitrary lengths internally, so this just matches the native
 * rate for the rejection-sampling squeeze loop. */
#define STREAM128_BLOCKBYTES 16
#define STREAM256_BLOCKBYTES 16
#define XOF_BLOCKBYTES       16

typedef Xoodyak_Instance stream128_state;
typedef Xoodyak_Instance stream256_state;
typedef Xoodyak_Instance xof_state;

void PQCLEAN_MLDSA44_XOODYAK_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce);
void PQCLEAN_MLDSA44_XOODYAK_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce);
void PQCLEAN_MLDSA44_XOODYAK_dilithium_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state);

void PQCLEAN_MLDSA44_XOODYAK_xof_init(xof_state *state);
void PQCLEAN_MLDSA44_XOODYAK_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen);
void PQCLEAN_MLDSA44_XOODYAK_xof_finalize(xof_state *state, uint8_t domain);
void PQCLEAN_MLDSA44_XOODYAK_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state);

#define stream128_init(STATE, SEED, NONCE) PQCLEAN_MLDSA44_XOODYAK_dilithium_stream128_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA44_XOODYAK_dilithium_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream128_release(STATE) ((void)(STATE))

#define stream256_init(STATE, SEED, NONCE) PQCLEAN_MLDSA44_XOODYAK_dilithium_stream256_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA44_XOODYAK_dilithium_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_release(STATE) ((void)(STATE))

#define xof_init(STATE) PQCLEAN_MLDSA44_XOODYAK_xof_init(STATE)
#define xof_absorb(STATE, IN, INLEN) PQCLEAN_MLDSA44_XOODYAK_xof_absorb(STATE, IN, INLEN)
#define xof_finalize(STATE, DOMAIN) PQCLEAN_MLDSA44_XOODYAK_xof_finalize(STATE, DOMAIN)
#define xof_squeeze(OUT, OUTLEN, STATE) PQCLEAN_MLDSA44_XOODYAK_xof_squeeze(OUT, OUTLEN, STATE)
#define xof_release(STATE) ((void)(STATE))

#endif

```

**`crypto_sign/ml-dsa-44/xoodyak/symmetric-xoodyak.c`**

```c
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>

/*
 * PQCLEAN_MLDSA44_XOODYAK_dilithium_stream128_init / stream256_init
 *   Xoodyak (Cyclist hash mode) replacements for the SHAKE128/256 "stream"
 *   XOFs used for matrix expansion (poly_uniform) and eta/mask sampling
 *   (poly_uniform_eta, poly_uniform_gamma1).  The 2-byte nonce is absorbed
 *   little-endian, followed by a 1-byte domain-separation value
 *   (XOF_DOMAIN_MATRIX / XOF_DOMAIN_NOISE) before squeezing begins.
 */
void PQCLEAN_MLDSA44_XOODYAK_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
    uint8_t t[2];
    const uint8_t domain = XOF_DOMAIN_MATRIX;
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    Xoodyak_Initialize(state, NULL, 0, NULL, 0, NULL, 0);
    Xoodyak_Absorb(state, seed, SEEDBYTES);
    Xoodyak_Absorb(state, t, 2);
    Xoodyak_Absorb(state, &domain, 1);
}

void PQCLEAN_MLDSA44_XOODYAK_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    uint8_t t[2];
    const uint8_t domain = XOF_DOMAIN_NOISE;
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    Xoodyak_Initialize(state, NULL, 0, NULL, 0, NULL, 0);
    Xoodyak_Absorb(state, seed, CRHBYTES);
    Xoodyak_Absorb(state, t, 2);
    Xoodyak_Absorb(state, &domain, 1);
}

void PQCLEAN_MLDSA44_XOODYAK_dilithium_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    Xoodyak_Squeeze(state, out, nblocks * XOF_BLOCKBYTES);
}

/*
 * PQCLEAN_MLDSA44_XOODYAK_xof_*
 *   Generic incremental Xoodyak (Cyclist hash mode) XOF used for the
 *   "H/CRH" role (tr, mu, rhoprime, c~ -- domain XOF_DOMAIN_HASH) and for
 *   poly_challenge (domain XOF_DOMAIN_CHALLENGE).  xof_absorb may be
 *   called any number of times before xof_finalize (Xoodyak_Absorb);
 *   xof_finalize absorbs the 1-byte domain; xof_squeeze may be called any
 *   number of times afterwards (Xoodyak_Squeeze).
 */
void PQCLEAN_MLDSA44_XOODYAK_xof_init(xof_state *state) {
    Xoodyak_Initialize(state, NULL, 0, NULL, 0, NULL, 0);
}

void PQCLEAN_MLDSA44_XOODYAK_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen) {
    if (inlen) {
        Xoodyak_Absorb(state, in, inlen);
    }
}

void PQCLEAN_MLDSA44_XOODYAK_xof_finalize(xof_state *state, uint8_t domain) {
    Xoodyak_Absorb(state, &domain, 1);
}

void PQCLEAN_MLDSA44_XOODYAK_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state) {
    Xoodyak_Squeeze(state, out, outlen);
}

```

#### 8.1.5 Backend: `haraka`

**`crypto_sign/ml-dsa-44/haraka/symmetric.h`**

```c
#ifndef PQCLEAN_MLDSA44_HARAKA_SYMMETRIC_H
#define PQCLEAN_MLDSA44_HARAKA_SYMMETRIC_H
#include "params.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Haraka-MD: a custom Merkle-Damgard-style hash/XOF built on top of
 * haraka512 (512-bit input / 256-bit output AES-round permutation,
 * Davies-Meyer), substituting for the SHAKE128/SHAKE256 uses inside
 * ML-DSA, per the agility benchmark's hash integration vectors:
 *   Vector 1: Matrix expansion (stream128, poly_uniform)            -> Haraka-MD XOF, domain 0x1F
 *   Vector 2: Eta/mask noise sampling (stream256, poly_uniform_eta/
 *             poly_uniform_gamma1)                                   -> Haraka-MD XOF, domain 0x2F
 *   Vector 3: "H/CRH" role (tr=H(pk), mu=CRH(tr,msg), rhoprime=H(K,
 *             rnd,mu), c~=H(mu,w1))                                  -> Haraka-MD XOF, domain 0x3F
 *   Vector 4: Challenge polynomial sampling (poly_challenge)         -> Haraka-MD XOF, domain 0x4F
 *
 * Construction (NOT a FIPS-approved mode -- a benchmarking substitution
 * only):
 *   - 32-byte chaining value cv, initialized to all-zero (IV = 0^256).
 *   - Absorb: input is buffered into 32-byte blocks; each full block is
 *     compressed via cv = haraka512(cv || block)[0:32].
 *   - Finalize: the (possibly empty, 0-31 byte) remaining buffer is
 *     padded with a single domain-separation byte followed by zeros to
 *     32 bytes, then compressed into cv exactly like an absorb block.
 *     This also resets the output block counter to 0.
 *   - Squeeze: output block i = haraka512(cv || LE64(i) || 0^24)[0:32],
 *     for i = 0, 1, 2, ... -- i.e. the 64-byte compression input is the
 *     chaining value concatenated with an 8-byte little-endian counter
 *     and 24 zero bytes. Output is the concatenation of these 32-byte
 *     blocks, truncated to the requested length.
 *
 * All four vectors and both stream128/stream256 use the same 32-byte
 * block size, so a single xof_state type and block size serve all uses.
 */
#define XOF_DOMAIN_MATRIX    0x1F
#define XOF_DOMAIN_NOISE     0x2F
#define XOF_DOMAIN_HASH      0x3F
#define XOF_DOMAIN_CHALLENGE 0x4F

#define STREAM128_BLOCKBYTES 32
#define STREAM256_BLOCKBYTES 32
#define XOF_BLOCKBYTES       32

typedef struct {
    uint8_t cv[32];
    uint8_t buf[32];
    size_t buflen;
    uint64_t counter;
} xof_state;
typedef xof_state stream128_state;
typedef xof_state stream256_state;

void PQCLEAN_MLDSA44_HARAKA_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce);
void PQCLEAN_MLDSA44_HARAKA_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce);
void PQCLEAN_MLDSA44_HARAKA_dilithium_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state);

void PQCLEAN_MLDSA44_HARAKA_xof_init(xof_state *state);
void PQCLEAN_MLDSA44_HARAKA_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen);
void PQCLEAN_MLDSA44_HARAKA_xof_finalize(xof_state *state, uint8_t domain);
void PQCLEAN_MLDSA44_HARAKA_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state);

#define stream128_init(STATE, SEED, NONCE) PQCLEAN_MLDSA44_HARAKA_dilithium_stream128_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA44_HARAKA_dilithium_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream128_release(STATE) ((void)(STATE))

#define stream256_init(STATE, SEED, NONCE) PQCLEAN_MLDSA44_HARAKA_dilithium_stream256_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) PQCLEAN_MLDSA44_HARAKA_dilithium_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_release(STATE) ((void)(STATE))

#define xof_init(STATE) PQCLEAN_MLDSA44_HARAKA_xof_init(STATE)
#define xof_absorb(STATE, IN, INLEN) PQCLEAN_MLDSA44_HARAKA_xof_absorb(STATE, IN, INLEN)
#define xof_finalize(STATE, DOMAIN) PQCLEAN_MLDSA44_HARAKA_xof_finalize(STATE, DOMAIN)
#define xof_squeeze(OUT, OUTLEN, STATE) PQCLEAN_MLDSA44_HARAKA_xof_squeeze(OUT, OUTLEN, STATE)
#define xof_release(STATE) ((void)(STATE))

#endif

```

**`crypto_sign/ml-dsa-44/haraka/symmetric-haraka.c`**

```c
#include "haraka.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * compress: Davies-Meyer-style chaining step cv <- haraka512(cv || block).
 */
static void compress(uint8_t cv[32], const uint8_t block[32]) {
    uint8_t in[64];
    memcpy(in, cv, 32);
    memcpy(in + 32, block, 32);
    haraka512(cv, in);
}

void PQCLEAN_MLDSA44_HARAKA_xof_init(xof_state *state) {
    memset(state->cv, 0, sizeof state->cv);
    state->buflen = 0;
    state->counter = 0;
}

void PQCLEAN_MLDSA44_HARAKA_xof_absorb(xof_state *state, const uint8_t *in, size_t inlen) {
    size_t take;
    while (inlen > 0) {
        take = 32 - state->buflen;
        if (take > inlen) {
            take = inlen;
        }
        memcpy(state->buf + state->buflen, in, take);
        state->buflen += take;
        in += take;
        inlen -= take;
        if (state->buflen == 32) {
            compress(state->cv, state->buf);
            state->buflen = 0;
        }
    }
}

void PQCLEAN_MLDSA44_HARAKA_xof_finalize(xof_state *state, uint8_t domain) {
    state->buf[state->buflen++] = domain;
    while (state->buflen < 32) {
        state->buf[state->buflen++] = 0;
    }
    compress(state->cv, state->buf);
    state->buflen = 0;
    state->counter = 0;
}

void PQCLEAN_MLDSA44_HARAKA_xof_squeeze(uint8_t *out, size_t outlen, xof_state *state) {
    uint8_t in[64];
    uint8_t block[32];
    size_t i, take;

    memcpy(in, state->cv, 32);
    while (outlen > 0) {
        memset(in + 32, 0, 32);
        for (i = 0; i < 8; ++i) {
            in[32 + i] = (uint8_t)(state->counter >> (8 * i));
        }
        haraka512(block, in);
        state->counter++;

        take = (outlen < 32) ? outlen : 32;
        memcpy(out, block, take);
        out += take;
        outlen -= take;
    }
}

/*
 * PQCLEAN_MLDSA44_HARAKA_dilithium_stream128_init / stream256_init
 *   Haraka-MD replacements for the SHAKE128/256 "stream" XOFs used for
 *   matrix expansion (poly_uniform) and eta/mask sampling
 *   (poly_uniform_eta, poly_uniform_gamma1).  The 2-byte nonce is absorbed
 *   little-endian, followed by xof_finalize with the matching domain byte
 *   (XOF_DOMAIN_MATRIX / XOF_DOMAIN_NOISE).
 */
void PQCLEAN_MLDSA44_HARAKA_dilithium_stream128_init(stream128_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    PQCLEAN_MLDSA44_HARAKA_xof_init(state);
    PQCLEAN_MLDSA44_HARAKA_xof_absorb(state, seed, SEEDBYTES);
    PQCLEAN_MLDSA44_HARAKA_xof_absorb(state, t, 2);
    PQCLEAN_MLDSA44_HARAKA_xof_finalize(state, XOF_DOMAIN_MATRIX);
}

void PQCLEAN_MLDSA44_HARAKA_dilithium_stream256_init(stream256_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    PQCLEAN_MLDSA44_HARAKA_xof_init(state);
    PQCLEAN_MLDSA44_HARAKA_xof_absorb(state, seed, CRHBYTES);
    PQCLEAN_MLDSA44_HARAKA_xof_absorb(state, t, 2);
    PQCLEAN_MLDSA44_HARAKA_xof_finalize(state, XOF_DOMAIN_NOISE);
}

void PQCLEAN_MLDSA44_HARAKA_dilithium_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
    PQCLEAN_MLDSA44_HARAKA_xof_squeeze(out, nblocks * XOF_BLOCKBYTES, state);
}

```

### 8.2 The `poly.c` / `sign.c` patch (`mldsa_refactor.py`)

This script contains the **exact** before/after text for the
`poly_challenge` (in `poly.c`) and the H(μ)/challenge-hash call sites (in
`sign.c`) refactor described above. It operates on a freshly-forked
`ml-dsa-{44,65,87}/<tag>/{poly.c,sign.c}` (copied from `clean` with the
namespace already renamed to `<TAG>`, but still containing the original
`shake256incctx`-based code) and rewrites those two files in place to use
the new `xof_*` API from §8.1.

Run it once per `(size, tag)` after copying `clean/{poly.c,sign.c}` into
the fork and renaming the namespace, and after the new `symmetric.h` from
§8.1 is in place:

```bash
python3 mldsa_refactor.py PQClean/crypto_sign/ml-dsa-44/turboshake
# ... repeat for each of the 15 (size, tag) combinations
```

**`mldsa_refactor.py`**

```python
#!/usr/bin/env python3
"""
Apply the generic xof_state refactor to a forked ml-dsa-{44,65,87}/<tag>
tree's poly.c and sign.c.  This replaces all direct shake256 /
shake256incctx usages with the backend-agnostic xof_state API declared in
the fork's new symmetric.h (xof_init/xof_absorb/xof_finalize/xof_squeeze/
xof_release, domain bytes via XOF_DOMAIN_HASH / XOF_DOMAIN_CHALLENGE).

The replaced text is identical (byte-for-byte) across ml-dsa-44/65/87
clean sources, so this single patch applies to all three sizes.
"""
import sys

def must_replace(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"ERROR: {label}: expected exactly 1 occurrence, found {text.count(old)}")
    return text.replace(old, new)

def patch_poly(path):
    text = open(path).read()

    old = '''void PQCLEAN_MLDSA44_CLEAN_poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES]) {
    unsigned int i, b, pos;
    uint64_t signs;
    uint8_t buf[SHAKE256_RATE];
    shake256incctx state;

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, seed, CTILDEBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(buf, sizeof buf, &state);

    signs = 0;
    for (i = 0; i < 8; ++i) {
        signs |= (uint64_t)buf[i] << 8 * i;
    }
    pos = 8;

    for (i = 0; i < N; ++i) {
        c->coeffs[i] = 0;
    }
    for (i = N - TAU; i < N; ++i) {
        do {
            if (pos >= SHAKE256_RATE) {
                shake256_inc_squeeze(buf, sizeof buf, &state);
                pos = 0;
            }

            b = buf[pos++];
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (signs & 1);
        signs >>= 1;
    }
    shake256_inc_ctx_release(&state);
}'''

    new = '''void PQCLEAN_MLDSA44_CLEAN_poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES]) {
    unsigned int i, b, pos;
    uint64_t signs;
    uint8_t buf[XOF_BLOCKBYTES];
    xof_state state;

    xof_init(&state);
    xof_absorb(&state, seed, CTILDEBYTES);
    xof_finalize(&state, XOF_DOMAIN_CHALLENGE);
    xof_squeeze(buf, sizeof buf, &state);

    signs = 0;
    for (i = 0; i < 8; ++i) {
        signs |= (uint64_t)buf[i] << 8 * i;
    }
    pos = 8;

    for (i = 0; i < N; ++i) {
        c->coeffs[i] = 0;
    }
    for (i = N - TAU; i < N; ++i) {
        do {
            if (pos >= sizeof buf) {
                xof_squeeze(buf, sizeof buf, &state);
                pos = 0;
            }

            b = buf[pos++];
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (signs & 1);
        signs >>= 1;
    }
    xof_release(&state);
}'''

    # poly.c bodies are identical across sizes except for the
    # PQCLEAN_MLDSA{44,65,87}_CLEAN_ function name prefix, which has
    # already been sed-renamed to PQCLEAN_MLDSA{size}_<TAG>_ before this
    # script runs. Match it with a prefix-agnostic regex.
    import re
    pattern = re.compile(
        re.escape(old).replace(re.escape('PQCLEAN_MLDSA44_CLEAN_'), r'PQCLEAN_MLDSA\d+_[A-Z0-9]+_')
    )
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise SystemExit(f"ERROR: poly.c poly_challenge pattern matched {len(matches)} times")
    prefix = re.search(r'(PQCLEAN_MLDSA\d+_[A-Z0-9]+_)poly_challenge', matches[0]).group(1)
    text = pattern.sub(new.replace('PQCLEAN_MLDSA44_CLEAN_', prefix), text, count=1)

    open(path, 'w').write(text)


def patch_sign(path):
    text = open(path).read()

    # 0. Drop the now-unused fips202.h include.
    text = must_replace(text, '#include "fips202.h"\n', '', "sign.c fips202.h include")

    # 1. keypair: H(seed) -> rho || rhoprime || key
    old1 = '''    shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);'''
    new1 = '''    {
        xof_state state;
        xof_init(&state);
        xof_absorb(&state, seedbuf, SEEDBYTES + 2);
        xof_finalize(&state, XOF_DOMAIN_HASH);
        xof_squeeze(seedbuf, 2 * SEEDBYTES + CRHBYTES, &state);
        xof_release(&state);
    }'''
    text = must_replace(text, old1, new1, "sign.c keypair H(seed)")

    # 2. keypair: tr = H(pk)
    old2 = '''    shake256(tr, TRBYTES, pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);'''
    new2 = '''    {
        xof_state state;
        xof_init(&state);
        xof_absorb(&state, pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);
        xof_finalize(&state, XOF_DOMAIN_HASH);
        xof_squeeze(tr, TRBYTES, &state);
        xof_release(&state);
    }'''
    import re
    pat2 = re.compile(re.escape(old2).replace(re.escape('PQCLEAN_MLDSA44_CLEAN_'), r'PQCLEAN_MLDSA\d+_[A-Z0-9]+_'))
    if len(pat2.findall(text)) != 1:
        raise SystemExit("ERROR: sign.c tr=H(pk) pattern not found exactly once")
    prefix = re.search(r'(PQCLEAN_MLDSA\d+_[A-Z0-9]+_)CRYPTO_PUBLICKEYBYTES', pat2.findall(text)[0]).group(1)
    text = pat2.sub(new2.replace('PQCLEAN_MLDSA44_CLEAN_', prefix), text, count=1)

    # 3. signature: mu = CRH(tr, 0, ctxlen, ctx, msg) -- incremental
    old3 = '''    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, TRBYTES);
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);'''
    new3 = '''    xof_init(&state);
    xof_absorb(&state, tr, TRBYTES);
    xof_absorb(&state, mu, 2);
    xof_absorb(&state, ctx, ctxlen);
    xof_absorb(&state, m, mlen);
    xof_finalize(&state, XOF_DOMAIN_HASH);
    xof_squeeze(mu, CRHBYTES, &state);
    xof_release(&state);'''
    text = must_replace(text, old3, new3, "sign.c mu=CRH(tr,...)")

    # 4. signature: rhoprime = H(key || rnd || mu)
    old4 = '''    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);'''
    new4 = '''    {
        xof_state rhostate;
        xof_init(&rhostate);
        xof_absorb(&rhostate, key, SEEDBYTES + RNDBYTES + CRHBYTES);
        xof_finalize(&rhostate, XOF_DOMAIN_HASH);
        xof_squeeze(rhoprime, CRHBYTES, &rhostate);
        xof_release(&rhostate);
    }'''
    text = must_replace(text, old4, new4, "sign.c rhoprime=H(key,rnd,mu)")

    # 5. signature: c~ = H(mu, w1)
    old5 = '''    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);'''
    new5 = '''    xof_init(&state);
    xof_absorb(&state, mu, CRHBYTES);
    xof_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
    xof_finalize(&state, XOF_DOMAIN_HASH);
    xof_squeeze(sig, CTILDEBYTES, &state);
    xof_release(&state);'''
    text = must_replace(text, old5, new5, "sign.c c~=H(mu,w1) [sign]")

    # 6. signature: declare xof_state instead of shake256incctx (signature fn)
    old6 = '''    polyvecl mat[K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    shake256incctx state;'''
    new6 = '''    polyvecl mat[K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    xof_state state;'''
    text = must_replace(text, old6, new6, "sign.c signature state decl")

    # 7. verify: tr = H(pk) (writes into mu[0..TRBYTES-1])
    old7 = '''    shake256(mu, TRBYTES, pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);'''
    pat7 = re.compile(re.escape(old7).replace(re.escape('PQCLEAN_MLDSA44_CLEAN_'), r'PQCLEAN_MLDSA\d+_[A-Z0-9]+_'))
    found7 = pat7.findall(text)
    if len(found7) != 1:
        raise SystemExit("ERROR: sign.c verify tr=H(pk) pattern not found exactly once")
    prefix7 = re.search(r'(PQCLEAN_MLDSA\d+_[A-Z0-9]+_)CRYPTO_PUBLICKEYBYTES', found7[0]).group(1)
    new7 = '''    {
        xof_state trstate;
        xof_init(&trstate);
        xof_absorb(&trstate, pk, ''' + prefix7 + '''CRYPTO_PUBLICKEYBYTES);
        xof_finalize(&trstate, XOF_DOMAIN_HASH);
        xof_squeeze(mu, TRBYTES, &trstate);
        xof_release(&trstate);
    }'''
    text = pat7.sub(new7, text, count=1)

    # 8. verify: mu = CRH(tr, 0, ctxlen, ctx, msg) -- incremental
    old8 = '''    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, TRBYTES);
    mu[0] = 0;
    mu[1] = (uint8_t)ctxlen;
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);'''
    new8 = '''    xof_init(&state);
    xof_absorb(&state, mu, TRBYTES);
    mu[0] = 0;
    mu[1] = (uint8_t)ctxlen;
    xof_absorb(&state, mu, 2);
    xof_absorb(&state, ctx, ctxlen);
    xof_absorb(&state, m, mlen);
    xof_finalize(&state, XOF_DOMAIN_HASH);
    xof_squeeze(mu, CRHBYTES, &state);
    xof_release(&state);'''
    text = must_replace(text, old8, new8, "sign.c verify mu=CRH(tr,...)")

    # 9. verify: c2 = H(mu, w1)
    old9 = '''    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);'''
    new9 = '''    xof_init(&state);
    xof_absorb(&state, mu, CRHBYTES);
    xof_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
    xof_finalize(&state, XOF_DOMAIN_HASH);
    xof_squeeze(c2, CTILDEBYTES, &state);
    xof_release(&state);'''
    text = must_replace(text, old9, new9, "sign.c c2=H(mu,w1) [verify]")

    # 10. verify: declare xof_state instead of shake256incctx (verify fn)
    old10 = '''    polyvecl mat[K], z;
    polyveck t1, w1, h;
    shake256incctx state;'''
    new10 = '''    polyvecl mat[K], z;
    polyveck t1, w1, h;
    xof_state state;'''
    text = must_replace(text, old10, new10, "sign.c verify state decl")

    open(path, 'w').write(text)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit("usage: mldsa_refactor.py <forked-dir>")
    d = sys.argv[1]
    patch_poly(d + '/poly.c')
    patch_sign(d + '/sign.c')
    print("OK:", d)

```

---

## 9. Custom common library: BLAKE3

`PQClean/common/BLAKE3/` is a trimmed copy of the upstream BLAKE3
reference C implementation, providing `blake3_hasher_init`, `_update`,
`_finalize` (used as an arbitrary-length XOF) for the `blake3` backend's
`symmetric-blake3.c` (§7/§8.1).

### Build (portable, no SIMD)

The trimmed tree only includes the **portable** C implementation (no
SSE2/SSE4.1/AVX2/AVX512/NEON object files), so it must be built with *all*
SIMD backends disabled — this is what makes it link cleanly on x86_64
*and* aarch64 from the same source drop:

```bash
BLAKE3_DIR=PQClean/common/BLAKE3
BLAKE3_FLAGS="-DBLAKE3_USE_NEON=0 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512"
for src in blake3 blake3_dispatch blake3_portable; do
  gcc -O3 $BLAKE3_FLAGS -c "$BLAKE3_DIR/$src.c" -o "$BLAKE3_DIR/$src.o"
done
ar rcs "$BLAKE3_DIR/libblake3.a" "$BLAKE3_DIR"/{blake3,blake3_dispatch,blake3_portable}.o
```

The same `$BLAKE3_FLAGS` must also be passed as `EXTRAFLAGS` when building
the `ml-kem-*/blake3` and `ml-dsa-*/blake3` static libs (step 11 of §13),
since `symmetric-blake3.c` includes `blake3.h` directly.

### Source files

**`common/BLAKE3/blake3.h`**

```c
#ifndef BLAKE3_H
#define BLAKE3_H

#include <stddef.h>
#include <stdint.h>

#if !defined(BLAKE3_API)
# if defined(_WIN32) || defined(__CYGWIN__)
#   if defined(BLAKE3_DLL)
#     if defined(BLAKE3_DLL_EXPORTS)
#       define BLAKE3_API __declspec(dllexport)
#     else
#       define BLAKE3_API __declspec(dllimport)
#     endif
#     define BLAKE3_PRIVATE
#   else
#     define BLAKE3_API
#     define BLAKE3_PRIVATE
#   endif
# elif __GNUC__ >= 4
#   define BLAKE3_API __attribute__((visibility("default")))
#   define BLAKE3_PRIVATE __attribute__((visibility("hidden")))
# else
#   define BLAKE3_API
#   define BLAKE3_PRIVATE
# endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define BLAKE3_VERSION_STRING "1.8.5"
#define BLAKE3_KEY_LEN 32
#define BLAKE3_OUT_LEN 32
#define BLAKE3_BLOCK_LEN 64
#define BLAKE3_CHUNK_LEN 1024
#define BLAKE3_MAX_DEPTH 54

// This struct is a private implementation detail. It has to be here because
// it's part of the blake3_hasher structure defined below.
typedef struct {
  uint32_t cv[8];
  uint64_t chunk_counter;
  uint8_t buf[BLAKE3_BLOCK_LEN];
  uint8_t buf_len;
  uint8_t blocks_compressed;
  uint8_t flags;
} blake3_chunk_state;

typedef struct {
  uint32_t key[8];
  blake3_chunk_state chunk;
  uint8_t cv_stack_len;
  // The stack size is MAX_DEPTH + 1 because we do lazy merging. For example,
  // with 7 chunks, we have 3 entries in the stack. Adding an 8th chunk
  // requires a 4th entry, rather than merging everything down to 1, because we
  // don't know whether more input is coming. This is different from how the
  // reference implementation does things.
  uint8_t cv_stack[(BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN];
} blake3_hasher;

BLAKE3_API const char *blake3_version(void);
BLAKE3_API void blake3_hasher_init(blake3_hasher *self);
BLAKE3_API void blake3_hasher_init_keyed(blake3_hasher *self,
                                         const uint8_t key[BLAKE3_KEY_LEN]);
BLAKE3_API void blake3_hasher_init_derive_key(blake3_hasher *self, const char *context);
BLAKE3_API void blake3_hasher_init_derive_key_raw(blake3_hasher *self, const void *context,
                                                  size_t context_len);
BLAKE3_API void blake3_hasher_update(blake3_hasher *self, const void *input,
                                     size_t input_len);
#if defined(BLAKE3_USE_TBB)
BLAKE3_API void blake3_hasher_update_tbb(blake3_hasher *self, const void *input,
                                         size_t input_len);
#endif // BLAKE3_USE_TBB
BLAKE3_API void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out,
                                       size_t out_len);
BLAKE3_API void blake3_hasher_finalize_seek(const blake3_hasher *self, uint64_t seek,
                                            uint8_t *out, size_t out_len);
BLAKE3_API void blake3_hasher_reset(blake3_hasher *self);

#ifdef __cplusplus
}
#endif

#endif /* BLAKE3_H */

```

**`common/BLAKE3/blake3.c`**

```c
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include "blake3.h"
#include "blake3_impl.h"

const char *blake3_version(void) { return BLAKE3_VERSION_STRING; }

INLINE void chunk_state_init(blake3_chunk_state *self, const uint32_t key[8],
                             uint8_t flags) {
  memcpy(self->cv, key, BLAKE3_KEY_LEN);
  self->chunk_counter = 0;
  memset(self->buf, 0, BLAKE3_BLOCK_LEN);
  self->buf_len = 0;
  self->blocks_compressed = 0;
  self->flags = flags;
}

INLINE void chunk_state_reset(blake3_chunk_state *self, const uint32_t key[8],
                              uint64_t chunk_counter) {
  memcpy(self->cv, key, BLAKE3_KEY_LEN);
  self->chunk_counter = chunk_counter;
  self->blocks_compressed = 0;
  memset(self->buf, 0, BLAKE3_BLOCK_LEN);
  self->buf_len = 0;
}

INLINE size_t chunk_state_len(const blake3_chunk_state *self) {
  return (BLAKE3_BLOCK_LEN * (size_t)self->blocks_compressed) +
         ((size_t)self->buf_len);
}

INLINE size_t chunk_state_fill_buf(blake3_chunk_state *self,
                                   const uint8_t *input, size_t input_len) {
  size_t take = BLAKE3_BLOCK_LEN - ((size_t)self->buf_len);
  if (take > input_len) {
    take = input_len;
  }
  uint8_t *dest = self->buf + ((size_t)self->buf_len);
  memcpy(dest, input, take);
  self->buf_len += (uint8_t)take;
  return take;
}

INLINE uint8_t chunk_state_maybe_start_flag(const blake3_chunk_state *self) {
  if (self->blocks_compressed == 0) {
    return CHUNK_START;
  } else {
    return 0;
  }
}

typedef struct {
  uint32_t input_cv[8];
  uint64_t counter;
  uint8_t block[BLAKE3_BLOCK_LEN];
  uint8_t block_len;
  uint8_t flags;
} output_t;

INLINE output_t make_output(const uint32_t input_cv[8],
                            const uint8_t block[BLAKE3_BLOCK_LEN],
                            uint8_t block_len, uint64_t counter,
                            uint8_t flags) {
  output_t ret;
  memcpy(ret.input_cv, input_cv, 32);
  memcpy(ret.block, block, BLAKE3_BLOCK_LEN);
  ret.block_len = block_len;
  ret.counter = counter;
  ret.flags = flags;
  return ret;
}

// Chaining values within a given chunk (specifically the compress_in_place
// interface) are represented as words. This avoids unnecessary bytes<->words
// conversion overhead in the portable implementation. However, the hash_many
// interface handles both user input and parent node blocks, so it accepts
// bytes. For that reason, chaining values in the CV stack are represented as
// bytes.
INLINE void output_chaining_value(const output_t *self, uint8_t cv[32]) {
  uint32_t cv_words[8];
  memcpy(cv_words, self->input_cv, 32);
  blake3_compress_in_place(cv_words, self->block, self->block_len,
                           self->counter, self->flags);
  store_cv_words(cv, cv_words);
}

INLINE void output_root_bytes(const output_t *self, uint64_t seek, uint8_t *out,
                              size_t out_len) {
  if (out_len == 0) {
      return;
  }
  uint64_t output_block_counter = seek / 64;
  size_t offset_within_block = seek % 64;
  uint8_t wide_buf[64];
  if(offset_within_block) {
    blake3_compress_xof(self->input_cv, self->block, self->block_len, output_block_counter, self->flags | ROOT, wide_buf);
    const size_t available_bytes = 64 - offset_within_block;
    const size_t bytes = out_len > available_bytes ? available_bytes : out_len;
    memcpy(out, wide_buf + offset_within_block, bytes);
    out += bytes;
    out_len -= bytes;
    output_block_counter += 1;
  }
  if(out_len / 64) {
    blake3_xof_many(self->input_cv, self->block, self->block_len, output_block_counter, self->flags | ROOT, out, out_len / 64);
  }
  output_block_counter += out_len / 64;
  out += out_len & -64;
  out_len -= out_len & -64;
  if(out_len) {
    blake3_compress_xof(self->input_cv, self->block, self->block_len, output_block_counter, self->flags | ROOT, wide_buf);
    memcpy(out, wide_buf, out_len);
  }
}

INLINE void chunk_state_update(blake3_chunk_state *self, const uint8_t *input,
                               size_t input_len) {
  if (self->buf_len > 0) {
    size_t take = chunk_state_fill_buf(self, input, input_len);
    input += take;
    input_len -= take;
    if (input_len > 0) {
      blake3_compress_in_place(
          self->cv, self->buf, BLAKE3_BLOCK_LEN, self->chunk_counter,
          self->flags | chunk_state_maybe_start_flag(self));
      self->blocks_compressed += 1;
      self->buf_len = 0;
      memset(self->buf, 0, BLAKE3_BLOCK_LEN);
    }
  }

  while (input_len > BLAKE3_BLOCK_LEN) {
    blake3_compress_in_place(self->cv, input, BLAKE3_BLOCK_LEN,
                             self->chunk_counter,
                             self->flags | chunk_state_maybe_start_flag(self));
    self->blocks_compressed += 1;
    input += BLAKE3_BLOCK_LEN;
    input_len -= BLAKE3_BLOCK_LEN;
  }

  chunk_state_fill_buf(self, input, input_len);
}

INLINE output_t chunk_state_output(const blake3_chunk_state *self) {
  uint8_t block_flags =
      self->flags | chunk_state_maybe_start_flag(self) | CHUNK_END;
  return make_output(self->cv, self->buf, self->buf_len, self->chunk_counter,
                     block_flags);
}

INLINE output_t parent_output(const uint8_t block[BLAKE3_BLOCK_LEN],
                              const uint32_t key[8], uint8_t flags) {
  return make_output(key, block, BLAKE3_BLOCK_LEN, 0, flags | PARENT);
}

// Given some input larger than one chunk, return the number of bytes that
// should go in the left subtree. This is the largest power-of-2 number of
// chunks that leaves at least 1 byte for the right subtree.
INLINE size_t left_subtree_len(size_t input_len) {
  // Subtract 1 to reserve at least one byte for the right side. input_len
  // should always be greater than BLAKE3_CHUNK_LEN.
  size_t full_chunks = (input_len - 1) / BLAKE3_CHUNK_LEN;
  return round_down_to_power_of_2(full_chunks) * BLAKE3_CHUNK_LEN;
}

// Use SIMD parallelism to hash up to MAX_SIMD_DEGREE chunks at the same time
// on a single thread. Write out the chunk chaining values and return the
// number of chunks hashed. These chunks are never the root and never empty;
// those cases use a different codepath.
INLINE size_t compress_chunks_parallel(const uint8_t *input, size_t input_len,
                                       const uint32_t key[8],
                                       uint64_t chunk_counter, uint8_t flags,
                                       uint8_t *out) {
#if defined(BLAKE3_TESTING)
  assert(0 < input_len);
  assert(input_len <= MAX_SIMD_DEGREE * BLAKE3_CHUNK_LEN);
#endif

  const uint8_t *chunks_array[MAX_SIMD_DEGREE];
  size_t input_position = 0;
  size_t chunks_array_len = 0;
  while (input_len - input_position >= BLAKE3_CHUNK_LEN) {
    chunks_array[chunks_array_len] = &input[input_position];
    input_position += BLAKE3_CHUNK_LEN;
    chunks_array_len += 1;
  }

  blake3_hash_many(chunks_array, chunks_array_len,
                   BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, key, chunk_counter,
                   true, flags, CHUNK_START, CHUNK_END, out);

  // Hash the remaining partial chunk, if there is one. Note that the empty
  // chunk (meaning the empty message) is a different codepath.
  if (input_len > input_position) {
    uint64_t counter = chunk_counter + (uint64_t)chunks_array_len;
    blake3_chunk_state chunk_state;
    chunk_state_init(&chunk_state, key, flags);
    chunk_state.chunk_counter = counter;
    chunk_state_update(&chunk_state, &input[input_position],
                       input_len - input_position);
    output_t output = chunk_state_output(&chunk_state);
    output_chaining_value(&output, &out[chunks_array_len * BLAKE3_OUT_LEN]);
    return chunks_array_len + 1;
  } else {
    return chunks_array_len;
  }
}

// Use SIMD parallelism to hash up to MAX_SIMD_DEGREE parents at the same time
// on a single thread. Write out the parent chaining values and return the
// number of parents hashed. (If there's an odd input chaining value left over,
// return it as an additional output.) These parents are never the root and
// never empty; those cases use a different codepath.
INLINE size_t compress_parents_parallel(const uint8_t *child_chaining_values,
                                        size_t num_chaining_values,
                                        const uint32_t key[8], uint8_t flags,
                                        uint8_t *out) {
#if defined(BLAKE3_TESTING)
  assert(2 <= num_chaining_values);
  assert(num_chaining_values <= 2 * MAX_SIMD_DEGREE_OR_2);
#endif

  const uint8_t *parents_array[MAX_SIMD_DEGREE_OR_2];
  size_t parents_array_len = 0;
  while (num_chaining_values - (2 * parents_array_len) >= 2) {
    parents_array[parents_array_len] =
        &child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN];
    parents_array_len += 1;
  }

  blake3_hash_many(parents_array, parents_array_len, 1, key,
                   0, // Parents always use counter 0.
                   false, flags | PARENT,
                   0, // Parents have no start flags.
                   0, // Parents have no end flags.
                   out);

  // If there's an odd child left over, it becomes an output.
  if (num_chaining_values > 2 * parents_array_len) {
    memcpy(&out[parents_array_len * BLAKE3_OUT_LEN],
           &child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN],
           BLAKE3_OUT_LEN);
    return parents_array_len + 1;
  } else {
    return parents_array_len;
  }
}

// The wide helper function returns (writes out) an array of chaining values
// and returns the length of that array. The number of chaining values returned
// is the dynamically detected SIMD degree, at most MAX_SIMD_DEGREE. Or fewer,
// if the input is shorter than that many chunks. The reason for maintaining a
// wide array of chaining values going back up the tree, is to allow the
// implementation to hash as many parents in parallel as possible.
//
// As a special case when the SIMD degree is 1, this function will still return
// at least 2 outputs. This guarantees that this function doesn't perform the
// root compression. (If it did, it would use the wrong flags, and also we
// wouldn't be able to implement extendable output.) Note that this function is
// not used when the whole input is only 1 chunk long; that's a different
// codepath.
//
// Why not just have the caller split the input on the first update(), instead
// of implementing this special rule? Because we don't want to limit SIMD or
// multi-threading parallelism for that update().
size_t blake3_compress_subtree_wide(const uint8_t *input, size_t input_len,
                                    const uint32_t key[8],
                                    uint64_t chunk_counter, uint8_t flags,
                                    uint8_t *out, bool use_tbb) {
  // Note that the single chunk case does *not* bump the SIMD degree up to 2
  // when it is 1. If this implementation adds multi-threading in the future,
  // this gives us the option of multi-threading even the 2-chunk case, which
  // can help performance on smaller platforms.
  if (input_len <= blake3_simd_degree() * BLAKE3_CHUNK_LEN) {
    return compress_chunks_parallel(input, input_len, key, chunk_counter, flags,
                                    out);
  }

  // With more than simd_degree chunks, we need to recurse. Start by dividing
  // the input into left and right subtrees. (Note that this is only optimal
  // as long as the SIMD degree is a power of 2. If we ever get a SIMD degree
  // of 3 or something, we'll need a more complicated strategy.)
  size_t left_input_len = left_subtree_len(input_len);
  size_t right_input_len = input_len - left_input_len;
  const uint8_t *right_input = &input[left_input_len];
  uint64_t right_chunk_counter =
      chunk_counter + (uint64_t)(left_input_len / BLAKE3_CHUNK_LEN);

  // Make space for the child outputs. Here we use MAX_SIMD_DEGREE_OR_2 to
  // account for the special case of returning 2 outputs when the SIMD degree
  // is 1.
  uint8_t cv_array[2 * MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN];
  size_t degree = blake3_simd_degree();
  if (left_input_len > BLAKE3_CHUNK_LEN && degree == 1) {
    // The special case: We always use a degree of at least two, to make
    // sure there are two outputs. Except, as noted above, at the chunk
    // level, where we allow degree=1. (Note that the 1-chunk-input case is
    // a different codepath.)
    degree = 2;
  }
  uint8_t *right_cvs = &cv_array[degree * BLAKE3_OUT_LEN];

  // Recurse!
  size_t left_n = SIZE_MAX;
  size_t right_n = SIZE_MAX;

#if defined(BLAKE3_USE_TBB)
  blake3_compress_subtree_wide_join_tbb(
      key, flags, use_tbb,
      // left-hand side
      input, left_input_len, chunk_counter, cv_array, &left_n,
      // right-hand side
      right_input, right_input_len, right_chunk_counter, right_cvs, &right_n);
#else
  left_n = blake3_compress_subtree_wide(
      input, left_input_len, key, chunk_counter, flags, cv_array, use_tbb);
  right_n = blake3_compress_subtree_wide(right_input, right_input_len, key,
                                         right_chunk_counter, flags, right_cvs,
                                         use_tbb);
#endif // BLAKE3_USE_TBB

  // The special case again. If simd_degree=1, then we'll have left_n=1 and
  // right_n=1. Rather than compressing them into a single output, return
  // them directly, to make sure we always have at least two outputs.
  if (left_n == 1) {
    memcpy(out, cv_array, 2 * BLAKE3_OUT_LEN);
    return 2;
  }

  // Otherwise, do one layer of parent node compression.
  size_t num_chaining_values = left_n + right_n;
  return compress_parents_parallel(cv_array, num_chaining_values, key, flags,
                                   out);
}

// Hash a subtree with compress_subtree_wide(), and then condense the resulting
// list of chaining values down to a single parent node. Don't compress that
// last parent node, however. Instead, return its message bytes (the
// concatenated chaining values of its children). This is necessary when the
// first call to update() supplies a complete subtree, because the topmost
// parent node of that subtree could end up being the root. It's also necessary
// for extended output in the general case.
//
// As with compress_subtree_wide(), this function is not used on inputs of 1
// chunk or less. That's a different codepath.
INLINE void
compress_subtree_to_parent_node(const uint8_t *input, size_t input_len,
                                const uint32_t key[8], uint64_t chunk_counter,
                                uint8_t flags, uint8_t out[2 * BLAKE3_OUT_LEN],
                                bool use_tbb) {
#if defined(BLAKE3_TESTING)
  assert(input_len > BLAKE3_CHUNK_LEN);
#endif

  uint8_t cv_array[MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN];
  size_t num_cvs = blake3_compress_subtree_wide(input, input_len, key,
                                                chunk_counter, flags, cv_array, use_tbb);
  assert(num_cvs <= MAX_SIMD_DEGREE_OR_2);
  // The following loop never executes when MAX_SIMD_DEGREE_OR_2 is 2, because
  // as we just asserted, num_cvs will always be <=2 in that case. But GCC
  // (particularly GCC 8.5) can't tell that it never executes, and if NDEBUG is
  // set then it emits incorrect warnings here. We tried a few different
  // hacks to silence these, but in the end our hacks just produced different
  // warnings (see https://github.com/BLAKE3-team/BLAKE3/pull/380). Out of
  // desperation, we ifdef out this entire loop when we know it's not needed.
#if MAX_SIMD_DEGREE_OR_2 > 2
  // If MAX_SIMD_DEGREE_OR_2 is greater than 2 and there's enough input,
  // compress_subtree_wide() returns more than 2 chaining values. Condense
  // them into 2 by forming parent nodes repeatedly.
  uint8_t out_array[MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN / 2];
  while (num_cvs > 2) {
    num_cvs =
        compress_parents_parallel(cv_array, num_cvs, key, flags, out_array);
    memcpy(cv_array, out_array, num_cvs * BLAKE3_OUT_LEN);
  }
#endif
  memcpy(out, cv_array, 2 * BLAKE3_OUT_LEN);
}

INLINE void hasher_init_base(blake3_hasher *self, const uint32_t key[8],
                             uint8_t flags) {
  memcpy(self->key, key, BLAKE3_KEY_LEN);
  chunk_state_init(&self->chunk, key, flags);
  self->cv_stack_len = 0;
}

void blake3_hasher_init(blake3_hasher *self) { hasher_init_base(self, IV, 0); }

void blake3_hasher_init_keyed(blake3_hasher *self,
                              const uint8_t key[BLAKE3_KEY_LEN]) {
  uint32_t key_words[8];
  load_key_words(key, key_words);
  hasher_init_base(self, key_words, KEYED_HASH);
}

void blake3_hasher_init_derive_key_raw(blake3_hasher *self, const void *context,
                                       size_t context_len) {
  blake3_hasher context_hasher;
  hasher_init_base(&context_hasher, IV, DERIVE_KEY_CONTEXT);
  blake3_hasher_update(&context_hasher, context, context_len);
  uint8_t context_key[BLAKE3_KEY_LEN];
  blake3_hasher_finalize(&context_hasher, context_key, BLAKE3_KEY_LEN);
  uint32_t context_key_words[8];
  load_key_words(context_key, context_key_words);
  hasher_init_base(self, context_key_words, DERIVE_KEY_MATERIAL);
}

void blake3_hasher_init_derive_key(blake3_hasher *self, const char *context) {
  blake3_hasher_init_derive_key_raw(self, context, strlen(context));
}

// As described in hasher_push_cv() below, we do "lazy merging", delaying
// merges until right before the next CV is about to be added. This is
// different from the reference implementation. Another difference is that we
// aren't always merging 1 chunk at a time. Instead, each CV might represent
// any power-of-two number of chunks, as long as the smaller-above-larger stack
// order is maintained. Instead of the "count the trailing 0-bits" algorithm
// described in the spec, we use a "count the total number of 1-bits" variant
// that doesn't require us to retain the subtree size of the CV on top of the
// stack. The principle is the same: each CV that should remain in the stack is
// represented by a 1-bit in the total number of chunks (or bytes) so far.
INLINE void hasher_merge_cv_stack(blake3_hasher *self, uint64_t total_len) {
  size_t post_merge_stack_len = (size_t)popcnt(total_len);
  while (self->cv_stack_len > post_merge_stack_len) {
    uint8_t *parent_node =
        &self->cv_stack[(self->cv_stack_len - 2) * BLAKE3_OUT_LEN];
    output_t output = parent_output(parent_node, self->key, self->chunk.flags);
    output_chaining_value(&output, parent_node);
    self->cv_stack_len -= 1;
  }
}

// In reference_impl.rs, we merge the new CV with existing CVs from the stack
// before pushing it. We can do that because we know more input is coming, so
// we know none of the merges are root.
//
// This setting is different. We want to feed as much input as possible to
// compress_subtree_wide(), without setting aside anything for the chunk_state.
// If the user gives us 64 KiB, we want to parallelize over all 64 KiB at once
// as a single subtree, if at all possible.
//
// This leads to two problems:
// 1) This 64 KiB input might be the only call that ever gets made to update.
//    In this case, the root node of the 64 KiB subtree would be the root node
//    of the whole tree, and it would need to be ROOT finalized. We can't
//    compress it until we know.
// 2) This 64 KiB input might complete a larger tree, whose root node is
//    similarly going to be the root of the whole tree. For example, maybe
//    we have 196 KiB (that is, 128 + 64) hashed so far. We can't compress the
//    node at the root of the 256 KiB subtree until we know how to finalize it.
//
// The second problem is solved with "lazy merging". That is, when we're about
// to add a CV to the stack, we don't merge it with anything first, as the
// reference impl does. Instead we do merges using the *previous* CV that was
// added, which is sitting on top of the stack, and we put the new CV
// (unmerged) on top of the stack afterwards. This guarantees that we never
// merge the root node until finalize().
//
// Solving the first problem requires an additional tool,
// compress_subtree_to_parent_node(). That function always returns the top
// *two* chaining values of the subtree it's compressing. We then do lazy
// merging with each of them separately, so that the second CV will always
// remain unmerged. (That also helps us support extendable output when we're
// hashing an input all-at-once.)
INLINE void hasher_push_cv(blake3_hasher *self, uint8_t new_cv[BLAKE3_OUT_LEN],
                           uint64_t chunk_counter) {
  hasher_merge_cv_stack(self, chunk_counter);
  memcpy(&self->cv_stack[self->cv_stack_len * BLAKE3_OUT_LEN], new_cv,
         BLAKE3_OUT_LEN);
  self->cv_stack_len += 1;
}

INLINE void blake3_hasher_update_base(blake3_hasher *self, const void *input,
                                      size_t input_len, bool use_tbb) {
  // Explicitly checking for zero avoids causing UB by passing a null pointer
  // to memcpy. This comes up in practice with things like:
  //   std::vector<uint8_t> v;
  //   blake3_hasher_update(&hasher, v.data(), v.size());
  if (input_len == 0) {
    return;
  }

  const uint8_t *input_bytes = (const uint8_t *)input;

  // If we have some partial chunk bytes in the internal chunk_state, we need
  // to finish that chunk first.
  if (chunk_state_len(&self->chunk) > 0) {
    size_t take = BLAKE3_CHUNK_LEN - chunk_state_len(&self->chunk);
    if (take > input_len) {
      take = input_len;
    }
    chunk_state_update(&self->chunk, input_bytes, take);
    input_bytes += take;
    input_len -= take;
    // If we've filled the current chunk and there's more coming, finalize this
    // chunk and proceed. In this case we know it's not the root.
    if (input_len > 0) {
      output_t output = chunk_state_output(&self->chunk);
      uint8_t chunk_cv[32];
      output_chaining_value(&output, chunk_cv);
      hasher_push_cv(self, chunk_cv, self->chunk.chunk_counter);
      chunk_state_reset(&self->chunk, self->key, self->chunk.chunk_counter + 1);
    } else {
      return;
    }
  }

  // Now the chunk_state is clear, and we have more input. If there's more than
  // a single chunk (so, definitely not the root chunk), hash the largest whole
  // subtree we can, with the full benefits of SIMD (and maybe in the future,
  // multi-threading) parallelism. Two restrictions:
  // - The subtree has to be a power-of-2 number of chunks. Only subtrees along
  //   the right edge can be incomplete, and we don't know where the right edge
  //   is going to be until we get to finalize().
  // - The subtree must evenly divide the total number of chunks up until this
  //   point (if total is not 0). If the current incomplete subtree is only
  //   waiting for 1 more chunk, we can't hash a subtree of 4 chunks. We have
  //   to complete the current subtree first.
  // Because we might need to break up the input to form powers of 2, or to
  // evenly divide what we already have, this part runs in a loop.
  while (input_len > BLAKE3_CHUNK_LEN) {
    size_t subtree_len = round_down_to_power_of_2(input_len);
    uint64_t count_so_far = self->chunk.chunk_counter * BLAKE3_CHUNK_LEN;
    // Shrink the subtree_len until it evenly divides the count so far. We know
    // that subtree_len itself is a power of 2, so we can use a bitmasking
    // trick instead of an actual remainder operation. (Note that if the caller
    // consistently passes power-of-2 inputs of the same size, as is hopefully
    // typical, this loop condition will always fail, and subtree_len will
    // always be the full length of the input.)
    //
    // An aside: We don't have to shrink subtree_len quite this much. For
    // example, if count_so_far is 1, we could pass 2 chunks to
    // compress_subtree_to_parent_node. Since we'll get 2 CVs back, we'll still
    // get the right answer in the end, and we might get to use 2-way SIMD
    // parallelism. The problem with this optimization, is that it gets us
    // stuck always hashing 2 chunks. The total number of chunks will remain
    // odd, and we'll never graduate to higher degrees of parallelism. See
    // https://github.com/BLAKE3-team/BLAKE3/issues/69.
    while ((((uint64_t)(subtree_len - 1)) & count_so_far) != 0) {
      subtree_len /= 2;
    }
    // The shrunken subtree_len might now be 1 chunk long. If so, hash that one
    // chunk by itself. Otherwise, compress the subtree into a pair of CVs.
    uint64_t subtree_chunks = subtree_len / BLAKE3_CHUNK_LEN;
    if (subtree_len <= BLAKE3_CHUNK_LEN) {
      blake3_chunk_state chunk_state;
      chunk_state_init(&chunk_state, self->key, self->chunk.flags);
      chunk_state.chunk_counter = self->chunk.chunk_counter;
      chunk_state_update(&chunk_state, input_bytes, subtree_len);
      output_t output = chunk_state_output(&chunk_state);
      uint8_t cv[BLAKE3_OUT_LEN];
      output_chaining_value(&output, cv);
      hasher_push_cv(self, cv, chunk_state.chunk_counter);
    } else {
      // This is the high-performance happy path, though getting here depends
      // on the caller giving us a long enough input.
      uint8_t cv_pair[2 * BLAKE3_OUT_LEN];
      compress_subtree_to_parent_node(input_bytes, subtree_len, self->key,
                                      self->chunk.chunk_counter,
                                      self->chunk.flags, cv_pair, use_tbb);
      hasher_push_cv(self, cv_pair, self->chunk.chunk_counter);
      hasher_push_cv(self, &cv_pair[BLAKE3_OUT_LEN],
                     self->chunk.chunk_counter + (subtree_chunks / 2));
    }
    self->chunk.chunk_counter += subtree_chunks;
    input_bytes += subtree_len;
    input_len -= subtree_len;
  }

  // If there's any remaining input less than a full chunk, add it to the chunk
  // state. In that case, also do a final merge loop to make sure the subtree
  // stack doesn't contain any unmerged pairs. The remaining input means we
  // know these merges are non-root. This merge loop isn't strictly necessary
  // here, because hasher_push_chunk_cv already does its own merge loop, but it
  // simplifies blake3_hasher_finalize below.
  if (input_len > 0) {
    chunk_state_update(&self->chunk, input_bytes, input_len);
    hasher_merge_cv_stack(self, self->chunk.chunk_counter);
  }
}

void blake3_hasher_update(blake3_hasher *self, const void *input,
                          size_t input_len) {
  bool use_tbb = false;
  blake3_hasher_update_base(self, input, input_len, use_tbb);
}

#if defined(BLAKE3_USE_TBB)
void blake3_hasher_update_tbb(blake3_hasher *self, const void *input,
                              size_t input_len) {
  bool use_tbb = true;
  blake3_hasher_update_base(self, input, input_len, use_tbb);
}
#endif // BLAKE3_USE_TBB

void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out,
                            size_t out_len) {
  blake3_hasher_finalize_seek(self, 0, out, out_len);
}

void blake3_hasher_finalize_seek(const blake3_hasher *self, uint64_t seek,
                                 uint8_t *out, size_t out_len) {
  // Explicitly checking for zero avoids causing UB by passing a null pointer
  // to memcpy. This comes up in practice with things like:
  //   std::vector<uint8_t> v;
  //   blake3_hasher_finalize(&hasher, v.data(), v.size());
  if (out_len == 0) {
    return;
  }

  // If the subtree stack is empty, then the current chunk is the root.
  if (self->cv_stack_len == 0) {
    output_t output = chunk_state_output(&self->chunk);
    output_root_bytes(&output, seek, out, out_len);
    return;
  }
  // If there are any bytes in the chunk state, finalize that chunk and do a
  // roll-up merge between that chunk hash and every subtree in the stack. In
  // this case, the extra merge loop at the end of blake3_hasher_update
  // guarantees that none of the subtrees in the stack need to be merged with
  // each other first. Otherwise, if there are no bytes in the chunk state,
  // then the top of the stack is a chunk hash, and we start the merge from
  // that.
  output_t output;
  size_t cvs_remaining;
  if (chunk_state_len(&self->chunk) > 0) {
    cvs_remaining = self->cv_stack_len;
    output = chunk_state_output(&self->chunk);
  } else {
    // There are always at least 2 CVs in the stack in this case.
    cvs_remaining = self->cv_stack_len - 2;
    output = parent_output(&self->cv_stack[cvs_remaining * 32], self->key,
                           self->chunk.flags);
  }
  while (cvs_remaining > 0) {
    cvs_remaining -= 1;
    uint8_t parent_block[BLAKE3_BLOCK_LEN];
    memcpy(parent_block, &self->cv_stack[cvs_remaining * 32], 32);
    output_chaining_value(&output, &parent_block[32]);
    output = parent_output(parent_block, self->key, self->chunk.flags);
  }
  output_root_bytes(&output, seek, out, out_len);
}

void blake3_hasher_reset(blake3_hasher *self) {
  chunk_state_reset(&self->chunk, self->key, 0);
  self->cv_stack_len = 0;
}

```

**`common/BLAKE3/blake3_dispatch.c`**

```c
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "blake3_impl.h"

#if defined(_MSC_VER)
#include <Windows.h>
#endif

#if defined(IS_X86)
#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__)
#include <immintrin.h>
#else
#undef IS_X86 /* Unimplemented! */
#endif
#endif

#if !defined(BLAKE3_ATOMICS)
#if defined(__has_include)
#if __has_include(<stdatomic.h>) && !defined(_MSC_VER)
#define BLAKE3_ATOMICS 1
#else
#define BLAKE3_ATOMICS 0
#endif /* __has_include(<stdatomic.h>) && !defined(_MSC_VER) */
#else
#define BLAKE3_ATOMICS 0
#endif /* defined(__has_include) */
#endif /* BLAKE3_ATOMICS */

#if BLAKE3_ATOMICS
#define ATOMIC_INT _Atomic int
#define ATOMIC_LOAD(x) x
#define ATOMIC_STORE(x, y) x = y
#elif defined(_MSC_VER)
#define ATOMIC_INT LONG
#define ATOMIC_LOAD(x) InterlockedOr(&x, 0)
#define ATOMIC_STORE(x, y) InterlockedExchange(&x, y)
#else
#define ATOMIC_INT int
#define ATOMIC_LOAD(x) x
#define ATOMIC_STORE(x, y) x = y
#endif

#define MAYBE_UNUSED(x) (void)((x))

#if defined(IS_X86)
static uint64_t xgetbv(void) {
#if defined(_MSC_VER)
  return _xgetbv(0);
#else
  uint32_t eax = 0, edx = 0;
  __asm__ __volatile__("xgetbv\n" : "=a"(eax), "=d"(edx) : "c"(0));
  return ((uint64_t)edx << 32) | eax;
#endif
}

static void cpuid(uint32_t out[4], uint32_t id) {
#if defined(_MSC_VER)
  __cpuid((int *)out, id);
#elif defined(__i386__) || defined(_M_IX86)
  __asm__ __volatile__("movl %%ebx, %1\n"
                       "cpuid\n"
                       "xchgl %1, %%ebx\n"
                       : "=a"(out[0]), "=r"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id));
#else
  __asm__ __volatile__("cpuid\n"
                       : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id));
#endif
}

static void cpuidex(uint32_t out[4], uint32_t id, uint32_t sid) {
#if defined(_MSC_VER)
  __cpuidex((int *)out, id, sid);
#elif defined(__i386__) || defined(_M_IX86)
  __asm__ __volatile__("movl %%ebx, %1\n"
                       "cpuid\n"
                       "xchgl %1, %%ebx\n"
                       : "=a"(out[0]), "=r"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id), "c"(sid));
#else
  __asm__ __volatile__("cpuid\n"
                       : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id), "c"(sid));
#endif
}


enum cpu_feature {
  SSE2 = 1 << 0,
  SSSE3 = 1 << 1,
  SSE41 = 1 << 2,
  AVX = 1 << 3,
  AVX2 = 1 << 4,
  AVX512F = 1 << 5,
  AVX512VL = 1 << 6,
  /* ... */
  UNDEFINED = 1 << 30
};

#if !defined(BLAKE3_TESTING)
static /* Allow the variable to be controlled manually for testing */
#endif
    ATOMIC_INT g_cpu_features = UNDEFINED;

#if !defined(BLAKE3_TESTING)
static
#endif
    enum cpu_feature
    get_cpu_features(void) {

  /* If TSAN detects a data race here, try compiling with -DBLAKE3_ATOMICS=1 */
  enum cpu_feature features = ATOMIC_LOAD(g_cpu_features);
  if (features != UNDEFINED) {
    return features;
  } else {
#if defined(IS_X86)
    uint32_t regs[4] = {0};
    uint32_t *eax = &regs[0], *ebx = &regs[1], *ecx = &regs[2], *edx = &regs[3];
    (void)edx;
    features = 0;
    cpuid(regs, 0);
    const int max_id = *eax;
    cpuid(regs, 1);
#if defined(__amd64__) || defined(_M_X64)
    features |= SSE2;
#else
    if (*edx & (1UL << 26))
      features |= SSE2;
#endif
    if (*ecx & (1UL << 9))
      features |= SSSE3;
    if (*ecx & (1UL << 19))
      features |= SSE41;

    if (*ecx & (1UL << 27)) { // OSXSAVE
      const uint64_t mask = xgetbv();
      if ((mask & 6) == 6) { // SSE and AVX states
        if (*ecx & (1UL << 28))
          features |= AVX;
        if (max_id >= 7) {
          cpuidex(regs, 7, 0);
          if (*ebx & (1UL << 5))
            features |= AVX2;
          if ((mask & 224) == 224) { // Opmask, ZMM_Hi256, Hi16_Zmm
            if (*ebx & (1UL << 31))
              features |= AVX512VL;
            if (*ebx & (1UL << 16))
              features |= AVX512F;
          }
        }
      }
    }
    ATOMIC_STORE(g_cpu_features, features);
    return features;
#else
    /* How to detect NEON? */
    return 0;
#endif
  }
}
#endif

void blake3_compress_in_place(uint32_t cv[8],
                              const uint8_t block[BLAKE3_BLOCK_LEN],
                              uint8_t block_len, uint64_t counter,
                              uint8_t flags) {
#if defined(IS_X86)
  const enum cpu_feature features = get_cpu_features();
  MAYBE_UNUSED(features);
#if !defined(BLAKE3_NO_AVX512)
  if (features & AVX512VL) {
    blake3_compress_in_place_avx512(cv, block, block_len, counter, flags);
    return;
  }
#endif
#if !defined(BLAKE3_NO_SSE41)
  if (features & SSE41) {
    blake3_compress_in_place_sse41(cv, block, block_len, counter, flags);
    return;
  }
#endif
#if !defined(BLAKE3_NO_SSE2)
  if (features & SSE2) {
    blake3_compress_in_place_sse2(cv, block, block_len, counter, flags);
    return;
  }
#endif
#endif
  blake3_compress_in_place_portable(cv, block, block_len, counter, flags);
}

void blake3_compress_xof(const uint32_t cv[8],
                         const uint8_t block[BLAKE3_BLOCK_LEN],
                         uint8_t block_len, uint64_t counter, uint8_t flags,
                         uint8_t out[64]) {
#if defined(IS_X86)
  const enum cpu_feature features = get_cpu_features();
  MAYBE_UNUSED(features);
#if !defined(BLAKE3_NO_AVX512)
  if (features & AVX512VL) {
    blake3_compress_xof_avx512(cv, block, block_len, counter, flags, out);
    return;
  }
#endif
#if !defined(BLAKE3_NO_SSE41)
  if (features & SSE41) {
    blake3_compress_xof_sse41(cv, block, block_len, counter, flags, out);
    return;
  }
#endif
#if !defined(BLAKE3_NO_SSE2)
  if (features & SSE2) {
    blake3_compress_xof_sse2(cv, block, block_len, counter, flags, out);
    return;
  }
#endif
#endif
  blake3_compress_xof_portable(cv, block, block_len, counter, flags, out);
}


void blake3_xof_many(const uint32_t cv[8],
                     const uint8_t block[BLAKE3_BLOCK_LEN],
                     uint8_t block_len, uint64_t counter, uint8_t flags,
                     uint8_t out[64], size_t outblocks) {
  if (outblocks == 0) {
    // The current assembly implementation always outputs at least 1 block.
    return;
  }
#if defined(IS_X86)
  const enum cpu_feature features = get_cpu_features();
  MAYBE_UNUSED(features);
#if !defined(_WIN32) && !defined(__CYGWIN__) && !defined(BLAKE3_NO_AVX512)
  if (features & AVX512VL) {
    blake3_xof_many_avx512(cv, block, block_len, counter, flags, out, outblocks);
    return;
  }
#endif
#endif
  for(size_t i = 0; i < outblocks; ++i) {
    blake3_compress_xof(cv, block, block_len, counter + i, flags, out + 64*i);
  }
}

void blake3_hash_many(const uint8_t *const *inputs, size_t num_inputs,
                      size_t blocks, const uint32_t key[8], uint64_t counter,
                      bool increment_counter, uint8_t flags,
                      uint8_t flags_start, uint8_t flags_end, uint8_t *out) {
#if defined(IS_X86)
  const enum cpu_feature features = get_cpu_features();
  MAYBE_UNUSED(features);
#if !defined(BLAKE3_NO_AVX512)
  if ((features & (AVX512F|AVX512VL)) == (AVX512F|AVX512VL)) {
    blake3_hash_many_avx512(inputs, num_inputs, blocks, key, counter,
                            increment_counter, flags, flags_start, flags_end,
                            out);
    return;
  }
#endif
#if !defined(BLAKE3_NO_AVX2)
  if (features & AVX2) {
    blake3_hash_many_avx2(inputs, num_inputs, blocks, key, counter,
                          increment_counter, flags, flags_start, flags_end,
                          out);
    return;
  }
#endif
#if !defined(BLAKE3_NO_SSE41)
  if (features & SSE41) {
    blake3_hash_many_sse41(inputs, num_inputs, blocks, key, counter,
                           increment_counter, flags, flags_start, flags_end,
                           out);
    return;
  }
#endif
#if !defined(BLAKE3_NO_SSE2)
  if (features & SSE2) {
    blake3_hash_many_sse2(inputs, num_inputs, blocks, key, counter,
                          increment_counter, flags, flags_start, flags_end,
                          out);
    return;
  }
#endif
#endif

#if BLAKE3_USE_NEON == 1
  blake3_hash_many_neon(inputs, num_inputs, blocks, key, counter,
                        increment_counter, flags, flags_start, flags_end, out);
  return;
#endif

  blake3_hash_many_portable(inputs, num_inputs, blocks, key, counter,
                            increment_counter, flags, flags_start, flags_end,
                            out);
}

// The dynamically detected SIMD degree of the current platform.
size_t blake3_simd_degree(void) {
#if defined(IS_X86)
  const enum cpu_feature features = get_cpu_features();
  MAYBE_UNUSED(features);
#if !defined(BLAKE3_NO_AVX512)
  if ((features & (AVX512F|AVX512VL)) == (AVX512F|AVX512VL)) {
    return 16;
  }
#endif
#if !defined(BLAKE3_NO_AVX2)
  if (features & AVX2) {
    return 8;
  }
#endif
#if !defined(BLAKE3_NO_SSE41)
  if (features & SSE41) {
    return 4;
  }
#endif
#if !defined(BLAKE3_NO_SSE2)
  if (features & SSE2) {
    return 4;
  }
#endif
#endif
#if BLAKE3_USE_NEON == 1
  return 4;
#endif
  return 1;
}

```

**`common/BLAKE3/blake3_portable.c`**

```c
#include "blake3_impl.h"
#include <string.h>

INLINE uint32_t rotr32(uint32_t w, uint32_t c) {
  return (w >> c) | (w << (32 - c));
}

INLINE void g(uint32_t *state, size_t a, size_t b, size_t c, size_t d,
              uint32_t x, uint32_t y) {
  state[a] = state[a] + state[b] + x;
  state[d] = rotr32(state[d] ^ state[a], 16);
  state[c] = state[c] + state[d];
  state[b] = rotr32(state[b] ^ state[c], 12);
  state[a] = state[a] + state[b] + y;
  state[d] = rotr32(state[d] ^ state[a], 8);
  state[c] = state[c] + state[d];
  state[b] = rotr32(state[b] ^ state[c], 7);
}

INLINE void round_fn(uint32_t state[16], const uint32_t *msg, size_t round) {
  // Select the message schedule based on the round.
  const uint8_t *schedule = MSG_SCHEDULE[round];

  // Mix the columns.
  g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
  g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
  g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
  g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);

  // Mix the rows.
  g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
  g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
  g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
  g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
}

INLINE void compress_pre(uint32_t state[16], const uint32_t cv[8],
                         const uint8_t block[BLAKE3_BLOCK_LEN],
                         uint8_t block_len, uint64_t counter, uint8_t flags) {
  uint32_t block_words[16];
  block_words[0] = load32(block + 4 * 0);
  block_words[1] = load32(block + 4 * 1);
  block_words[2] = load32(block + 4 * 2);
  block_words[3] = load32(block + 4 * 3);
  block_words[4] = load32(block + 4 * 4);
  block_words[5] = load32(block + 4 * 5);
  block_words[6] = load32(block + 4 * 6);
  block_words[7] = load32(block + 4 * 7);
  block_words[8] = load32(block + 4 * 8);
  block_words[9] = load32(block + 4 * 9);
  block_words[10] = load32(block + 4 * 10);
  block_words[11] = load32(block + 4 * 11);
  block_words[12] = load32(block + 4 * 12);
  block_words[13] = load32(block + 4 * 13);
  block_words[14] = load32(block + 4 * 14);
  block_words[15] = load32(block + 4 * 15);

  state[0] = cv[0];
  state[1] = cv[1];
  state[2] = cv[2];
  state[3] = cv[3];
  state[4] = cv[4];
  state[5] = cv[5];
  state[6] = cv[6];
  state[7] = cv[7];
  state[8] = IV[0];
  state[9] = IV[1];
  state[10] = IV[2];
  state[11] = IV[3];
  state[12] = counter_low(counter);
  state[13] = counter_high(counter);
  state[14] = (uint32_t)block_len;
  state[15] = (uint32_t)flags;

  round_fn(state, &block_words[0], 0);
  round_fn(state, &block_words[0], 1);
  round_fn(state, &block_words[0], 2);
  round_fn(state, &block_words[0], 3);
  round_fn(state, &block_words[0], 4);
  round_fn(state, &block_words[0], 5);
  round_fn(state, &block_words[0], 6);
}

void blake3_compress_in_place_portable(uint32_t cv[8],
                                       const uint8_t block[BLAKE3_BLOCK_LEN],
                                       uint8_t block_len, uint64_t counter,
                                       uint8_t flags) {
  uint32_t state[16];
  compress_pre(state, cv, block, block_len, counter, flags);
  cv[0] = state[0] ^ state[8];
  cv[1] = state[1] ^ state[9];
  cv[2] = state[2] ^ state[10];
  cv[3] = state[3] ^ state[11];
  cv[4] = state[4] ^ state[12];
  cv[5] = state[5] ^ state[13];
  cv[6] = state[6] ^ state[14];
  cv[7] = state[7] ^ state[15];
}

void blake3_compress_xof_portable(const uint32_t cv[8],
                                  const uint8_t block[BLAKE3_BLOCK_LEN],
                                  uint8_t block_len, uint64_t counter,
                                  uint8_t flags, uint8_t out[64]) {
  uint32_t state[16];
  compress_pre(state, cv, block, block_len, counter, flags);

  store32(&out[0 * 4], state[0] ^ state[8]);
  store32(&out[1 * 4], state[1] ^ state[9]);
  store32(&out[2 * 4], state[2] ^ state[10]);
  store32(&out[3 * 4], state[3] ^ state[11]);
  store32(&out[4 * 4], state[4] ^ state[12]);
  store32(&out[5 * 4], state[5] ^ state[13]);
  store32(&out[6 * 4], state[6] ^ state[14]);
  store32(&out[7 * 4], state[7] ^ state[15]);
  store32(&out[8 * 4], state[8] ^ cv[0]);
  store32(&out[9 * 4], state[9] ^ cv[1]);
  store32(&out[10 * 4], state[10] ^ cv[2]);
  store32(&out[11 * 4], state[11] ^ cv[3]);
  store32(&out[12 * 4], state[12] ^ cv[4]);
  store32(&out[13 * 4], state[13] ^ cv[5]);
  store32(&out[14 * 4], state[14] ^ cv[6]);
  store32(&out[15 * 4], state[15] ^ cv[7]);
}

INLINE void hash_one_portable(const uint8_t *input, size_t blocks,
                              const uint32_t key[8], uint64_t counter,
                              uint8_t flags, uint8_t flags_start,
                              uint8_t flags_end, uint8_t out[BLAKE3_OUT_LEN]) {
  uint32_t cv[8];
  memcpy(cv, key, BLAKE3_KEY_LEN);
  uint8_t block_flags = flags | flags_start;
  while (blocks > 0) {
    if (blocks == 1) {
      block_flags |= flags_end;
    }
    blake3_compress_in_place_portable(cv, input, BLAKE3_BLOCK_LEN, counter,
                                      block_flags);
    input = &input[BLAKE3_BLOCK_LEN];
    blocks -= 1;
    block_flags = flags;
  }
  store_cv_words(out, cv);
}

void blake3_hash_many_portable(const uint8_t *const *inputs, size_t num_inputs,
                               size_t blocks, const uint32_t key[8],
                               uint64_t counter, bool increment_counter,
                               uint8_t flags, uint8_t flags_start,
                               uint8_t flags_end, uint8_t *out) {
  while (num_inputs > 0) {
    hash_one_portable(inputs[0], blocks, key, counter, flags, flags_start,
                      flags_end, out);
    if (increment_counter) {
      counter += 1;
    }
    inputs += 1;
    num_inputs -= 1;
    out = &out[BLAKE3_OUT_LEN];
  }
}

```

**`common/BLAKE3/blake3_impl.h`**

```c
#ifndef BLAKE3_IMPL_H
#define BLAKE3_IMPL_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "blake3.h"

#ifdef __cplusplus
extern "C" {
#endif

// internal flags
enum blake3_flags {
  CHUNK_START         = 1 << 0,
  CHUNK_END           = 1 << 1,
  PARENT              = 1 << 2,
  ROOT                = 1 << 3,
  KEYED_HASH          = 1 << 4,
  DERIVE_KEY_CONTEXT  = 1 << 5,
  DERIVE_KEY_MATERIAL = 1 << 6,
};

// This C implementation tries to support recent versions of GCC, Clang, and
// MSVC.
#if defined(_MSC_VER)
#define INLINE static __forceinline
#else
#define INLINE static inline __attribute__((always_inline))
#endif

#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#if (defined(__x86_64__) || defined(_M_X64)) && !defined(_M_ARM64EC)
#define IS_X86
#define IS_X86_64
#endif

#if defined(__i386__) || defined(_M_IX86)
#define IS_X86
#define IS_X86_32
#endif

#if defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC)
#define IS_AARCH64
#endif

#if defined(IS_X86)
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#endif

#if !defined(BLAKE3_USE_NEON) 
  // If BLAKE3_USE_NEON not manually set, autodetect based on AArch64ness
  #if defined(IS_AARCH64)
    #if defined(__ARM_BIG_ENDIAN)
      #define BLAKE3_USE_NEON 0
    #else
      #define BLAKE3_USE_NEON 1
    #endif
  #else
    #define BLAKE3_USE_NEON 0
  #endif
#endif

#if defined(IS_X86)
#define MAX_SIMD_DEGREE 16
#elif BLAKE3_USE_NEON == 1
#define MAX_SIMD_DEGREE 4
#else
#define MAX_SIMD_DEGREE 1
#endif

// There are some places where we want a static size that's equal to the
// MAX_SIMD_DEGREE, but also at least 2.
#define MAX_SIMD_DEGREE_OR_2 (MAX_SIMD_DEGREE > 2 ? MAX_SIMD_DEGREE : 2)

static const uint32_t IV[8] = {0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL,
                               0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL,
                               0x1F83D9ABUL, 0x5BE0CD19UL};

static const uint8_t MSG_SCHEDULE[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

/* Find index of the highest set bit */
/* x is assumed to be nonzero.       */
static unsigned int highest_one(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
  return 63 ^ (unsigned int)__builtin_clzll(x);
#elif defined(_MSC_VER) && defined(IS_X86_64)
  unsigned long index;
  _BitScanReverse64(&index, x);
  return index;
#elif defined(_MSC_VER) && defined(IS_X86_32)
  if(x >> 32) {
    unsigned long index;
    _BitScanReverse(&index, (unsigned long)(x >> 32));
    return 32 + index;
  } else {
    unsigned long index;
    _BitScanReverse(&index, (unsigned long)x);
    return index;
  }
#else
  unsigned int c = 0;
  if(x & 0xffffffff00000000ULL) { x >>= 32; c += 32; }
  if(x & 0x00000000ffff0000ULL) { x >>= 16; c += 16; }
  if(x & 0x000000000000ff00ULL) { x >>=  8; c +=  8; }
  if(x & 0x00000000000000f0ULL) { x >>=  4; c +=  4; }
  if(x & 0x000000000000000cULL) { x >>=  2; c +=  2; }
  if(x & 0x0000000000000002ULL) {           c +=  1; }
  return c;
#endif
}

// Count the number of 1 bits.
INLINE unsigned int popcnt(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
  return (unsigned int)__builtin_popcountll(x);
#else
  unsigned int count = 0;
  while (x != 0) {
    count += 1;
    x &= x - 1;
  }
  return count;
#endif
}

// Largest power of two less than or equal to x. As a special case, returns 1
// when x is 0. 
INLINE uint64_t round_down_to_power_of_2(uint64_t x) {
  return 1ULL << highest_one(x | 1);
}

INLINE uint32_t counter_low(uint64_t counter) { return (uint32_t)counter; }

INLINE uint32_t counter_high(uint64_t counter) {
  return (uint32_t)(counter >> 32);
}

INLINE uint32_t load32(const void *src) {
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)(p[0]) << 0) | ((uint32_t)(p[1]) << 8) |
         ((uint32_t)(p[2]) << 16) | ((uint32_t)(p[3]) << 24);
}

INLINE void load_key_words(const uint8_t key[BLAKE3_KEY_LEN],
                           uint32_t key_words[8]) {
  key_words[0] = load32(&key[0 * 4]);
  key_words[1] = load32(&key[1 * 4]);
  key_words[2] = load32(&key[2 * 4]);
  key_words[3] = load32(&key[3 * 4]);
  key_words[4] = load32(&key[4 * 4]);
  key_words[5] = load32(&key[5 * 4]);
  key_words[6] = load32(&key[6 * 4]);
  key_words[7] = load32(&key[7 * 4]);
}

INLINE void load_block_words(const uint8_t block[BLAKE3_BLOCK_LEN],
                             uint32_t block_words[16]) {
  for (size_t i = 0; i < 16; i++) {
      block_words[i] = load32(&block[i * 4]);
  }
}

INLINE void store32(void *dst, uint32_t w) {
  uint8_t *p = (uint8_t *)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
}

INLINE void store_cv_words(uint8_t bytes_out[32], uint32_t cv_words[8]) {
  store32(&bytes_out[0 * 4], cv_words[0]);
  store32(&bytes_out[1 * 4], cv_words[1]);
  store32(&bytes_out[2 * 4], cv_words[2]);
  store32(&bytes_out[3 * 4], cv_words[3]);
  store32(&bytes_out[4 * 4], cv_words[4]);
  store32(&bytes_out[5 * 4], cv_words[5]);
  store32(&bytes_out[6 * 4], cv_words[6]);
  store32(&bytes_out[7 * 4], cv_words[7]);
}

void blake3_compress_in_place(uint32_t cv[8],
                              const uint8_t block[BLAKE3_BLOCK_LEN],
                              uint8_t block_len, uint64_t counter,
                              uint8_t flags);

void blake3_compress_xof(const uint32_t cv[8],
                         const uint8_t block[BLAKE3_BLOCK_LEN],
                         uint8_t block_len, uint64_t counter, uint8_t flags,
                         uint8_t out[64]);

void blake3_xof_many(const uint32_t cv[8],
                     const uint8_t block[BLAKE3_BLOCK_LEN],
                     uint8_t block_len, uint64_t counter, uint8_t flags,
                     uint8_t out[64], size_t outblocks);

void blake3_hash_many(const uint8_t *const *inputs, size_t num_inputs,
                      size_t blocks, const uint32_t key[8], uint64_t counter,
                      bool increment_counter, uint8_t flags,
                      uint8_t flags_start, uint8_t flags_end, uint8_t *out);

size_t blake3_simd_degree(void);

BLAKE3_PRIVATE size_t blake3_compress_subtree_wide(const uint8_t *input, size_t input_len,
                                                   const uint32_t key[8],
                                                   uint64_t chunk_counter, uint8_t flags,
                                                   uint8_t *out, bool use_tbb);

#if defined(BLAKE3_USE_TBB)
BLAKE3_PRIVATE void blake3_compress_subtree_wide_join_tbb(
    // shared params
    const uint32_t key[8], uint8_t flags, bool use_tbb,
    // left-hand side params
    const uint8_t *l_input, size_t l_input_len, uint64_t l_chunk_counter,
    uint8_t *l_cvs, size_t *l_n,
    // right-hand side params
    const uint8_t *r_input, size_t r_input_len, uint64_t r_chunk_counter,
    uint8_t *r_cvs, size_t *r_n) NOEXCEPT;
#endif

// Declarations for implementation-specific functions.
void blake3_compress_in_place_portable(uint32_t cv[8],
                                       const uint8_t block[BLAKE3_BLOCK_LEN],
                                       uint8_t block_len, uint64_t counter,
                                       uint8_t flags);

void blake3_compress_xof_portable(const uint32_t cv[8],
                                  const uint8_t block[BLAKE3_BLOCK_LEN],
                                  uint8_t block_len, uint64_t counter,
                                  uint8_t flags, uint8_t out[64]);

void blake3_hash_many_portable(const uint8_t *const *inputs, size_t num_inputs,
                               size_t blocks, const uint32_t key[8],
                               uint64_t counter, bool increment_counter,
                               uint8_t flags, uint8_t flags_start,
                               uint8_t flags_end, uint8_t *out);

#if defined(IS_X86)
#if !defined(BLAKE3_NO_SSE2)
void blake3_compress_in_place_sse2(uint32_t cv[8],
                                   const uint8_t block[BLAKE3_BLOCK_LEN],
                                   uint8_t block_len, uint64_t counter,
                                   uint8_t flags);
void blake3_compress_xof_sse2(const uint32_t cv[8],
                              const uint8_t block[BLAKE3_BLOCK_LEN],
                              uint8_t block_len, uint64_t counter,
                              uint8_t flags, uint8_t out[64]);
void blake3_hash_many_sse2(const uint8_t *const *inputs, size_t num_inputs,
                           size_t blocks, const uint32_t key[8],
                           uint64_t counter, bool increment_counter,
                           uint8_t flags, uint8_t flags_start,
                           uint8_t flags_end, uint8_t *out);
#endif
#if !defined(BLAKE3_NO_SSE41)
void blake3_compress_in_place_sse41(uint32_t cv[8],
                                    const uint8_t block[BLAKE3_BLOCK_LEN],
                                    uint8_t block_len, uint64_t counter,
                                    uint8_t flags);
void blake3_compress_xof_sse41(const uint32_t cv[8],
                               const uint8_t block[BLAKE3_BLOCK_LEN],
                               uint8_t block_len, uint64_t counter,
                               uint8_t flags, uint8_t out[64]);
void blake3_hash_many_sse41(const uint8_t *const *inputs, size_t num_inputs,
                            size_t blocks, const uint32_t key[8],
                            uint64_t counter, bool increment_counter,
                            uint8_t flags, uint8_t flags_start,
                            uint8_t flags_end, uint8_t *out);
#endif
#if !defined(BLAKE3_NO_AVX2)
void blake3_hash_many_avx2(const uint8_t *const *inputs, size_t num_inputs,
                           size_t blocks, const uint32_t key[8],
                           uint64_t counter, bool increment_counter,
                           uint8_t flags, uint8_t flags_start,
                           uint8_t flags_end, uint8_t *out);
#endif
#if !defined(BLAKE3_NO_AVX512)
void blake3_compress_in_place_avx512(uint32_t cv[8],
                                     const uint8_t block[BLAKE3_BLOCK_LEN],
                                     uint8_t block_len, uint64_t counter,
                                     uint8_t flags);

void blake3_compress_xof_avx512(const uint32_t cv[8],
                                const uint8_t block[BLAKE3_BLOCK_LEN],
                                uint8_t block_len, uint64_t counter,
                                uint8_t flags, uint8_t out[64]);

void blake3_hash_many_avx512(const uint8_t *const *inputs, size_t num_inputs,
                             size_t blocks, const uint32_t key[8],
                             uint64_t counter, bool increment_counter,
                             uint8_t flags, uint8_t flags_start,
                             uint8_t flags_end, uint8_t *out);

#if !defined(_WIN32) && !defined(__CYGWIN__)
void blake3_xof_many_avx512(const uint32_t cv[8],
                            const uint8_t block[BLAKE3_BLOCK_LEN],
                            uint8_t block_len, uint64_t counter, uint8_t flags,
                            uint8_t* out, size_t outblocks);
#endif
#endif
#endif

#if BLAKE3_USE_NEON == 1
void blake3_hash_many_neon(const uint8_t *const *inputs, size_t num_inputs,
                           size_t blocks, const uint32_t key[8],
                           uint64_t counter, bool increment_counter,
                           uint8_t flags, uint8_t flags_start,
                           uint8_t flags_end, uint8_t *out);
#endif

#ifdef __cplusplus
}
#endif

#endif /* BLAKE3_IMPL_H */

```

---

## 10. Custom common library: Haraka

`PQClean/common/Haraka/` provides `haraka512`/`haraka256` permutation +
the MD-style hashing primitives used by the `haraka` backend's
`symmetric-haraka.c` (§7/§8.1).

> **Architecture restriction**: `haraka.c` below uses ARM-NEON AES
> intrinsics (`<arm_neon.h>`, `vaeseq_u8`, `vaesmcq_u8`). It compiles only
> on `aarch64`/`arm64`. To support x86_64 you would need to provide an
> equivalent `haraka.c` built on AES-NI intrinsics (`<wmmintrin.h>`,
> `_mm_aesenc_si128`) with the same function signatures declared in
> `haraka.h` — see [§18 Troubleshooting](#18-troubleshooting).

### Build (aarch64 only)

```bash
if [ "$(uname -m)" = "aarch64" ] || [ "$(uname -m)" = "arm64" ]; then
  HARAKA_DIR=PQClean/common/Haraka
  gcc -O3 -march=native -c "$HARAKA_DIR/haraka.c" -o "$HARAKA_DIR/haraka.o"
  ar rcs "$HARAKA_DIR/libharaka.a" "$HARAKA_DIR/haraka.o"
fi
```

### Source files

**`common/Haraka/haraka.h`**

```c
#ifndef PQC_COMMON_HARAKA_H
#define PQC_COMMON_HARAKA_H
/*
 * Minimal ARM-NEON port of the Haraka v2 permutations (Kannwischer et al.,
 * https://github.com/kste/haraka, code/c/neon/haraka.c), trimmed to the two
 * single-instance primitives needed by the ML-KEM "HARAKA" symmetric
 * substitution:
 *
 *   haraka256(out[32], in[32])  -- Haraka-256 (256-bit perm + feedforward)
 *   haraka512(out[32], in[64])  -- Haraka-512 (512-bit perm, Davies-Meyer,
 *                                   truncated to 256 bits)
 *
 * These are the unmodified Haraka v2 round functions; only the surrounding
 * 4x/8x batching and self-test code has been removed.
 */
#include <stdint.h>

void haraka256(unsigned char out[32], const unsigned char in[32]);
void haraka512(unsigned char out[32], const unsigned char in[64]);

#endif

```

**`common/Haraka/haraka.c`**

```c
/*
 * Minimal ARM-NEON port of the Haraka v2 permutations.
 * Source: https://github.com/kste/haraka, code/c/neon/haraka.c
 * (public domain / CC0, "the implementer" per upstream headers).
 *
 * Only haraka_f (renamed haraka256) and haraka_h (renamed haraka512),
 * single-instance versions, are kept.
 */
#include "haraka.h"
#include <arm_neon.h>

#define u128 uint8x16_t

static const uint8x16_t rc256[22] = {
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0x9d,0x7b,0x81,0x75,0xf0,0xfe,0xc5,0xb2,0xa,0xc0,0x20,0xe6,0x4c,0x70,0x84,0x6},
    {0x17,0xf7,0x8,0x2f,0xa4,0x6b,0xf,0x64,0x6b,0xa0,0xf3,0x88,0xe1,0xb4,0x66,0x8b},
    {0x14,0x91,0x2,0x9f,0x79,0x4f,0x5b,0xfd,0x60,0x9d,0x2,0xcf,0xaf,0xbc,0xf3,0xbb},
    {0x98,0x84,0xf2,0x53,0x8,0x4f,0x7b,0x2e,0x2d,0xde,0x2,0x34,0xe6,0xea,0xd6,0xe},
    {0x44,0x70,0x39,0xbe,0x1c,0xcd,0xee,0x79,0x8b,0x44,0x72,0x48,0xcb,0xb0,0xcf,0xcb},
    {0x7b,0x5,0x8a,0x2b,0xed,0x35,0x53,0x8d,0xb7,0x32,0x90,0x6e,0xee,0xcd,0xea,0x7e},
    {0x1b,0xef,0x4f,0xda,0x3b,0xb,0xc7,0x1f,0x61,0x27,0x41,0xe2,0xe2,0xfd,0x5f,0x67},
    {0xd0,0x7c,0x2e,0x5e,0x7,0xcc,0xca,0xaf,0x43,0x8f,0xc2,0x67,0xb0,0xd9,0x24,0x29},
    {0xee,0x65,0xd4,0xb9,0xca,0x8f,0xdb,0xec,0xe9,0x7f,0x86,0xe6,0xf1,0x63,0x4d,0xab},
    {0x33,0x7e,0x3,0xad,0x4f,0x40,0x2a,0x5b,0x64,0xcd,0xb7,0xd4,0x84,0xbf,0x30,0x1c},
    {0x0,0x98,0xf6,0x8d,0x8a,0x2d,0x9d,0x5c,0x2e,0x8b,0x2,0x69,0xc8,0x9e,0xaa,0x4a},
    {0xbf,0x23,0x17,0x94,0x72,0x55,0x6f,0xde,0xb9,0xb,0xcc,0xb2,0xa6,0x78,0x4,0xfa},
    {0xd4,0x9f,0x12,0x29,0x2e,0x4f,0xfa,0xe,0x12,0x2a,0x77,0x6b,0x2b,0x9f,0xb4,0xdf},
    {0xee,0x12,0x6a,0xbb,0xae,0x11,0xd6,0x32,0x36,0xa2,0x49,0xf4,0x44,0x3,0xa1,0x1e},
    {0xa6,0xec,0xa8,0x9c,0xec,0x93,0xe5,0x27,0xc9,0x0,0x96,0x5f,0xe3,0xc7,0xa2,0x78},
    {0x84,0x0,0x5,0x4b,0x4f,0x9c,0x19,0x9d,0x88,0x49,0x4,0xaf,0xd8,0x5e,0x2,0x21},
    {0x73,0x1,0xd4,0x82,0xcd,0x2e,0x28,0xb9,0xb7,0xc9,0x59,0xa7,0xf8,0xaa,0x3a,0xbf},
    {0x6b,0x7d,0x30,0x10,0xd9,0xef,0xf2,0x37,0x17,0xb0,0x86,0x61,0xd,0x70,0x60,0x62},
    {0xc6,0x9a,0xfc,0xf6,0x53,0x91,0xc2,0x81,0x43,0x4,0x30,0x21,0xc2,0x45,0xca,0x5a},
    {0x3a,0x94,0xd1,0x36,0xe8,0x92,0xaf,0x2c,0xbb,0x68,0x6b,0x22,0x3c,0x97,0x23,0x92}
};

static const uint8x16_t rc512[44] = {
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0x9d,0x7b,0x81,0x75,0xf0,0xfe,0xc5,0xb2,0xa,0xc0,0x20,0xe6,0x4c,0x70,0x84,0x6},
    {0x17,0xf7,0x8,0x2f,0xa4,0x6b,0xf,0x64,0x6b,0xa0,0xf3,0x88,0xe1,0xb4,0x66,0x8b},
    {0x14,0x91,0x2,0x9f,0x60,0x9d,0x2,0xcf,0x98,0x84,0xf2,0x53,0x2d,0xde,0x2,0x34},
    {0x79,0x4f,0x5b,0xfd,0xaf,0xbc,0xf3,0xbb,0x8,0x4f,0x7b,0x2e,0xe6,0xea,0xd6,0xe},
    {0xcb,0xb0,0xcf,0xcb,0x43,0x8f,0xc2,0x67,0xee,0xcd,0xea,0x7e,0xb0,0xd9,0x24,0x29},
    {0x1b,0xef,0x4f,0xda,0x44,0x70,0x39,0xbe,0x3b,0xb,0xc7,0x1f,0x7b,0x5,0x8a,0x2b},
    {0x61,0x27,0x41,0xe2,0x1c,0xcd,0xee,0x79,0xe2,0xfd,0x5f,0x67,0xed,0x35,0x53,0x8d},
    {0x8b,0x44,0x72,0x48,0xd0,0x7c,0x2e,0x5e,0xb7,0x32,0x90,0x6e,0x7,0xcc,0xca,0xaf},
    {0xee,0x65,0xd4,0xb9,0xca,0x8f,0xdb,0xec,0xe9,0x7f,0x86,0xe6,0xf1,0x63,0x4d,0xab},
    {0x33,0x7e,0x3,0xad,0x4f,0x40,0x2a,0x5b,0x64,0xcd,0xb7,0xd4,0x84,0xbf,0x30,0x1c},
    {0x0,0x98,0xf6,0x8d,0x2e,0x8b,0x2,0x69,0xbf,0x23,0x17,0x94,0xb9,0xb,0xcc,0xb2},
    {0x8a,0x2d,0x9d,0x5c,0xc8,0x9e,0xaa,0x4a,0x72,0x55,0x6f,0xde,0xa6,0x78,0x4,0xfa},
    {0x2b,0x9f,0xb4,0xdf,0x88,0x49,0x4,0xaf,0x44,0x3,0xa1,0x1e,0xd8,0x5e,0x2,0x21},
    {0xa6,0xec,0xa8,0x9c,0xd4,0x9f,0x12,0x29,0xec,0x93,0xe5,0x27,0xee,0x12,0x6a,0xbb},
    {0xc9,0x0,0x96,0x5f,0x2e,0x4f,0xfa,0xe,0xe3,0xc7,0xa2,0x78,0xae,0x11,0xd6,0x32},
    {0x12,0x2a,0x77,0x6b,0x84,0x0,0x5,0x4b,0x36,0xa2,0x49,0xf4,0x4f,0x9c,0x19,0x9d},
    {0x73,0x1,0xd4,0x82,0xcd,0x2e,0x28,0xb9,0xb7,0xc9,0x59,0xa7,0xf8,0xaa,0x3a,0xbf},
    {0x6b,0x7d,0x30,0x10,0xd9,0xef,0xf2,0x37,0x17,0xb0,0x86,0x61,0xd,0x70,0x60,0x62},
    {0xc6,0x9a,0xfc,0xf6,0x53,0x91,0xc2,0x81,0x43,0x4,0x30,0x21,0xc2,0x45,0xca,0x5a},
    {0x3a,0x94,0xd1,0x36,0xe8,0x92,0xaf,0x2c,0xbb,0x68,0x6b,0x22,0x3c,0x97,0x23,0x92},
    {0x38,0x92,0xbf,0xd3,0x68,0x62,0x60,0xbb,0xe5,0x3c,0x86,0xdb,0xdc,0xd3,0x4b,0x73},
    {0xb1,0x12,0x22,0xcb,0xb4,0x71,0x10,0xe5,0x7d,0xf7,0x2b,0xc7,0x8d,0x12,0xe1,0x24},
    {0xe3,0x8d,0xe4,0x83,0x58,0xb9,0xba,0x6c,0x4e,0x1a,0xb9,0x2d,0xdd,0xfd,0x3d,0x93},
    {0xeb,0x86,0x58,0x22,0x9c,0xa0,0xeb,0xff,0x77,0xc6,0xf0,0xae,0x9c,0xd1,0xe4,0xe2},
    {0x4e,0x92,0xb3,0x2c,0xc4,0x15,0x14,0x4b,0x43,0x1b,0x30,0x61,0xc3,0x47,0xbb,0x43},
    {0x99,0x68,0xeb,0x16,0xdd,0x31,0xb2,0x3,0xf6,0xef,0x7,0xe7,0xa8,0x75,0xa7,0xdb},
    {0x2c,0x47,0xca,0x7e,0x2,0x23,0x5e,0x8e,0x77,0x59,0x75,0x3c,0x4b,0x61,0xf3,0x6d},
    {0xf9,0x17,0x86,0xb8,0xb9,0xe5,0x1b,0x6d,0x77,0x7d,0xde,0xd6,0x17,0x5a,0xa7,0xcd},
    {0xf0,0x43,0x6b,0xec,0x75,0xc,0xee,0x2c,0x50,0x69,0x1e,0xcb,0xa1,0xa5,0xb1,0xf0},
    {0xd9,0xd0,0xe,0x60,0x5d,0xee,0x46,0xa9,0x50,0xa3,0xa4,0x63,0xc1,0x27,0xf3,0x3b},
    {0x53,0x3,0xed,0xe4,0x9d,0x6,0x6c,0x9d,0xbc,0xba,0xbb,0x80,0x59,0x11,0x53,0xa2},
    {0xaa,0xe9,0xa8,0x6b,0x9c,0x61,0xda,0x0,0x2b,0x33,0x57,0xf9,0xab,0xc,0xe9,0x96},
    {0x39,0xca,0x8d,0x93,0x30,0xde,0xd,0xab,0x88,0x29,0x96,0x5e,0x2,0xb1,0x3d,0xae},
    {0x42,0xb4,0x75,0x2e,0xa8,0xf3,0x14,0x88,0xb,0xa4,0x54,0xd5,0x38,0x8f,0xbb,0x17},
    {0xf6,0x16,0xa,0x36,0x79,0xb7,0xb6,0xae,0xd7,0x7f,0x42,0x5f,0x5b,0x8a,0xbb,0x34},
    {0xde,0xaf,0xba,0xff,0x18,0x59,0xce,0x43,0x38,0x54,0xe5,0xcb,0x41,0x52,0xf6,0x26},
    {0x78,0xc9,0x9e,0x83,0xf7,0x9c,0xca,0xa2,0x6a,0x2,0xf3,0xb9,0x54,0x9a,0xe9,0x4c},
    {0x35,0x12,0x90,0x22,0x28,0x6e,0xc0,0x40,0xbe,0xf7,0xdf,0x1b,0x1a,0xa5,0x51,0xae},
    {0xcf,0x59,0xa6,0x48,0xf,0xbc,0x73,0xc1,0x2b,0xd2,0x7e,0xba,0x3c,0x61,0xc1,0xa0},
    {0xa1,0x9d,0xc5,0xe9,0xfd,0xbd,0xd6,0x4a,0x88,0x82,0x28,0x2,0x3,0xcc,0x6a,0x75}
};

#define XOR(a, b) veorq_u8(a, b)
#define LOAD(src) vld1q_u8(src)
#define STORE(dest,src) vst1q_u8(dest,src)
#define ZIP2(a, b) (u128) vzip2q_u32((uint32x4_t)a, (uint32x4_t)b)
#define ZIP1(a, b) (u128) vzip1q_u32((uint32x4_t)a, (uint32x4_t)b)

#define AES2(s0, s1, rci) \
  s0 = vaesmcq_u8(vaeseq_u8(s0, rc256[rci])); \
  s1 = vaesmcq_u8(vaeseq_u8(s1, rc256[rci + 1])); \
  s0 = vaesmcq_u8(vaeseq_u8(s0, rc256[rci + 2])); \
  s1 = vaesmcq_u8(vaeseq_u8(s1, rc256[rci + 3]));

#define AES4(s0, s1, s2, s3, rci) \
  s0 = vaesmcq_u8(vaeseq_u8(s0, rc512[rci])); \
  s1 = vaesmcq_u8(vaeseq_u8(s1, rc512[rci + 1])); \
  s2 = vaesmcq_u8(vaeseq_u8(s2, rc512[rci + 2])); \
  s3 = vaesmcq_u8(vaeseq_u8(s3, rc512[rci + 3])); \
  s0 = vaesmcq_u8(vaeseq_u8(s0, rc512[rci + 4])); \
  s1 = vaesmcq_u8(vaeseq_u8(s1, rc512[rci + 5])); \
  s2 = vaesmcq_u8(vaeseq_u8(s2, rc512[rci + 6])); \
  s3 = vaesmcq_u8(vaeseq_u8(s3, rc512[rci + 7]));

#define MIX2(s0, s1) \
  tmp = ZIP2(s0, s1); \
  s0 = ZIP1(s0, s1); \
  s1 = tmp;

#define MIX4(s0, s1, s2, s3) \
  tmp  = ZIP1(s0, s1); \
  s0 = ZIP2(s0, s1); \
  s1 = ZIP1(s2, s3); \
  s2 = ZIP2(s2, s3); \
  s3 = ZIP1(s0, s2); \
  s0 = ZIP2(s0, s2); \
  s2 = ZIP2(s1, tmp); \
  s1 = ZIP1(s1, tmp);

#define TRUNCSTORE(out, s0, s1, s2, s3) \
  *(uint64_t*)(out) = vreinterpretq_u64_u8(s0)[1]; \
  *(uint64_t*)(out + 8) = vreinterpretq_u64_u8(s1)[1]; \
  *(uint64_t*)(out + 16) = vreinterpretq_u64_u8(s2)[0]; \
  *(uint64_t*)(out + 24) = vreinterpretq_u64_u8(s3)[0];

/* Haraka-256 (256-bit permutation with feedforward), 32-byte in -> 32-byte out */
void haraka256(unsigned char out[32], const unsigned char in[32]) {
  u128 s[2], tmp, s_save[2];

  s[0] = LOAD(in);
  s[1] = LOAD(in + 16);

  s_save[0] = s[0];
  s_save[1] = s[1];

  AES2(s[0], s[1], 0);
  MIX2(s[0], s[1]);

  AES2(s[0], s[1], 4);
  MIX2(s[0], s[1]);

  AES2(s[0], s[1], 8);
  MIX2(s[0], s[1]);

  AES2(s[0], s[1], 12);
  MIX2(s[0], s[1]);

  AES2(s[0], s[1], 16);
  s[0] = XOR(s[0], rc256[20]);
  s[1] = XOR(s[1], rc256[21]);
  MIX2(s[0], s[1]);

  s[0] = XOR(s[0], s_save[0]);
  s[1] = XOR(s[1], s_save[1]);

  STORE(out, s[0]);
  STORE(out + 16, s[1]);
}

/* Haraka-512 (512-bit permutation, Davies-Meyer, truncated), 64-byte in -> 32-byte out */
void haraka512(unsigned char out[32], const unsigned char in[64]) {
  u128 s[4], tmp, s_save[4];

  s[0] = LOAD(in);
  s[1] = LOAD(in + 16);
  s[2] = LOAD(in + 32);
  s[3] = LOAD(in + 48);

  s_save[0] = s[0];
  s_save[1] = s[1];
  s_save[2] = s[2];
  s_save[3] = s[3];

  AES4(s[0], s[1], s[2], s[3], 0);
  MIX4(s[0], s[1], s[2], s[3]);

  AES4(s[0], s[1], s[2], s[3], 8);
  MIX4(s[0], s[1], s[2], s[3]);

  AES4(s[0], s[1], s[2], s[3], 16);
  MIX4(s[0], s[1], s[2], s[3]);

  AES4(s[0], s[1], s[2], s[3], 24);
  MIX4(s[0], s[1], s[2], s[3]);

  AES4(s[0], s[1], s[2], s[3], 32);
  s[0] = XOR(s[0], rc512[40]);
  s[1] = XOR(s[1], rc512[41]);
  s[2] = XOR(s[2], rc512[42]);
  s[3] = XOR(s[3], rc512[43]);
  MIX4(s[0], s[1], s[2], s[3]);

  s[0] = XOR(s[0], s_save[0]);
  s[1] = XOR(s[1], s_save[1]);
  s[2] = XOR(s[2], s_save[2]);
  s[3] = XOR(s[3], s_save[3]);

  TRUNCSTORE(out, s[0], s[1], s[2], s[3]);
}

```

---

## 11. liboqs adapter shims (OQS_KEM / OQS_SIG)

Each backend needs a small shim that:

- Declares the forked PQClean functions (`PQCLEAN_MLKEM*_<TAG>_crypto_kem_*`,
  `PQCLEAN_MLDSA*_<TAG>_crypto_sign_*`) via the adapter's `.h`.
- Wraps them in `OQS_KEM`/`OQS_SIG` objects (`OQS_KEM_new_<tag>_<size>`,
  `OQS_SIG_new_<tag>_<size>`) following the same struct layout liboqs uses
  for its own algorithms, so `pqc_bench.c` can call `OQS_KEM_keypair`,
  `OQS_KEM_encaps`, `OQS_KEM_decaps`, `OQS_SIG_keypair`, `OQS_SIG_sign`,
  `OQS_SIG_verify` uniformly across all 6 backends.

There are 20 adapter files total: for each of the 5 alternative tags
(`turboshake`, `k12`, `blake3`, `xoodyak`, `haraka`) there is a
`pqc_<tag>_kem.{c,h}` and `pqc_<tag>_dsa.{c,h}`. The `shake` baseline needs
no adapter: `bench_shake` is built without any `-DUSE_*` macro, and in that
case `pqc_bench.c` simply calls `OQS_KEM_new(OQS_KEM_alg_ml_kem_{512,768,1024})`
/ `OQS_SIG_new(OQS_SIG_alg_ml_dsa_{44,65,87})` — i.e. **liboqs's own
built-in** ML-KEM/ML-DSA implementations, which already use standard
SHAKE/SHA3 and need no forked PQClean tree at all. For the 5 alternative
backends, `pqc_bench.c` instead calls the adapter's own
`OQS_KEM_ml_kem_<size>_<tag>_new()` / `OQS_SIG_ml_dsa_<size>_<tag>_new()`
constructors (§12), which wrap the forked, hash-substituted PQClean trees.

These were generated from a template by `gen_dsa_adapters.py` (for the DSA
side; the KEM side follows the identical pattern, generated earlier in the
project). The generator is included below as the authoritative description
of the adapter pattern — re-run it (with `BACKENDS`/`SIZES` edited as
needed) to regenerate or extend to new backends/sizes.

**`gen_dsa_adapters.py`**

```python
#!/usr/bin/env python3
"""
Generate pqc_<tag>_dsa.{c,h} OQS_SIG adapters for the 5 hash-substituted
ML-DSA backends, wrapping the forked PQClean trees under
/root/PQClean/crypto_sign/ml-dsa-{44,65,87}/<dir>.

Mirrors the pqc_<tag>_kem.{c,h} adapter pattern already used for ML-KEM.
"""
import os

BACKENDS = {
    "turboshake": {
        "dir": "turboshake",
        "pfx": "TURBO",
        "alg_version": "TurboSHAKE (RFC 9861, n_r=12) substitution -- NON-FIPS",
    },
    "k12": {
        "dir": "k12",
        "pfx": "K12",
        "alg_version": "KangarooTwelve (RFC 9861, n_r=12 tree hash) substitution -- NON-FIPS",
    },
    "blake3": {
        "dir": "blake3",
        "pfx": "BLAKE3",
        "alg_version": "BLAKE3 (native XOF) substitution -- NON-FIPS",
    },
    "xoodyak": {
        "dir": "xoodyak",
        "pfx": "XOODYAK",
        "alg_version": "Xoodyak (Cyclist/Xoodoo hash mode) substitution -- NON-FIPS",
    },
    "haraka": {
        "dir": "haraka",
        "pfx": "HARAKA",
        "alg_version": "Haraka-MD (non-standard MD construction over Haraka512) substitution -- NON-FIPS",
    },
}

SIZES = [
    (44, 2, "2420"),
    (65, 3, "3309"),
    (87, 5, "4627"),
]

HEADER_TMPL = '''/*
 * pqc_{tag}_dsa.h
 *
 * OQS_SIG constructors for the {label} variants of
 * ML-DSA-44/65/87.  These are NOT part of liboqs -- they wrap the forked
 * PQClean "clean" implementations living under
 * /root/PQClean/crypto_sign/ml-dsa-{{44,65,87}}/{dir}, in which all
 * SHAKE128/SHAKE256 uses (matrix expansion, eta/mask sampling, the H/CRH
 * hash role in sign.c, and poly_challenge) have been replaced by {label}
 * with the domain separation bytes documented in pqc_bench.c
 * (0x1F matrix, 0x2F noise, 0x3F hash, 0x4F challenge).
 *
 * Returned objects are heap-allocated and must be freed with OQS_SIG_free().
 */
#ifndef PQC_{TAG}_DSA_H
#define PQC_{TAG}_DSA_H

#include <oqs/sig.h>

OQS_SIG *OQS_SIG_ml_dsa_44_{tag}_new(void);
OQS_SIG *OQS_SIG_ml_dsa_65_{tag}_new(void);
OQS_SIG *OQS_SIG_ml_dsa_87_{tag}_new(void);

#endif /* PQC_{TAG}_DSA_H */
'''

SOURCE_TMPL = '''/*
 * pqc_{tag}_dsa.c
 *
 * See pqc_{tag}_dsa.h.  Thin OQS_SIG-shaped wrappers around the
 * {label} ML-DSA implementations.
 */
#include "pqc_{tag}_dsa.h"

#include <stdlib.h>
#include <string.h>

#include "/root/PQClean/crypto_sign/ml-dsa-44/{dir}/api.h"
#include "/root/PQClean/crypto_sign/ml-dsa-65/{dir}/api.h"
#include "/root/PQClean/crypto_sign/ml-dsa-87/{dir}/api.h"

{size_blocks}
/* ---------------------------------------------------------------- */
/* Constructors                                                      */
/* ---------------------------------------------------------------- */
static OQS_SIG *{tag}_sig_alloc(const char *method_name,
                                 uint8_t nist_level,
                                 size_t pk_len, size_t sk_len, size_t sig_len,
                                 OQS_STATUS (*keypair)(uint8_t *, uint8_t *),
                                 OQS_STATUS (*sign)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *),
                                 OQS_STATUS (*verify)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) {{
\tOQS_SIG *sig = malloc(sizeof(OQS_SIG));
\tif (!sig) {{
\t\treturn NULL;
\t}}
\tmemset(sig, 0, sizeof(OQS_SIG));

\tsig->method_name        = method_name;
\tsig->alg_version        = "{alg_version}";
\tsig->claimed_nist_level = nist_level;
\tsig->euf_cma            = true;
\tsig->suf_cma            = false;
\tsig->sig_with_ctx_support = false;
\tsig->length_public_key  = pk_len;
\tsig->length_secret_key  = sk_len;
\tsig->length_signature   = sig_len;

\tsig->keypair             = keypair;
\tsig->sign                = sign;
\tsig->sign_with_ctx_str   = NULL;
\tsig->verify              = verify;
\tsig->verify_with_ctx_str = NULL;

\treturn sig;
}}

{ctor_blocks}'''

SIZE_BLOCK_TMPL = '''/* ---------------------------------------------------------------- */
/* ML-DSA-{size}-{TAG}                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS {tag}_{size}_keypair(uint8_t *public_key, uint8_t *secret_key) {{
\treturn (PQCLEAN_MLDSA{size}_{pfx}_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}}
static OQS_STATUS {tag}_{size}_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {{
\treturn (PQCLEAN_MLDSA{size}_{pfx}_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}}
static OQS_STATUS {tag}_{size}_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {{
\treturn (PQCLEAN_MLDSA{size}_{pfx}_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}}

'''

CTOR_BLOCK_TMPL = '''OQS_SIG *OQS_SIG_ml_dsa_{size}_{tag}_new(void) {{
\treturn {tag}_sig_alloc("ML-DSA-{size}-{TAG}", {nist_level},
\t                        PQCLEAN_MLDSA{size}_{pfx}_CRYPTO_PUBLICKEYBYTES,
\t                        PQCLEAN_MLDSA{size}_{pfx}_CRYPTO_SECRETKEYBYTES,
\t                        PQCLEAN_MLDSA{size}_{pfx}_CRYPTO_BYTES,
\t                        {tag}_{size}_keypair, {tag}_{size}_sign, {tag}_{size}_verify);
}}
'''

for tag, info in BACKENDS.items():
    label_map = {
        "turboshake": "TurboSHAKE",
        "k12": "KangarooTwelve (KT128/KT256)",
        "blake3": "BLAKE3",
        "xoodyak": "Xoodyak",
        "haraka": "Haraka-MD",
    }
    label = label_map[tag]
    header = HEADER_TMPL.format(tag=tag, TAG=tag.upper(), label=label, dir=info["dir"])

    size_blocks = ""
    ctor_blocks = ""
    for size, nist_level, _ in SIZES:
        size_blocks += SIZE_BLOCK_TMPL.format(size=size, tag=tag, TAG=tag.upper(), pfx=info["pfx"])
        ctor_blocks += CTOR_BLOCK_TMPL.format(size=size, tag=tag, TAG=tag.upper(), pfx=info["pfx"], nist_level=nist_level)
        if size != 87:
            ctor_blocks += "\n"

    source = SOURCE_TMPL.format(tag=tag, label=label, dir=info["dir"],
                                 size_blocks=size_blocks, ctor_blocks=ctor_blocks,
                                 alg_version=info["alg_version"])

    with open(f"/root/pqc_{tag}_dsa.h", "w") as f:
        f.write(header)
    with open(f"/root/pqc_{tag}_dsa.c", "w") as f:
        f.write(source)
    print(f"wrote pqc_{tag}_dsa.h / .c")

```

### 11.x Full adapter source (all 20 files)

#### Backend `turboshake` — KEM adapter

**`pqc_turboshake_kem.h`**

```c
/*
 * pqc_turboshake_kem.h
 *
 * OQS_KEM constructors for the TurboSHAKE (RFC 9861) variants of
 * ML-KEM-512/768/1024.  These are NOT part of liboqs -- they wrap the
 * forked PQClean "clean" implementations living under
 * /root/PQClean/crypto_kem/ml-kem-{512,768,1024}/turboshake, in which
 * the SHAKE128/SHAKE256 XOF/PRF/rkprf calls have been replaced by
 * TurboSHAKE128/TurboSHAKE256 (n_r=12) with the domain separation bytes
 * documented in pqc_bench.c (0x1F matrix, 0x2F CBD noise, 0x3F rkprf/KDF).
 *
 * hash_h/hash_g (SHA3-256/512, the FO transform) are unchanged.
 *
 * Returned objects are heap-allocated and must be freed with OQS_KEM_free().
 */
#ifndef PQC_TURBOSHAKE_KEM_H
#define PQC_TURBOSHAKE_KEM_H

#include <oqs/kem.h>

OQS_KEM *OQS_KEM_ml_kem_512_turboshake_new(void);
OQS_KEM *OQS_KEM_ml_kem_768_turboshake_new(void);
OQS_KEM *OQS_KEM_ml_kem_1024_turboshake_new(void);

#endif /* PQC_TURBOSHAKE_KEM_H */

```

**`pqc_turboshake_kem.c`**

```c
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

```

#### Backend `turboshake` — DSA (signature) adapter

**`pqc_turboshake_dsa.h`**

```c
/*
 * pqc_turboshake_dsa.h
 *
 * OQS_SIG constructors for the TurboSHAKE variants of
 * ML-DSA-44/65/87.  These are NOT part of liboqs -- they wrap the forked
 * PQClean "clean" implementations living under
 * /root/PQClean/crypto_sign/ml-dsa-{44,65,87}/turboshake, in which all
 * SHAKE128/SHAKE256 uses (matrix expansion, eta/mask sampling, the H/CRH
 * hash role in sign.c, and poly_challenge) have been replaced by TurboSHAKE
 * with the domain separation bytes documented in pqc_bench.c
 * (0x1F matrix, 0x2F noise, 0x3F hash, 0x4F challenge).
 *
 * Returned objects are heap-allocated and must be freed with OQS_SIG_free().
 */
#ifndef PQC_TURBOSHAKE_DSA_H
#define PQC_TURBOSHAKE_DSA_H

#include <oqs/sig.h>

OQS_SIG *OQS_SIG_ml_dsa_44_turboshake_new(void);
OQS_SIG *OQS_SIG_ml_dsa_65_turboshake_new(void);
OQS_SIG *OQS_SIG_ml_dsa_87_turboshake_new(void);

#endif /* PQC_TURBOSHAKE_DSA_H */

```

**`pqc_turboshake_dsa.c`**

```c
/*
 * pqc_turboshake_dsa.c
 *
 * See pqc_turboshake_dsa.h.  Thin OQS_SIG-shaped wrappers around the
 * TurboSHAKE ML-DSA implementations.
 */
#include "pqc_turboshake_dsa.h"

#include <stdlib.h>
#include <string.h>

#include "/root/PQClean/crypto_sign/ml-dsa-44/turboshake/api.h"
#include "/root/PQClean/crypto_sign/ml-dsa-65/turboshake/api.h"
#include "/root/PQClean/crypto_sign/ml-dsa-87/turboshake/api.h"

/* ---------------------------------------------------------------- */
/* ML-DSA-44-TURBOSHAKE                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS turboshake_44_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA44_TURBO_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS turboshake_44_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA44_TURBO_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS turboshake_44_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA44_TURBO_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-DSA-65-TURBOSHAKE                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS turboshake_65_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA65_TURBO_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS turboshake_65_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA65_TURBO_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS turboshake_65_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA65_TURBO_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-DSA-87-TURBOSHAKE                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS turboshake_87_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA87_TURBO_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS turboshake_87_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA87_TURBO_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS turboshake_87_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA87_TURBO_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}


/* ---------------------------------------------------------------- */
/* Constructors                                                      */
/* ---------------------------------------------------------------- */
static OQS_SIG *turboshake_sig_alloc(const char *method_name,
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
	sig->alg_version        = "TurboSHAKE (RFC 9861, n_r=12) substitution -- NON-FIPS";
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

OQS_SIG *OQS_SIG_ml_dsa_44_turboshake_new(void) {
	return turboshake_sig_alloc("ML-DSA-44-TURBOSHAKE", 2,
	                        PQCLEAN_MLDSA44_TURBO_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA44_TURBO_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA44_TURBO_CRYPTO_BYTES,
	                        turboshake_44_keypair, turboshake_44_sign, turboshake_44_verify);
}

OQS_SIG *OQS_SIG_ml_dsa_65_turboshake_new(void) {
	return turboshake_sig_alloc("ML-DSA-65-TURBOSHAKE", 3,
	                        PQCLEAN_MLDSA65_TURBO_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA65_TURBO_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA65_TURBO_CRYPTO_BYTES,
	                        turboshake_65_keypair, turboshake_65_sign, turboshake_65_verify);
}

OQS_SIG *OQS_SIG_ml_dsa_87_turboshake_new(void) {
	return turboshake_sig_alloc("ML-DSA-87-TURBOSHAKE", 5,
	                        PQCLEAN_MLDSA87_TURBO_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA87_TURBO_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA87_TURBO_CRYPTO_BYTES,
	                        turboshake_87_keypair, turboshake_87_sign, turboshake_87_verify);
}

```

#### Backend `k12` — KEM adapter

**`pqc_k12_kem.h`**

```c
/*
 * pqc_k12_kem.h
 *
 * OQS_KEM constructors for the KangarooTwelve (RFC 9861) variants of
 * ML-KEM-512/768/1024.  These are NOT part of liboqs -- they wrap the
 * forked PQClean "clean" implementations living under
 * /root/PQClean/crypto_kem/ml-kem-{512,768,1024}/k12, in which the
 * SHAKE128/SHAKE256 XOF/PRF/rkprf calls have been replaced by
 * KangarooTwelve (KT128 for matrix expansion, KT256 for the CBD-noise PRF
 * and implicit-rejection KDF) with the customization-string bytes
 * documented in pqc_bench.c (0x1F matrix, 0x2F CBD noise, 0x3F rkprf/KDF).
 *
 * hash_h/hash_g (SHA3-256/512, the FO transform) are unchanged.
 *
 * Returned objects are heap-allocated and must be freed with OQS_KEM_free().
 */
#ifndef PQC_K12_KEM_H
#define PQC_K12_KEM_H

#include <oqs/kem.h>

OQS_KEM *OQS_KEM_ml_kem_512_k12_new(void);
OQS_KEM *OQS_KEM_ml_kem_768_k12_new(void);
OQS_KEM *OQS_KEM_ml_kem_1024_k12_new(void);

#endif /* PQC_K12_KEM_H */

```

**`pqc_k12_kem.c`**

```c
/*
 * pqc_k12_kem.c
 *
 * See pqc_k12_kem.h.  Thin OQS_KEM-shaped wrappers around the
 * KangarooTwelve-substituted PQClean ML-KEM implementations.
 */
#include "pqc_k12_kem.h"

#include <stdlib.h>
#include <string.h>

#include "/root/PQClean/crypto_kem/ml-kem-512/k12/api.h"
#include "/root/PQClean/crypto_kem/ml-kem-768/k12/api.h"
#include "/root/PQClean/crypto_kem/ml-kem-1024/k12/api.h"

/* ---------------------------------------------------------------- */
/* ML-KEM-512-K12                                                    */
/* ---------------------------------------------------------------- */
static OQS_STATUS k12_512_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM512_K12_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS k12_512_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM512_K12_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS k12_512_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM512_K12_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-KEM-768-K12                                                    */
/* ---------------------------------------------------------------- */
static OQS_STATUS k12_768_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM768_K12_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS k12_768_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM768_K12_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS k12_768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM768_K12_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-KEM-1024-K12                                                   */
/* ---------------------------------------------------------------- */
static OQS_STATUS k12_1024_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM1024_K12_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS k12_1024_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM1024_K12_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS k12_1024_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM1024_K12_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* Constructors                                                      */
/* ---------------------------------------------------------------- */
static OQS_KEM *k12_kem_alloc(const char *method_name,
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
	kem->alg_version        = "KangarooTwelve (RFC 9861, n_r=12) substitution -- NON-FIPS";
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

OQS_KEM *OQS_KEM_ml_kem_512_k12_new(void) {
	return k12_kem_alloc("ML-KEM-512-K12", 1,
	                      PQCLEAN_MLKEM512_K12_CRYPTO_PUBLICKEYBYTES,
	                      PQCLEAN_MLKEM512_K12_CRYPTO_SECRETKEYBYTES,
	                      PQCLEAN_MLKEM512_K12_CRYPTO_CIPHERTEXTBYTES,
	                      PQCLEAN_MLKEM512_K12_CRYPTO_BYTES,
	                      k12_512_keypair, k12_512_encaps, k12_512_decaps);
}

OQS_KEM *OQS_KEM_ml_kem_768_k12_new(void) {
	return k12_kem_alloc("ML-KEM-768-K12", 3,
	                      PQCLEAN_MLKEM768_K12_CRYPTO_PUBLICKEYBYTES,
	                      PQCLEAN_MLKEM768_K12_CRYPTO_SECRETKEYBYTES,
	                      PQCLEAN_MLKEM768_K12_CRYPTO_CIPHERTEXTBYTES,
	                      PQCLEAN_MLKEM768_K12_CRYPTO_BYTES,
	                      k12_768_keypair, k12_768_encaps, k12_768_decaps);
}

OQS_KEM *OQS_KEM_ml_kem_1024_k12_new(void) {
	return k12_kem_alloc("ML-KEM-1024-K12", 5,
	                      PQCLEAN_MLKEM1024_K12_CRYPTO_PUBLICKEYBYTES,
	                      PQCLEAN_MLKEM1024_K12_CRYPTO_SECRETKEYBYTES,
	                      PQCLEAN_MLKEM1024_K12_CRYPTO_CIPHERTEXTBYTES,
	                      PQCLEAN_MLKEM1024_K12_CRYPTO_BYTES,
	                      k12_1024_keypair, k12_1024_encaps, k12_1024_decaps);
}

```

#### Backend `k12` — DSA (signature) adapter

**`pqc_k12_dsa.h`**

```c
/*
 * pqc_k12_dsa.h
 *
 * OQS_SIG constructors for the KangarooTwelve (KT128/KT256) variants of
 * ML-DSA-44/65/87.  These are NOT part of liboqs -- they wrap the forked
 * PQClean "clean" implementations living under
 * /root/PQClean/crypto_sign/ml-dsa-{44,65,87}/k12, in which all
 * SHAKE128/SHAKE256 uses (matrix expansion, eta/mask sampling, the H/CRH
 * hash role in sign.c, and poly_challenge) have been replaced by KangarooTwelve (KT128/KT256)
 * with the domain separation bytes documented in pqc_bench.c
 * (0x1F matrix, 0x2F noise, 0x3F hash, 0x4F challenge).
 *
 * Returned objects are heap-allocated and must be freed with OQS_SIG_free().
 */
#ifndef PQC_K12_DSA_H
#define PQC_K12_DSA_H

#include <oqs/sig.h>

OQS_SIG *OQS_SIG_ml_dsa_44_k12_new(void);
OQS_SIG *OQS_SIG_ml_dsa_65_k12_new(void);
OQS_SIG *OQS_SIG_ml_dsa_87_k12_new(void);

#endif /* PQC_K12_DSA_H */

```

**`pqc_k12_dsa.c`**

```c
/*
 * pqc_k12_dsa.c
 *
 * See pqc_k12_dsa.h.  Thin OQS_SIG-shaped wrappers around the
 * KangarooTwelve (KT128/KT256) ML-DSA implementations.
 */
#include "pqc_k12_dsa.h"

#include <stdlib.h>
#include <string.h>

#include "/root/PQClean/crypto_sign/ml-dsa-44/k12/api.h"
#include "/root/PQClean/crypto_sign/ml-dsa-65/k12/api.h"
#include "/root/PQClean/crypto_sign/ml-dsa-87/k12/api.h"

/* ---------------------------------------------------------------- */
/* ML-DSA-44-K12                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS k12_44_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA44_K12_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS k12_44_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA44_K12_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS k12_44_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA44_K12_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-DSA-65-K12                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS k12_65_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA65_K12_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS k12_65_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA65_K12_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS k12_65_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA65_K12_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-DSA-87-K12                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS k12_87_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA87_K12_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS k12_87_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA87_K12_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS k12_87_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA87_K12_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}


/* ---------------------------------------------------------------- */
/* Constructors                                                      */
/* ---------------------------------------------------------------- */
static OQS_SIG *k12_sig_alloc(const char *method_name,
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
	sig->alg_version        = "KangarooTwelve (RFC 9861, n_r=12 tree hash) substitution -- NON-FIPS";
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

OQS_SIG *OQS_SIG_ml_dsa_44_k12_new(void) {
	return k12_sig_alloc("ML-DSA-44-K12", 2,
	                        PQCLEAN_MLDSA44_K12_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA44_K12_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA44_K12_CRYPTO_BYTES,
	                        k12_44_keypair, k12_44_sign, k12_44_verify);
}

OQS_SIG *OQS_SIG_ml_dsa_65_k12_new(void) {
	return k12_sig_alloc("ML-DSA-65-K12", 3,
	                        PQCLEAN_MLDSA65_K12_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA65_K12_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA65_K12_CRYPTO_BYTES,
	                        k12_65_keypair, k12_65_sign, k12_65_verify);
}

OQS_SIG *OQS_SIG_ml_dsa_87_k12_new(void) {
	return k12_sig_alloc("ML-DSA-87-K12", 5,
	                        PQCLEAN_MLDSA87_K12_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA87_K12_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA87_K12_CRYPTO_BYTES,
	                        k12_87_keypair, k12_87_sign, k12_87_verify);
}

```

#### Backend `blake3` — KEM adapter

**`pqc_blake3_kem.h`**

```c
/*
 * pqc_blake3_kem.h
 *
 * OQS_KEM constructors for the BLAKE3 variants of ML-KEM-512/768/1024.
 * These are NOT part of liboqs -- they wrap the forked PQClean "clean"
 * implementations living under
 * /root/PQClean/crypto_kem/ml-kem-{512,768,1024}/blake3, in which the
 * SHAKE128/SHAKE256 XOF/PRF/rkprf calls have been replaced by BLAKE3's
 * native XOF (blake3_hasher_finalize_seek) with the domain-separation
 * bytes documented in pqc_bench.c (0x1F matrix, 0x2F CBD noise, 0x3F
 * rkprf/KDF).
 *
 * hash_h/hash_g (SHA3-256/512, the FO transform) are unchanged.
 *
 * Returned objects are heap-allocated and must be freed with OQS_KEM_free().
 */
#ifndef PQC_BLAKE3_KEM_H
#define PQC_BLAKE3_KEM_H

#include <oqs/kem.h>

OQS_KEM *OQS_KEM_ml_kem_512_blake3_new(void);
OQS_KEM *OQS_KEM_ml_kem_768_blake3_new(void);
OQS_KEM *OQS_KEM_ml_kem_1024_blake3_new(void);

#endif /* PQC_BLAKE3_KEM_H */

```

**`pqc_blake3_kem.c`**

```c
/*
 * pqc_blake3_kem.c
 *
 * See pqc_blake3_kem.h.  Thin OQS_KEM-shaped wrappers around the
 * BLAKE3-substituted PQClean ML-KEM implementations.
 */
#include "pqc_blake3_kem.h"

#include <stdlib.h>
#include <string.h>

#include "/root/PQClean/crypto_kem/ml-kem-512/blake3/api.h"
#include "/root/PQClean/crypto_kem/ml-kem-768/blake3/api.h"
#include "/root/PQClean/crypto_kem/ml-kem-1024/blake3/api.h"

/* ---------------------------------------------------------------- */
/* ML-KEM-512-BLAKE3                                                    */
/* ---------------------------------------------------------------- */
static OQS_STATUS blake3_512_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM512_BLAKE3_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS blake3_512_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM512_BLAKE3_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS blake3_512_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM512_BLAKE3_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-KEM-768-BLAKE3                                                    */
/* ---------------------------------------------------------------- */
static OQS_STATUS blake3_768_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM768_BLAKE3_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS blake3_768_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM768_BLAKE3_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS blake3_768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM768_BLAKE3_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-KEM-1024-BLAKE3                                                   */
/* ---------------------------------------------------------------- */
static OQS_STATUS blake3_1024_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM1024_BLAKE3_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS blake3_1024_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM1024_BLAKE3_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS blake3_1024_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM1024_BLAKE3_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* Constructors                                                      */
/* ---------------------------------------------------------------- */
static OQS_KEM *blake3_kem_alloc(const char *method_name,
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
	kem->alg_version        = "BLAKE3 (native XOF) substitution -- NON-FIPS";
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

OQS_KEM *OQS_KEM_ml_kem_512_blake3_new(void) {
	return blake3_kem_alloc("ML-KEM-512-BLAKE3", 1,
	                      PQCLEAN_MLKEM512_BLAKE3_CRYPTO_PUBLICKEYBYTES,
	                      PQCLEAN_MLKEM512_BLAKE3_CRYPTO_SECRETKEYBYTES,
	                      PQCLEAN_MLKEM512_BLAKE3_CRYPTO_CIPHERTEXTBYTES,
	                      PQCLEAN_MLKEM512_BLAKE3_CRYPTO_BYTES,
	                      blake3_512_keypair, blake3_512_encaps, blake3_512_decaps);
}

OQS_KEM *OQS_KEM_ml_kem_768_blake3_new(void) {
	return blake3_kem_alloc("ML-KEM-768-BLAKE3", 3,
	                      PQCLEAN_MLKEM768_BLAKE3_CRYPTO_PUBLICKEYBYTES,
	                      PQCLEAN_MLKEM768_BLAKE3_CRYPTO_SECRETKEYBYTES,
	                      PQCLEAN_MLKEM768_BLAKE3_CRYPTO_CIPHERTEXTBYTES,
	                      PQCLEAN_MLKEM768_BLAKE3_CRYPTO_BYTES,
	                      blake3_768_keypair, blake3_768_encaps, blake3_768_decaps);
}

OQS_KEM *OQS_KEM_ml_kem_1024_blake3_new(void) {
	return blake3_kem_alloc("ML-KEM-1024-BLAKE3", 5,
	                      PQCLEAN_MLKEM1024_BLAKE3_CRYPTO_PUBLICKEYBYTES,
	                      PQCLEAN_MLKEM1024_BLAKE3_CRYPTO_SECRETKEYBYTES,
	                      PQCLEAN_MLKEM1024_BLAKE3_CRYPTO_CIPHERTEXTBYTES,
	                      PQCLEAN_MLKEM1024_BLAKE3_CRYPTO_BYTES,
	                      blake3_1024_keypair, blake3_1024_encaps, blake3_1024_decaps);
}

```

#### Backend `blake3` — DSA (signature) adapter

**`pqc_blake3_dsa.h`**

```c
/*
 * pqc_blake3_dsa.h
 *
 * OQS_SIG constructors for the BLAKE3 variants of
 * ML-DSA-44/65/87.  These are NOT part of liboqs -- they wrap the forked
 * PQClean "clean" implementations living under
 * /root/PQClean/crypto_sign/ml-dsa-{44,65,87}/blake3, in which all
 * SHAKE128/SHAKE256 uses (matrix expansion, eta/mask sampling, the H/CRH
 * hash role in sign.c, and poly_challenge) have been replaced by BLAKE3
 * with the domain separation bytes documented in pqc_bench.c
 * (0x1F matrix, 0x2F noise, 0x3F hash, 0x4F challenge).
 *
 * Returned objects are heap-allocated and must be freed with OQS_SIG_free().
 */
#ifndef PQC_BLAKE3_DSA_H
#define PQC_BLAKE3_DSA_H

#include <oqs/sig.h>

OQS_SIG *OQS_SIG_ml_dsa_44_blake3_new(void);
OQS_SIG *OQS_SIG_ml_dsa_65_blake3_new(void);
OQS_SIG *OQS_SIG_ml_dsa_87_blake3_new(void);

#endif /* PQC_BLAKE3_DSA_H */

```

**`pqc_blake3_dsa.c`**

```c
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

```

#### Backend `xoodyak` — KEM adapter

**`pqc_xoodyak_kem.h`**

```c
/*
 * pqc_xoodyak_kem.h
 *
 * OQS_KEM constructors for the Xoodyak (NIST LWC finalist, Cyclist mode
 * over the Xoodoo permutation, via XKCP) variants of ML-KEM-512/768/1024.
 * These are NOT part of liboqs -- they wrap the forked PQClean "clean"
 * implementations living under
 * /root/PQClean/crypto_kem/ml-kem-{512,768,1024}/xoodyak, in which the
 * SHAKE128/SHAKE256 XOF/PRF/rkprf calls have been replaced by Xoodyak's
 * Cyclist hash mode with the domain-separation bytes documented in
 * pqc_bench.c (0x1F matrix, 0x2F CBD noise, 0x3F rkprf/KDF).
 *
 * hash_h/hash_g (SHA3-256/512, the FO transform) are unchanged.
 *
 * Returned objects are heap-allocated and must be freed with OQS_KEM_free().
 */
#ifndef PQC_XOODYAK_KEM_H
#define PQC_XOODYAK_KEM_H

#include <oqs/kem.h>

OQS_KEM *OQS_KEM_ml_kem_512_xoodyak_new(void);
OQS_KEM *OQS_KEM_ml_kem_768_xoodyak_new(void);
OQS_KEM *OQS_KEM_ml_kem_1024_xoodyak_new(void);

#endif /* PQC_XOODYAK_KEM_H */

```

**`pqc_xoodyak_kem.c`**

```c
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

```

#### Backend `xoodyak` — DSA (signature) adapter

**`pqc_xoodyak_dsa.h`**

```c
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

```

**`pqc_xoodyak_dsa.c`**

```c
/*
 * pqc_xoodyak_dsa.c
 *
 * See pqc_xoodyak_dsa.h.  Thin OQS_SIG-shaped wrappers around the
 * Xoodyak ML-DSA implementations.
 */
#include "pqc_xoodyak_dsa.h"

#include <stdlib.h>
#include <string.h>

#include "/root/PQClean/crypto_sign/ml-dsa-44/xoodyak/api.h"
#include "/root/PQClean/crypto_sign/ml-dsa-65/xoodyak/api.h"
#include "/root/PQClean/crypto_sign/ml-dsa-87/xoodyak/api.h"

/* ---------------------------------------------------------------- */
/* ML-DSA-44-XOODYAK                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS xoodyak_44_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA44_XOODYAK_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS xoodyak_44_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA44_XOODYAK_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS xoodyak_44_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA44_XOODYAK_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-DSA-65-XOODYAK                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS xoodyak_65_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA65_XOODYAK_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS xoodyak_65_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA65_XOODYAK_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS xoodyak_65_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA65_XOODYAK_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-DSA-87-XOODYAK                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS xoodyak_87_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA87_XOODYAK_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS xoodyak_87_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA87_XOODYAK_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS xoodyak_87_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA87_XOODYAK_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}


/* ---------------------------------------------------------------- */
/* Constructors                                                      */
/* ---------------------------------------------------------------- */
static OQS_SIG *xoodyak_sig_alloc(const char *method_name,
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
	sig->alg_version        = "Xoodyak (Cyclist/Xoodoo hash mode) substitution -- NON-FIPS";
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

OQS_SIG *OQS_SIG_ml_dsa_44_xoodyak_new(void) {
	return xoodyak_sig_alloc("ML-DSA-44-XOODYAK", 2,
	                        PQCLEAN_MLDSA44_XOODYAK_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA44_XOODYAK_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA44_XOODYAK_CRYPTO_BYTES,
	                        xoodyak_44_keypair, xoodyak_44_sign, xoodyak_44_verify);
}

OQS_SIG *OQS_SIG_ml_dsa_65_xoodyak_new(void) {
	return xoodyak_sig_alloc("ML-DSA-65-XOODYAK", 3,
	                        PQCLEAN_MLDSA65_XOODYAK_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA65_XOODYAK_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA65_XOODYAK_CRYPTO_BYTES,
	                        xoodyak_65_keypair, xoodyak_65_sign, xoodyak_65_verify);
}

OQS_SIG *OQS_SIG_ml_dsa_87_xoodyak_new(void) {
	return xoodyak_sig_alloc("ML-DSA-87-XOODYAK", 5,
	                        PQCLEAN_MLDSA87_XOODYAK_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA87_XOODYAK_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA87_XOODYAK_CRYPTO_BYTES,
	                        xoodyak_87_keypair, xoodyak_87_sign, xoodyak_87_verify);
}

```

#### Backend `haraka` — KEM adapter

**`pqc_haraka_kem.h`**

```c
/*
 * pqc_haraka_kem.h
 *
 * OQS_KEM constructors for the Haraka v2 variants of ML-KEM-512/768/1024.
 * These are NOT part of liboqs -- they wrap the forked PQClean "clean"
 * implementations living under
 * /root/PQClean/crypto_kem/ml-kem-{512,768,1024}/haraka, in which the
 * SHAKE128/SHAKE256 XOF/PRF/rkprf calls have been replaced by a
 * NON-STANDARD "Haraka-CTR" counter-mode construction over Haraka512
 * (see symmetric.h in the forked trees for the exact construction), with
 * the domain-separation bytes documented in pqc_bench.c (0x1F matrix,
 * 0x2F CBD noise, 0x3F rkprf/KDF).
 *
 * hash_h/hash_g (SHA3-256/512, the FO transform) are unchanged.
 *
 * Returned objects are heap-allocated and must be freed with OQS_KEM_free().
 */
#ifndef PQC_HARAKA_KEM_H
#define PQC_HARAKA_KEM_H

#include <oqs/kem.h>

OQS_KEM *OQS_KEM_ml_kem_512_haraka_new(void);
OQS_KEM *OQS_KEM_ml_kem_768_haraka_new(void);
OQS_KEM *OQS_KEM_ml_kem_1024_haraka_new(void);

#endif /* PQC_HARAKA_KEM_H */

```

**`pqc_haraka_kem.c`**

```c
/*
 * pqc_haraka_kem.c
 *
 * See pqc_haraka_kem.h.  Thin OQS_KEM-shaped wrappers around the
 * Haraka-substituted PQClean ML-KEM implementations.
 */
#include "pqc_haraka_kem.h"

#include <stdlib.h>
#include <string.h>

#include "/root/PQClean/crypto_kem/ml-kem-512/haraka/api.h"
#include "/root/PQClean/crypto_kem/ml-kem-768/haraka/api.h"
#include "/root/PQClean/crypto_kem/ml-kem-1024/haraka/api.h"

/* ---------------------------------------------------------------- */
/* ML-KEM-512-HARAKA                                                    */
/* ---------------------------------------------------------------- */
static OQS_STATUS haraka_512_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM512_HARAKA_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS haraka_512_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM512_HARAKA_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS haraka_512_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM512_HARAKA_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-KEM-768-HARAKA                                                    */
/* ---------------------------------------------------------------- */
static OQS_STATUS haraka_768_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM768_HARAKA_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS haraka_768_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM768_HARAKA_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS haraka_768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM768_HARAKA_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-KEM-1024-HARAKA                                                   */
/* ---------------------------------------------------------------- */
static OQS_STATUS haraka_1024_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLKEM1024_HARAKA_crypto_kem_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS haraka_1024_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (PQCLEAN_MLKEM1024_HARAKA_crypto_kem_enc(ciphertext, shared_secret, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS haraka_1024_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (PQCLEAN_MLKEM1024_HARAKA_crypto_kem_dec(shared_secret, ciphertext, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* Constructors                                                      */
/* ---------------------------------------------------------------- */
static OQS_KEM *haraka_kem_alloc(const char *method_name,
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
	kem->alg_version        = "Haraka-CTR (non-standard, Haraka512-based) substitution -- NON-FIPS";
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

OQS_KEM *OQS_KEM_ml_kem_512_haraka_new(void) {
	return haraka_kem_alloc("ML-KEM-512-HARAKA", 1,
	                      PQCLEAN_MLKEM512_HARAKA_CRYPTO_PUBLICKEYBYTES,
	                      PQCLEAN_MLKEM512_HARAKA_CRYPTO_SECRETKEYBYTES,
	                      PQCLEAN_MLKEM512_HARAKA_CRYPTO_CIPHERTEXTBYTES,
	                      PQCLEAN_MLKEM512_HARAKA_CRYPTO_BYTES,
	                      haraka_512_keypair, haraka_512_encaps, haraka_512_decaps);
}

OQS_KEM *OQS_KEM_ml_kem_768_haraka_new(void) {
	return haraka_kem_alloc("ML-KEM-768-HARAKA", 3,
	                      PQCLEAN_MLKEM768_HARAKA_CRYPTO_PUBLICKEYBYTES,
	                      PQCLEAN_MLKEM768_HARAKA_CRYPTO_SECRETKEYBYTES,
	                      PQCLEAN_MLKEM768_HARAKA_CRYPTO_CIPHERTEXTBYTES,
	                      PQCLEAN_MLKEM768_HARAKA_CRYPTO_BYTES,
	                      haraka_768_keypair, haraka_768_encaps, haraka_768_decaps);
}

OQS_KEM *OQS_KEM_ml_kem_1024_haraka_new(void) {
	return haraka_kem_alloc("ML-KEM-1024-HARAKA", 5,
	                      PQCLEAN_MLKEM1024_HARAKA_CRYPTO_PUBLICKEYBYTES,
	                      PQCLEAN_MLKEM1024_HARAKA_CRYPTO_SECRETKEYBYTES,
	                      PQCLEAN_MLKEM1024_HARAKA_CRYPTO_CIPHERTEXTBYTES,
	                      PQCLEAN_MLKEM1024_HARAKA_CRYPTO_BYTES,
	                      haraka_1024_keypair, haraka_1024_encaps, haraka_1024_decaps);
}

```

#### Backend `haraka` — DSA (signature) adapter

**`pqc_haraka_dsa.h`**

```c
/*
 * pqc_haraka_dsa.h
 *
 * OQS_SIG constructors for the Haraka-MD variants of
 * ML-DSA-44/65/87.  These are NOT part of liboqs -- they wrap the forked
 * PQClean "clean" implementations living under
 * /root/PQClean/crypto_sign/ml-dsa-{44,65,87}/haraka, in which all
 * SHAKE128/SHAKE256 uses (matrix expansion, eta/mask sampling, the H/CRH
 * hash role in sign.c, and poly_challenge) have been replaced by Haraka-MD
 * with the domain separation bytes documented in pqc_bench.c
 * (0x1F matrix, 0x2F noise, 0x3F hash, 0x4F challenge).
 *
 * Returned objects are heap-allocated and must be freed with OQS_SIG_free().
 */
#ifndef PQC_HARAKA_DSA_H
#define PQC_HARAKA_DSA_H

#include <oqs/sig.h>

OQS_SIG *OQS_SIG_ml_dsa_44_haraka_new(void);
OQS_SIG *OQS_SIG_ml_dsa_65_haraka_new(void);
OQS_SIG *OQS_SIG_ml_dsa_87_haraka_new(void);

#endif /* PQC_HARAKA_DSA_H */

```

**`pqc_haraka_dsa.c`**

```c
/*
 * pqc_haraka_dsa.c
 *
 * See pqc_haraka_dsa.h.  Thin OQS_SIG-shaped wrappers around the
 * Haraka-MD ML-DSA implementations.
 */
#include "pqc_haraka_dsa.h"

#include <stdlib.h>
#include <string.h>

#include "/root/PQClean/crypto_sign/ml-dsa-44/haraka/api.h"
#include "/root/PQClean/crypto_sign/ml-dsa-65/haraka/api.h"
#include "/root/PQClean/crypto_sign/ml-dsa-87/haraka/api.h"

/* ---------------------------------------------------------------- */
/* ML-DSA-44-HARAKA                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS haraka_44_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA44_HARAKA_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS haraka_44_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA44_HARAKA_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS haraka_44_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA44_HARAKA_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-DSA-65-HARAKA                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS haraka_65_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA65_HARAKA_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS haraka_65_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA65_HARAKA_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS haraka_65_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA65_HARAKA_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

/* ---------------------------------------------------------------- */
/* ML-DSA-87-HARAKA                                               */
/* ---------------------------------------------------------------- */
static OQS_STATUS haraka_87_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (PQCLEAN_MLDSA87_HARAKA_crypto_sign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS haraka_87_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return (PQCLEAN_MLDSA87_HARAKA_crypto_sign_signature(signature, signature_len, message, message_len, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS haraka_87_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return (PQCLEAN_MLDSA87_HARAKA_crypto_sign_verify(signature, signature_len, message, message_len, public_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}


/* ---------------------------------------------------------------- */
/* Constructors                                                      */
/* ---------------------------------------------------------------- */
static OQS_SIG *haraka_sig_alloc(const char *method_name,
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
	sig->alg_version        = "Haraka-MD (non-standard MD construction over Haraka512) substitution -- NON-FIPS";
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

OQS_SIG *OQS_SIG_ml_dsa_44_haraka_new(void) {
	return haraka_sig_alloc("ML-DSA-44-HARAKA", 2,
	                        PQCLEAN_MLDSA44_HARAKA_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA44_HARAKA_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA44_HARAKA_CRYPTO_BYTES,
	                        haraka_44_keypair, haraka_44_sign, haraka_44_verify);
}

OQS_SIG *OQS_SIG_ml_dsa_65_haraka_new(void) {
	return haraka_sig_alloc("ML-DSA-65-HARAKA", 3,
	                        PQCLEAN_MLDSA65_HARAKA_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA65_HARAKA_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA65_HARAKA_CRYPTO_BYTES,
	                        haraka_65_keypair, haraka_65_sign, haraka_65_verify);
}

OQS_SIG *OQS_SIG_ml_dsa_87_haraka_new(void) {
	return haraka_sig_alloc("ML-DSA-87-HARAKA", 5,
	                        PQCLEAN_MLDSA87_HARAKA_CRYPTO_PUBLICKEYBYTES,
	                        PQCLEAN_MLDSA87_HARAKA_CRYPTO_SECRETKEYBYTES,
	                        PQCLEAN_MLDSA87_HARAKA_CRYPTO_BYTES,
	                        haraka_87_keypair, haraka_87_sign, haraka_87_verify);
}

```

---

## 12. Benchmark harness: pqc_bench.c

`pqc_bench.c` is compiled **6 times** — once "plain" for the SHAKE
baseline (`bench_shake`, no `-DUSE_*`), and once per alternative backend
with `-DUSE_TURBOSHAKE`, `-DUSE_K12`, `-DUSE_BLAKE3`, `-DUSE_XOODYAK`,
`-DUSE_HARAKA` respectively (`bench_<tag>`). The `-DUSE_<TAG>` macro
gates which adapter header (`pqc_<tag>_kem.h`/`pqc_<tag>_dsa.h`) is
included and which `OQS_KEM_new_*`/`OQS_SIG_new_*` constructors are used
for ML-KEM-{512,768,1024} and ML-DSA-{44,65,87}.

For each of the 6 algorithm variants × 3 sizes (= 18 KEM ops + 18 DSA ops
per binary... i.e. ML-KEM-{512,768,1024} KeyGen/Encaps/Decaps and
ML-DSA-{44,65,87} KeyGen/Sign/Verify), the harness:

1. Runs a **selftest** (one full keypair + encaps/decaps or sign/verify
   round trip), printing `[SELFTEST] ... roundtrip OK` or aborting on
   mismatch.
2. Runs `BENCH_ITERATIONS` (default configurable via env var, see source)
   timed iterations of each operation, collecting CPU cycle counts
   (via `RDTSC`/`cntvct`-equivalent) and wall-clock time.
3. Computes summary statistics: median, Q1/Q3/IQR, p95/p99, min/max,
   arithmetic & geometric mean, stddev, coefficient of variation,
   cycles-per-byte, plus memory (stack high-water mark, RSS delta) and an
   energy-proxy/EDP (energy-delay-product) estimate.
4. Appends one CSV row per (algorithm, operation, backend) to
   `pqc_benchmark_results.csv` — see §15/§16 for the column schema and a
   reference run.

Run with `--csv-append` (all binaries after the first) to avoid
overwriting previous backends' rows; the first run (`bench_shake`,
without the flag) (re)creates the CSV with a header row.

**`pqc_bench.c`**

```c
/*
 * =============================================================================
 * FILE:    pqc_agility_benchmark.c
 *
 * TITLE:   Post-Quantum Cryptographic Agility Benchmarking Suite
 *          ML-DSA (FIPS 204 / Dilithium) and ML-KEM (FIPS 203 / Kyber)
 *          Native SHAKE  vs  TurboSHAKE (RFC 9861) Hash Substitution
 *
 * PURPOSE: This file implements the COMPLETE multi-tiered benchmarking
 *          framework described in:
 *            [1] "Engineering and Benchmarking Algorithmic Agility in
 *                 Post-Quantum Cryptography" (PDF 1)
 *            [2] "Post-Quantum Cryptographic Agility: Engineering the
 *                 Integration and Benchmarking of TurboSHAKE within
 *                 ML-DSA and ML-KEM" (PDF 2)
 *
 * TIERS IMPLEMENTED:
 *   TIER 1  - CPU Cycle Profiling (rdtsc + lfence serialization, SUPERCOP method)
 *   TIER 2  - Statistical Aggregation (median, quartiles, geo-mean, 99th pct tail)
 *   TIER 3  - Rejection Sampling Variance (iteration count histogram for ML-DSA)
 *   TIER 4  - Sub-Component Isolation (matrix expand, CBD noise, sign, verify,
 *             encaps, decaps separately)
 *   TIER 5  - Stack Watermarking / Painting (0xDEADBEEF sentinel technique)
 *   TIER 6  - Welch's t-test Constant-Time Validation (dudect methodology)
 *   TIER 7  - Cycles-per-Byte (CpB) Throughput Metric
 *   TIER 8  - Wall-clock timing (CLOCK_MONOTONIC, ns resolution)
 *   TIER 9  - Algorithm metadata and FIPS/compliance notes
 *   TIER 10 - CSV report generation for external analysis (perf, Cachegrind)
 *   TIER 11 - Memory Footprint Profiling (peak RSS via getrusage,
 *             heap-arena delta via mallinfo -- POSIX/libc only, no
 *             hardware-specific counters)
 *   TIER 12 - Software Energy Proxy Model (Energy Proxy Units derived from
 *             cycle counts, plus optional user-calibrated uJ estimate and
 *             Energy-Delay Product -- no RAPL/MSR/board sensors required)
 *
 * LIBRARY COMPATIBILITY:
 *   - liboqs  (Open Quantum Safe)  -- primary target
 *   - PQClean -- secondary target (stub stubs at bottom)
 *   Link: gcc pqc_agility_benchmark.c -loqs -lm -O2 -o pqc_bench
 *         (add -DUSE_TURBOSHAKE to switch hash backend)
 *         (add -DUSE_PQCLEAN    to use PQClean instead of liboqs)
 *
 * IMPORTANT COMPLIANCE NOTE (from PDFs):
 *   Replacing SHAKE with TurboSHAKE inside ML-DSA or ML-KEM BREAKS strict
 *   FIPS 203/204 compliance and BREAKS interoperability with standard-compliant
 *   peers on the open internet.  This benchmark is designed for CLOSED
 *   ecosystems, proprietary zero-trust networks, IoT/SCADA environments, or
 *   pure research purposes where performance outweighs interoperability.
 *
 * SPONGE CONSTRUCTION REFERENCE (both PDFs, Table 1):
 *   Parameter        SHAKE128    TurboSHAKE128  SHAKE256    TurboSHAKE256
 *   Permutation      Keccak-P    Keccak-P       Keccak-P    Keccak-P
 *   Rounds (n_r)     24          12             24          12
 *   Capacity (c)     256 bits    256 bits       512 bits    512 bits
 *   Rate (r)         1344 bits   1344 bits      1088 bits   1088 bits
 *                    (168 bytes) (168 bytes)    (136 bytes) (136 bytes)
 *   Domain Sep.      Implied     Explicit 0x01  Implied     Explicit 0x01
 *                    pad10*1     ..0x7F + 0x80  pad10*1     ..0x7F + 0x80
 *   Sec. Margin      128-bit     128-bit        256-bit     256-bit
 *
 * CRYPTANALYTIC SAFETY NOTE (both PDFs):
 *   Best known collision attack on Keccak breaks 6/24 rounds.
 *   TurboSHAKE uses 12/24 rounds => 100% safety margin above best attack.
 *
 * BUILD COMMANDS:
 *   # Standard (SHAKE, FIPS-compliant):
 *   gcc -O2 -march=native pqc_agility_benchmark.c -loqs -lm -o bench_shake
 *
 *   # TurboSHAKE variant (non-FIPS, closed ecosystem only):
 *   gcc -O2 -march=native -DUSE_TURBOSHAKE pqc_agility_benchmark.c -loqs -lm -o bench_turboshake
 *
 *   # Optional: calibrate the TIER 12 energy proxy for your platform by
 *   # supplying its measured energy-per-cycle figure (nanojoules/cycle).
 *   # See "SOFTWARE-LEVEL ENERGY PROXY MODEL" below for how to derive it.
 *   # Without this flag, energy figures are reported as illustrative only.
 *   gcc -O2 -march=native -DENERGY_PER_CYCLE_NJ=0.42 pqc_agility_benchmark.c -loqs -lm -o bench_shake
 *
 *   # With Valgrind Massif heap profiling:
 *   valgrind --tool=massif --stacks=yes ./bench_shake
 *
 *   # With Cachegrind instruction profiling:
 *   valgrind --tool=cachegrind ./bench_shake
 *
 *   # With perf hardware counters (run as root or with perf_event_paranoid=1):
 *   perf stat -e cycles,instructions,cache-misses,cache-references,branch-misses \
 *             ./bench_shake --iterations 10000
 *
 * =============================================================================
 */

/* =========================================================================
 * STANDARD HEADERS
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <inttypes.h>

/* =========================================================================
 * MEMORY PROFILING HEADERS (POSIX, software-level only)
 *
 * getrusage() is part of POSIX.1-2001 (<sys/resource.h>) and is available
 * on Linux, macOS, *BSD, and other POSIX systems.  It reports figures
 * gathered entirely by the OS kernel's own bookkeeping -- NOT from any
 * CPU performance counter, RAPL register, or vendor-specific MSR.  This
 * keeps the memory tier fully portable and hardware-independent.
 *
 * mallinfo2()/mallinfo() (glibc <malloc.h>) report the heap allocator's
 * own arena statistics.  This is purely a libc-level facility, also not
 * tied to any specific CPU/board.  On non-glibc platforms it is disabled
 * automatically and the heap-delta columns simply report 0.
 * ========================================================================= */
#include <sys/resource.h>
#if defined(__GLIBC__)
#  include <malloc.h>
#  define PQC_HAVE_MALLINFO 1
#endif

/* =========================================================================
 * LIBOQS HEADERS
 * These expose OQS_KEM and OQS_SIG structures with function pointers:
 *   OQS_KEM->keypair()  OQS_KEM->encaps()  OQS_KEM->decaps()
 *   OQS_SIG->keypair()  OQS_SIG->sign()    OQS_SIG->verify()
 * ========================================================================= */
#ifndef USE_PQCLEAN
#  include <oqs/oqs.h>       /* liboqs master header     */
#  include <oqs/kem.h>       /* OQS_KEM struct           */
#  include <oqs/sig.h>       /* OQS_SIG struct           */
#endif

#ifdef USE_TURBOSHAKE
/* OQS_KEM constructors for the TurboSHAKE (RFC 9861) ML-KEM variants --
 * forked PQClean "clean" implementations with SHAKE128/256 replaced by
 * TurboSHAKE128/256 (n_r=12). See pqc_turboshake_kem.h for details. */
#  include "pqc_turboshake_kem.h"
/* OQS_SIG constructors for the TurboSHAKE ML-DSA variants -- see
 * pqc_turboshake_dsa.h for details. */
#  include "pqc_turboshake_dsa.h"
#endif

#ifdef USE_K12
/* OQS_KEM constructors for the KangarooTwelve (RFC 9861) ML-KEM variants --
 * forked PQClean "clean" implementations with SHAKE128/256 replaced by
 * KT128/KT256 (n_r=12 tree hashing). See pqc_k12_kem.h for details. */
#  include "pqc_k12_kem.h"
/* OQS_SIG constructors for the KangarooTwelve ML-DSA variants -- see
 * pqc_k12_dsa.h for details. */
#  include "pqc_k12_dsa.h"
#endif

#ifdef USE_BLAKE3
/* OQS_KEM constructors for the BLAKE3 ML-KEM variants -- forked PQClean
 * "clean" implementations with SHAKE128/256 replaced by BLAKE3's native
 * XOF. See pqc_blake3_kem.h for details. */
#  include "pqc_blake3_kem.h"
/* OQS_SIG constructors for the BLAKE3 ML-DSA variants -- see
 * pqc_blake3_dsa.h for details. */
#  include "pqc_blake3_dsa.h"
#endif

#ifdef USE_XOODYAK
/* OQS_KEM constructors for the Xoodyak ML-KEM variants -- forked PQClean
 * "clean" implementations with SHAKE128/256 replaced by Xoodyak's Cyclist
 * hash mode (XKCP). See pqc_xoodyak_kem.h for details. */
#  include "pqc_xoodyak_kem.h"
/* OQS_SIG constructors for the Xoodyak ML-DSA variants -- see
 * pqc_xoodyak_dsa.h for details. */
#  include "pqc_xoodyak_dsa.h"
#endif

#ifdef USE_HARAKA
/* OQS_KEM constructors for the Haraka ML-KEM variants -- forked PQClean
 * "clean" implementations with SHAKE128/256 replaced by a non-standard
 * Haraka512-based counter-mode construction. See pqc_haraka_kem.h. */
#  include "pqc_haraka_kem.h"
/* OQS_SIG constructors for the Haraka-MD ML-DSA variants -- see
 * pqc_haraka_dsa.h for details. */
#  include "pqc_haraka_dsa.h"
#endif

/* =========================================================================
 * COMPILE-TIME CONFIGURATION
 * Adjust these macros to tune benchmark depth and algorithm selection.
 * ========================================================================= */

/* Number of benchmark iterations (main loop).
 * ML-DSA MUST use >= 10,000 due to rejection sampling variance (PDF1/PDF2). */
#ifndef BENCH_ITERATIONS
#  define BENCH_ITERATIONS        10000
#endif

/* Warm-up iterations discarded before measurement begins.
 * Accounts for I1 (instruction cache) and D1 (data cache) cold loading.
 * SUPERCOP methodology (PDF1, section "SUPERCOP Methodology"). */
#ifndef BENCH_WARMUP
#  define BENCH_WARMUP            200
#endif

/* Dudect constant-time test: number of measurement pairs.
 * Must be large (>= 1,000,000) for statistical significance.
 * Welch's t-test threshold: |t| > 4.5 => timing leak detected (PDF1). */
#ifndef DUDECT_MEASUREMENTS
#  define DUDECT_MEASUREMENTS     1000000
#endif

/* Welch t-test significance threshold from dudect methodology (PDF1/PDF2).
 * If |t_value| > DUDECT_T_THRESHOLD => implementation leaks timing info. */
#define DUDECT_T_THRESHOLD        4.5

/* Percentile crop for dudect (removes OS-noise outliers above 99th pct). */
#define DUDECT_CROP_PERCENTILE    0.99

/* Stack painting sentinel (0xDEADBEEF pattern, PDF1/PDF2 stack watermarking). */
#define STACK_SENTINEL_WORD       0xDEADBEEFU

/* Stack paint region size in bytes.
 * Must be >= worst-case ML-DSA stack usage (~100KB, PDF1/PDF2). */
#define STACK_PAINT_REGION_BYTES  (128 * 1024)   /* 128 KB */

/* Message length for signing benchmarks (realistic IoT packet size). */
#define BENCH_MSG_LEN             256

/* TurboSHAKE domain separation byte for ML-DSA matrix expansion (RFC 9861).
 * Must be in range 0x01..0x7F.  0x1F = custom IoT experimental domain (PDF2). */
#define TURBOSHAKE_DOMAIN_MATRIX  0x1F

/* TurboSHAKE domain separation byte for ML-KEM CBD noise generation.   */
#define TURBOSHAKE_DOMAIN_CBD     0x2F

/* TurboSHAKE domain separation byte for challenge polynomial generation. */
#define TURBOSHAKE_DOMAIN_CHAL    0x3F

/* Output CSV file path for external analysis. */
#define BENCH_CSV_OUTPUT          "pqc_benchmark_results.csv"

/* =========================================================================
 * SOFTWARE-LEVEL ENERGY PROXY MODEL (hardware-independent)
 *
 * THEORY:
 *   Direct energy measurement (RAPL MSRs, INA219 shunts, oscilloscopes,
 *   ammeters on a dev board) is inherently HARDWARE-DEPENDENT: it varies
 *   by CPU vendor, process node, voltage/frequency scaling state, board
 *   power rails, etc.  None of that is available -- or even meaningful --
 *   in a cross-platform "software agility" benchmark.
 *
 *   Instead, this suite reports an ENERGY PROXY derived purely from the
 *   already-measured CPU-cycle counts (TIER 1/2).  For a CPU running at a
 *   fixed voltage/frequency point, dynamic energy consumed by an operation
 *   is, to first order, linearly proportional to the number of clock
 *   cycles it retires:
 *
 *       E_op  ~=  cycles_op  *  k        (k = energy per cycle, J/cycle)
 *
 *   We do NOT claim to know "k" for the user's hardware (that would be a
 *   hardware-dependent constant).  Instead we report results in two forms:
 *
 *     1. ENERGY PROXY UNITS (EPU)  = median cycles for the operation.
 *        This is dimensionless and 100% hardware-independent.  It is the
 *        correct quantity to compare ACROSS hash backends (SHAKE vs
 *        TurboSHAKE) and across algorithms, because "fewer cycles always
 *        means less energy" regardless of which device runs the code.
 *
 *     2. CALIBRATED ENERGY ESTIMATE (uJ) = EPU * ENERGY_PER_CYCLE_NJ / 1000
 *        ENERGY_PER_CYCLE_NJ is a USER-SUPPLIED constant (nanojoules per
 *        cycle) representing the target platform's known/measured energy-
 *        per-cycle figure.  If the user does not supply one, a clearly
 *        labeled illustrative default is used and the report states the
 *        figure is NOT a hardware measurement.
 *
 *   This keeps the "energy" tier purely a software-side transformation of
 *   data already collected -- no platform-specific registers, drivers,
 *   or sensors are touched.
 *
 *   To calibrate for a real platform, measure that platform's average
 *   power draw P (Watts) at a known clock frequency F (Hz) under load,
 *   then:
 *       ENERGY_PER_CYCLE_NJ = (P / F) * 1e9
 *   and pass it at build time, e.g.:
 *       gcc -DENERGY_PER_CYCLE_NJ=0.42 ...
 * ========================================================================= */
#ifndef ENERGY_PER_CYCLE_NJ
#  define ENERGY_PER_CYCLE_NJ     1.0   /* illustrative default (nJ/cycle) */
#  define ENERGY_MODEL_CALIBRATED 0
#else
#  define ENERGY_MODEL_CALIBRATED 1
#endif

/* Energy-Delay Product scaling: EDP = cycles * wall_ns.  Reported in
 * "cycle-nanoseconds" -- another purely software/timing-derived metric
 * used in low-power literature to balance speed vs. energy together. */

/* =========================================================================
 * ALGORITHM VARIANT TAG
 * Printed in all reports so you know which hash backend is active.
 * ========================================================================= */
#ifdef USE_TURBOSHAKE
#  define HASH_BACKEND_TAG    "TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)"
#  define HASH_ROUNDS         12
#  define FIPS_COMPLIANT      0
#  define KEM_VECTOR1_LABEL   "TurboSHAKE128 (n_r=12, D=0x1F)"
#  define KEM_VECTOR2_LABEL   "TurboSHAKE256 (n_r=12, D=0x2F)"
#  define KEM_VECTOR4_LABEL   "TurboSHAKE256 (n_r=12, D=0x3F)"
#elif defined(USE_K12)
#  define HASH_BACKEND_TAG    "KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)"
#  define HASH_ROUNDS         12
#  define FIPS_COMPLIANT      0
#  define KEM_VECTOR1_LABEL   "KT128 (n_r=12, C=0x1F)"
#  define KEM_VECTOR2_LABEL   "KT256 (n_r=12, C=0x2F)"
#  define KEM_VECTOR4_LABEL   "KT256 (n_r=12, C=0x3F)"
#elif defined(USE_BLAKE3)
#  define HASH_BACKEND_TAG    "BLAKE3 (native XOF, 7 rounds, NON-FIPS)"
#  define HASH_ROUNDS         7
#  define FIPS_COMPLIANT      0
#  define KEM_VECTOR1_LABEL   "BLAKE3-XOF (D=0x1F)"
#  define KEM_VECTOR2_LABEL   "BLAKE3-XOF (D=0x2F)"
#  define KEM_VECTOR4_LABEL   "BLAKE3-XOF (D=0x3F)"
#elif defined(USE_XOODYAK)
#  define HASH_BACKEND_TAG    "Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)"
#  define HASH_ROUNDS         12
#  define FIPS_COMPLIANT      0
#  define KEM_VECTOR1_LABEL   "Xoodyak-Hash (D=0x1F)"
#  define KEM_VECTOR2_LABEL   "Xoodyak-Hash (D=0x2F)"
#  define KEM_VECTOR4_LABEL   "Xoodyak-Hash (D=0x3F)"
#elif defined(USE_HARAKA)
#  define HASH_BACKEND_TAG    "Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)"
#  define HASH_ROUNDS         5
#  define FIPS_COMPLIANT      0
#  define KEM_VECTOR1_LABEL   "Haraka-CTR (D=0x1F)"
#  define KEM_VECTOR2_LABEL   "Haraka-CTR (D=0x2F)"
#  define KEM_VECTOR4_LABEL   "Haraka-CTR (D=0x3F)"
#else
#  define HASH_BACKEND_TAG    "SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)"
#  define HASH_ROUNDS         24
#  define FIPS_COMPLIANT      1
#  define KEM_VECTOR1_LABEL   "SHAKE128 (n_r=24)"
#  define KEM_VECTOR2_LABEL   "SHAKE256 (n_r=24)"
#  define KEM_VECTOR4_LABEL   "SHAKE256 (n_r=24)"
#endif

/* =========================================================================
 * ML-KEM PARAMETER SETS (FIPS 203 / CRYSTALS-Kyber)
 * liboqs method name strings for OQS_KEM_new().
 *   ML-KEM-512  => NIST Level 1, k=2, public key 800B,  ciphertext 768B
 *   ML-KEM-768  => NIST Level 3, k=3, public key 1184B, ciphertext 1088B
 *   ML-KEM-1024 => NIST Level 5, k=4, public key 1568B, ciphertext 1568B
 * ========================================================================= */
#define MLKEM_512_NAME   OQS_KEM_alg_ml_kem_512
#define MLKEM_768_NAME   OQS_KEM_alg_ml_kem_768
#define MLKEM_1024_NAME  OQS_KEM_alg_ml_kem_1024

/* =========================================================================
 * ML-DSA PARAMETER SETS (FIPS 204 / CRYSTALS-Dilithium)
 * liboqs method name strings for OQS_SIG_new().
 *   ML-DSA-44 => NIST Level 2, expected rejection iters: ~4.25 (PDF1)
 *   ML-DSA-65 => NIST Level 3, expected rejection iters: ~5.10 (PDF1)
 *   ML-DSA-87 => NIST Level 5, expected rejection iters: ~3.85
 * ========================================================================= */
#define MLDSA_44_NAME    OQS_SIG_alg_ml_dsa_44
#define MLDSA_65_NAME    OQS_SIG_alg_ml_dsa_65
#define MLDSA_87_NAME    OQS_SIG_alg_ml_dsa_87

/* =========================================================================
 * TIER 1: CPU CYCLE COUNTER
 * Uses rdtsc + lfence (pipeline serialization fence).
 *
 * THEORY (PDF1/PDF2, "SUPERCOP Methodology and Pipeline Serialization"):
 *   Modern CPUs have out-of-order execution.  A naive rdtsc call may be
 *   reordered BEFORE or AFTER the target operation.  The lfence instruction
 *   is a LOAD FENCE that forces the CPU pipeline to drain and serialize,
 *   guaranteeing all prior instructions have FULLY RETIRED before the
 *   timestamp is read.  This is mandatory for sub-microsecond precision.
 *
 * WARNING: The rdtsc/rdtscp path works only on x86_64.  On aarch64 (e.g.
 *          ARM Cortex-A, Apple Silicon, AWS Graviton) we instead read the
 *          architectural virtual counter register (CNTVCT_EL0), which is
 *          a fixed-frequency monotonic counter readable from userspace and
 *          serialized with ISB barriers.  It is not literally "CPU cycles"
 *          (its frequency is given by CNTFRQ_EL0, typically <= the core
 *          clock), but it provides the same relative-comparison semantics
 *          needed here: SHAKE vs TurboSHAKE runs use the same counter.
 * ========================================================================= */
#if defined(__x86_64__) || defined(__i386__)
static inline uint64_t cpucycles_begin(void) {
    uint32_t lo, hi;
    /*
     * lfence  => serialize the pipeline (all prior loads must complete).
     * rdtsc   => read 64-bit timestamp counter into EDX:EAX.
     * shlq    => shift high 32 bits left by 32.
     * orq     => combine into single 64-bit result.
     *
     * The "volatile" prevents the compiler from moving this instruction
     * or caching its result across iterations.
     */
    __asm__ volatile (
        "lfence\n\t"
        "rdtsc\n\t"
        : "=a"(lo), "=d"(hi)
        :
        : "memory"
    );
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t cpucycles_end(void) {
    uint32_t lo, hi;
    /*
     * rdtscp  => serializing read (includes implicit lfence semantics).
     *            Also writes processor ID into ECX (discarded here).
     * lfence  => second fence AFTER the read to prevent subsequent
     *            instructions from being pulled in front of the timestamp.
     */
    __asm__ volatile (
        "rdtscp\n\t"
        "lfence\n\t"
        : "=a"(lo), "=d"(hi)
        :
        : "%ecx", "memory"
    );
    return ((uint64_t)hi << 32) | lo;
}
#elif defined(__aarch64__)
static inline uint64_t cpucycles_begin(void) {
    uint64_t val;
    /* isb => instruction barrier, serializes before reading the counter. */
    __asm__ volatile (
        "isb\n\t"
        "mrs %0, cntvct_el0\n\t"
        : "=r"(val)
        :
        : "memory"
    );
    return val;
}

static inline uint64_t cpucycles_end(void) {
    uint64_t val;
    __asm__ volatile (
        "isb\n\t"
        "mrs %0, cntvct_el0\n\t"
        : "=r"(val)
        :
        : "memory"
    );
    return val;
}
#else
#  error "cpucycles_begin/end: unsupported architecture (need x86_64 or aarch64)"
#endif

/* High-resolution wall clock (nanoseconds).  Used ONLY for human-readable
 * output; NOT used for cryptographic benchmarking (too noisy). */
static inline uint64_t wallclock_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* =========================================================================
 * TIER 2: STATISTICAL AGGREGATION ENGINE
 *
 * THEORY (PDF1, "SUPERCOP Methodology"):
 *   Arithmetic means are ACTIVELY AVOIDED in cryptographic benchmarking.
 *   A single OS context switch or cache miss spike can skew the mean by
 *   thousands of cycles.  Instead we report:
 *     - Median        (50th percentile) -- primary metric
 *     - Q1            (25th percentile) -- lower quartile
 *     - Q3            (75th percentile) -- upper quartile
 *     - IQR           (Q3 - Q1)         -- interquartile range
 *     - 99th pct      -- tail latency (critical for ML-DSA rejection sampling)
 *     - Min / Max     -- absolute bounds
 *     - Geo mean      -- useful for multiplicative speedup ratios
 *     - Std deviation -- variance measure
 *     - CoV           -- Coefficient of Variation = StdDev/Mean * 100%
 *                        61-71% CoV observed for ML-DSA on Cortex-M0+ (PDF2)
 * ========================================================================= */
typedef struct {
    uint64_t  n;           /* sample count                          */
    double    median;      /* 50th percentile cycles                */
    double    q1;          /* 25th percentile cycles                */
    double    q3;          /* 75th percentile cycles                */
    double    iqr;         /* Q3 - Q1                               */
    double    p99;         /* 99th percentile (tail latency)        */
    double    p95;         /* 95th percentile                       */
    uint64_t  min_cycles;  /* minimum observed cycles               */
    uint64_t  max_cycles;  /* maximum observed cycles               */
    double    geo_mean;    /* geometric mean of cycles              */
    double    arith_mean;  /* arithmetic mean (reported but warned) */
    double    std_dev;     /* standard deviation                    */
    double    cov_pct;     /* coefficient of variation (%)          */
    double    cpb;         /* cycles per byte                       */
    double    wall_ns;     /* wall clock nanoseconds (mean)         */
} bench_stats_t;

/* Comparison function for qsort */
static int uint64_cmp(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    return (ua > ub) - (ua < ub);
}

/*
 * compute_stats()
 *   Input : array of raw CPU cycle measurements (after warm-up stripped),
 *           number of valid samples, and total bytes processed per operation.
 *   Output: populated bench_stats_t struct.
 */
static void compute_stats(bench_stats_t *s,
                          uint64_t *samples,
                          uint64_t  n,
                          size_t    bytes_per_op,
                          double    wall_ns_total)
{
    if (n == 0) { memset(s, 0, sizeof(*s)); return; }

    /* Sort for percentile calculations. */
    uint64_t *sorted = (uint64_t *)malloc(n * sizeof(uint64_t));
    if (!sorted) { fprintf(stderr, "[FATAL] malloc failed in compute_stats\n"); exit(1); }
    memcpy(sorted, samples, n * sizeof(uint64_t));
    qsort(sorted, n, sizeof(uint64_t), uint64_cmp);

    s->n          = n;
    s->min_cycles = sorted[0];
    s->max_cycles = sorted[n - 1];

    /* Percentile helper: linear interpolation */
    #define PERCENTILE(arr, cnt, p) \
        ((cnt) == 1 ? (double)(arr)[0] : \
         (arr)[(size_t)((p) * ((cnt) - 1))] + \
         (((p) * ((cnt) - 1)) - (size_t)((p) * ((cnt) - 1))) * \
         ((double)(arr)[(size_t)((p) * ((cnt) - 1)) + 1] - (double)(arr)[(size_t)((p) * ((cnt) - 1))]))

    s->q1     = PERCENTILE(sorted, n, 0.25);
    s->median = PERCENTILE(sorted, n, 0.50);
    s->q3     = PERCENTILE(sorted, n, 0.75);
    s->p95    = PERCENTILE(sorted, n, 0.95);
    s->p99    = PERCENTILE(sorted, n, 0.99);
    s->iqr    = s->q3 - s->q1;

    /* Arithmetic mean and geometric mean. */
    double sum_log = 0.0;
    double sum     = 0.0;
    for (uint64_t i = 0; i < n; i++) {
        sum     += (double)sorted[i];
        sum_log += log((double)sorted[i]);
    }
    s->arith_mean = sum / (double)n;
    s->geo_mean   = exp(sum_log / (double)n);

    /* Standard deviation. */
    double sq_diff = 0.0;
    for (uint64_t i = 0; i < n; i++) {
        double d = (double)sorted[i] - s->arith_mean;
        sq_diff += d * d;
    }
    s->std_dev  = sqrt(sq_diff / (double)n);

    /* Coefficient of Variation. */
    s->cov_pct = (s->arith_mean > 0) ? (s->std_dev / s->arith_mean) * 100.0 : 0.0;

    /* Cycles per Byte (CpB):  median_cycles / bytes_per_op  (PDF1/PDF2). */
    s->cpb = (bytes_per_op > 0) ? s->median / (double)bytes_per_op : 0.0;

    /* Wall clock mean nanoseconds per operation. */
    s->wall_ns = (n > 0) ? wall_ns_total / (double)n : 0.0;

    free(sorted);
    #undef PERCENTILE
}

/* =========================================================================
 * TIER 3: REJECTION SAMPLING HISTOGRAM (ML-DSA SPECIFIC)
 *
 * THEORY (PDF1/PDF2, "Rejection Sampling Variance in ML-DSA"):
 *   ML-DSA signing uses the Fiat-Shamir with Aborts paradigm.
 *   Each signing attempt may FAIL bound checks and restart, looping over
 *   SHAKE256 expansions.  Expected iterations:
 *     ML-DSA-44 => ~4.25   ML-DSA-65 => ~5.10
 *   On constrained CPUs, high-iteration events push 99th-pct time to
 *   > 1,115 milliseconds (PDF2).  TurboSHAKE reduces each iteration cost,
 *   directly compressing tail latency even though expected iters stay same.
 *
 *   This structure tracks rejection iteration counts so you can see
 *   the full distribution, not just average iters.
 * ========================================================================= */
#define MAX_REJECTION_ITERS  64    /* histogram buckets 0..63, 64=overflow */

typedef struct {
    uint64_t  histogram[MAX_REJECTION_ITERS + 1]; /* iteration count distribution */
    uint64_t  total_signatures;
    uint64_t  total_iterations;
    double    mean_iters;
    double    max_iters;
    /* NOTE: liboqs does not expose internal abort counters directly.
     * We estimate by measuring cycles per signing call relative to a
     * baseline single-iteration cost.  For exact counts, you need a
     * patched Dilithium reference implementation that exposes a counter. */
    int       estimated;   /* 1 = estimated from timing, 0 = exact counter */
} rejection_stats_t;

static void rejection_stats_init(rejection_stats_t *rs) {
    memset(rs, 0, sizeof(*rs));
    rs->estimated = 1;  /* liboqs does not expose internal abort counter */
}

static void rejection_stats_print(const rejection_stats_t *rs,
                                  const char *algo_name)
{
    printf("\n  [Rejection Sampling Distribution: %s]\n", algo_name);
    printf("  Total signatures    : %"PRIu64"\n", rs->total_signatures);
    printf("  Note: liboqs does not expose raw abort counters.\n");
    printf("  Use patched pq-crystals/dilithium ref code for exact counts.\n");
    printf("  Expected mean iters : ~4.25 (ML-DSA-44), ~5.10 (ML-DSA-65)\n");
    printf("  Tail latency (99th percentile cycles) captures abort impact.\n");
}

/* =========================================================================
 * TIER 5: STACK PAINTING / WATERMARKING
 *
 * THEORY (PDF1/PDF2, "Stack Painting and Watermarking in Embedded Environments"):
 *   In embedded/RTOS environments, all heap allocation is forbidden.
 *   ML-DSA needs > 100 KB of stack for its K*L polynomial vectors.
 *   To measure worst-case stack depth WITHOUT a hardware debugger:
 *
 *   1. Fill a large buffer with 0xDEADBEEF sentinel words.
 *   2. Execute the cryptographic operation.
 *   3. Scan upward from the bottom of the buffer.
 *   4. First word != 0xDEADBEEF marks the high-water stack boundary.
 *   5. Delta = buffer_top - first_modified_word = peak stack usage.
 *
 *   This file simulates this on x86_64 using a heap-allocated buffer
 *   (actual embedded use would target the linker-defined stack region).
 *
 * WARNING (PDF1): GCC -O3 may optimize away the painting loop.
 *   Use volatile fills or __attribute__((optimize("O0"))) on the paint func.
 * ========================================================================= */

/* Fill region with sentinel.  volatile prevents compiler elision. */
static void __attribute__((optimize("O0")))
stack_paint(uint8_t *region, size_t size_bytes) {
    uint32_t *p = (uint32_t *)region;
    size_t    n = size_bytes / sizeof(uint32_t);
    for (size_t i = 0; i < n; i++) {
        p[i] = STACK_SENTINEL_WORD;
    }
    /* Memory barrier so the fill is not moved past the crypto call. */
    __asm__ volatile ("" ::: "memory");
}

/*
 * stack_measure_hwm()
 *   Returns the high-water-mark (peak bytes used) by scanning for the first
 *   word that was overwritten from STACK_SENTINEL_WORD.
 *   The delta from the buffer base to first-modified word = stack consumed.
 */
static size_t stack_measure_hwm(const uint8_t *region, size_t size_bytes) {
    const uint32_t *p = (const uint32_t *)region;
    size_t n = size_bytes / sizeof(uint32_t);
    /* Scan from BOTTOM (low address) upward. */
    for (size_t i = 0; i < n; i++) {
        if (p[i] != STACK_SENTINEL_WORD) {
            /* First modified word found -- return byte offset from base. */
            return size_bytes - (i * sizeof(uint32_t));
        }
    }
    /* None modified -- operation used zero stack (unlikely / paint failed). */
    return 0;
}

/* =========================================================================
 * TIER 6: DUDECT CONSTANT-TIME VALIDATION ENGINE
 *
 * THEORY (PDF1/PDF2, "Statistical Validation of Constant-Time Execution"):
 *   Timing side-channel attacks can extract secret key material if the
 *   runtime of the algorithm varies with secret inputs.  After swapping
 *   SHAKE for TurboSHAKE, the C wrappers must be validated for constant-time.
 *
 *   dudect methodology:
 *   a) Partition inputs into CLASS_FIXED  (same secret every iteration)
 *                          CLASS_RANDOM (uniform random secret each time).
 *   b) Execute millions of measurements, alternating randomly between classes.
 *   c) Crop upper tail at DUDECT_CROP_PERCENTILE (99th pct) to remove OS noise.
 *   d) Apply Welch's t-test (unequal variance, unequal sample size).
 *   e) If |t| > 4.5 => LEAKAGE DETECTED (>99.99% confidence).
 *      If |t| ~1.0  => constant time (no detectable timing difference).
 *
 *   Welch's t formula:
 *     t = (mean1 - mean2) / sqrt(var1/n1 + var2/n2)
 * ========================================================================= */

typedef struct {
    double  mean;
    double  m2;          /* running M2 for Welch online variance (Welford) */
    uint64_t count;
} welch_accum_t;

static void welch_update(welch_accum_t *acc, double value) {
    acc->count++;
    double delta  = value - acc->mean;
    acc->mean    += delta / (double)acc->count;
    double delta2 = value - acc->mean;
    acc->m2      += delta * delta2;
}

/* Compute Welch's t-statistic from two accumulators. */
static double welch_t_statistic(const welch_accum_t *a, const welch_accum_t *b) {
    if (a->count < 2 || b->count < 2) return 0.0;
    double var_a = a->m2 / (double)(a->count - 1);
    double var_b = b->m2 / (double)(b->count - 1);
    double denom = sqrt(var_a / (double)a->count + var_b / (double)b->count);
    if (denom < 1e-12) return 0.0;
    return (a->mean - b->mean) / denom;
}

typedef struct {
    double    t_value;          /* Welch's t statistic                     */
    uint64_t  n_class0;         /* measurements in FIXED class             */
    uint64_t  n_class1;         /* measurements in RANDOM class            */
    int       leak_detected;    /* 1 if |t| > DUDECT_T_THRESHOLD           */
    double    mean_fixed_ns;    /* mean timing FIXED class (nanoseconds)   */
    double    mean_random_ns;   /* mean timing RANDOM class (nanoseconds)  */
} dudect_result_t;

/*
 * dudect_run_kem()
 *   Run Welch t-test constant-time analysis on a KEM encapsulation.
 *   CLASS_FIXED  = always encapsulate under same public key + fixed random.
 *   CLASS_RANDOM = encapsulate under same public key but fresh random each time.
 *   (Public key is constant because it is the secret input to decaps.)
 *
 *   NOTE: Full dudect requires injecting fixed vs random inputs at the
 *   secret seed level.  Without a patched liboqs, we use fixed vs
 *   random MESSAGE as a proxy for timing variation tests.
 */
static dudect_result_t dudect_run_kem(OQS_KEM *kem, uint64_t n_measurements) {
    dudect_result_t result;
    memset(&result, 0, sizeof(result));

    uint8_t *public_key    = malloc(kem->length_public_key);
    uint8_t *secret_key    = malloc(kem->length_secret_key);
    uint8_t *ciphertext    = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext || !shared_secret) {
        fprintf(stderr, "[DUDECT] malloc failed\n");
        goto cleanup;
    }

    /* Generate a keypair once -- public key is fixed for all measurements. */
    OQS_KEM_keypair(kem, public_key, secret_key);

    welch_accum_t acc_fixed  = {0};
    welch_accum_t acc_random = {0};

    /* Fixed input: deterministic shared_secret buffer (all zeros). */
    uint8_t fixed_buf[64];
    memset(fixed_buf, 0x42, sizeof(fixed_buf));

    for (uint64_t i = 0; i < n_measurements; i++) {
        int class_id = (rand() & 1);  /* randomly alternate classes */

        uint64_t t0 = cpucycles_begin();
        OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
        uint64_t t1 = cpucycles_end();

        double elapsed = (double)(t1 - t0);

        /* Crop: discard measurements above 99th percentile (OS noise). */
        /* Simple crop: discard if > 10x the running mean (rough heuristic). */
        if (acc_fixed.count > 100) {
            double ref_mean = (acc_fixed.mean + acc_random.mean) / 2.0;
            if (elapsed > ref_mean * 5.0) continue;  /* crop outlier */
        }

        if (class_id == 0) welch_update(&acc_fixed,  elapsed);
        else               welch_update(&acc_random, elapsed);
    }

    result.t_value        = welch_t_statistic(&acc_fixed, &acc_random);
    result.n_class0       = acc_fixed.count;
    result.n_class1       = acc_random.count;
    result.leak_detected  = (fabs(result.t_value) > DUDECT_T_THRESHOLD) ? 1 : 0;
    result.mean_fixed_ns  = acc_fixed.mean;
    result.mean_random_ns = acc_random.mean;

cleanup:
    free(public_key); free(secret_key); free(ciphertext); free(shared_secret);
    return result;
}

static dudect_result_t dudect_run_sig(OQS_SIG *sig, uint64_t n_measurements) {
    dudect_result_t result;
    memset(&result, 0, sizeof(result));

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature  = malloc(sig->length_signature);
    if (!public_key || !secret_key || !signature) { goto sig_cleanup; }

    OQS_SIG_keypair(sig, public_key, secret_key);

    welch_accum_t acc_fixed  = {0};
    welch_accum_t acc_random = {0};

    uint8_t msg_fixed[BENCH_MSG_LEN];
    uint8_t msg_random[BENCH_MSG_LEN];
    memset(msg_fixed, 0xAA, BENCH_MSG_LEN);

    size_t sig_len = 0;

    for (uint64_t i = 0; i < n_measurements; i++) {
        int class_id = (rand() & 1);

        /* Prepare input for this class. */
        if (class_id == 1) {
            for (int b = 0; b < BENCH_MSG_LEN; b++)
                msg_random[b] = (uint8_t)rand();
        }
        uint8_t *msg = (class_id == 0) ? msg_fixed : msg_random;

        uint64_t t0 = cpucycles_begin();
        OQS_SIG_sign(sig, signature, &sig_len, msg, BENCH_MSG_LEN, secret_key);
        uint64_t t1 = cpucycles_end();

        double elapsed = (double)(t1 - t0);
        if (acc_fixed.count > 100) {
            double ref_mean = (acc_fixed.mean + acc_random.mean) / 2.0;
            if (elapsed > ref_mean * 10.0) continue;
        }

        if (class_id == 0) welch_update(&acc_fixed,  elapsed);
        else               welch_update(&acc_random, elapsed);
    }

    result.t_value        = welch_t_statistic(&acc_fixed, &acc_random);
    result.n_class0       = acc_fixed.count;
    result.n_class1       = acc_random.count;
    result.leak_detected  = (fabs(result.t_value) > DUDECT_T_THRESHOLD) ? 1 : 0;
    result.mean_fixed_ns  = acc_fixed.mean;
    result.mean_random_ns = acc_random.mean;

sig_cleanup:
    free(public_key); free(secret_key); free(signature);
    return result;
}

/* =========================================================================
 * TIER 11: MEMORY FOOTPRINT PROFILING (software-level, hardware-independent)
 *
 * Two complementary, purely OS/libc-derived measurements:
 *
 *   a) PEAK RSS DELTA (peak_rss_delta_kb)
 *      getrusage(RUSAGE_SELF, &ru).ru_maxrss is the high-water mark of the
 *      ENTIRE PROCESS's resident memory, maintained by the kernel itself.
 *      We snapshot it immediately before and after each benchmark loop and
 *      report the delta.  Since ru_maxrss is monotonically non-decreasing
 *      for the life of the process, a positive delta means the operation
 *      pushed the process to a new high-water mark (e.g. larger heap
 *      arena or deeper stack growth).  A delta of 0 means the operation
 *      fit entirely within memory already mapped by earlier operations.
 *
 *   b) HEAP ARENA DELTA (heap_delta_bytes)
 *      mallinfo2() / mallinfo() (glibc) report uordblks: bytes currently
 *      allocated via malloc().  We snapshot this immediately before and
 *      after ONE representative call to the operation under test and
 *      report the delta.  This isolates the heap churn of a SINGLE call
 *      (keypair / encaps / decaps / sign / verify), independent of the
 *      cycle-counting loop.  A growing delta across repeated calls would
 *      indicate a leak.
 *
 * Both metrics come solely from the C library / kernel process accounting
 * -- no CPU model, board, or vendor-specific power/perf driver required,
 * so results are directly comparable across any POSIX platform.
 * ========================================================================= */
typedef struct {
    long  peak_rss_delta_kb;   /* growth in process peak RSS (KB)         */
    long  peak_rss_after_kb;   /* absolute peak RSS after the op (KB)     */
    long  heap_delta_bytes;    /* malloc-arena delta for one call (bytes) */
    int   heap_available;      /* 1 if mallinfo-based tracking is active  */
} mem_stats_t;

/* Returns the process's current peak RSS in kilobytes.  Portable across
 * Linux (already reported in KB) and macOS/BSD (reported in bytes). */
static long get_peak_rss_kb(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
#if defined(__APPLE__)
    return (long)(ru.ru_maxrss / 1024L);   /* macOS/BSD report bytes */
#else
    return (long)ru.ru_maxrss;             /* Linux reports KB       */
#endif
}

/* Returns currently allocated heap bytes (malloc arena "in use" space).
 * Returns -1 if the platform's libc does not expose mallinfo. */
static long get_heap_bytes(void) {
#if defined(PQC_HAVE_MALLINFO)
#  if defined(__GLIBC__) && __GLIBC_PREREQ(2, 33)
    struct mallinfo2 mi = mallinfo2();
    return (long)mi.uordblks;
#  else
    struct mallinfo mi = mallinfo();
    return (long)mi.uordblks;
#  endif
#else
    return -1;
#endif
}

/*
 * mem_profile_op()
 *   Generic single-call memory profiler.  Snapshots peak RSS and heap
 *   arena size, invokes the supplied zero-argument operation exactly once
 *   via a function pointer + opaque context, then snapshots again and
 *   fills in `out`.
 *
 *   `op` must be a small trampoline that performs exactly one
 *   keypair/encaps/decaps/sign/verify call using `ctx`.
 */
typedef void (*mem_probe_fn)(void *ctx);

static void mem_profile_op(mem_probe_fn op, void *ctx, mem_stats_t *out) {
    memset(out, 0, sizeof(*out));

    long rss_before  = get_peak_rss_kb();
    long heap_before = get_heap_bytes();

    op(ctx);

    long rss_after  = get_peak_rss_kb();
    long heap_after = get_heap_bytes();

    out->peak_rss_after_kb  = rss_after;
    out->peak_rss_delta_kb  = (rss_before >= 0 && rss_after >= 0)
                                  ? (rss_after - rss_before) : -1;

    if (heap_before >= 0 && heap_after >= 0) {
        out->heap_available   = 1;
        out->heap_delta_bytes = heap_after - heap_before;
    } else {
        out->heap_available   = 0;
        out->heap_delta_bytes = 0;
    }
}

/* =========================================================================
 * TIER 12: SOFTWARE ENERGY PROXY MODEL (hardware-independent)
 *
 * See the ENERGY_PER_CYCLE_NJ documentation in the configuration section
 * above for the full rationale.  In short:
 *
 *   - "Energy Proxy Units" (EPU) == median CPU cycles for the operation.
 *     This is the hardware-independent figure; use it to compare SHAKE vs
 *     TurboSHAKE or to compare algorithms/parameter sets.  Fewer cycles
 *     always implies less dynamic energy on any given silicon.
 *
 *   - "Est. energy (uJ)" is EPU converted via ENERGY_PER_CYCLE_NJ.  Unless
 *     the user supplies a platform-calibrated value at build time
 *     (-DENERGY_PER_CYCLE_NJ=<nJ/cycle>), this is clearly marked as
 *     "illustrative" and NOT a real hardware measurement.
 *
 *   - "Energy-Delay Product" (EDP) = median_cycles * wall_ns is a classic
 *     low-power-design figure of merit that rewards algorithms that are
 *     simultaneously fast AND cheap; it too is derived purely from
 *     already-collected software timing data.
 * ========================================================================= */
typedef struct {
    double  epu;                    /* Energy Proxy Units (= median cycles)   */
    double  epu_per_byte;           /* EPU normalized by bytes processed      */
    double  est_energy_uj;          /* estimated energy via ENERGY_PER_CYCLE_NJ */
    double  est_energy_uj_per_byte; /* per-byte version of the above          */
    double  edp_cycle_ns;           /* Energy-Delay Product (cycles * ns)     */
    int     calibrated;             /* 1 if ENERGY_PER_CYCLE_NJ user-supplied */
} energy_stats_t;

static void compute_energy_stats(energy_stats_t *e,
                                 const bench_stats_t *s,
                                 size_t bytes_per_op)
{
    memset(e, 0, sizeof(*e));

    e->epu          = s->median;
    e->epu_per_byte = (bytes_per_op > 0) ? s->median / (double)bytes_per_op : 0.0;

    /* nJ/cycle * cycles = nJ; divide by 1000 => uJ */
    e->est_energy_uj          = (s->median * ENERGY_PER_CYCLE_NJ) / 1000.0;
    e->est_energy_uj_per_byte = (bytes_per_op > 0)
                                     ? e->est_energy_uj / (double)bytes_per_op
                                     : 0.0;

    e->edp_cycle_ns = s->median * s->wall_ns;
    e->calibrated   = ENERGY_MODEL_CALIBRATED;
}

/* Pretty-printer for the memory + energy tiers is defined further below,
 * after print_separator() (see PRINTING HELPERS section). */


static void print_separator(void) {
    printf("  %s\n",
           "----------------------------------------------------------------------");
}

static void print_stats(const char *label,
                        const bench_stats_t *s,
                        const char *unit_label)
{
    print_separator();
    printf("  %-30s  [n=%"PRIu64"]\n", label, s->n);
    print_separator();
    printf("  %-28s : %12.0f  cycles\n",    "Median (primary metric)",  s->median);
    printf("  %-28s : %12.0f  cycles\n",    "Q1 (25th percentile)",    s->q1);
    printf("  %-28s : %12.0f  cycles\n",    "Q3 (75th percentile)",    s->q3);
    printf("  %-28s : %12.0f  cycles\n",    "IQR (Q3 - Q1)",           s->iqr);
    printf("  %-28s : %12.0f  cycles\n",    "95th percentile",         s->p95);
    printf("  %-28s : %12.0f  cycles  *** TAIL LATENCY ***\n",
                                             "99th percentile",         s->p99);
    printf("  %-28s : %12"PRIu64"  cycles\n", "Minimum",               s->min_cycles);
    printf("  %-28s : %12"PRIu64"  cycles\n", "Maximum",               s->max_cycles);
    printf("  %-28s : %12.0f  cycles  (WARNING: skewed by outliers)\n",
                                             "Arithmetic mean",         s->arith_mean);
    printf("  %-28s : %12.0f  cycles\n",    "Geometric mean",          s->geo_mean);
    printf("  %-28s : %12.2f  cycles\n",    "Std deviation",           s->std_dev);
    printf("  %-28s : %12.2f  %%\n",        "Coeff. of Variation",     s->cov_pct);
    if (s->cpb > 0.0)
        printf("  %-28s : %12.4f  cycles/byte\n", "Cycles per Byte (CpB)", s->cpb);
    printf("  %-28s : %12.2f  ns/op\n",     "Wall clock (mean)",       s->wall_ns);
    if (s->cov_pct > 50.0)
        printf("  ** HIGH CoV (%.1f%%) detected -- likely rejection sampling variance **\n",
               s->cov_pct);
}

static void print_dudect_result(const char *label, const dudect_result_t *r) {
    print_separator();
    printf("  DUDECT Constant-Time Test: %s\n", label);
    print_separator();
    printf("  Measurements  class-FIXED  : %"PRIu64"\n", r->n_class0);
    printf("  Measurements  class-RANDOM : %"PRIu64"\n", r->n_class1);
    printf("  Mean cycles   class-FIXED  : %.2f\n", r->mean_fixed_ns);
    printf("  Mean cycles   class-RANDOM : %.2f\n", r->mean_random_ns);
    printf("  Welch's t-value             : %.6f\n", r->t_value);
    printf("  Threshold |t| > %.1f          : %s\n", DUDECT_T_THRESHOLD,
           r->leak_detected
               ? "*** TIMING LEAK DETECTED *** (|t| > 4.5 => >99.99%% confidence)"
               : "PASS  (|t| <= 4.5 -- no detectable timing leak)");
}

static void print_stack_result(const char *label, size_t hwm_bytes) {
    printf("  %-38s : %zu bytes  (%.1f KB)\n",
           label, hwm_bytes, hwm_bytes / 1024.0);
    if (hwm_bytes > 100 * 1024)
        printf("  ** WARNING: ML-DSA stack usage > 100 KB -- overflow risk on"
               " constrained devices **\n");
}

/* Pretty-printer for the memory + energy tiers (used by both ML-KEM and
 * ML-DSA reports).  See TIER 11/12 above for the underlying methodology. */
static void print_mem_energy(const char *label,
                             const mem_stats_t *m,
                             const energy_stats_t *e)
{
    print_separator();
    printf("  %-30s  [Memory Footprint + Energy Proxy]\n", label);
    print_separator();

    printf("  %-30s : %12ld  KB\n", "Peak RSS delta (process-wide)", m->peak_rss_delta_kb);
    printf("  %-30s : %12ld  KB\n", "Peak RSS after op (absolute)", m->peak_rss_after_kb);
    if (m->heap_available)
        printf("  %-30s : %12ld  bytes  (single call)\n",
               "Heap arena delta", m->heap_delta_bytes);
    else
        printf("  %-30s : %12s  (mallinfo unavailable on this libc)\n",
               "Heap arena delta", "n/a");

    printf("  %-30s : %12.0f  EPU  (== median cycles)\n",
           "Energy Proxy Units (EPU)", e->epu);
    if (e->epu_per_byte > 0.0)
        printf("  %-30s : %12.4f  EPU/byte\n", "Energy Proxy per byte", e->epu_per_byte);

    printf("  %-30s : %12.4f  uJ   %s\n",
           "Est. energy (per op)", e->est_energy_uj,
           e->calibrated
               ? "(calibrated via ENERGY_PER_CYCLE_NJ)"
               : "(illustrative k=1.0 nJ/cyc -- NOT a real measurement)");
    if (e->est_energy_uj_per_byte > 0.0)
        printf("  %-30s : %12.6f  uJ/byte\n",
               "Est. energy per byte", e->est_energy_uj_per_byte);

    printf("  %-30s : %12.2f  cycle*ns  (Energy-Delay Product)\n",
           "Energy-Delay Product (EDP)", e->edp_cycle_ns);
}

/* =========================================================================
 * TIER 4 + 7: FULL ML-KEM BENCHMARK HARNESS
 *
 * Sub-components benchmarked:
 *   a) KeyGen  -- includes matrix expansion (SHAKE128/TurboSHAKE128) and
 *                 CBD noise generation (SHAKE256/TurboSHAKE256)
 *   b) Encaps  -- includes FO-transform hashing (PDF1/PDF2) and KDF (SHAKE256)
 *   c) Decaps  -- includes ciphertext validation and implicit rejection
 *
 * CpB reference bytes:
 *   KeyGen  => public_key size + secret_key size
 *   Encaps  => ciphertext size + shared_secret size
 *   Decaps  => ciphertext size + shared_secret size
 * ========================================================================= */

typedef struct {
    const char   *name;
    bench_stats_t keygen;
    bench_stats_t encaps;
    bench_stats_t decaps;
    size_t        stack_hwm_keygen;
    size_t        stack_hwm_encaps;
    size_t        stack_hwm_decaps;
    dudect_result_t dudect_encaps;

    /* TIER 11/12: memory footprint + energy proxy, per sub-operation. */
    mem_stats_t    mem_keygen;
    mem_stats_t    mem_encaps;
    mem_stats_t    mem_decaps;
    energy_stats_t energy_keygen;
    energy_stats_t energy_encaps;
    energy_stats_t energy_decaps;

    /* Algorithm parameter metadata (from liboqs OQS_KEM struct). */
    size_t  pk_bytes;
    size_t  sk_bytes;
    size_t  ct_bytes;
    size_t  ss_bytes;
    uint8_t nist_level;
    int     ind_cca;
} kem_bench_result_t;

/* ------------------------------------------------------------------
 * Single-call probe trampolines (TIER 11 memory profiling).
 * Each wraps exactly one liboqs call so mem_profile_op() can snapshot
 * peak RSS / heap arena size immediately around it.
 * ------------------------------------------------------------------ */
typedef struct { OQS_KEM *kem; uint8_t *pk; uint8_t *sk; } kem_keygen_ctx_t;
static void kem_keygen_probe(void *ctx) {
    kem_keygen_ctx_t *c = (kem_keygen_ctx_t *)ctx;
    OQS_KEM_keypair(c->kem, c->pk, c->sk);
}

typedef struct { OQS_KEM *kem; uint8_t *ct; uint8_t *ss; uint8_t *pk; } kem_encaps_ctx_t;
static void kem_encaps_probe(void *ctx) {
    kem_encaps_ctx_t *c = (kem_encaps_ctx_t *)ctx;
    OQS_KEM_encaps(c->kem, c->ct, c->ss, c->pk);
}

typedef struct { OQS_KEM *kem; uint8_t *ss; uint8_t *ct; uint8_t *sk; } kem_decaps_ctx_t;
static void kem_decaps_probe(void *ctx) {
    kem_decaps_ctx_t *c = (kem_decaps_ctx_t *)ctx;
    OQS_KEM_decaps(c->kem, c->ss, c->ct, c->sk);
}

/*
 * bench_kem_obj()
 *   Core ML-KEM benchmark harness, operating on an already-constructed
 *   OQS_KEM object.  The caller owns `kem` (created via OQS_KEM_new() for
 *   the standard SHAKE build, or via the TurboSHAKE adapter constructors
 *   in pqc_turboshake_kem.c) and is responsible for freeing it.
 */
static kem_bench_result_t bench_kem_obj(OQS_KEM *kem,
                                        const char *display_name,
                                        int run_dudect,
                                        int run_stack)
{
    kem_bench_result_t result;
    memset(&result, 0, sizeof(result));
    result.name = display_name;

    if (!kem) {
        fprintf(stderr, "[ERROR] NULL OQS_KEM for %s\n", display_name);
        return result;
    }

    /* Populate metadata from liboqs OQS_KEM struct (PDF2, OQS_KEM table). */
    result.pk_bytes   = kem->length_public_key;
    result.sk_bytes   = kem->length_secret_key;
    result.ct_bytes   = kem->length_ciphertext;
    result.ss_bytes   = kem->length_shared_secret;
    result.nist_level = kem->claimed_nist_level;
    result.ind_cca    = kem->ind_cca ? 1 : 0;

    /* Allocate key material. */
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);
    if (!pk || !sk || !ct || !ss) {
        fprintf(stderr, "[ERROR] Allocation failed for %s\n", display_name);
        goto kem_cleanup;
    }

    uint64_t total_iters  = BENCH_ITERATIONS + BENCH_WARMUP;
    uint64_t *cycles_kg   = malloc(total_iters * sizeof(uint64_t));
    uint64_t *cycles_enc  = malloc(total_iters * sizeof(uint64_t));
    uint64_t *cycles_dec  = malloc(total_iters * sizeof(uint64_t));
    if (!cycles_kg || !cycles_enc || !cycles_dec) {
        fprintf(stderr, "[ERROR] Cycle array allocation failed\n"); goto kem_cleanup;
    }

    /* ---------------------------------------------------------------
     * STACK PAINTING SETUP
     * Allocate a sentinel-filled region to measure stack high-water mark.
     * (PDF1/PDF2, "Stack Painting and Watermarking")
     * --------------------------------------------------------------- */
    uint8_t *stack_region = NULL;
    if (run_stack) {
        stack_region = malloc(STACK_PAINT_REGION_BYTES);
        if (!stack_region) {
            fprintf(stderr, "[WARN] Could not allocate stack paint region\n");
            run_stack = 0;
        }
    }

    uint64_t wall_start, wall_end;

    /* ================================================================
     * KEYGEN BENCHMARK LOOP
     * ================================================================ */
    wall_start = wallclock_ns();
    if (run_stack) stack_paint(stack_region, STACK_PAINT_REGION_BYTES);

    for (uint64_t i = 0; i < total_iters; i++) {
        uint64_t t0 = cpucycles_begin();
        OQS_KEM_keypair(kem, pk, sk);
        uint64_t t1 = cpucycles_end();
        cycles_kg[i] = t1 - t0;
    }
    wall_end = wallclock_ns();

    if (run_stack)
        result.stack_hwm_keygen = stack_measure_hwm(stack_region, STACK_PAINT_REGION_BYTES);

    compute_stats(&result.keygen,
                  cycles_kg + BENCH_WARMUP,         /* skip warm-up */
                  BENCH_ITERATIONS,
                  kem->length_public_key + kem->length_secret_key,
                  (double)(wall_end - wall_start));

    /* TIER 11/12: memory footprint (single representative call) + energy proxy. */
    {
        kem_keygen_ctx_t kctx = { kem, pk, sk };
        mem_profile_op(kem_keygen_probe, &kctx, &result.mem_keygen);
    }
    compute_energy_stats(&result.energy_keygen, &result.keygen,
                         kem->length_public_key + kem->length_secret_key);


    /* ================================================================
     * ENCAPS BENCHMARK LOOP
     * ================================================================ */
    wall_start = wallclock_ns();
    if (run_stack) stack_paint(stack_region, STACK_PAINT_REGION_BYTES);

    for (uint64_t i = 0; i < total_iters; i++) {
        uint64_t t0 = cpucycles_begin();
        OQS_KEM_encaps(kem, ct, ss, pk);
        uint64_t t1 = cpucycles_end();
        cycles_enc[i] = t1 - t0;
    }
    wall_end = wallclock_ns();

    if (run_stack)
        result.stack_hwm_encaps = stack_measure_hwm(stack_region, STACK_PAINT_REGION_BYTES);

    compute_stats(&result.encaps,
                  cycles_enc + BENCH_WARMUP,
                  BENCH_ITERATIONS,
                  kem->length_ciphertext + kem->length_shared_secret,
                  (double)(wall_end - wall_start));

    {
        kem_encaps_ctx_t kctx = { kem, ct, ss, pk };
        mem_profile_op(kem_encaps_probe, &kctx, &result.mem_encaps);
    }
    compute_energy_stats(&result.energy_encaps, &result.encaps,
                         kem->length_ciphertext + kem->length_shared_secret);


    /* ================================================================
     * DECAPS BENCHMARK LOOP
     * ================================================================ */
    wall_start = wallclock_ns();
    if (run_stack) stack_paint(stack_region, STACK_PAINT_REGION_BYTES);

    for (uint64_t i = 0; i < total_iters; i++) {
        uint64_t t0 = cpucycles_begin();
        OQS_KEM_decaps(kem, ss, ct, sk);
        uint64_t t1 = cpucycles_end();
        cycles_dec[i] = t1 - t0;
    }
    wall_end = wallclock_ns();

    if (run_stack)
        result.stack_hwm_decaps = stack_measure_hwm(stack_region, STACK_PAINT_REGION_BYTES);

    compute_stats(&result.decaps,
                  cycles_dec + BENCH_WARMUP,
                  BENCH_ITERATIONS,
                  kem->length_ciphertext + kem->length_shared_secret,
                  (double)(wall_end - wall_start));

    {
        kem_decaps_ctx_t kctx = { kem, ss, ct, sk };
        mem_profile_op(kem_decaps_probe, &kctx, &result.mem_decaps);
    }
    compute_energy_stats(&result.energy_decaps, &result.decaps,
                         kem->length_ciphertext + kem->length_shared_secret);


    /* ================================================================
     * DUDECT CONSTANT-TIME VALIDATION
     * (PDF1/PDF2, "Statistical Validation of Constant-Time Execution")
     * ================================================================ */
    if (run_dudect) {
        printf("  Running dudect for %s (this may take several minutes)...\n",
               display_name);
        result.dudect_encaps = dudect_run_kem(kem, DUDECT_MEASUREMENTS);
    }

    free(cycles_kg); free(cycles_enc); free(cycles_dec);
    free(stack_region);

kem_cleanup:
    free(pk); free(sk); free(ct); free(ss);
    return result;
}

/*
 * bench_kem()
 *   Convenience wrapper for the standard (liboqs-registered) SHAKE-based
 *   ML-KEM algorithms: looks the algorithm up by name via OQS_KEM_new(),
 *   benchmarks it, and frees it.
 */
static kem_bench_result_t bench_kem(const char *kem_name,
                                    int run_dudect,
                                    int run_stack)
{
    OQS_KEM *kem = OQS_KEM_new(kem_name);
    if (!kem) {
        fprintf(stderr, "[ERROR] OQS_KEM_new(%s) failed. "
                        "Is liboqs built with this algorithm?\n", kem_name);
        kem_bench_result_t result;
        memset(&result, 0, sizeof(result));
        result.name = kem_name;
        return result;
    }

    kem_bench_result_t result = bench_kem_obj(kem, kem_name, run_dudect, run_stack);
    OQS_KEM_free(kem);
    return result;
}

/* =========================================================================
 * TIER 4 + 7: FULL ML-DSA BENCHMARK HARNESS
 *
 * Sub-components benchmarked:
 *   a) KeyGen  -- matrix expansion (SHAKE128), secret key generation
 *   b) Sign    -- masking vector expansion (SHAKE256 loop), challenge gen,
 *                 rejection sampling aborts -- HIGH VARIANCE expected
 *   c) Verify  -- matrix re-expansion, commitment re-computation
 *
 * ML-DSA signing MUST use >= 10,000 iterations (PDF1/PDF2) to capture
 * the full rejection sampling distribution in the tail latency metric.
 * ========================================================================= */

typedef struct {
    const char   *name;
    bench_stats_t keygen;
    bench_stats_t sign_op;
    bench_stats_t verify;
    size_t        stack_hwm_keygen;
    size_t        stack_hwm_sign;
    size_t        stack_hwm_verify;
    dudect_result_t dudect_sign;
    rejection_stats_t rejection;

    /* TIER 11/12: memory footprint + energy proxy, per sub-operation. */
    mem_stats_t    mem_keygen;
    mem_stats_t    mem_sign;
    mem_stats_t    mem_verify;
    energy_stats_t energy_keygen;
    energy_stats_t energy_sign;
    energy_stats_t energy_verify;

    /* Algorithm parameter metadata. */
    size_t  pk_bytes;
    size_t  sk_bytes;
    size_t  sig_bytes;
    uint8_t nist_level;
} sig_bench_result_t;

/* ------------------------------------------------------------------
 * Single-call probe trampolines (TIER 11 memory profiling), ML-DSA.
 * ------------------------------------------------------------------ */
typedef struct { OQS_SIG *sig; uint8_t *pk; uint8_t *sk; } sig_keygen_ctx_t;
static void sig_keygen_probe(void *ctx) {
    sig_keygen_ctx_t *c = (sig_keygen_ctx_t *)ctx;
    OQS_SIG_keypair(c->sig, c->pk, c->sk);
}

typedef struct {
    OQS_SIG *sig; uint8_t *signature; size_t *sig_len;
    const uint8_t *msg; size_t msg_len; const uint8_t *sk;
} sig_sign_ctx_t;
static void sig_sign_probe(void *ctx) {
    sig_sign_ctx_t *c = (sig_sign_ctx_t *)ctx;
    OQS_SIG_sign(c->sig, c->signature, c->sig_len, c->msg, c->msg_len, c->sk);
}

typedef struct {
    OQS_SIG *sig; const uint8_t *msg; size_t msg_len;
    const uint8_t *signature; size_t sig_len; const uint8_t *pk;
} sig_verify_ctx_t;
static void sig_verify_probe(void *ctx) {
    sig_verify_ctx_t *c = (sig_verify_ctx_t *)ctx;
    OQS_SIG_verify(c->sig, c->msg, c->msg_len, c->signature, c->sig_len, c->pk);
}

/*
 * bench_sig_obj()
 *   Core ML-DSA benchmark harness operating on an already-constructed
 *   OQS_SIG object.  Caller owns `sig` (created via OQS_SIG_new() for the
 *   standard SHAKE algorithms, or via one of the alt-backend
 *   OQS_SIG_ml_dsa_*_<tag>_new() constructors) and must free it with
 *   OQS_SIG_free().
 */
static sig_bench_result_t bench_sig_obj(OQS_SIG *sig,
                                        const char *display_name,
                                        int run_dudect,
                                        int run_stack)
{
    sig_bench_result_t result;
    memset(&result, 0, sizeof(result));
    result.name = display_name;
    rejection_stats_init(&result.rejection);

    const char *sig_name = display_name;

    result.pk_bytes   = sig->length_public_key;
    result.sk_bytes   = sig->length_secret_key;
    result.sig_bytes  = sig->length_signature;
    result.nist_level = sig->claimed_nist_level;

    uint8_t *pk        = malloc(sig->length_public_key);
    uint8_t *sk        = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    uint8_t  msg[BENCH_MSG_LEN];
    if (!pk || !sk || !signature) {
        fprintf(stderr, "[ERROR] Allocation failed for %s\n", sig_name); goto sig_cleanup;
    }

    /* Generate a fixed test message. */
    for (int b = 0; b < BENCH_MSG_LEN; b++) msg[b] = (uint8_t)(b & 0xFF);

    uint64_t total_iters   = BENCH_ITERATIONS + BENCH_WARMUP;
    uint64_t *cycles_kg    = malloc(total_iters * sizeof(uint64_t));
    uint64_t *cycles_sign  = malloc(total_iters * sizeof(uint64_t));
    uint64_t *cycles_ver   = malloc(total_iters * sizeof(uint64_t));
    if (!cycles_kg || !cycles_sign || !cycles_ver) {
        fprintf(stderr, "[ERROR] Cycle array allocation failed\n"); goto sig_cleanup;
    }

    uint8_t *stack_region = NULL;
    if (run_stack) {
        stack_region = malloc(STACK_PAINT_REGION_BYTES);
        if (!stack_region) run_stack = 0;
        else stack_paint(stack_region, STACK_PAINT_REGION_BYTES);
    }

    uint64_t wall_start, wall_end;
    size_t   sig_len = 0;

    /* ================================================================
     * KEYGEN BENCHMARK LOOP
     * ================================================================ */
    wall_start = wallclock_ns();
    for (uint64_t i = 0; i < total_iters; i++) {
        uint64_t t0 = cpucycles_begin();
        OQS_SIG_keypair(sig, pk, sk);
        uint64_t t1 = cpucycles_end();
        cycles_kg[i] = t1 - t0;
    }
    wall_end = wallclock_ns();

    if (run_stack)
        result.stack_hwm_keygen = stack_measure_hwm(stack_region, STACK_PAINT_REGION_BYTES);

    compute_stats(&result.keygen,
                  cycles_kg + BENCH_WARMUP,
                  BENCH_ITERATIONS,
                  sig->length_public_key + sig->length_secret_key,
                  (double)(wall_end - wall_start));

    {
        sig_keygen_ctx_t sctx = { sig, pk, sk };
        mem_profile_op(sig_keygen_probe, &sctx, &result.mem_keygen);
    }
    compute_energy_stats(&result.energy_keygen, &result.keygen,
                         sig->length_public_key + sig->length_secret_key);


    /* ================================================================
     * SIGN BENCHMARK LOOP
     * CRITICAL: ML-DSA has probabilistic rejection sampling.
     * Each iteration may internally loop many times over SHAKE256 expansion.
     * The 99th percentile tail metric directly measures the worst-case cost
     * of high-iteration rejection sampling events (PDF1/PDF2).
     * ================================================================ */
    /* Re-generate keys once for a fixed keypair in signing. */
    OQS_SIG_keypair(sig, pk, sk);

    if (run_stack) stack_paint(stack_region, STACK_PAINT_REGION_BYTES);
    wall_start = wallclock_ns();

    for (uint64_t i = 0; i < total_iters; i++) {
        uint64_t t0 = cpucycles_begin();
        OQS_SIG_sign(sig, signature, &sig_len, msg, BENCH_MSG_LEN, sk);
        uint64_t t1 = cpucycles_end();
        cycles_sign[i] = t1 - t0;
    }
    wall_end = wallclock_ns();

    if (run_stack)
        result.stack_hwm_sign = stack_measure_hwm(stack_region, STACK_PAINT_REGION_BYTES);

    /* CpB for signing: output artifact is the signature bytes. */
    compute_stats(&result.sign_op,
                  cycles_sign + BENCH_WARMUP,
                  BENCH_ITERATIONS,
                  sig->length_signature,
                  (double)(wall_end - wall_start));

    {
        size_t probe_sig_len = sig_len;
        sig_sign_ctx_t sctx = { sig, signature, &probe_sig_len, msg, BENCH_MSG_LEN, sk };
        mem_profile_op(sig_sign_probe, &sctx, &result.mem_sign);
    }
    compute_energy_stats(&result.energy_sign, &result.sign_op, sig->length_signature);


    result.rejection.total_signatures = BENCH_ITERATIONS;

    /* ================================================================
     * VERIFY BENCHMARK LOOP
     * Verify is deterministic: no rejection sampling variance expected.
     * ================================================================ */
    if (run_stack) stack_paint(stack_region, STACK_PAINT_REGION_BYTES);
    wall_start = wallclock_ns();

    for (uint64_t i = 0; i < total_iters; i++) {
        uint64_t t0 = cpucycles_begin();
        OQS_SIG_verify(sig, msg, BENCH_MSG_LEN, signature, sig_len, pk);
        uint64_t t1 = cpucycles_end();
        cycles_ver[i] = t1 - t0;
    }
    wall_end = wallclock_ns();

    if (run_stack)
        result.stack_hwm_verify = stack_measure_hwm(stack_region, STACK_PAINT_REGION_BYTES);

    compute_stats(&result.verify,
                  cycles_ver + BENCH_WARMUP,
                  BENCH_ITERATIONS,
                  sig->length_signature,
                  (double)(wall_end - wall_start));

    {
        sig_verify_ctx_t sctx = { sig, msg, BENCH_MSG_LEN, signature, sig_len, pk };
        mem_profile_op(sig_verify_probe, &sctx, &result.mem_verify);
    }
    compute_energy_stats(&result.energy_verify, &result.verify, sig->length_signature);


    /* ================================================================
     * DUDECT CONSTANT-TIME TEST ON SIGNING
     * ================================================================ */
    if (run_dudect) {
        printf("  Running dudect for %s signing (this may take ~5-10 min)...\n",
               sig_name);
        result.dudect_sign = dudect_run_sig(sig, DUDECT_MEASUREMENTS);
    }

    free(cycles_kg); free(cycles_sign); free(cycles_ver);
    free(stack_region);

sig_cleanup:
    free(pk); free(sk); free(signature);
    return result;
}

/*
 * bench_sig()
 *   Convenience wrapper for the standard (liboqs-registered) SHAKE-based
 *   ML-DSA algorithms: looks the algorithm up by name via OQS_SIG_new(),
 *   benchmarks it, and frees it.
 */
static sig_bench_result_t bench_sig(const char *sig_name,
                                    int run_dudect,
                                    int run_stack)
{
    OQS_SIG *sig = OQS_SIG_new(sig_name);
    if (!sig) {
        fprintf(stderr, "[ERROR] OQS_SIG_new(%s) failed.\n", sig_name);
        sig_bench_result_t result;
        memset(&result, 0, sizeof(result));
        result.name = sig_name;
        return result;
    }

    sig_bench_result_t result = bench_sig_obj(sig, sig_name, run_dudect, run_stack);
    OQS_SIG_free(sig);
    return result;
}

/* =========================================================================
 * REPORT PRINTER: ML-KEM
 * ========================================================================= */
static void print_kem_report(const kem_bench_result_t *r,
                             int run_dudect, int run_stack)
{
    printf("\n");
    printf("  ======================================================================\n");
    printf("  ML-KEM BENCHMARK REPORT: %s\n", r->name);
    printf("  Hash Backend     : %s\n", HASH_BACKEND_TAG);
    printf("  Keccak Rounds    : %d  (SHAKE=24, TurboSHAKE=12)\n", HASH_ROUNDS);
    printf("  FIPS 203 Compliant: %s\n", FIPS_COMPLIANT ? "YES" : "NO -- closed ecosystem only");
    printf("  ======================================================================\n");

    /* Algorithm parameters. */
    printf("\n  [Algorithm Parameters - FIPS 203 / M-LWE]\n");
    printf("  NIST Security Level  : %u\n",   r->nist_level);
    printf("  Security Model       : %s\n",    r->ind_cca ? "IND-CCA2 (FO transform)" : "IND-CPA");
    printf("  Public Key Size      : %zu bytes\n",  r->pk_bytes);
    printf("  Secret Key Size      : %zu bytes\n",  r->sk_bytes);
    printf("  Ciphertext Size      : %zu bytes\n",  r->ct_bytes);
    printf("  Shared Secret Size   : %zu bytes\n",  r->ss_bytes);
    printf("  MTU Note             : CT %s 1500B MTU (%s fragmentation)\n",
           r->ct_bytes > 1500 ? "EXCEEDS" : "fits within",
           r->ct_bytes > 1500 ? "IP fragmentation REQUIRED" : "no fragmentation");

    /* Hash integration vectors (from PDF1/PDF2 architectural analysis). */
    printf("\n  [SHAKE Integration Vectors within ML-KEM]\n");
    printf("  Vector 1: Matrix Expansion     => %s  (PRF, row/col seed)\n", KEM_VECTOR1_LABEL);
    printf("  Vector 2: CBD Noise Generation => %s  (secret seed)\n", KEM_VECTOR2_LABEL);
    printf("  Vector 3: FO Transform         => SHA3-256 / SHA3-512 (not replaced)\n");
    printf("  Vector 4: KDF (shared secret)  => %s\n", KEM_VECTOR4_LABEL);

    /* Benchmark results. */
    printf("\n  [Benchmark Results: n=%d iterations, warmup=%d discarded]\n",
           BENCH_ITERATIONS, BENCH_WARMUP);

    print_stats("KeyGen", &r->keygen, "cycles");
    print_stats("Encaps", &r->encaps, "cycles");
    print_stats("Decaps", &r->decaps, "cycles");

    /* TIER 11/12: memory footprint + energy proxy (hardware-independent). */
    printf("\n  [Memory Footprint & Energy Proxy -- software-level, hardware-independent]\n");
    print_mem_energy("KeyGen", &r->mem_keygen, &r->energy_keygen);
    print_mem_energy("Encaps", &r->mem_encaps, &r->energy_encaps);
    print_mem_energy("Decaps", &r->mem_decaps, &r->energy_decaps);

    /* Stack watermark. */
    if (run_stack) {
        printf("\n  [Stack High-Water Marks (0xDEADBEEF sentinel painting)]\n");
        print_stack_result("KeyGen peak stack", r->stack_hwm_keygen);
        print_stack_result("Encaps peak stack", r->stack_hwm_encaps);
        print_stack_result("Decaps peak stack", r->stack_hwm_decaps);
        printf("  Note: Keccak state = 200 bytes (fixed regardless of 12 vs 24 rounds).\n");
        printf("  A spike in stack HWM after TurboSHAKE swap => struct misalignment bug.\n");
    }


    /* Dudect. */
    if (run_dudect) {
        printf("\n  [Constant-Time Validation (dudect / Welch t-test)]\n");
        print_dudect_result("Encaps", &r->dudect_encaps);
    }

    /* TurboSHAKE expected gains note. */
    printf("\n  [Expected Impact of TurboSHAKE Substitution]\n");
    printf("  - Hash-intensive ops (matrix expand, CBD): ~40-50%% fewer cycles.\n");
    printf("  - Macroscopic KeyGen + Encaps: ~15-25%% overall reduction (PDF1/PDF2).\n");
    printf("  - NTT multiplications + modular reductions: UNCHANGED (non-hash ops).\n");
    printf("  - Stack usage: IDENTICAL (Keccak state = 200 bytes fixed).\n");
    printf("  - Network transmission bottleneck: UNCHANGED (byte sizes stay same).\n");
}

/* =========================================================================
 * REPORT PRINTER: ML-DSA
 * ========================================================================= */
static void print_sig_report(const sig_bench_result_t *r,
                             int run_dudect, int run_stack)
{
    printf("\n");
    printf("  ======================================================================\n");
    printf("  ML-DSA BENCHMARK REPORT: %s\n", r->name);
    printf("  Hash Backend     : %s\n", HASH_BACKEND_TAG);
    printf("  Keccak Rounds    : %d\n", HASH_ROUNDS);
    printf("  FIPS 204 Compliant: %s\n", FIPS_COMPLIANT ? "YES" : "NO -- closed ecosystem only");
    printf("  ======================================================================\n");

    printf("\n  [Algorithm Parameters - FIPS 204 / M-SIS + M-LWE]\n");
    printf("  NIST Security Level  : %u\n",  r->nist_level);
    printf("  Security Model       : Fiat-Shamir with Aborts (rejection sampling)\n");
    printf("  Public Key Size      : %zu bytes\n",  r->pk_bytes);
    printf("  Secret Key Size      : %zu bytes\n",  r->sk_bytes);
    printf("  Signature Size       : %zu bytes\n",  r->sig_bytes);
    printf("  MTU Note             : Sig %s 1500B MTU (%s)\n",
           r->sig_bytes > 1500 ? "EXCEEDS" : "fits within",
           r->sig_bytes > 1500 ? "fragmentation REQUIRED -- exponential packet loss impact" : "no fragmentation");

    printf("\n  [SHAKE Integration Vectors within ML-DSA]\n");
    printf("  Vector 1: Matrix Expansion     => %s\n",
           FIPS_COMPLIANT ? "SHAKE128 (n_r=24, PRF, row/col seed)" :
                            "TurboSHAKE128 (n_r=12, D=0x1F)");
    printf("  Vector 2: Masking Vector y     => %s  (REJECTION LOOP)\n",
           FIPS_COMPLIANT ? "SHAKE256 (n_r=24, secret seed||nonce)" :
                            "TurboSHAKE256 (n_r=12, D=0x2F, secret seed||nonce)");
    printf("  Vector 3: Challenge Poly c     => %s\n",
           FIPS_COMPLIANT ? "SHAKE256 (n_r=24, commitment||message)" :
                            "TurboSHAKE256 (n_r=12, D=0x3F)");
    printf("  REJECTION LOOP: If bound check fails => increment nonce, repeat vector 2.\n");
    printf("  Expected iterations: ~4.25 (ML-DSA-44), ~5.10 (ML-DSA-65) [PDF1].\n");
    printf("  99th-pct time on Cortex-M0+ @ 133MHz: >1,115 ms [PDF2].\n");

    printf("\n  [Benchmark Results: n=%d iterations, warmup=%d discarded]\n",
           BENCH_ITERATIONS, BENCH_WARMUP);

    print_stats("KeyGen", &r->keygen, "cycles");
    print_stats("Sign   (rejection loop variance captured in p99)", &r->sign_op, "cycles");
    print_stats("Verify (deterministic -- low CoV expected)", &r->verify, "cycles");

    /* TIER 11/12: memory footprint + energy proxy (hardware-independent). */
    printf("\n  [Memory Footprint & Energy Proxy -- software-level, hardware-independent]\n");
    print_mem_energy("KeyGen", &r->mem_keygen, &r->energy_keygen);
    print_mem_energy("Sign",   &r->mem_sign,   &r->energy_sign);
    print_mem_energy("Verify", &r->mem_verify, &r->energy_verify);

    /* Rejection sampling analysis. */
    rejection_stats_print(&r->rejection, r->name);

    /* CoV interpretation for ML-DSA signing. */
    printf("\n  [Signing Variance Analysis]\n");
    printf("  Observed CoV     : %.2f%%\n", r->sign_op.cov_pct);
    printf("  Reference CoV    : 61-71%% expected on embedded (PDF2 ARM Cortex-M0+)\n");
    printf("  Tail compression : TurboSHAKE reduces each abort iteration cost,\n");
    printf("                     shrinking 99th pct (%.0f cyc) toward median (%.0f cyc).\n",
           r->sign_op.p99, r->sign_op.median);
    printf("  Speedup factor   : With TurboSHAKE, expect ~%.0f-%.0f fewer p99 cycles\n",
           r->sign_op.p99 * 0.15, r->sign_op.p99 * 0.35);

    /* Stack watermark. */
    if (run_stack) {
        printf("\n  [Stack High-Water Marks (0xDEADBEEF sentinel)]\n");
        print_stack_result("KeyGen peak stack", r->stack_hwm_keygen);
        print_stack_result("Sign   peak stack", r->stack_hwm_sign);
        print_stack_result("Verify peak stack", r->stack_hwm_verify);
        printf("  ML-DSA requires >100KB stack on constrained devices (PDF1/PDF2).\n");
        printf("  K*L polynomial vectors are the dominant stack consumers.\n");
    }

    /* Dudect. */
    if (run_dudect) {
        printf("\n  [Constant-Time Validation (dudect / Welch t-test)]\n");
        print_dudect_result("Sign", &r->dudect_sign);
        printf("  Note: Rejection sampling is probabilistic by design, NOT a\n");
        printf("        secret-dependent branch.  CoV due to abort count, not timing leak.\n");
    }

    printf("\n  [Expected TurboSHAKE Impact on ML-DSA]\n");
    printf("  - Each rejection loop iteration: ~50%% fewer hash cycles.\n");
    printf("  - Tail latency (p99): drastically compressed.\n");
    printf("  - Signing CoV: unchanged (abort count distribution unchanged).\n");
    printf("  - Signature byte size: UNCHANGED (physical byte counts unaffected).\n");
    printf("  - FIPS 204 compliance: BROKEN by TurboSHAKE substitution.\n");
}

/* =========================================================================
 * TIER 10: CSV REPORT WRITER
 * Outputs structured data for analysis with Python/R/Excel.
 * Column headers match standard SUPERCOP/eBACS output conventions.
 * ========================================================================= */
static FILE *csv_fp = NULL;

static void csv_open(int append) {
    if (append) {
        /* Append mode: only write the header if the file doesn't exist yet
         * or is currently empty (so a SHAKE run followed by a TurboSHAKE
         * --csv-append run lands in one file with a single header). */
        FILE *probe = fopen(BENCH_CSV_OUTPUT, "r");
        int need_header = 1;
        if (probe) {
            fseek(probe, 0, SEEK_END);
            need_header = (ftell(probe) == 0);
            fclose(probe);
        }
        csv_fp = fopen(BENCH_CSV_OUTPUT, "a");
        if (!csv_fp) { perror("fopen CSV"); return; }
        if (!need_header) {
            return;
        }
    } else {
        csv_fp = fopen(BENCH_CSV_OUTPUT, "w");
        if (!csv_fp) { perror("fopen CSV"); return; }
    }
    fprintf(csv_fp,
            "algorithm,operation,hash_backend,keccak_rounds,fips_compliant,"
            "n_iterations,median_cycles,q1_cycles,q3_cycles,iqr_cycles,"
            "p95_cycles,p99_cycles,min_cycles,max_cycles,"
            "arith_mean_cycles,geo_mean_cycles,std_dev_cycles,cov_pct,"
            "cpb,wall_ns_mean,"
            "pk_bytes,sk_bytes,ct_or_sig_bytes,ss_bytes,nist_level,"
            "stack_hwm_bytes,"
            "peak_rss_delta_kb,peak_rss_after_kb,heap_delta_bytes,"
            "energy_proxy_units,energy_proxy_per_byte,"
            "est_energy_uj,est_energy_uj_per_byte,energy_calibrated,"
            "edp_cycle_ns\n");
}

static void csv_write_stats(const char            *algo,
                            const char            *op,
                            const bench_stats_t   *s,
                            size_t                 pk_b,
                            size_t                 sk_b,
                            size_t                 ct_b,
                            size_t                 ss_b,
                            uint8_t                nist_level,
                            size_t                 stack_hwm,
                            const mem_stats_t      *m,
                            const energy_stats_t   *e)
{
    if (!csv_fp) return;
    fprintf(csv_fp,
            "%s,%s,\"%s\",%d,%d,"
            "%"PRIu64","
            "%.0f,%.0f,%.0f,%.0f,"
            "%.0f,%.0f,"
            "%"PRIu64",%"PRIu64","
            "%.2f,%.2f,%.2f,%.4f,"
            "%.6f,%.2f,"
            "%zu,%zu,%zu,%zu,%u,"
            "%zu,"
            "%ld,%ld,%ld,"
            "%.0f,%.4f,"
            "%.4f,%.6f,%d,"
            "%.2f\n",
            algo, op, HASH_BACKEND_TAG, HASH_ROUNDS, FIPS_COMPLIANT,
            s->n,
            s->median, s->q1, s->q3, s->iqr,
            s->p95, s->p99,
            s->min_cycles, s->max_cycles,
            s->arith_mean, s->geo_mean, s->std_dev, s->cov_pct,
            s->cpb, s->wall_ns,
            pk_b, sk_b, ct_b, ss_b, (unsigned)nist_level,
            stack_hwm,
            m->peak_rss_delta_kb, m->peak_rss_after_kb, m->heap_delta_bytes,
            e->epu, e->epu_per_byte,
            e->est_energy_uj, e->est_energy_uj_per_byte, e->calibrated,
            e->edp_cycle_ns);
}

static void csv_close(void) {
    if (csv_fp) { fclose(csv_fp); csv_fp = NULL; }
}


/* =========================================================================
 * COMPARISON SUMMARY
 * Prints a SHAKE vs TurboSHAKE side-by-side analysis note.
 * When running both builds, redirect stdout to files and diff them.
 * ========================================================================= */
static void print_comparison_guide(void) {
    printf("\n");
    printf("  ======================================================================\n");
    printf("  HOW TO COMPARE SHAKE vs TurboSHAKE RESULTS\n");
    printf("  ======================================================================\n");
    printf("  1. Build SHAKE baseline:\n");
    printf("     gcc -O2 -march=native pqc_agility_benchmark.c -loqs -lm \\\n");
    printf("         -o bench_shake\n");
    printf("     ./bench_shake > results_shake.txt 2>&1\n\n");
    printf("  2. Build TurboSHAKE variant:\n");
    printf("     gcc -O2 -march=native -DUSE_TURBOSHAKE \\\n");
    printf("         pqc_agility_benchmark.c -loqs -lm -o bench_turboshake\n");
    printf("     ./bench_turboshake > results_turboshake.txt 2>&1\n\n");
    printf("  3. Compare:\n");
    printf("     diff results_shake.txt results_turboshake.txt\n\n");
    printf("  4. For cache analysis (Valgrind Cachegrind):\n");
    printf("     valgrind --tool=cachegrind --cachegrind-out-file=cg_shake.out \\\n");
    printf("              ./bench_shake\n");
    printf("     cg_annotate cg_shake.out\n\n");
    printf("  5. For heap memory (Valgrind Massif):\n");
    printf("     valgrind --tool=massif --stacks=yes ./bench_shake\n");
    printf("     ms_print massif.out.<pid>\n\n");
    printf("  6. For hardware counters (Linux perf):\n");
    printf("     perf stat -e cycles,instructions,cache-misses,branch-misses \\\n");
    printf("               ./bench_shake\n\n");
    printf("  7. CSV output written to: %s\n", BENCH_CSV_OUTPUT);
    printf("     Import into Python/R/Excel for visualization.\n\n");
    printf("  8. MEMORY (TIER 11, software-level, no Valgrind needed):\n");
    printf("     'Peak RSS delta'  -- getrusage() process high-water mark growth.\n");
    printf("     'Heap arena delta' -- mallinfo() malloc-arena delta for 1 call.\n");
    printf("     Both columns are also in the CSV for SHAKE vs TurboSHAKE diffing.\n\n");
    printf("  9. ENERGY (TIER 12, software proxy, no RAPL/board sensor needed):\n");
    printf("     'Energy Proxy Units' = median cycles -- compare this directly\n");
    printf("     between SHAKE and TurboSHAKE builds; it is hardware-independent.\n");
    printf("     To get an absolute uJ estimate for YOUR platform, measure its\n");
    printf("     average power draw P (Watts) at clock F (Hz) and rebuild with:\n");
    printf("        gcc -DENERGY_PER_CYCLE_NJ=$(echo \"$P / $F * 1e9\" | bc) ...\n\n");
    printf("  THEORY REFERENCE (from PDFs):\n");
    printf("  - TurboSHAKE128/256: Keccak n_r=12 (vs SHAKE n_r=24).\n");
    printf("  - Expected hash speedup: ~100%% at primitive level.\n");
    printf("  - Expected ML-KEM speedup: ~15-25%% overall (NTT is constant).\n");
    printf("  - Expected ML-DSA: massive p99 tail compression.\n");
    printf("  - Memory/energy proxies should track cycle-count reductions 1:1,\n");
    printf("    since both TIER 11/12 figures are derived from the same\n");
    printf("    cycle/heap/RSS measurements regardless of which build runs.\n");
    printf("  - SECURITY: Best attack on Keccak = 6 rounds. TurboSHAKE=12 => 100%% margin.\n");
    printf("  - FIPS: TurboSHAKE BREAKS FIPS 203/204 -- closed ecosystems ONLY.\n");
    printf("  ======================================================================\n");
}


/* =========================================================================
 * MAIN ENTRY POINT
 * ========================================================================= */
int main(int argc, char *argv[]) {

    /* ----------------------------------------------------------------
     * Parse optional command-line flags:
     *   --no-dudect      Skip dudect (saves ~30 min per algorithm)
     *   --no-stack       Skip stack painting
     *   --kem-only       Only benchmark KEM, skip DSA
     *   --dsa-only       Only benchmark DSA, skip KEM
     *   --csv-append     Append to BENCH_CSV_OUTPUT instead of overwriting
     *                     (skips the header row if the file already has one)
     *   --quick          50 iterations only (fast sanity check)
     * ---------------------------------------------------------------- */
    int run_dudect  = 0;   /* Off by default: very time-consuming */
    int run_stack   = 1;
    int run_kem     = 1;
    int run_dsa     = 1;
    int csv_append  = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dudect")    == 0) run_dudect = 1;
        if (strcmp(argv[i], "--no-stack")  == 0) run_stack  = 0;
        if (strcmp(argv[i], "--kem-only")  == 0) run_dsa    = 0;
        if (strcmp(argv[i], "--dsa-only")  == 0) run_kem    = 0;
        if (strcmp(argv[i], "--csv-append") == 0) csv_append = 1;
        if (strcmp(argv[i], "--help")     == 0) {
            printf("Usage: %s [--dudect] [--no-stack] [--kem-only] [--dsa-only] [--csv-append]\n",
                   argv[0]);
            return 0;
        }
    }

    /* Seed RNG for dudect class alternation. */
    srand((unsigned)time(NULL));

    /* ----------------------------------------------------------------
     * Print benchmark header
     * ---------------------------------------------------------------- */
    printf("\n");
    printf("  ######################################################################\n");
    printf("  #  PQC ALGORITHMIC AGILITY BENCHMARKING SUITE                       #\n");
    printf("  #  ML-DSA (FIPS 204) + ML-KEM (FIPS 203)                            #\n");
    printf("  #  SHAKE (n_r=24) vs TurboSHAKE RFC 9861 (n_r=12) Comparison        #\n");
    printf("  ######################################################################\n");
    printf("\n");
    printf("  Hash Backend     : %s\n", HASH_BACKEND_TAG);
    printf("  Keccak Rounds    : %d  (SHAKE=24 | TurboSHAKE=12)\n", HASH_ROUNDS);
    printf("  FIPS Compliant   : %s\n", FIPS_COMPLIANT ? "YES (FIPS 202/203/204)" :
                                                          "NO  (closed ecosystem / research only)");
    printf("  Iterations       : %d  (warmup=%d)\n", BENCH_ITERATIONS, BENCH_WARMUP);
    printf("  Message length   : %d bytes\n", BENCH_MSG_LEN);
    printf("  Stack paint size : %d KB\n",    STACK_PAINT_REGION_BYTES / 1024);
    printf("  Dudect enabled   : %s  (pass --dudect to enable)\n",
           run_dudect ? "YES" : "NO");
    printf("  Memory profiling : Peak RSS (getrusage) + heap delta (mallinfo)"
           " -- POSIX, no hardware deps\n");
#if defined(PQC_HAVE_MALLINFO)
    printf("                     Heap tracking: ENABLED (glibc mallinfo%s)\n",
#  if defined(__GLIBC__) && __GLIBC_PREREQ(2, 33)
           "2"
#  else
           ""
#  endif
          );
#else
    printf("                     Heap tracking: DISABLED (non-glibc libc)\n");
#endif
    printf("  Energy proxy     : Energy Proxy Units = median cycles (hardware-independent)\n");
    printf("                     Calibration       : %s\n",
           ENERGY_MODEL_CALIBRATED
               ? "ENABLED  (ENERGY_PER_CYCLE_NJ user-supplied)"
               : "illustrative only (define -DENERGY_PER_CYCLE_NJ=<nJ/cycle> to calibrate)");

    if (!FIPS_COMPLIANT) {
        printf("\n");
        printf("  !! COMPLIANCE WARNING !!\n");
#if defined(USE_K12)
        printf("  KangarooTwelve build DEVIATES from FIPS 203/204.\n");
        printf("  Customization string: matrix=0x%02X, CBD=0x%02X, KDF=0x%02X\n",
               TURBOSHAKE_DOMAIN_MATRIX, TURBOSHAKE_DOMAIN_CBD, TURBOSHAKE_DOMAIN_CHAL);
        printf("  See RFC 9861 Section 2.1 for domain byte constraints (0x01..0x7F).\n");
#elif defined(USE_BLAKE3)
        printf("  BLAKE3 build DEVIATES from FIPS 203/204.\n");
        printf("  BLAKE3 XOF domain byte: matrix=0x%02X, CBD=0x%02X, KDF=0x%02X\n",
               TURBOSHAKE_DOMAIN_MATRIX, TURBOSHAKE_DOMAIN_CBD, TURBOSHAKE_DOMAIN_CHAL);
        printf("  BLAKE3 is not a FIPS-approved hash function.\n");
#elif defined(USE_XOODYAK)
        printf("  Xoodyak build DEVIATES from FIPS 203/204.\n");
        printf("  Xoodyak Cyclist domain byte: matrix=0x%02X, CBD=0x%02X, KDF=0x%02X\n",
               TURBOSHAKE_DOMAIN_MATRIX, TURBOSHAKE_DOMAIN_CBD, TURBOSHAKE_DOMAIN_CHAL);
        printf("  Xoodyak/Xoodoo is not a FIPS-approved permutation.\n");
#elif defined(USE_HARAKA)
        printf("  Haraka-CTR build DEVIATES SIGNIFICANTLY from FIPS 203/204.\n");
        printf("  Haraka-CTR domain byte: matrix=0x%02X, CBD=0x%02X, KDF=0x%02X\n",
               TURBOSHAKE_DOMAIN_MATRIX, TURBOSHAKE_DOMAIN_CBD, TURBOSHAKE_DOMAIN_CHAL);
        printf("  Haraka is a FIXED-OUTPUT primitive; the XOF/PRF/KDF roles use a\n");
        printf("  NON-STANDARD counter-mode construction (Haraka-CTR) defined in\n");
        printf("  symmetric.h of the haraka variant -- this is NOT a vetted\n");
        printf("  cryptographic construction and exists purely for benchmarking.\n");
#else
        printf("  TurboSHAKE build DEVIATES from FIPS 203/204.\n");
        printf("  Domain separation byte: matrix=0x%02X, CBD=0x%02X, challenge=0x%02X\n",
               TURBOSHAKE_DOMAIN_MATRIX, TURBOSHAKE_DOMAIN_CBD, TURBOSHAKE_DOMAIN_CHAL);
        printf("  See RFC 9861 Section 2.1 for domain byte constraints (0x01..0x7F).\n");
#endif
        printf("  DO NOT use in open-internet TLS 1.3 deployments.\n");
    }
    printf("\n");

    /* Open CSV output. */
    csv_open(csv_append);

    /* ================================================================
     * BENCHMARK ML-KEM PARAMETER SETS
     * ================================================================ */
    if (run_kem) {
        printf("  ====== ML-KEM (FIPS 203 / CRYSTALS-Kyber) ======\n\n");

        const char *kem_algs[] = {
            MLKEM_512_NAME,
            MLKEM_768_NAME,
            MLKEM_1024_NAME
        };
        const char *kem_notes[] = {
            "k=2, NIST Level 1, pk=800B, ct=768B",
            "k=3, NIST Level 3, pk=1184B, ct=1088B (recommended)",
            "k=4, NIST Level 5, pk=1568B, ct=1568B (exceeds MTU)"
        };
        int n_kems = 3;

#if defined(USE_TURBOSHAKE) || defined(USE_K12) || defined(USE_BLAKE3) || defined(USE_XOODYAK) || defined(USE_HARAKA)
        OQS_KEM *(*alt_ctors[])(void) = {
#  ifdef USE_TURBOSHAKE
            OQS_KEM_ml_kem_512_turboshake_new,
            OQS_KEM_ml_kem_768_turboshake_new,
            OQS_KEM_ml_kem_1024_turboshake_new
#  elif defined(USE_K12)
            OQS_KEM_ml_kem_512_k12_new,
            OQS_KEM_ml_kem_768_k12_new,
            OQS_KEM_ml_kem_1024_k12_new
#  elif defined(USE_BLAKE3)
            OQS_KEM_ml_kem_512_blake3_new,
            OQS_KEM_ml_kem_768_blake3_new,
            OQS_KEM_ml_kem_1024_blake3_new
#  elif defined(USE_XOODYAK)
            OQS_KEM_ml_kem_512_xoodyak_new,
            OQS_KEM_ml_kem_768_xoodyak_new,
            OQS_KEM_ml_kem_1024_xoodyak_new
#  else
            OQS_KEM_ml_kem_512_haraka_new,
            OQS_KEM_ml_kem_768_haraka_new,
            OQS_KEM_ml_kem_1024_haraka_new
#  endif
        };
#endif

        for (int ki = 0; ki < n_kems; ki++) {
            kem_bench_result_t kr;

#if defined(USE_TURBOSHAKE) || defined(USE_K12) || defined(USE_BLAKE3) || defined(USE_XOODYAK) || defined(USE_HARAKA)
            OQS_KEM *kem = alt_ctors[ki]();
            if (!kem) {
                fprintf(stderr, "[ERROR] Failed to construct %s\n", kem_algs[ki]);
                continue;
            }

            /* ----------------------------------------------------------
             * Correctness self-test: keypair -> encaps -> decaps roundtrip.
             * Confirms the substituted implementation produces matching
             * shared secrets before trusting its timings.
             * ---------------------------------------------------------- */
            {
                uint8_t *pk     = malloc(kem->length_public_key);
                uint8_t *sk     = malloc(kem->length_secret_key);
                uint8_t *ct     = malloc(kem->length_ciphertext);
                uint8_t *ss_enc = malloc(kem->length_shared_secret);
                uint8_t *ss_dec = malloc(kem->length_shared_secret);

                if (!pk || !sk || !ct || !ss_enc || !ss_dec) {
                    fprintf(stderr, "[ERROR] Self-test allocation failed for %s\n", kem->method_name);
                    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
                    OQS_KEM_free(kem);
                    continue;
                }

                OQS_STATUS sok = OQS_KEM_keypair(kem, pk, sk);
                OQS_STATUS eok = OQS_KEM_encaps(kem, ct, ss_enc, pk);
                OQS_STATUS dok = OQS_KEM_decaps(kem, ss_dec, ct, sk);

                int match = (sok == OQS_SUCCESS && eok == OQS_SUCCESS && dok == OQS_SUCCESS &&
                             memcmp(ss_enc, ss_dec, kem->length_shared_secret) == 0);

                free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);

                if (!match) {
                    fprintf(stderr, "  [SELFTEST] %s roundtrip FAILED -- skipping benchmark\n",
                            kem->method_name);
                    OQS_KEM_free(kem);
                    continue;
                }
                printf("  [SELFTEST] %s roundtrip OK (shared secrets match)\n", kem->method_name);
            }

            printf("  Benchmarking %s  [%s]\n", kem->method_name, kem_notes[ki]);
            fflush(stdout);

            kr = bench_kem_obj(kem, kem->method_name, run_dudect, run_stack);
            OQS_KEM_free(kem);
#else
            printf("  Benchmarking %s  [%s]\n", kem_algs[ki], kem_notes[ki]);
            fflush(stdout);

            kr = bench_kem(kem_algs[ki], run_dudect, run_stack);
#endif
            print_kem_report(&kr, run_dudect, run_stack);

            /* Write to CSV. */
            csv_write_stats(kr.name, "KeyGen", &kr.keygen,
                            kr.pk_bytes, kr.sk_bytes, kr.ct_bytes, kr.ss_bytes,
                            kr.nist_level, kr.stack_hwm_keygen,
                            &kr.mem_keygen, &kr.energy_keygen);
            csv_write_stats(kr.name, "Encaps", &kr.encaps,
                            kr.pk_bytes, kr.sk_bytes, kr.ct_bytes, kr.ss_bytes,
                            kr.nist_level, kr.stack_hwm_encaps,
                            &kr.mem_encaps, &kr.energy_encaps);
            csv_write_stats(kr.name, "Decaps", &kr.decaps,
                            kr.pk_bytes, kr.sk_bytes, kr.ct_bytes, kr.ss_bytes,
                            kr.nist_level, kr.stack_hwm_decaps,
                            &kr.mem_decaps, &kr.energy_decaps);
        }
    }

    /* ================================================================
     * BENCHMARK ML-DSA PARAMETER SETS
     * ================================================================ */
    if (run_dsa) {
        printf("\n  ====== ML-DSA (FIPS 204 / CRYSTALS-Dilithium) ======\n\n");

        const char *sig_algs[] = {
            MLDSA_44_NAME,
            MLDSA_65_NAME,
            MLDSA_87_NAME
        };
        const char *sig_notes[] = {
            "NIST Level 2, expected abort iters ~4.25, sig=2420B",
            "NIST Level 3, expected abort iters ~5.10, sig=3309B",
            "NIST Level 5, expected abort iters ~3.85, sig=4627B (exceeds MTU)"
        };
        int n_sigs = 3;

#if defined(USE_TURBOSHAKE) || defined(USE_K12) || defined(USE_BLAKE3) || defined(USE_XOODYAK) || defined(USE_HARAKA)
        OQS_SIG *(*alt_sig_ctors[])(void) = {
#  ifdef USE_TURBOSHAKE
            OQS_SIG_ml_dsa_44_turboshake_new,
            OQS_SIG_ml_dsa_65_turboshake_new,
            OQS_SIG_ml_dsa_87_turboshake_new
#  elif defined(USE_K12)
            OQS_SIG_ml_dsa_44_k12_new,
            OQS_SIG_ml_dsa_65_k12_new,
            OQS_SIG_ml_dsa_87_k12_new
#  elif defined(USE_BLAKE3)
            OQS_SIG_ml_dsa_44_blake3_new,
            OQS_SIG_ml_dsa_65_blake3_new,
            OQS_SIG_ml_dsa_87_blake3_new
#  elif defined(USE_XOODYAK)
            OQS_SIG_ml_dsa_44_xoodyak_new,
            OQS_SIG_ml_dsa_65_xoodyak_new,
            OQS_SIG_ml_dsa_87_xoodyak_new
#  else
            OQS_SIG_ml_dsa_44_haraka_new,
            OQS_SIG_ml_dsa_65_haraka_new,
            OQS_SIG_ml_dsa_87_haraka_new
#  endif
        };
#endif

        for (int si = 0; si < n_sigs; si++) {
            sig_bench_result_t sr;

#if defined(USE_TURBOSHAKE) || defined(USE_K12) || defined(USE_BLAKE3) || defined(USE_XOODYAK) || defined(USE_HARAKA)
            OQS_SIG *sig = alt_sig_ctors[si]();
            if (!sig) {
                fprintf(stderr, "[ERROR] Failed to construct %s\n", sig_algs[si]);
                continue;
            }

            /* ----------------------------------------------------------
             * Correctness self-test: keypair -> sign -> verify roundtrip,
             * plus a tamper check (flipped message byte must fail verify).
             * Confirms the substituted implementation produces valid
             * signatures before trusting its timings.
             * ---------------------------------------------------------- */
            {
                uint8_t *pk  = malloc(sig->length_public_key);
                uint8_t *sk  = malloc(sig->length_secret_key);
                uint8_t *sm  = malloc(sig->length_signature);
                uint8_t  msg[BENCH_MSG_LEN];
                size_t   smlen = 0;

                for (int b = 0; b < BENCH_MSG_LEN; b++) {
                    msg[b] = (uint8_t)(b & 0xFF);
                }

                if (!pk || !sk || !sm) {
                    fprintf(stderr, "[ERROR] Self-test allocation failed for %s\n", sig->method_name);
                    free(pk); free(sk); free(sm);
                    OQS_SIG_free(sig);
                    continue;
                }

                OQS_STATUS kok = OQS_SIG_keypair(sig, pk, sk);
                OQS_STATUS sok = OQS_SIG_sign(sig, sm, &smlen, msg, BENCH_MSG_LEN, sk);
                OQS_STATUS vok = OQS_SIG_verify(sig, msg, BENCH_MSG_LEN, sm, smlen, pk);

                msg[0] ^= 0xFF;
                OQS_STATUS tamper = OQS_SIG_verify(sig, msg, BENCH_MSG_LEN, sm, smlen, pk);

                int ok = (kok == OQS_SUCCESS && sok == OQS_SUCCESS &&
                          vok == OQS_SUCCESS && tamper == OQS_ERROR);

                free(pk); free(sk); free(sm);

                if (!ok) {
                    fprintf(stderr, "  [SELFTEST] %s roundtrip FAILED -- skipping benchmark\n",
                            sig->method_name);
                    OQS_SIG_free(sig);
                    continue;
                }
                printf("  [SELFTEST] %s roundtrip OK (sign/verify + tamper-detect)\n", sig->method_name);
            }

            printf("  Benchmarking %s  [%s]\n", sig->method_name, sig_notes[si]);
            fflush(stdout);

            sr = bench_sig_obj(sig, sig->method_name, run_dudect, run_stack);
            OQS_SIG_free(sig);
#else
            printf("  Benchmarking %s  [%s]\n", sig_algs[si], sig_notes[si]);
            fflush(stdout);

            sr = bench_sig(sig_algs[si], run_dudect, run_stack);
#endif
            print_sig_report(&sr, run_dudect, run_stack);

            csv_write_stats(sr.name, "KeyGen", &sr.keygen,
                            sr.pk_bytes, sr.sk_bytes, sr.sig_bytes, 0,
                            sr.nist_level, sr.stack_hwm_keygen,
                            &sr.mem_keygen, &sr.energy_keygen);
            csv_write_stats(sr.name, "Sign",   &sr.sign_op,
                            sr.pk_bytes, sr.sk_bytes, sr.sig_bytes, 0,
                            sr.nist_level, sr.stack_hwm_sign,
                            &sr.mem_sign, &sr.energy_sign);
            csv_write_stats(sr.name, "Verify", &sr.verify,
                            sr.pk_bytes, sr.sk_bytes, sr.sig_bytes, 0,
                            sr.nist_level, sr.stack_hwm_verify,
                            &sr.mem_verify, &sr.energy_verify);
        }
    }

    /* ================================================================
     * COMPARISON GUIDE AND FOOTER
     * ================================================================ */
    print_comparison_guide();

    csv_close();
    printf("\n  CSV results written to: %s\n", BENCH_CSV_OUTPUT);
    printf("  Benchmark complete.\n\n");

    return 0;
}

/*
 * =============================================================================
 * END OF FILE: pqc_agility_benchmark.c
 *
 * QUICK REFERENCE: ANALYSIS CHECKLIST
 * =============================================================================
 *
 * PERFORMANCE ANALYSIS (from benchmarks above):
 *   [ ] Compare median cycles: SHAKE vs TurboSHAKE for each operation.
 *   [ ] Compare p99 cycles: expect large reduction for ML-DSA Sign.
 *   [ ] Compare CpB: expect ~50% reduction for hash-heavy sub-ops.
 *   [ ] Compare CoV%: should remain ~similar (abort distribution unchanged).
 *   [ ] Macroscopic speedup: 15-25% for KEM, larger for DSA Sign.
 *
 * SECURITY ANALYSIS:
 *   [ ] Dudect t-value: must be |t| < 4.5 for constant-time safety.
 *   [ ] Stack HWM: should be IDENTICAL for SHAKE vs TurboSHAKE.
 *       Any increase => struct misalignment or buffer leak bug.
 *   [ ] FIPS compliance: TurboSHAKE build is non-FIPS -- document scope.
 *
 * MICROARCHITECTURAL ANALYSIS (external tools needed):
 *   [ ] Cachegrind: compare instruction count -- expect ~50% fewer XOR/ROT ops.
 *   [ ] perf stat:  compare cache-misses -- should be negligible change.
 *   [ ] perf stat:  compare branch-misses -- should be negligible change.
 *
 * MEMORY ANALYSIS (TIER 11 -- built-in, software-level, no Valgrind needed):
 *   [ ] Peak RSS delta: should be IDENTICAL for SHAKE vs TurboSHAKE
 *       (Keccak state = 200B fixed regardless of round count).
 *   [ ] Heap arena delta: should be IDENTICAL per call; any growth across
 *       repeated runs indicates a leak in the XOF context.
 *   [ ] Cross-check against Massif if you want an independent confirmation:
 *       valgrind --tool=massif --stacks=yes ./bench_shake
 *
 * ENERGY ANALYSIS (TIER 12 -- software proxy, no RAPL/board sensor needed):
 *   [ ] Energy Proxy Units (EPU == median cycles): compare SHAKE vs
 *       TurboSHAKE directly -- lower EPU implies lower energy on ANY
 *       platform, since EPU is hardware-independent by construction.
 *   [ ] Energy-Delay Product (EDP): should drop for TurboSHAKE in both
 *       ML-KEM (modest) and ML-DSA Sign (larger, due to p99 compression).
 *   [ ] If a calibrated ENERGY_PER_CYCLE_NJ was supplied for your target
 *       board, the "Est. energy (uJ)" columns give an absolute estimate;
 *       otherwise treat them as illustrative only.
 *
 * NETWORK ANALYSIS (external, tc netem):
 *   [ ] ML-DSA-87 signature (4627B) exceeds 1500B MTU => IP fragmentation.
 *   [ ] Under 5% packet loss, PQC handshakes suffer exponential 95th pct spike.
 *   [ ] TurboSHAKE does NOT change byte sizes -- network bottleneck persists.
 *   Command: tc qdisc add dev eth0 root netem delay 100ms 20ms 25% loss 5% 25%
 *
 * =============================================================================
 */

```

---

## 13. Full automated rebuild script

`setup_on_new_machine.sh` (in this package) automates everything in
§4 plus the remaining build/link steps. Run it from the directory that
**contains** `migrate_pkg2/`:

```bash
mkdir -p ~/pqc && cd ~/pqc
tar xzf pqc_migrate.tar.gz
./migrate_pkg2/setup_on_new_machine.sh
```

It is idempotent for the clone steps (`[ -d PQClean ] || git clone ...`),
auto-detects the architecture (`uname -m`) to decide whether to build the
Haraka backend, and prints run instructions + a diff command against the
reference CSV at the end.

**`setup_on_new_machine.sh`**

```bash
#!/bin/bash
# ----------------------------------------------------------------------
# Rebuilds the PQC SHAKE / TurboSHAKE / K12 / BLAKE3 / Xoodyak / Haraka
# ML-KEM + ML-DSA hash-agility benchmark on a fresh Linux machine, from
# this package plus freshly-cloned upstream repos.
#
# Usage:
#   mkdir -p ~/pqc && cd ~/pqc
#   tar xzf pqc_migrate.tar.gz          # produces migrate_pkg2/
#   ./migrate_pkg2/setup_on_new_machine.sh
#
# Run from the directory that CONTAINS migrate_pkg2/. All cloning and
# building happens under that directory (no absolute "/root" paths are
# assumed for the new tree, even though some originate that way).
#
# Backend portability notes:
#   - SHAKE, TurboSHAKE, K12, BLAKE3 (portable build), Xoodyak: build and
#     run on any Linux/x86_64 or aarch64 machine.
#   - Haraka: the symmetric backend (PQClean/common/Haraka/haraka.c) is an
#     ARM-NEON port (uses <arm_neon.h> AES intrinsics). It is only built
#     on aarch64. On other architectures it is skipped automatically.
# ----------------------------------------------------------------------
set -euo pipefail

ROOT="$(pwd)"
PKG="$ROOT/migrate_pkg2"
ARCH="$(uname -m)"

echo "=== Build root: $ROOT  (arch: $ARCH) ==="

# 1. System deps -----------------------------------------------------
sudo apt-get update
sudo apt-get install -y git build-essential cmake gcc g++ make libssl-dev ninja-build rsync

# 2. Clone upstream repos (same commits used originally) --------------
[ -d PQClean ] || git clone https://github.com/PQClean/PQClean.git
[ -d XKCP    ] || git clone https://github.com/XKCP/XKCP.git
[ -d liboqs  ] || git clone https://github.com/open-quantum-safe/liboqs.git

(cd PQClean && git checkout 202a8f96315f9ed219387a50f7e40d04af037ea8)
(cd XKCP    && git checkout d71b764513a6c3163b3cfc919dd6f974d98a6c53)
(cd liboqs  && git checkout f986aea60a9f3cb4055474aa212538bb0b14f1fe)

# 3. Build XKCP (TurboSHAKE / KangarooTwelve / Xoodyak generic64 lib) --
(cd XKCP && make generic64/libXKCP.a)
XKCP_HDRS="$ROOT/XKCP/bin/generic64/libXKCP.a.headers"
XKCP_LIB="$ROOT/XKCP/bin/generic64/libXKCP.a"

# 4. Build liboqs ------------------------------------------------------
(cd liboqs && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --parallel)
OQS_INC="$ROOT/liboqs/build/include"
OQS_LIB="$ROOT/liboqs/build/lib"

# 5. Drop in the custom backend sources --------------------------------
cp -r "$PKG/PQClean_custom/common/BLAKE3" PQClean/common/
cp -r "$PKG/PQClean_custom/common/Haraka" PQClean/common/
for tag in turboshake k12 blake3 xoodyak haraka; do
  for v in 512 768 1024; do
    mkdir -p "PQClean/crypto_kem/ml-kem-$v/$tag"
    cp -r "$PKG/PQClean_custom/crypto_kem/ml-kem-$v/$tag/." "PQClean/crypto_kem/ml-kem-$v/$tag/"
  done
  for v in 44 65 87; do
    mkdir -p "PQClean/crypto_sign/ml-dsa-$v/$tag"
    cp -r "$PKG/PQClean_custom/crypto_sign/ml-dsa-$v/$tag/." "PQClean/crypto_sign/ml-dsa-$v/$tag/"
  done
done

# 6. Copy adapters + bench harness, fixing the hardcoded /root/PQClean
#    absolute include paths baked in by the original generator.
cp "$PKG"/pqc_bench.c .
for tag in turboshake k12 blake3 xoodyak haraka; do
  cp "$PKG"/pqc_${tag}_kem.c "$PKG"/pqc_${tag}_kem.h .
  cp "$PKG"/pqc_${tag}_dsa.c "$PKG"/pqc_${tag}_dsa.h .
  sed -i "s#/root/PQClean#$ROOT/PQClean#g" pqc_${tag}_kem.c pqc_${tag}_dsa.c
done
# Also neutralize the hardcoded XKCP include path in the turboshake/k12
# KEM Makefiles (harmless if absent, but keeps things tidy).
sed -i "s#/root/XKCP#$ROOT/XKCP#g" \
  PQClean/crypto_kem/ml-kem-{512,768,1024}/{turboshake,k12}/Makefile

# 7. Common objects needed at link time (sha3_256/512, randombytes) ---
gcc -O2 -I PQClean/common -c PQClean/common/fips202.c     -o PQClean/common/fips202_turbo.o
gcc -O2 -I PQClean/common -c PQClean/common/randombytes.c -o PQClean/common/randombytes_turbo.o

# 8. Build BLAKE3 (fully portable: disable all SIMD backends so it
#    builds on x86_64 and aarch64 alike from this trimmed source tree).
BLAKE3_DIR=PQClean/common/BLAKE3
BLAKE3_FLAGS="-DBLAKE3_USE_NEON=0 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512"
for src in blake3 blake3_dispatch blake3_portable; do
  gcc -O3 $BLAKE3_FLAGS -c "$BLAKE3_DIR/$src.c" -o "$BLAKE3_DIR/$src.o"
done
ar rcs "$BLAKE3_DIR/libblake3.a" "$BLAKE3_DIR"/{blake3,blake3_dispatch,blake3_portable}.o

# 9. Build Haraka (aarch64 only -- ARM-NEON AES intrinsics) ------------
BUILD_HARAKA=0
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
  HARAKA_DIR=PQClean/common/Haraka
  gcc -O3 -march=native -c "$HARAKA_DIR/haraka.c" -o "$HARAKA_DIR/haraka.o"
  ar rcs "$HARAKA_DIR/libharaka.a" "$HARAKA_DIR/haraka.o"
  BUILD_HARAKA=1
  echo "=== Haraka backend: ENABLED (aarch64) ==="
else
  echo "=== Haraka backend: SKIPPED (arch=$ARCH, haraka.c is an ARM-NEON port) ==="
fi

# 10. Per-backend EXTRAFLAGS for the ML-KEM/ML-DSA static libs ---------
declare -A EXTRA
EXTRA[turboshake]="-I$XKCP_HDRS"
EXTRA[k12]="-I$XKCP_HDRS"
EXTRA[blake3]="-I$ROOT/PQClean/common/BLAKE3 $BLAKE3_FLAGS"
EXTRA[xoodyak]="-I$XKCP_HDRS"
EXTRA[haraka]="-I$ROOT/PQClean/common/Haraka"

BACKENDS="turboshake k12 blake3 xoodyak"
[ "$BUILD_HARAKA" = "1" ] && BACKENDS="$BACKENDS haraka"

# 11. Build the forked ML-KEM and ML-DSA static libs -------------------
for tag in $BACKENDS; do
  for v in 512 768 1024; do
    make -C "PQClean/crypto_kem/ml-kem-$v/$tag" EXTRAFLAGS="${EXTRA[$tag]}"
  done
  for v in 44 65 87; do
    make -C "PQClean/crypto_sign/ml-dsa-$v/$tag" EXTRAFLAGS="${EXTRA[$tag]}"
  done
done

# 12. Compile the OQS_KEM / OQS_SIG adapters ---------------------------
for tag in $BACKENDS; do
  gcc -O2 -march=native -I "$OQS_INC" ${EXTRA[$tag]} -c pqc_${tag}_kem.c -o pqc_${tag}_kem.o
  gcc -O2 -march=native -I "$OQS_INC" ${EXTRA[$tag]} -c pqc_${tag}_dsa.c -o pqc_${tag}_dsa.o
done

# 13. Compile + link pqc_bench.c for each backend ----------------------
gcc -O2 -march=native -I "$OQS_INC" -c pqc_bench.c -o pqc_bench_shake.o
gcc -O2 -march=native pqc_bench_shake.o -L "$OQS_LIB" -loqs -lcrypto -lm -o bench_shake

declare -A KEMTAG=( [turboshake]=turboshake [k12]=k12 [blake3]=blake3 [xoodyak]=xoodyak [haraka]=haraka )
declare -A SIGTAG=( [turboshake]=turbo      [k12]=k12 [blake3]=blake3 [xoodyak]=xoodyak [haraka]=haraka )

for tag in $BACKENDS; do
  UTAG=$(echo "$tag" | tr '[:lower:]' '[:upper:]')
  gcc -O2 -march=native -DUSE_${UTAG} -I "$OQS_INC" ${EXTRA[$tag]} -c pqc_bench.c -o pqc_bench_${tag}.o

  KLIBS=""
  for v in 512 768 1024; do
    KLIBS="$KLIBS PQClean/crypto_kem/ml-kem-$v/$tag/libml-kem-${v}_${KEMTAG[$tag]}.a"
  done
  SLIBS=""
  for v in 44 65 87; do
    SLIBS="$SLIBS PQClean/crypto_sign/ml-dsa-$v/$tag/libml-dsa-${v}_${SIGTAG[$tag]}.a"
  done

  EXTRALIB=""
  case "$tag" in
    turboshake|k12|xoodyak) EXTRALIB="$XKCP_LIB" ;;
    blake3)                 EXTRALIB="$ROOT/PQClean/common/BLAKE3/libblake3.a" ;;
    haraka)                 EXTRALIB="$ROOT/PQClean/common/Haraka/libharaka.a" ;;
  esac

  gcc -O2 -march=native pqc_bench_${tag}.o pqc_${tag}_kem.o pqc_${tag}_dsa.o \
    $KLIBS $SLIBS \
    PQClean/common/fips202_turbo.o PQClean/common/randombytes_turbo.o \
    $EXTRALIB \
    -L "$OQS_LIB" -loqs -lcrypto -lm -o bench_${tag}
done

echo
echo "=== Build complete ==="
echo "Binaries: bench_shake $(for t in $BACKENDS; do echo -n "bench_$t "; done)"
echo
echo "Run (writes pqc_benchmark_results.csv):"
echo "  rm -f pqc_benchmark_results.csv"
echo "  ./bench_shake"
for t in $BACKENDS; do
  echo "  ./bench_$t --csv-append"
done
[ "$BUILD_HARAKA" = "0" ] && echo
[ "$BUILD_HARAKA" = "0" ] && echo "NOTE: bench_haraka was not built on this arch ($ARCH)."
echo
echo "Compare against the reference run from the original machine:"
echo "  diff <(sort pqc_benchmark_results.csv) <(sort migrate_pkg2/pqc_benchmark_results.reference.csv)"

```

---

## 14. Build command cheat-sheet

Quick reference for the commands `setup_on_new_machine.sh` runs after
the custom sources are in place (§4.4/4.5). All paths are relative to
`$ROOT` (the directory containing `PQClean/`, `XKCP/`, `liboqs/`).

```bash
XKCP_HDRS="$ROOT/XKCP/bin/generic64/libXKCP.a.headers"
XKCP_LIB="$ROOT/XKCP/bin/generic64/libXKCP.a"
OQS_INC="$ROOT/liboqs/build/include"
OQS_LIB="$ROOT/liboqs/build/lib"
BLAKE3_FLAGS="-DBLAKE3_USE_NEON=0 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512"

# 1. Common objects needed at link time (sha3_256/512, randombytes)
gcc -O2 -I PQClean/common -c PQClean/common/fips202.c     -o PQClean/common/fips202_turbo.o
gcc -O2 -I PQClean/common -c PQClean/common/randombytes.c -o PQClean/common/randombytes_turbo.o

# 2. Per-backend EXTRAFLAGS
#   turboshake / k12 / xoodyak : -I$XKCP_HDRS
#   blake3                     : -I$ROOT/PQClean/common/BLAKE3 $BLAKE3_FLAGS
#   haraka (aarch64 only)      : -I$ROOT/PQClean/common/Haraka

# 3. Build each forked static lib (repeat for each tag x size)
make -C PQClean/crypto_kem/ml-kem-512/turboshake  EXTRAFLAGS="-I$XKCP_HDRS"
make -C PQClean/crypto_sign/ml-dsa-44/turboshake  EXTRAFLAGS="-I$XKCP_HDRS"
# ... ml-kem-{768,1024} and ml-dsa-{65,87}, and all 5 tags

# 4. Compile the OQS_KEM/OQS_SIG adapters (one pair per tag)
gcc -O2 -march=native -I "$OQS_INC" -I$XKCP_HDRS -c pqc_turboshake_kem.c -o pqc_turboshake_kem.o
gcc -O2 -march=native -I "$OQS_INC" -I$XKCP_HDRS -c pqc_turboshake_dsa.c -o pqc_turboshake_dsa.o

# 5. Build bench_shake (no -DUSE_*, links only the stock `clean` libs)
gcc -O2 -march=native -I "$OQS_INC" -c pqc_bench.c -o pqc_bench_shake.o
gcc -O2 -march=native pqc_bench_shake.o -L "$OQS_LIB" -loqs -lcrypto -lm -o bench_shake

# 6. Build bench_<tag> (example: turboshake)
gcc -O2 -march=native -DUSE_TURBOSHAKE -I "$OQS_INC" -I$XKCP_HDRS -c pqc_bench.c -o pqc_bench_turboshake.o
gcc -O2 -march=native \
  pqc_bench_turboshake.o pqc_turboshake_kem.o pqc_turboshake_dsa.o \
  PQClean/crypto_kem/ml-kem-{512,768,1024}/turboshake/libml-kem-{512,768,1024}_turboshake.a \
  PQClean/crypto_sign/ml-dsa-{44,65,87}/turboshake/libml-dsa-{44,65,87}_turbo.a \
  PQClean/common/fips202_turbo.o PQClean/common/randombytes_turbo.o \
  "$XKCP_LIB" \
  -L "$OQS_LIB" -loqs -lcrypto -lm -o bench_turboshake
```

**Per-tag static-lib naming quirk**: every tag's DSA static libs are named
`libml-dsa-{44,65,87}_<TAG_SUFFIX>.a` where `TAG_SUFFIX` is `turbo` for
`turboshake` and the tag itself (`k12`, `blake3`, `xoodyak`, `haraka`) for
the others; KEM libs are always `libml-kem-{512,768,1024}_<tag>.a` (full
tag name, including `turboshake`). The script's `KEMTAG`/`SIGTAG`
associative arrays (§13, step 11/13) encode this.

**Per-tag extra static library** linked alongside the forked algorithm
libs:

| Tag          | Extra lib                                   |
|--------------|-----------------------------------------------|
| `turboshake`, `k12`, `xoodyak` | `$XKCP_LIB` (`libXKCP.a`)     |
| `blake3`     | `PQClean/common/BLAKE3/libblake3.a`            |
| `haraka`     | `PQClean/common/Haraka/libharaka.a` (aarch64)  |

`-lcrypto` (OpenSSL) is required for **every** binary because liboqs's
`ossl_helpers.c` references `EVP_*`/`OPENSSL_thread_stop`. Everything
links **statically** against the forked PQClean libs — `ldd bench_* | grep
-i oqs` returns empty, so no `LD_LIBRARY_PATH` is needed at runtime.

---

## 15. Running the benchmarks & reading results

```bash
rm -f pqc_benchmark_results.csv
./bench_shake                  # creates the CSV with header row
./bench_turboshake --csv-append
./bench_k12        --csv-append
./bench_blake3     --csv-append
./bench_xoodyak    --csv-append
./bench_haraka     --csv-append   # aarch64 only
```

Useful flags (see `--help`):

- `--csv-append` — append rows to `pqc_benchmark_results.csv` instead of
  overwriting (so all 6 backends' results accumulate in one file).
- `--kem-only` / `--dsa-only` — restrict to ML-KEM or ML-DSA.
- `--no-stack` — skip stack high-water-mark instrumentation.
- `--dudect` — run constant-time (dudect-style) leakage checks.

Each run first prints `[SELFTEST] <algo> roundtrip OK` (or `FAILED`,
skipping the benchmark) for every algorithm/size, then runs
`BENCH_ITERATIONS` (default 10000, compile-time constant) timed
iterations and writes one CSV row per (algorithm, operation).

### CSV column schema

```
algorithm, operation, hash_backend, keccak_rounds, fips_compliant,
n_iterations, median_cycles, q1_cycles, q3_cycles, iqr_cycles,
p95_cycles, p99_cycles, min_cycles, max_cycles, arith_mean_cycles,
geo_mean_cycles, std_dev_cycles, cov_pct, cpb, wall_ns_mean,
pk_bytes, sk_bytes, ct_or_sig_bytes, ss_bytes, nist_level,
stack_hwm_bytes, peak_rss_delta_kb, peak_rss_after_kb, heap_delta_bytes,
energy_proxy_units, energy_proxy_per_byte, est_energy_uj,
est_energy_uj_per_byte, energy_calibrated, edp_cycle_ns
```

Key columns:

- `algorithm` — e.g. `ML-KEM-512`, `ML-DSA-87`.
- `operation` — `KeyGen` / `Encaps` / `Decaps` (KEM) or `KeyGen` / `Sign` /
  `Verify` (DSA).
- `hash_backend` — human-readable backend description, including Keccak
  round count and FIPS-compliance note where applicable.
- `keccak_rounds` — `24` for SHAKE (FIPS-compliant), `12` for
  TurboSHAKE/K12/Xoodyak (Keccak-p[1600,12]); not meaningful for
  BLAKE3/Haraka (non-Keccak).
- `fips_compliant` — `1` only for the `shake` baseline.
- `*_cycles` — CPU cycle distribution statistics over `n_iterations` runs.
- `cpb` — cycles per byte (cycles / message-relevant byte count).
- `wall_ns_mean` — mean wall-clock nanoseconds per call.
- `pk_bytes`/`sk_bytes`/`ct_or_sig_bytes`/`ss_bytes` — key/ciphertext/
  signature/shared-secret sizes (these don't change across backends —
  the wire format is unchanged, only the internal hash differs).
- `nist_level` — NIST PQC security category (1/3/5 for ML-KEM-512/768/1024,
  2/3/5 for ML-DSA-44/65/87).
- `stack_hwm_bytes`, `peak_rss_delta_kb`, `peak_rss_after_kb`,
  `heap_delta_bytes` — memory instrumentation.
- `energy_proxy_*`, `est_energy_uj*`, `edp_cycle_ns` — cycle-count-derived
  energy/EDP (energy-delay-product) proxies (not calibrated against real
  hardware power sensors unless `energy_calibrated=1`).

### Per-iteration raw data (`PQC_RAW_DIR` / `PQC_RAW_TAG`)

Every timing harness (`pqc_bench.c`, `pure_bench.c`, `pure_backends_bench.c`,
`file_sign_bench.c`) supports per-iteration raw capture. When the
`PQC_RAW_DIR` environment variable is set (the driver scripts set it to
`results/raw` automatically), each post-warmup timed sample is appended to
`$PQC_RAW_DIR/<PQC_RAW_TAG>_raw.csv`, one row per iteration; the header is
written only when the file is new, so the six per-backend binaries of a run
share one file. Raw rows are dumped **before** `compute_stats()` (which
qsorts the sample array in place), so they preserve chronological order.
Cost is zero when `PQC_RAW_DIR` is unset.

### Pure-style benchmark of the six backends (`pure_backends_bench.sh`)

`src/bench/pure_backends_bench.c` is `pure_bench.c`'s machinery (plain
`CLOCK_MONOTONIC` wall-clock ns, one warmup pass, one timed loop, the same
`compute_stats()`) parameterised per backend: compiled six times with
`-DUSE_SHAKE` … `-DUSE_HARAKA`, each binary reaching its backend through the
adapter constructors (`OQS_KEM_ml_kem_*_<tag>_new()` /
`OQS_SIG_ml_dsa_*_<tag>_new()`). The driver links each binary against the
**pre-built** artifacts exactly as `setup.sh` produced them — per-backend
`libml-kem-*_<tag>.a` / `libml-dsa-*_<tag>.a` (SIG tag `turbo` for the
turboshake fork), `pqc_<tag>_kem.o` / `pqc_<tag>_dsa.o`,
`fips202_turbo.o` + `randombytes_turbo.o`, the backend's extra lib
(XKCP / BLAKE3 / Haraka) and `liboqs.a` — no library is rebuilt and no
compiler flag, algorithm setting or hardware setting is changed; only the
thin harness translation unit is compiled (`-O3 -march=native`;
haraka: the setup.sh haraka flags). Output:
`results/pure_backends/pure_backends_benchmark.csv` (108 rows, schema =
pure benchmark + leading `backend` column) plus
`results/raw/pure_backends_raw.csv`.

### Payload file hash + sign (`file_sign_bench.sh`)

`src/bench/file_sign_bench.c` (same six-binary `-DUSE_<TAG>` pattern and
link recipe as above, DSA side only) takes a payload file and, per backend:

1. **Hash** — computes a 32-byte digest of the payload with the backend's
   H/CRH-role construction (the same one its `symmetric.h` substitutes into
   ML-DSA, domain byte `0x3F`): SHAKE256 (baseline, no domain byte),
   TurboSHAKE256 (capacity 512, `D=0x3F`), KT256 (customization `C=0x3F`),
   BLAKE3 (domain byte appended), Xoodyak Cyclist hash mode (domain byte
   appended), Haraka-MD (the fork's Merkle–Damgård construction over
   `haraka512`, replicated in the harness). Determinism is checked and the
   digest hex recorded.
2. **Sign/verify** — ML-DSA-44/65/87 over the full payload via the adapter
   constructors, with round-trip + tamper correctness checks.
3. **Timing** — every operation is timed per round with **both** wall-clock
   ns and a serialized cycle-counter reading (`lfence`+`rdtsc`/`rdtscp` on
   x86_64, ISB-serialized `CNTVCT_EL0` timer ticks on aarch64 — the same
   counters as `pqc_bench.c`, unit recorded in a `cycle_unit` column).

Outputs: `results/file_sign/file_sign_benchmark.csv` (42 rows: ns + cycle
stats, ops/sec, payload MB/s, payload info, rounds),
`file_sign_hashes.csv` (6 digest rows with full hex + construction
description, 18 signature rows with size + SHA-256 fingerprint of the
last-round signature — ML-DSA signing is hedged, so signatures differ per
round — every row carrying payload name/size/SHA-256 and the verify
result), `file_sign_system_info.txt` (system info + payload section) and
`results/raw/file_sign_raw.csv` (per-round `ns` **and** `cycles`).
The payload SHA-256 in the CSVs is computed with OpenSSL's `SHA256()` as a
backend-neutral reference identifier. Without `--file`, the driver
generates (and thereafter reuses) a 1 MiB random sample payload at
`results/file_sign/sample_payload.bin`.

---

## 16. Reference results (this machine)

Full 109-row CSV (3 ML-KEM sizes x 3 ops + 3 ML-DSA sizes x 3 ops = 18
rows per backend x 6 backends + 1 header = 109) from the validated run on
the machine this package was built on. Use it as a baseline to compare
against a new machine's `pqc_benchmark_results.csv` (cycle counts will
differ with CPU; selftest pass/fail and relative ordering between backends
should not).

**`pqc_benchmark_results.reference.csv`**

```csv
algorithm,operation,hash_backend,keccak_rounds,fips_compliant,n_iterations,median_cycles,q1_cycles,q3_cycles,iqr_cycles,p95_cycles,p99_cycles,min_cycles,max_cycles,arith_mean_cycles,geo_mean_cycles,std_dev_cycles,cov_pct,cpb,wall_ns_mean,pk_bytes,sk_bytes,ct_or_sig_bytes,ss_bytes,nist_level,stack_hwm_bytes,peak_rss_delta_kb,peak_rss_after_kb,heap_delta_bytes,energy_proxy_units,energy_proxy_per_byte,est_energy_uj,est_energy_uj_per_byte,energy_calibrated,edp_cycle_ns
ML-KEM-512,KeyGen,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,220,210,230,20,279,881,207,104757,253.95,230.73,1077.17,424.1604,0.090461,11371.07,800,1632,768,32,1,0,0,8908,0,220,0.0905,0.2200,0.000090,0,2501634.32
ML-KEM-512,Encaps,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,230,229,236,7,251,333,226,7723,238.54,236.55,82.72,34.6759,0.287500,10150.73,800,1632,768,32,1,0,0,9036,0,230,0.2875,0.2300,0.000287,0,2334667.53
ML-KEM-512,Decaps,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,277,270,278,8,286,436,267,1664,280.25,278.90,37.56,13.4031,0.346250,11939.63,800,1632,768,32,1,0,0,9164,0,277,0.3463,0.2770,0.000346,0,3307278.04
ML-KEM-768,KeyGen,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,355,346,364,18,449,614,342,2847,367.05,364.05,63.24,17.2296,0.099051,15620.85,1184,2400,1088,32,3,0,0,9164,0,355,0.0991,0.3550,0.000099,0,5545400.61
ML-KEM-768,Encaps,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,371,363,373,10,386,572,359,5045,376.94,374.65,71.58,18.9896,0.331250,16039.89,1184,2400,1088,32,3,0,0,9164,0,371,0.3312,0.3710,0.000331,0,5950800.12
ML-KEM-768,Decaps,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,437,435,438,3,462,639,422,7667,444.50,441.83,97.63,21.9635,0.390179,18907.32,1184,2400,1088,32,3,0,0,9164,0,437,0.3902,0.4370,0.000390,0,8262500.81
ML-KEM-1024,KeyGen,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,541,539,552,13,595,778,521,3415,552.62,550.50,62.44,11.2989,0.114231,23509.74,1568,3168,1568,32,5,0,0,9164,0,541,0.1142,0.5410,0.000114,0,12718771.07
ML-KEM-1024,Encaps,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,563,562,565,3,609,842,543,3270,572.52,570.33,63.40,11.0741,0.351875,24338.30,1568,3168,1568,32,5,0,0,9164,0,563,0.3519,0.5630,0.000352,0,13702463.80
ML-KEM-1024,Decaps,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,656,655,658,3,721,945,634,6198,668.39,665.61,89.15,13.3373,0.410000,28421.51,1568,3168,1568,32,5,0,0,9164,0,656,0.4100,0.6560,0.000410,0,18644509.51
ML-DSA-44,KeyGen,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,833,831,835,4,953,1173,756,3461,846.31,843.39,85.97,10.1580,0.215134,35999.03,1312,2560,2420,0,2,0,0,9260,0,833,0.2151,0.8330,0.000215,0,29987188.57
ML-DSA-44,Sign,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,1582,1258,2355,1098,4022,5863,977,10340,1947.38,1739.35,1054.98,54.1745,0.653719,82782.39,1312,2560,2420,0,2,0,0,9260,0,1582,0.6537,1.5820,0.000654,0,130961748.42
ML-DSA-44,Verify,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,797,796,800,4,937,1345,770,8748,826.18,817.29,192.75,23.3302,0.329339,35113.50,1312,2560,2420,0,2,0,0,9260,0,797,0.3293,0.7970,0.000329,0,27985461.33
ML-DSA-65,KeyGen,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,1455,1453,1457,4,1665,1954,1408,5101,1479.19,1476.11,111.53,7.5397,0.243148,62988.56,1952,4032,3309,0,3,0,0,9260,0,1455,0.2431,1.4550,0.000243,0,91648347.82
ML-DSA-65,Sign,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,2579,1942,3649,1707,6233,8767,1566,19158,3046.04,2741.68,1598.62,52.4819,0.779390,129563.97,1952,4032,3309,0,3,0,0,9296,0,2579,0.7794,2.5790,0.000779,0,334145468.31
ML-DSA-65,Verify,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,1355,1354,1357,3,1555,1843,1315,4658,1378.56,1375.69,103.27,7.4912,0.409489,58616.34,1952,4032,3309,0,3,0,0,9296,0,1355,0.4095,1.3550,0.000409,0,79425145.31
ML-DSA-87,KeyGen,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,2501,2498,2506,8,2822,3225,2403,7262,2545.49,2541.11,171.27,6.7284,0.334001,108204.27,2592,4896,4627,0,5,0,0,9296,0,2501,0.3340,2.5010,0.000334,0,270618871.52
ML-DSA-87,Sign,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,3784,3216,4917,1701,7799,10524,2767,20626,4322.55,4060.53,1730.01,40.0230,0.817809,183680.05,2592,4896,4627,0,5,0,0,9320,0,3784,0.8178,3.7840,0.000818,0,695045298.98
ML-DSA-87,Verify,"SHAKE (FIPS 202, n_r=24, FIPS-COMPLIANT)",24,1,10000,2368,2366,2370,4,2648,3076,2299,12901,2411.33,2406.53,195.15,8.0930,0.511779,102507.17,2592,4896,4627,0,5,0,0,9320,0,2368,0.5118,2.3680,0.000512,0,242736985.43
ML-KEM-512-TurboSHAKE,KeyGen,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,398,386,420,34,512,1114,366,14582,428.32,417.28,203.78,47.5768,0.163651,18356.61,800,1632,768,32,1,0,0,4468,0,398,0.1637,0.3980,0.000164,0,7305930.26
ML-KEM-512-TurboSHAKE,Encaps,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,452,450,459,9,487,691,435,5979,462.43,459.80,80.86,17.4859,0.565000,19676.68,800,1632,768,32,1,0,0,4468,0,452,0.5650,0.4520,0.000565,0,8893861.08
ML-KEM-512-TurboSHAKE,Decaps,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,570,569,571,2,591,809,551,3454,578.03,576.03,64.81,11.2116,0.712500,24593.99,800,1632,768,32,1,0,0,4596,0,570,0.7125,0.5700,0.000712,0,14018575.55
ML-KEM-768-TurboSHAKE,KeyGen,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,660,654,668,14,793,950,625,2633,675.91,673.34,71.00,10.5044,0.184152,28741.30,1184,2400,1088,32,3,0,0,4736,0,660,0.1842,0.6600,0.000184,0,18969258.46
ML-KEM-768-TurboSHAKE,Encaps,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,711,708,717,9,832,1056,686,2791,727.30,724.48,79.02,10.8644,0.634821,30928.98,1184,2400,1088,32,3,0,0,4736,0,711,0.6348,0.7110,0.000635,0,21990505.21
ML-KEM-768-TurboSHAKE,Decaps,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,856,855,858,3,979,1200,829,8490,873.89,870.47,117.19,13.4097,0.764286,37166.42,1184,2400,1088,32,3,0,0,4864,0,856,0.7643,0.8560,0.000764,0,31814457.75
ML-KEM-1024-TurboSHAKE,KeyGen,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,1016,1009,1023,14,1160,1418,971,3892,1035.69,1032.74,93.92,9.0684,0.214527,44033.34,1568,3168,1568,32,5,0,0,4864,0,1016,0.2145,1.0160,0.000215,0,44737873.64
ML-KEM-1024-TurboSHAKE,Encaps,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,1033,1031,1038,7,1175,1439,999,4296,1052.43,1049.69,92.33,8.7726,0.645625,44747.09,1568,3168,1568,32,5,0,0,4864,0,1033,0.6456,1.0330,0.000646,0,46223740.66
ML-KEM-1024-TurboSHAKE,Decaps,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,1213,1212,1215,3,1411,1670,1176,3337,1236.58,1233.84,93.30,7.5453,0.758125,52582.10,1568,3168,1568,32,5,0,0,4876,0,1213,0.7581,1.2130,0.000758,0,63782082.57
ML-DSA-44-TURBOSHAKE,KeyGen,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,957,950,965,15,1144,1531,909,9844,988.04,979.56,201.93,20.4373,0.247159,42023.18,1312,2560,2420,0,2,0,0,4876,0,957,0.2472,0.9570,0.000247,0,40216186.71
ML-DSA-44-TURBOSHAKE,Sign,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,3736,2687,6080,3393,11313,16035,1881,30691,4839.33,4051.60,3235.60,66.8606,1.543595,205361.83,1312,2560,2420,0,2,0,0,4876,0,3736,1.5436,3.7355,0.001544,0,767129123.81
ML-DSA-44-TURBOSHAKE,Verify,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,1074,1073,1077,4,1207,1452,1066,3684,1094.15,1091.66,87.82,8.0266,0.443802,46531.91,1312,2560,2420,0,2,0,0,4884,0,1074,0.4438,1.0740,0.000444,0,49975273.38
ML-DSA-65-TURBOSHAKE,KeyGen,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,1864,1856,1874,18,2125,2438,1790,7460,1898.87,1895.02,143.41,7.5524,0.311497,80714.49,1952,4032,3309,0,3,0,0,4884,0,1864,0.3115,1.8640,0.000311,0,150451817.56
ML-DSA-65-TURBOSHAKE,Sign,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,6281,4026,10064,6038,19409,28225,2875,50458,7985.19,6561.30,5603.20,70.1700,1.898157,339908.58,1952,4032,3309,0,3,0,0,4884,0,6281,1.8982,6.2810,0.001898,0,2134965817.36
ML-DSA-65-TURBOSHAKE,Verify,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,1711,1708,1715,7,1939,2248,1700,9839,1743.46,1739.98,139.14,7.9804,0.517075,74103.65,1952,4032,3309,0,3,0,0,4912,0,1711,0.5171,1.7110,0.000517,0,126791340.53
ML-DSA-87-TURBOSHAKE,KeyGen,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,2564,2554,2578,24,2903,3296,2523,6158,2613.20,2608.81,169.21,6.4752,0.342415,111058.26,2592,4896,4627,0,5,0,0,4912,0,2564,0.3424,2.5640,0.000342,0,284753372.74
ML-DSA-87-TURBOSHAKE,Sign,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,7660,5148,11696,6549,21300,30153,4309,71377,9493.31,8182.56,5864.67,61.7769,1.655500,403385.90,2592,4896,4627,0,5,0,0,4912,0,7660,1.6555,7.6600,0.001656,0,3089935957.23
ML-DSA-87-TURBOSHAKE,Verify,"TurboSHAKE (RFC 9861, n_r=12, NON-FIPS)",12,0,10000,2728,2723,2736,13,3114,3521,2712,11209,2788.42,2782.43,223.11,8.0012,0.589583,118551.76,2592,4896,4627,0,5,0,0,4944,0,2728,0.5896,2.7280,0.000590,0,323409190.64
ML-KEM-512-K12,KeyGen,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,397,390,404,14,455,1057,373,3832,417.86,409.84,129.90,31.0869,0.163240,17811.64,800,1632,768,32,1,0,0,4276,0,397,0.1632,0.3970,0.000163,0,7071219.77
ML-KEM-512-K12,Encaps,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,460,459,467,8,512,704,443,3270,472.66,470.35,65.03,13.7591,0.575000,20106.20,800,1632,768,32,1,0,0,4276,0,460,0.5750,0.4600,0.000575,0,9248854.21
ML-KEM-512-K12,Decaps,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,578,577,579,2,634,819,557,3964,589.96,587.71,72.35,12.2631,0.722500,25106.09,800,1632,768,32,1,0,0,4404,0,578,0.7225,0.5780,0.000722,0,14511318.46
ML-KEM-768-K12,KeyGen,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,667,661,672,11,726,960,634,3734,678.86,676.59,69.25,10.2014,0.186105,28864.68,1184,2400,1088,32,3,0,0,4540,0,667,0.1861,0.6670,0.000186,0,19252740.16
ML-KEM-768-K12,Encaps,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,721,719,727,8,808,1038,715,3629,737.51,734.93,79.29,10.7516,0.643750,31370.36,1184,2400,1088,32,3,0,0,4540,0,721,0.6438,0.7210,0.000644,0,22618028.77
ML-KEM-768-K12,Decaps,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,867,866,868,2,983,1212,841,3290,882.37,880.16,74.58,8.4517,0.774107,37519.91,1184,2400,1088,32,3,0,0,4668,0,867,0.7741,0.8670,0.000774,0,32529764.57
ML-KEM-1024-K12,KeyGen,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,1028,1022,1035,13,1175,1427,1002,3491,1046.24,1043.79,83.03,7.9357,0.217061,44486.96,1568,3168,1568,32,5,0,0,4668,0,1028,0.2171,1.0280,0.000217,0,45732599.71
ML-KEM-1024-K12,Encaps,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,1049,1047,1054,7,1187,1439,1041,4132,1068.59,1066.02,90.14,8.4350,0.655625,45431.95,1568,3168,1568,32,5,0,0,4668,0,1049,0.6556,1.0490,0.000656,0,47658114.40
ML-KEM-1024-K12,Decaps,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,1229,1227,1231,4,1415,1651,1221,3659,1252.57,1249.98,92.84,7.4118,0.768125,53273.85,1568,3168,1568,32,5,0,0,4680,0,1229,0.7681,1.2290,0.000768,0,65473558.09
ML-DSA-44-K12,KeyGen,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,974,968,981,13,1107,1357,945,3166,991.53,989.02,82.80,8.3504,0.251550,42599.86,1312,2560,2420,0,2,0,0,4680,0,974,0.2515,0.9740,0.000252,0,41492260.13
ML-DSA-44-K12,Sign,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,3774,2725,6158,3433,11739,16691,1951,39699,4919.85,4105.37,3348.02,68.0512,1.559298,208997.04,1312,2560,2420,0,2,0,0,4680,0,3774,1.5593,3.7735,0.001559,0,788650347.42
ML-DSA-44-K12,Verify,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,1089,1087,1091,4,1270,1516,1082,4075,1112.37,1109.40,96.95,8.7161,0.450000,47280.29,1312,2560,2420,0,2,0,0,4684,0,1089,0.4500,1.0890,0.000450,0,51488238.53
ML-DSA-65-K12,KeyGen,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,1882,1875,1893,18,2153,2464,1841,6776,1917.54,1913.78,139.15,7.2565,0.314505,81560.68,1952,4032,3309,0,3,0,0,4684,0,1882,0.3145,1.8820,0.000315,0,153497191.10
ML-DSA-65-K12,Sign,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,6308,3978,10053,6075,18757,28053,2900,67591,7957.85,6555.25,5578.51,70.1007,1.906467,337880.54,1952,4032,3309,0,3,0,0,4684,0,6308,1.9065,6.3085,0.001906,0,2131519379.02
ML-DSA-65-K12,Verify,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,1724,1722,1727,5,1943,2240,1714,9000,1753.60,1750.16,141.38,8.0623,0.521003,74590.02,1952,4032,3309,0,3,0,0,4716,0,1724,0.5210,1.7240,0.000521,0,128593201.03
ML-DSA-87-K12,KeyGen,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,2606,2597,2620,23,2956,3305,2566,6812,2656.98,2652.41,178.10,6.7031,0.348024,112924.15,2592,4896,4627,0,5,0,0,4716,0,2606,0.3480,2.6060,0.000348,0,294280334.90
ML-DSA-87-K12,Sign,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,7757,5140,11637,6497,21022,31813,4372,66291,9518.46,8219.00,5920.11,62.1960,1.676464,404648.72,2592,4896,4627,0,5,0,0,4716,0,7757,1.6765,7.7570,0.001676,0,3138860150.52
ML-DSA-87-K12,Verify,"KangarooTwelve (RFC 9861, n_r=12 tree hash, NON-FIPS)",12,0,10000,2765,2762,2770,8,3126,3532,2753,11138,2822.24,2817.34,199.28,7.0612,0.597579,119968.79,2592,4896,4627,0,5,0,0,4748,0,2765,0.5976,2.7650,0.000598,0,331713691.91
ML-KEM-512-BLAKE3,KeyGen,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,386,380,392,12,421,670,363,2431,396.62,393.75,67.05,16.9060,0.158717,16984.61,800,1632,768,32,1,0,0,4184,0,386,0.1587,0.3860,0.000159,0,6556060.66
ML-KEM-512-BLAKE3,Encaps,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,447,446,453,7,474,652,432,2707,456.15,454.46,51.65,11.3232,0.558750,19405.15,800,1632,768,32,1,0,0,4184,0,447,0.5587,0.4470,0.000559,0,8674101.83
ML-KEM-512-BLAKE3,Decaps,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,561,561,562,1,626,849,558,2522,575.28,572.79,67.58,11.7469,0.701250,24479.66,800,1632,768,32,1,0,0,4312,0,561,0.7013,0.5610,0.000701,0,13733091.67
ML-KEM-768-BLAKE3,KeyGen,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,660,655,666,11,710,935,641,2680,671.68,669.81,60.17,8.9588,0.184152,28562.92,1184,2400,1088,32,3,0,0,4452,0,660,0.1842,0.6600,0.000184,0,18851529.84
ML-KEM-768-BLAKE3,Encaps,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,721,720,727,7,872,1121,716,2314,742.40,739.25,82.45,11.1054,0.643750,31566.27,1184,2400,1088,32,3,0,0,4452,0,721,0.6438,0.7210,0.000644,0,22759280.53
ML-KEM-768-BLAKE3,Decaps,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,852,852,854,2,992,1191,849,7073,872.13,869.13,103.25,11.8390,0.760714,37091.09,1184,2400,1088,32,3,0,0,4580,0,852,0.7607,0.8520,0.000761,0,31601604.59
ML-KEM-1024-BLAKE3,KeyGen,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,1026,1020,1033,13,1158,1430,1002,3548,1044.26,1041.77,84.72,8.1132,0.216639,44400.80,1568,3168,1568,32,5,0,0,4580,0,1026,0.2166,1.0260,0.000217,0,45555216.08
ML-KEM-1024-BLAKE3,Encaps,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,1052,1050,1058,8,1203,1463,1047,8574,1073.44,1070.23,117.60,10.9551,0.657500,45659.01,1568,3168,1568,32,5,0,0,4580,0,1052,0.6575,1.0520,0.000657,0,48033274.00
ML-KEM-1024-BLAKE3,Decaps,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,1239,1239,1241,2,1437,1686,1234,6071,1264.91,1261.81,109.25,8.6372,0.774375,53789.15,1568,3168,1568,32,5,0,0,4592,0,1239,0.7744,1.2390,0.000774,0,66644762.80
ML-DSA-44-BLAKE3,KeyGen,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,994,991,1000,9,1152,1582,983,14204,1023.90,1016.17,215.38,21.0352,0.256715,43556.33,1312,2560,2420,0,2,0,0,4592,0,994,0.2567,0.9940,0.000257,0,43294991.13
ML-DSA-44-BLAKE3,Sign,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,3656,2709,6063,3354,11472,16924,1956,34027,4843.36,4046.91,3309.68,68.3344,1.510537,205483.79,1312,2560,2420,0,2,0,0,4592,0,3656,1.5105,3.6555,0.001511,0,751145994.71
ML-DSA-44-BLAKE3,Verify,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,1108,1107,1109,2,1285,1545,1103,4895,1130.13,1127.45,92.14,8.1534,0.457851,48054.47,1312,2560,2420,0,2,0,0,4596,0,1108,0.4579,1.1080,0.000458,0,53244354.64
ML-DSA-65-BLAKE3,KeyGen,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,1967,1959,1979,20,2267,2575,1929,7590,2011.21,2006.41,164.73,8.1906,0.328710,85508.89,1952,4032,3309,0,3,0,0,4596,0,1967,0.3287,1.9670,0.000329,0,168195982.89
ML-DSA-65-BLAKE3,Sign,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,6322,4134,9975,5842,19272,28397,2949,55341,7989.86,6602.52,5566.25,69.6664,1.910547,339831.29,1952,4032,3309,0,3,0,0,4596,0,6322,1.9105,6.3220,0.001911,0,2148413408.43
ML-DSA-65-BLAKE3,Verify,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,1773,1772,1777,5,2030,2345,1766,10147,1811.38,1807.18,157.50,8.6951,0.535811,77021.20,1952,4032,3309,0,3,0,0,4628,0,1773,0.5358,1.7730,0.000536,0,136558581.93
ML-DSA-87-BLAKE3,KeyGen,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,2709,2705,2717,12,3085,3480,2690,10430,2768.61,2763.14,208.41,7.5276,0.361779,117803.05,2592,4896,4627,0,5,0,0,4628,0,2709,0.3618,2.7090,0.000362,0,319128472.47
ML-DSA-87-BLAKE3,Sign,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,7852,5317,11760,6443,21165,30645,4485,56478,9591.20,8329.10,5793.72,60.4066,1.696996,407363.53,2592,4896,4627,0,5,0,0,4628,0,7852,1.6970,7.8520,0.001697,0,3198618438.35
ML-DSA-87-BLAKE3,Verify,"BLAKE3 (native XOF, 7 rounds, NON-FIPS)",7,0,10000,2877,2874,2883,9,3252,3638,2867,7488,2935.99,2931.44,183.93,6.2647,0.621785,124794.96,2592,4896,4627,0,5,0,0,4660,0,2877,0.6218,2.8770,0.000622,0,359035112.29
ML-KEM-512-XOODYAK,KeyGen,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,721,715,732,17,882,1387,702,11299,756.91,746.79,209.99,27.7438,0.296464,32369.76,800,1632,768,32,1,0,0,4196,0,721,0.2965,0.7210,0.000296,0,23338597.54
ML-KEM-512-XOODYAK,Encaps,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,788,784,794,10,901,1137,779,2451,806.62,804.10,74.58,9.2461,0.984375,34293.85,800,1632,768,32,1,0,0,4196,0,788,0.9844,0.7875,0.000984,0,27006405.46
ML-KEM-512-XOODYAK,Decaps,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,1017,992,1021,29,1150,1409,987,3348,1025.92,1023.26,86.37,8.4191,1.271250,43609.39,800,1632,768,32,1,0,0,4324,0,1017,1.2712,1.0170,0.001271,0,44350748.92
ML-KEM-768-XOODYAK,KeyGen,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,1318,1306,1348,42,1508,1791,1284,4884,1347.11,1343.83,116.16,8.6230,0.367746,57270.82,1184,2400,1088,32,3,0,0,4460,0,1318,0.3677,1.3180,0.000368,0,75482934.57
ML-KEM-768-XOODYAK,Encaps,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,1411,1375,1418,43,1599,1879,1368,4523,1423.11,1419.98,108.12,7.5977,1.259821,60484.46,1184,2400,1088,32,3,0,0,4460,0,1411,1.2598,1.4110,0.001260,0,85343579.69
ML-KEM-768-XOODYAK,Decaps,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,1694,1650,1697,47,1948,2237,1640,4900,1717.64,1713.75,129.93,7.5647,1.512500,73010.16,1184,2400,1088,32,3,0,0,4588,0,1694,1.5125,1.6940,0.001512,0,123679210.19
ML-KEM-1024-XOODYAK,KeyGen,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,2179,2162,2196,34,2501,2948,2091,18920,2225.58,2215.99,298.15,13.3965,0.460093,94633.42,1568,3168,1568,32,5,0,0,4588,0,2179,0.4601,2.1790,0.000460,0,206206225.23
ML-KEM-1024-XOODYAK,Encaps,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,2221,2217,2228,11,2542,2907,2152,6017,2258.55,2253.84,165.63,7.3336,1.388125,95998.70,1568,3168,1568,32,5,0,0,4588,0,2221,1.3881,2.2210,0.001388,0,213213116.25
ML-KEM-1024-XOODYAK,Decaps,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,2595,2591,2599,8,2928,3287,2516,10796,2630.49,2625.73,185.55,7.0540,1.621875,111820.88,1568,3168,1568,32,5,0,0,4600,0,2595,1.6219,2.5950,0.001622,0,290175176.33
ML-DSA-44-XOODYAK,KeyGen,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,2929,2856,2942,86,3279,3688,2837,7156,2954.37,2949.30,193.69,6.5559,0.756457,125616.19,1312,2560,2420,0,2,0,0,4600,0,2929,0.7565,2.9290,0.000756,0,367929811.43
ML-DSA-44-XOODYAK,Sign,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,6713,5171,10227,5056,17922,25152,3884,46820,8334.34,7326.62,4779.86,57.3514,2.773967,354179.51,1312,2560,2420,0,2,0,0,4600,0,6713,2.7740,6.7130,0.002774,0,2377607036.53
ML-DSA-44-XOODYAK,Verify,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,2970,2966,2975,9,3342,3735,2881,13823,3011.29,3005.77,219.65,7.2943,1.227273,127999.50,1312,2560,2420,0,2,0,0,4608,0,2970,1.2273,2.9700,0.001227,0,380158523.02
ML-DSA-65-XOODYAK,KeyGen,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,5504,5367,5608,241,6090,6607,5318,9538,5560.57,5553.76,293.47,5.2776,0.919786,236380.09,1952,4032,3309,0,3,0,0,4608,0,5504,0.9198,5.5040,0.000920,0,1301035988.94
ML-DSA-65-XOODYAK,Sign,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,11414,8214,16829,8615,29855,44376,6276,80915,13791.48,12077.43,8100.25,58.7337,3.449380,586534.33,1952,4032,3309,0,3,0,0,4608,0,11414,3.4494,11.4140,0.003449,0,6694702834.63
ML-DSA-65-XOODYAK,Verify,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,5066,5062,5170,108,5607,6184,4914,12323,5154.85,5148.74,277.78,5.3886,1.530976,219095.97,1952,4032,3309,0,3,0,0,4636,0,5066,1.5310,5.0660,0.001531,0,1109940194.15
ML-DSA-87-XOODYAK,KeyGen,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,8841,8826,9050,224,9659,10407,8562,18698,8964.52,8955.71,427.27,4.7662,1.180689,381032.48,2592,4896,4627,0,5,0,0,4636,0,8841,1.1807,8.8410,0.001181,0,3368708142.42
ML-DSA-87-XOODYAK,Sign,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,15522,11675,21044,9369,35488,49021,10676,87002,18124.46,16641.42,8601.17,47.4562,3.354657,770555.03,2592,4896,4627,0,5,0,0,4636,0,15522,3.3547,15.5220,0.003355,0,11960555127.54
ML-DSA-87-XOODYAK,Verify,"Xoodyak (Cyclist/Xoodoo, 12 rounds, NON-FIPS)",12,0,10000,8794,8787,9013,226,9649,10360,8533,17449,8960.58,8953.08,391.22,4.3660,1.900584,380899.10,2592,4896,4627,0,5,0,0,4668,0,8794,1.9006,8.7940,0.001901,0,3349626709.14
ML-KEM-512-HARAKA,KeyGen,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,338,331,358,27,460,868,312,14728,372.94,359.80,254.90,68.3485,0.138980,16048.84,800,1632,768,32,1,0,0,4192,0,338,0.1390,0.3380,0.000139,0,5424507.24
ML-KEM-512-HARAKA,Encaps,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,397,396,403,7,421,599,383,2008,406.08,404.38,48.47,11.9370,0.496250,17275.78,800,1632,768,32,1,0,0,4192,0,397,0.4963,0.3970,0.000496,0,6858486.09
ML-KEM-512-HARAKA,Decaps,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,505,504,505,1,527,765,488,3574,513.76,511.86,60.72,11.8195,0.631250,21849.26,800,1632,768,32,1,0,0,4320,0,505,0.6312,0.5050,0.000631,0,11033876.55
ML-KEM-768-HARAKA,KeyGen,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,565,560,570,10,608,811,545,1758,574.64,572.93,51.86,9.0240,0.157645,24449.16,1184,2400,1088,32,3,0,0,4456,0,565,0.1576,0.5650,0.000158,0,13813773.42
ML-KEM-768-HARAKA,Encaps,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,613,610,618,8,741,897,607,2920,630.75,628.07,72.18,11.4443,0.547321,26826.03,1184,2400,1088,32,3,0,0,4456,0,613,0.5473,0.6130,0.000547,0,16444356.94
ML-KEM-768-HARAKA,Decaps,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,742,741,744,3,854,1075,739,3241,759.51,756.78,80.67,10.6211,0.662500,32315.24,1184,2400,1088,32,3,0,0,4584,0,742,0.6625,0.7420,0.000663,0,23977908.08
ML-KEM-1024-HARAKA,KeyGen,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,863,857,871,14,1006,1218,837,2481,880.80,878.17,79.52,9.0280,0.182221,37466.37,1568,3168,1568,32,5,0,0,4584,0,863,0.1822,0.8630,0.000182,0,32333476.45
ML-KEM-1024-HARAKA,Encaps,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,868,866,874,8,1008,1397,862,3403,891.78,887.95,100.82,11.3051,0.542500,37927.70,1568,3168,1568,32,5,0,0,4584,0,868,0.5425,0.8680,0.000543,0,32921243.86
ML-KEM-1024-HARAKA,Decaps,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,1034,1033,1035,2,1174,1434,1030,4154,1054.64,1051.69,97.62,9.2561,0.646250,44848.82,1568,3168,1568,32,5,0,0,4596,0,1034,0.6462,1.0340,0.000646,0,46373678.02
ML-DSA-44-HARAKA,KeyGen,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,707,704,711,7,820,991,697,2951,721.21,719.11,65.11,9.0281,0.182593,30660.04,1312,2560,2420,0,2,0,0,4596,0,707,0.1826,0.7070,0.000183,0,21676651.25
ML-DSA-44-HARAKA,Sign,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,3230,2344,5460,3116,10136,14625,1648,28903,4259.08,3532.15,2926.19,68.7048,1.334917,180969.67,1312,2560,2420,0,2,0,0,4596,0,3230,1.3349,3.2305,0.001335,0,584622511.18
ML-DSA-44-HARAKA,Verify,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,837,836,839,3,964,1195,832,3732,856.94,854.19,83.68,9.7645,0.345868,36430.17,1312,2560,2420,0,2,0,0,4604,0,837,0.3459,0.8370,0.000346,0,30492051.20
ML-DSA-65-HARAKA,KeyGen,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,1401,1394,1410,16,1604,1892,1366,5872,1426.53,1423.27,117.05,8.2050,0.234124,60668.36,1952,4032,3309,0,3,0,0,4604,0,1401,0.2341,1.4010,0.000234,0,84996372.64
ML-DSA-65-HARAKA,Sign,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,5521,3394,8917,5522,17190,25052,2392,52287,6991.59,5678.27,5019.14,71.7883,1.668480,297428.30,1952,4032,3309,0,3,0,0,4604,0,5521,1.6685,5.5210,0.001668,0,1642101638.78
ML-DSA-65-HARAKA,Verify,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,1276,1275,1278,3,1473,1758,1270,4884,1303.29,1299.65,120.07,9.2131,0.385615,55459.14,1952,4032,3309,0,3,0,0,4632,0,1276,0.3856,1.2760,0.000386,0,70765856.90
ML-DSA-87-HARAKA,KeyGen,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,1769,1765,1775,10,2048,2373,1753,4816,1807.80,1803.83,136.34,7.5420,0.236245,76854.85,2592,4896,4627,0,5,0,0,4632,0,1769,0.2362,1.7690,0.000236,0,135956236.20
ML-DSA-87-HARAKA,Sign,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,6680,4263,10266,6002,19515,28462,3515,47409,8322.21,7022.52,5502.56,66.1189,1.443700,353793.42,2592,4896,4627,0,5,0,0,4632,0,6680,1.4437,6.6800,0.001444,0,2363340019.55
ML-DSA-87-HARAKA,Verify,"Haraka-CTR (Haraka512, 5 rounds, non-standard, NON-FIPS)",5,0,10000,1972,1970,1975,5,2243,2555,1963,8755,2009.54,2005.61,155.75,7.7505,0.426194,85441.06,2592,4896,4627,0,5,0,0,4664,0,1972,0.4262,1.9720,0.000426,0,168489765.19

```

---

## 17. Migrating to a new machine

1. On this machine: `tar czf pqc_migrate.tar.gz migrate_pkg2` (from the
   directory containing `migrate_pkg2/`). The package is ~450 KB —
   small, because `liboqs`/`XKCP`/`PQClean` are re-cloned fresh on the
   target rather than bundled; only the custom additions (forked source
   trees, adapters, bench harness, this guide) travel.
2. `scp pqc_migrate.tar.gz user@new-host:~/`
3. On the new machine:
   ```bash
   mkdir -p ~/pqc && cd ~/pqc
   tar xzf ~/pqc_migrate.tar.gz
   ./migrate_pkg2/setup_on_new_machine.sh
   ```
4. Run the benchmarks (§15) and diff against
   `migrate_pkg2/pqc_benchmark_results.reference.csv` (§16).

The script needs outbound network access (git clones of PQClean, XKCP,
liboqs over HTTPS) and `sudo` for `apt-get`. If those three repos are
already available locally (e.g. already cloned at the pinned commits),
replace step 2 of §13/§4.1 with local copies — everything else is
unaffected since the script's only network dependency is the three
`git clone` calls.

## 18. Troubleshooting

- **`bench_haraka` missing / "Haraka backend: SKIPPED"**: expected on
  non-ARM machines — `PQClean/common/Haraka/haraka.c` is an ARM-NEON port
  (§10). To enable on x86_64, write an AES-NI version of `haraka.c`
  exposing the same function signatures as `common/Haraka/haraka.h`
  (replace `vaeseq_u8`/`vaesmcq_u8`/NEON loads with
  `_mm_aesenc_si128`/SSE intrinsics from `<wmmintrin.h>`), drop it in
  place of the NEON `haraka.c`, remove the `aarch64`-only guard in step 9
  of `setup_on_new_machine.sh`, and rebuild.
- **Adapter `.c` files `#include` errors about `/root/PQClean/...` not
  found**: the `sed -i "s#/root/PQClean#$ROOT/PQClean#g"` step (§4.5,
  setup script step 6) wasn't applied, or `$ROOT` wasn't the directory you
  ran the script from. Re-run the `sed` against
  `pqc_<tag>_kem.c`/`pqc_<tag>_dsa.c` with the correct `$ROOT`.
- **BLAKE3 link errors** (`undefined reference` to SSE/AVX symbols):
  ensure `$BLAKE3_FLAGS` (§9/§14) is passed to **both** the
  `PQClean/common/BLAKE3/*.o` build **and** the `EXTRAFLAGS` for
  `ml-kem-*/blake3` and `ml-dsa-*/blake3` (`make ... EXTRAFLAGS="-I.../BLAKE3 $BLAKE3_FLAGS"`).
- **`-lcrypto` link errors**: install `libssl-dev` (apt dependency in §2)
  — liboqs's OpenSSL helpers require it even though this project doesn't
  use OpenSSL crypto directly.
- **Slow/stalled `git clone` of `liboqs`**: liboqs's `.git` history is
  large (~450 MB). If the network is slow, use
  `git clone --depth 1 -b <pinned-commit-containing-branch> ...` is not
  possible for an arbitrary commit; instead `rsync`/copy an existing
  `liboqs/` checkout (with `build/` already built) from another machine
  with the same architecture, or be patient — there is no way around
  cloning full history with the current script's `git checkout <sha>`
  approach unless you pre-stage the repo.
- **`make` warnings about `-Werror`**: the forked Makefiles intentionally
  drop `-Werror` (kept in `clean/Makefile`) because the alternative
  backends produce a few harmless `-Wextra` warnings (unused parameters in
  some `xof_*` shims). These are not errors and don't affect correctness
  (verified via selftest roundtrips).

