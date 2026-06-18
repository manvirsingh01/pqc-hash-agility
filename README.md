# PQC Hash-Agility Benchmark

Benchmarks **ML-KEM** (FIPS 203) and **ML-DSA** (FIPS 204) across six hash backends, showing the performance cost or gain of replacing the default SHAKE/SHA-3 XOF with alternative hash functions.

| Backend | Hash primitive | FIPS compliant |
|---|---|---|
| `shake` | SHAKE128/256 (n_r=24) — liboqs built-in | Yes |
| `turboshake` | TurboSHAKE128/256 (n_r=12, RFC 9861) | No |
| `k12` | KangarooTwelve (tree hash, n_r=12, RFC 9861) | No |
| `blake3` | BLAKE3 XOF (portable, all SIMD off) | No |
| `xoodyak` | Xoodyak / Xoodoo\[12\] permutation | No |
| `haraka` | Haraka-256/512 v2 (AES-NI on x86_64, NEON on aarch64) | No |

**Algorithms benchmarked:** ML-KEM-512 / 768 / 1024 and ML-DSA-44 / 65 / 87

**Operations benchmarked:** keygen, encaps/decaps (KEM), sign/verify (DSA)

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/manvirsingh01/pqc-hash-agility.git
cd pqc-hash-agility

# 2. Build everything (takes ~15–25 min; clones PQClean, XKCP, liboqs)
bash setup.sh

# 3. Run benchmarks — produces TWO CSV files + system_info.txt
bash bench.sh

# 4. View results
cat custom_benchmark.csv          # our 6 backends x 6 algorithms
cat library_default_benchmark.csv # same 6 algorithms via OQS API, all 6 backends
cat system_info.txt               # CPU cores, threads, frequency, ISA features

# 5. (Optional) Run variable k-value KEM benchmark
bash kem_k_bench.sh               # interactive: choose backend + k=1..8
```

---

## Prerequisites

- Linux x86\_64 or aarch64
- Root or sudo-free user (setup.sh uses `apt-get` directly)
- Internet access (to clone three upstream repos)
- ~4 GB free disk space

The setup script installs these packages automatically:
```
build-essential  cmake  gcc  g++  make  libssl-dev
ninja-build  rsync  xsltproc  git
```

---

## Repository Layout

```
pqc-hash-agility/
├── setup.sh                  # one-shot: clone, patch, build everything
├── bench.sh                  # run all backends -> two CSV files
├── kem_k_bench.sh            # interactive variable-k ML-KEM benchmark
├── system_info.sh            # generate system_info.txt (CPU/memory/ISA)
├── src/
│   ├── pqc_bench.c           # benchmark harness (compiled 6x with -DUSE_<TAG>)
│   ├── adapters/             # OQS_KEM / OQS_SIG wrapper shims (10 adapter pairs)
│   │   ├── pqc_turboshake_kem.{c,h}
│   │   ├── pqc_turboshake_dsa.{c,h}
│   │   ├── pqc_k12_kem.{c,h}
│   │   ├── pqc_k12_dsa.{c,h}
│   │   ├── pqc_blake3_kem.{c,h}
│   │   ├── pqc_blake3_dsa.{c,h}
│   │   ├── pqc_xoodyak_kem.{c,h}
│   │   ├── pqc_xoodyak_dsa.{c,h}
│   │   ├── pqc_haraka_kem.{c,h}
│   │   └── pqc_haraka_dsa.{c,h}
│   ├── common/
│   │   ├── BLAKE3/           # blake3.{c,h}, dispatch, portable implementation
│   │   └── Haraka/           # haraka.c (aarch64 NEON) + haraka_x86.c (AES-NI)
│   └── bench/
│       ├── full_bench.c      # single binary: all backends, correctness + timing
│       ├── liboqs_bench.c    # all 6 backends via OQS adapter API
│       └── Makefile
├── PQClean_custom/           # forked ML-KEM/ML-DSA backend implementations
│   ├── crypto_kem/
│   │   └── ml-kem-{512,768,1024}/{turboshake,k12,blake3,xoodyak,haraka}/
│   └── crypto_sign/
│       └── ml-dsa-{44,65,87}/{turboshake,k12,blake3,xoodyak,haraka}/
├── results/
│   └── reference_aarch64.csv  # reference run on ARM (Kali Linux, aarch64)
└── IMPLEMENTATION_GUIDE.md    # full code walkthrough and design rationale
```

---

## What setup.sh Does (Step by Step)

| Step | Action |
|---|---|
| 1 | `apt-get install` build deps including `xsltproc` (required by XKCP) |
| 2 | Clone PQClean, XKCP (with `--recurse-submodules`), liboqs at pinned commits |
| 3 | Build XKCP `generic64/libXKCP.a` (provides TurboSHAKE, K12, Xoodyak) |
| 4 | Build liboqs with Ninja, full build (provides `liboqs.a` static lib) |
| 5 | Drop custom backend sources into `PQClean/common/` and each variant dir |
| 6 | Patch hardcoded `/root/PQClean` paths to the actual install path |
| 7 | Select Haraka source: `haraka_x86.c` (AES-NI) or `haraka.c` (NEON) |
| 8 | Compile `fips202_turbo.o` and `randombytes_turbo.o` helper objects |
| 9 | Build BLAKE3 with all SIMD disabled (portable across x86\_64 + aarch64) |
| 10 | Build Haraka common lib with architecture-specific flags |
| 11–13 | Build all 30 forked static libs in parallel; compile 10 adapter objects |
| 14–15 | Link 6 benchmark binaries **statically** against `liboqs.a` (no runtime `LD_LIBRARY_PATH` needed) |

### Pinned upstream commits

| Repo | Commit |
|---|---|
| PQClean | `202a8f96315f9ed219387a50f7e40d04af037ea8` |
| XKCP | `d71b764513a6c3163b3cfc919dd6f974d98a6c53` |
| liboqs | `f986aea60a9f3cb4055474aa212538bb0b14f1fe` |

---

## Benchmark Scripts

### bench.sh — Main Benchmark (Two CSV Files)

Produces **two separate CSV files** in one run, plus a `system_info.txt` with full hardware details.

#### CSV 1 — `custom_benchmark.csv`

Runs all six custom backends sequentially using the per-backend binaries:

```
bench_shake        # FIPS baseline
bench_turboshake   # appends
bench_k12
bench_blake3
bench_xoodyak
bench_haraka       # AES-NI (x86_64) or NEON (aarch64)
```

108 rows: 6 backends x 6 algorithms x 3 operations (keygen/encaps/decaps or keygen/sign/verify).

#### CSV 2 — `library_default_benchmark.csv`

Tests the same **6 backends x 6 algorithms** (ML-KEM-512/768/1024 + ML-DSA-44/65/87) through the liboqs `OQS_KEM` / `OQS_SIG` adapter API. Uses our custom adapter constructors for each backend.

108 rows with the same structure, allowing direct column-for-column comparison with `custom_benchmark.csv`.

#### Options

```
--iters   N       custom benchmark iterations per operation (default 1000)
--liters  N       default benchmark iterations per operation (default 200)
--warmup  N       warmup iterations before timing            (default 100)
--no-haraka       skip Haraka backend
--custom-only     produce custom_benchmark.csv only
--default-only    produce library_default_benchmark.csv only
```

---

### kem_k_bench.sh — Variable k-Value ML-KEM Benchmark

Interactive script to benchmark ML-KEM with **non-standard module ranks** (k=1 through k=8).

Standard ML-KEM uses k=2 (ML-KEM-512), k=3 (ML-KEM-768), k=4 (ML-KEM-1024). This script lets you go beyond that range for research purposes.

```bash
bash kem_k_bench.sh
bash kem_k_bench.sh --iters 500 --warmup 50
```

#### How it works

1. Interactive menu to select backend (shake/turboshake/k12/blake3/xoodyak/haraka or ALL)
2. Enter k values (space-separated, e.g. `1 2 3 4 5 6 7 8`)
3. For each combination, the script:
   - Copies ML-KEM source from the closest standard variant
   - Patches `params.h` with the requested k value and derived parameters
   - Patches `api.h` with computed key/ciphertext sizes
   - Recompiles and links the variant
   - Runs correctness check (keygen -> encaps -> decaps -> memcmp)
   - Times keygen, encaps, decaps
4. Results appended to `kem_k_benchmark.csv`

#### k-value parameter table

| k | ETA1 | ETA2 | du | dv | pk bytes | sk bytes | ct bytes |
|---|---|---|---|---|---|---|---|
| 1 | 3 | 2 | 10 | 4 | 416 | 864 | 448 |
| 2 | 3 | 2 | 10 | 4 | 800 | 1632 | 768 |
| 3 | 2 | 2 | 10 | 4 | 1184 | 2400 | 1088 |
| 4 | 2 | 2 | 11 | 5 | 1568 | 3168 | 1568 |
| 5 | 2 | 2 | 11 | 5 | 1952 | 3936 | 1920 |
| 6 | 2 | 2 | 11 | 5 | 2336 | 4704 | 2272 |
| 7 | 2 | 2 | 11 | 5 | 2720 | 5472 | 2624 |
| 8 | 2 | 2 | 11 | 5 | 3104 | 6240 | 2976 |

#### CSV columns (`kem_k_benchmark.csv`)

```
backend, k_value, algorithm, type, operation,
correctness, iterations,
mean_ns, median_ns, min_ns, max_ns,
stddev_ns, p95_ns, p99_ns, ops_per_sec,
pk_bytes, sk_bytes, ct_bytes, ss_bytes,
eta1, eta2, du_bits, dv_bits
```

---

### system_info.sh — Hardware Information

Generated automatically by `bench.sh` and `kem_k_bench.sh`. Produces `system_info.txt` with:

| Section | Details |
|---|---|
| CPU | Model, architecture, physical cores, logical CPUs, threads/core, hyperthreading |
| Frequency | Current/min/max MHz, CPU governor |
| ISA Features | AES-NI, AVX2, AVX-512, SSE4.1, SHA-NI, NEON |
| Memory | Total RAM, available RAM |
| OS/Kernel | Kernel version, OS name, compiler version |
| Threading | Confirms single-threaded sequential execution, no CPU pinning |

---

## Benchmark Design: Why Results Are Unbiased

| Property | How it's achieved |
|---|---|
| **Fixed iteration count** | `--iterations N` (not time-based), so results are the same regardless of CPU speed |
| **Wall-clock timing** | `clock_gettime(CLOCK_MONOTONIC)` — portable, no rdtsc, no architecture dependency |
| **Sequential** | All operations are single-threaded; no async, no parallel tasks |
| **Warmup** | `--warmup 100` discards first 100 calls (cache/branch-predictor warm-up) |
| **Median reported** | Median latency is reported (robust to OS scheduling outliers) |
| **Static linking** | Binaries statically link `liboqs.a` — no shared-lib lookup overhead |
| **Same compiler flags** | All backends compiled with `-O3 -march=native` |
| **System info captured** | `system_info.txt` records CPU model, cores, frequency, governor, ISA features alongside every benchmark run |

> **Note on CPU frequency:** For the most stable numbers, pin your CPU governor before running:
> ```bash
> cpupower frequency-set --governor performance   # bench.sh does this automatically if cpupower is installed
> ```

---

## CSV Output Format

### `custom_benchmark.csv`

108 rows (6 backends x 6 algorithms x 3 operations). Key columns:

| Column | Description |
|---|---|
| `hash_backend` | Which of the 6 backends |
| `algorithm` | ML-KEM-512/768/1024 or ML-DSA-44/65/87 |
| `operation` | keygen / encaps / decaps / sign / verify |
| `fips_compliant` | `yes` (shake only) or `no` |
| `wall_ns_median` | Median operation latency in nanoseconds |
| `ops_per_sec` | Operations per second |
| `nist_level` | NIST security category (1/3/5) |

### `library_default_benchmark.csv`

108 rows (same structure). Tests all 6 backends through OQS adapter API. Columns:

| Column | Description |
|---|---|
| `backend` | shake / turboshake / k12 / blake3 / xoodyak / haraka |
| `algorithm` | ML-KEM-512/768/1024 or ML-DSA-44/65/87 |
| `type` | `KEM` or `SIG` |
| `operation` | keygen / encaps / decaps / sign / verify |
| `correctness` | `PASS` or `FAIL` |
| `mean_ns`, `median_ns`, `min_ns`, `max_ns` | Timing statistics |
| `stddev_ns`, `p95_ns`, `p99_ns` | Dispersion statistics |
| `ops_per_sec` | Operations per second |
| `pk_bytes`, `sk_bytes`, `ct_or_sig_bytes`, `ss_bytes` | Key/ciphertext sizes |
| `nist_level` | NIST security category (1/3/5) |

### `kem_k_benchmark.csv`

Variable number of rows depending on chosen k values and backends. See [kem_k_bench.sh](#kem_k_benchsh--variable-k-value-ml-kem-benchmark) for column details.

---

## How the Code Works

### Symmetric backend substitution

Each backend replaces `symmetric-shake.c` in PQClean with a custom `symmetric-<tag>.c`. This file implements:
- `hash_h(out, in, inlen)` — SHA3-256 equivalent
- `hash_g(out, in, inlen)` — SHA3-512 equivalent
- `xof_*(state, ...)` — XOF absorb/squeeze for matrix sampling
- `prf(out, outlen, key, nonce)` — PRF for noise sampling
- `rkprf(ss, key, ct)` — KDF for final shared secret

### The 5 custom `symmetric-<tag>.c` files

```
symmetric-turboshake.c  — TurboSHAKE128/256 (n_r=12, XKCP)
symmetric-k12.c         — KangarooTwelve (tree hash, XKCP)
symmetric-blake3.c      — BLAKE3 XOF (blake3_hasher_init_derive_key_raw)
symmetric-xoodyak.c     — Xoodyak (Cyclist mode, XKCP)
symmetric-haraka.c      — Haraka-256/512 (AES round function)
```

### Adapter shims

The 10 adapter files (`pqc_<tag>_{kem,dsa}.{c,h}`) wrap each variant's PQClean API into liboqs `OQS_KEM` / `OQS_SIG` structs:

```c
OQS_KEM *OQS_KEM_ml_kem_512_turboshake_new(void);
OQS_SIG *OQS_SIG_ml_dsa_44_blake3_new(void);
// etc.
```

### Benchmark harness

`pqc_bench.c` is compiled six times:
```bash
gcc -DUSE_TURBOSHAKE  ... -o bench_turboshake
gcc -DUSE_K12         ... -o bench_k12
# etc. (no -DUSE_* -> bench_shake uses liboqs OQS_KEM_new)
```

### liboqs_bench — All backends via OQS API

`liboqs_bench.c` uses a function pointer table to test all 6 backends:
- `shake` — calls `OQS_KEM_new()` / `OQS_SIG_new()` (liboqs default)
- `turboshake` — calls `OQS_KEM_ml_kem_512_turboshake_new()` etc.
- `k12` / `blake3` / `xoodyak` / `haraka` — same pattern via adapter constructors

Each backend x algorithm combination goes through the same `OQS_KEM_keypair()` / `OQS_KEM_encaps()` / `OQS_KEM_decaps()` API with correctness verification before timing.

---

## All-in-one Correctness + Benchmark Binary

For full correctness testing alongside benchmarks:

```bash
# Build (from build root where setup.sh ran)
make -f pqc-hash-agility/src/bench/Makefile

# Run with correctness checks
./full_bench --iters 500 --warmup 20 --csv full_benchmark_results.csv
```

This runs all 36 variants (6 backends x 6 algorithms) in one pass,
tests keygen->encaps->decaps and keygen->sign->verify correctness (PASS/FAIL),
and reports detailed timing stats (mean, median, min, max, stddev, ops/sec).

---

## Reference Results (aarch64, ARM Kali Linux)

See `results/reference_aarch64.csv` for the complete custom benchmark reference run.

Quick comparison (median keygen latency, us):

| Algorithm | shake | turboshake | k12 | blake3 | xoodyak | haraka |
|---|---|---|---|---|---|---|
| ML-KEM-512 | **11** | 16 | 16 | 16 | 31 | 14 |
| ML-KEM-768 | **16** | 27 | 29 | 27 | 56 | 24 |
| ML-KEM-1024 | **22** | 41 | 43 | 43 | 93 | 36 |
| ML-DSA-44 | 34 | 40 | 40 | 42 | 119 | **31** |
| ML-DSA-65 | 59 | 76 | 80 | 87 | 224 | **58** |
| ML-DSA-87 | 102 | 104 | 108 | 113 | 359 | **74** |

Variable-k results (median keygen latency, us, turboshake backend):

| k | pk bytes | ct bytes | keygen | encaps | decaps |
|---|---|---|---|---|---|
| 1 | 416 | 448 | 7 | 10 | 13 |
| 2 | 800 | 768 | 16 | 19 | 23 |
| 3 | 1184 | 1088 | 27 | 29 | 35 |
| 4 | 1568 | 1568 | 44 | 45 | 52 |
| 5 | 1952 | 1920 | 61 | 57 | 66 |
| 8 | 3104 | 2976 | 129 | 139 | 139 |

**Observations:**
- `shake` wins on KEM (liboqs has hardware-accelerated Keccak on ARM)
- `haraka` is fastest on DSA (ARM NEON AES is extremely fast)
- `xoodyak` is consistently the slowest (Xoodoo has high cycle cost per output byte)
- `turboshake` and `k12` are close to each other; ~30–40% slower than shake on ARM
- Keygen scales roughly as O(k^2), encaps/decaps similarly, consistent with lattice matrix multiplication

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Makefile:2: support/XKCBuild/src/Main.makefile: No such file or directory` | Fixed in this repo: XKCP is cloned without `--depth=1` so submodules initialise |
| `xsltproc: command not found` | Fixed: `xsltproc` is now in the `apt-get install` line |
| `bench_shake` shows 0 for all results | Fixed: all binaries now statically link `liboqs.a`; no `LD_LIBRARY_PATH` needed |
| `error: cannot find -loqs` | Run `setup.sh` first to build liboqs |
| Haraka: `requires AES-NI` | On x86\_64 without AES-NI, run `bench.sh --no-haraka` |
| Slow liboqs clone | The script uses `--depth=1` for liboqs; still ~100MB on slow networks |
| `-Werror` from PQClean | PQClean uses `-Werror`; if gcc version differs, ignore (builds succeed) |
| `kem_k_bench.sh` FAIL for high k | Ensure setup.sh completed; the script recompiles from PQClean sources |

---

## Implementation Guide

See [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) for the full code walkthrough:
all `symmetric-<tag>.c` implementations, the `mldsa_refactor.py` patch script,
all 20 adapter files, the full benchmark harness source, build commands, and
design rationale for every decision.
