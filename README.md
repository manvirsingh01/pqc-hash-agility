# PQC Hash-Agility Benchmark

Benchmarks **ML-KEM** (FIPS 203) and **ML-DSA** (FIPS 204) across six hash backends, showing the performance cost or gain of replacing the default SHAKE/SHA-3 XOF with alternative hash functions.

| Backend | Hash primitive | Keccak rounds | SIMD tier | FIPS |
|---|---|---|---|---|
| `shake` | SHAKE128/256 — liboqs scalar Keccak | 24 | None (scalar) | Yes |
| `turboshake` | TurboSHAKE128/256 (RFC 9861) | 12 | None (scalar) | No |
| `k12` | KangarooTwelve (tree hash, RFC 9861) | 12 | None (scalar) | No |
| `blake3` | BLAKE3 XOF (portable) | N/A (7) | None (all SIMD disabled) | No |
| `xoodyak` | Xoodyak / Xoodoo\[12\] | 12 (Xoodoo) | None (scalar) | No |
| `haraka` | Haraka-256/512 v2 (AES round) | N/A (5) | AES-NI / NEON | No |

> **Implementation parity:** All backends are compiled at the same scalar optimisation tier (`-O3`, no `-march=native`). liboqs is built with `OQS_DIST_BUILD=OFF` and `OQS_USE_OPENSSL=OFF` to force scalar Keccak. This ensures the comparison measures algorithm properties (round count, permutation) rather than SIMD vectorisation differences.

**Algorithms benchmarked:** ML-KEM-512 / 768 / 1024 and ML-DSA-44 / 65 / 87

**Operations benchmarked:** keygen, encaps/decaps (KEM), sign/verify (DSA)

### Algorithm Payloads

| Algorithm | PK (bytes) | SK (bytes) | CT/SIG (bytes) | SS (bytes) | NIST Level |
|---|---|---|---|---|---|
| ML-KEM-512 | 800 | 1,632 | 768 | 32 | 1 |
| ML-KEM-768 | 1,184 | 2,400 | 1,088 | 32 | 3 |
| ML-KEM-1024 | 1,568 | 3,168 | 1,568 | 32 | 5 |
| ML-DSA-44 | 1,312 | 2,560 | 2,420 | — | 2 |
| ML-DSA-65 | 1,952 | 4,032 | 3,309 | — | 3 |
| ML-DSA-87 | 2,592 | 4,896 | 4,627 | — | 5 |

> **MTU note:** ML-DSA-87 signatures (4,627 bytes) exceed the 1,500-byte Ethernet MTU, requiring IP fragmentation. ML-KEM-1024 ciphertexts (1,568 bytes) fit within MTU.

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/manvirsingh01/pqc-hash-agility.git
cd pqc-hash-agility

# 2. Build everything (takes ~15–25 min; clones PQClean, XKCP, liboqs)
bash setup.sh

# 3. Run benchmarks — produces CSV files in results/ directory
bash bench.sh

# 4. View results (all output goes to results/)
cat results/custom_benchmark.csv           # our 6 backends x 6 algorithms
cat results/library_default_benchmark.csv  # same algorithms via OQS API
cat results/system_info.txt                # CPU cores, threads, frequency, ISA

# 5. (Optional) Run variable k-value KEM benchmark
bash kem_k_bench.sh               # interactive: choose backend + k=1..8
# Produces: results/custom_kem_k_benchmark.csv + results/library_default_kem_k_benchmark.csv

# 6. (Optional) Run hyperparameter benchmark
bash hyper_bench.sh               # interactive: tweak ML-KEM/ML-DSA params
# Produces: results/custom_*_hyper_benchmark.csv + results/library_default_*_hyper_benchmark.csv

# 7. (Optional) Run PURE benchmark (stock liboqs, no custom backends)
bash pure_bench.sh
# Produces: results/pure/pure_benchmark.csv + results/pure/pure_system_info.txt

# 8. (Optional) Run controlled benchmark with replication for statistical rigor
sudo bash bench_controlled.sh     # 10 rounds, CPU pinned, turbo off
python3 compute_ci.py --shuffled results/controlled_benchmark.csv
# Produces: results/controlled_benchmark.csv (single file, all rounds)
#           results/replications/roundN_*.csv (per-round files)
#           results/summary_with_ci.csv + results/effect_sizes.csv

# 9. (Optional) Shuffled benchmark — randomised backend order each round
sudo bash bench_shuffled.sh       # 10 rounds, shuffled order, single CSV
python3 compute_ci.py --shuffled results/shuffled_benchmark.csv
# Produces: results/shuffled_benchmark.csv (one file, all rounds + run_order)

# 10. (Optional) Run correctness-only tests (no timing)
./bench_shake --correctness-only --trials 1000
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
├── hyper_bench.sh            # interactive hyperparameter benchmark (KEM + DSA)
├── pure_bench.sh             # benchmark stock liboqs (no custom backends)
├── pure_system_info.sh       # system info for the pure benchmark
├── bench_controlled.sh       # controlled runner: CPU pinning, replication, CI
├── bench_shuffled.sh         # shuffled-order runner: randomised backend order per round
├── compute_ci.py             # compute 95% CI and effect sizes from replications
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
│       ├── pure_bench.c      # stock liboqs only, no custom backends
│       └── Makefile
├── PQClean_custom/           # forked ML-KEM/ML-DSA backend implementations
│   ├── crypto_kem/
│   │   └── ml-kem-{512,768,1024}/{turboshake,k12,blake3,xoodyak,haraka}/
│   └── crypto_sign/
│       └── ml-dsa-{44,65,87}/{turboshake,k12,blake3,xoodyak,haraka}/
├── results/                      # all benchmark output goes here (auto-created)
│   ├── custom_benchmark.csv
│   ├── library_default_benchmark.csv
│   ├── custom_kem_k_benchmark.csv
│   ├── library_default_kem_k_benchmark.csv
│   ├── custom_kem_hyper_benchmark.csv
│   ├── library_default_kem_hyper_benchmark.csv
│   ├── custom_dsa_hyper_benchmark.csv
│   ├── library_default_dsa_hyper_benchmark.csv
│   ├── system_info.txt
│   ├── summary_with_ci.csv       # (from compute_ci.py) per-op summary with 95% CI
│   ├── effect_sizes.csv          # (from compute_ci.py) backend comparisons
│   ├── controlled_benchmark.csv   # (from bench_controlled.sh) all rounds, single file
│   ├── shuffled_benchmark.csv     # (from bench_shuffled.sh) all rounds, single file
│   ├── replications/             # (from bench_controlled.sh) per-round CSVs also kept
│   ├── pure/                     # (from pure_bench.sh) stock liboqs benchmark
│   │   ├── pure_benchmark.csv
│   │   └── pure_system_info.txt
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
| 4 | Build liboqs with Ninja (scalar Keccak: `OQS_DIST_BUILD=OFF`, `OQS_USE_OPENSSL=OFF`) |
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

## Benchmark Methodology

### Implementation Parity

All backends are compiled at a matched optimisation tier to ensure fair comparison:

- **liboqs** (SHAKE): Built with `-O3` (no `-march=native`), `OQS_DIST_BUILD=OFF`, `OQS_USE_OPENSSL=OFF` — forces scalar Keccak, no AVX2 dispatch
- **XKCP** (TurboSHAKE, K12, Xoodyak): Built as `generic64` — scalar C Keccak/Xoodoo
- **BLAKE3**: All SIMD explicitly disabled (`-DBLAKE3_NO_SSE2/SSE41/AVX2/AVX512`)
- **Haraka**: Uses AES-NI (x86\_64) or ARM Crypto (aarch64) by design — this is intentional since Haraka's performance comes from hardware AES

This ensures the comparison measures **round count** (24 vs 12) and **permutation choice**, not vectorisation tier differences.

### Timing and Overhead

- **x86\_64**: `rdtsc`/`rdtscp` with `lfence` serialisation (true CPU cycles)
- **aarch64**: `CNTVCT_EL0` timer ticks (fixed-frequency counter, NOT CPU cycles). Wall-clock columns should be used for cross-architecture comparison
- **Overhead subtraction**: Measurement harness overhead (rdtsc/lfence cost) is measured via an empty timing loop and subtracted from each sample

### Energy Measurement

- **RAPL** (Intel x86): When `/sys/class/powercap/intel-rapl/` is accessible, actual hardware energy is measured per operation in microjoules
- **Software proxy**: When RAPL is unavailable, Energy Proxy Units (EPU = median cycles) serve as a relative comparison metric. The `est_energy_uj` column uses an illustrative constant unless calibrated via `-DENERGY_PER_CYCLE_NJ=<value>`

### Statistical Rigor

Use `bench_controlled.sh` for publication-quality results:

1. CPU frequency locked to `performance` governor
2. Intel turbo boost disabled
3. Process pinned to a single core (`taskset -c 0`)
4. 10 independent rounds with 5,000 iterations each
5. `compute_ci.py` produces 95% confidence intervals and flags cells where CI > 5% of median
6. Effect sizes (speedup claims) are only reported when confidence intervals do not overlap

Use `bench_shuffled.sh` for the strongest noise reduction: it **randomises backend execution order** each round, eliminating ordering bias (cache warming, thermal throttle, OS scheduler drift). The `run_order` column in the output lets you verify that first-vs-last position doesn't affect results.

### Memory Profiling

- **VmRSS**: Current resident set via `/proc/self/status` (not peak-only `getrusage`)
- **Heap delta**: `mallinfo2()` arena tracking per single call
- **Stack HWM**: 128 KB sentinel-painted region measures peak stack depth

### Correctness Testing

- `--correctness-only` mode runs N independent round-trip tests with tamper detection
- KEM: keygen → encaps → decaps → shared secret match, plus ciphertext flip → implicit rejection
- DSA: keygen → sign → verify → pass, plus message flip → verify must fail

---

## Benchmark Scripts

### bench.sh — Main Benchmark (Two CSV Files)

Produces **two separate CSV files** in the `results/` directory, plus `system_info.txt` with full hardware details.

#### CSV 1 — `results/custom_benchmark.csv`

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

#### CSV 2 — `results/library_default_benchmark.csv`

Tests the same **6 backends x 6 algorithms** (ML-KEM-512/768/1024 + ML-DSA-44/65/87) through the liboqs `OQS_KEM` / `OQS_SIG` adapter API. Uses our custom adapter constructors for each backend.

108 rows with the same structure, allowing direct column-for-column comparison with `custom_benchmark.csv`.

#### Options

```
--iters   N       custom benchmark iterations per operation (default 200)
--liters  N       default benchmark iterations per operation (default 200)
--warmup  N       warmup iterations before timing            (default 20)
--no-haraka       skip Haraka backend
--custom-only     produce custom_benchmark.csv only
--default-only    produce library_default_benchmark.csv only
```

---

### pure_bench.sh — Pure Stock Implementation Benchmark

Benchmarks ML-KEM and ML-DSA using their **unmodified stock liboqs implementations** — no custom hash backends, no PQClean forks, no parameter tweaks. This is the baseline that shows how the algorithms perform exactly as they ship.

```bash
bash pure_bench.sh                     # default: 200 iterations, 20 warmup
bash pure_bench.sh --iters 1000 --warmup 100
```

Output in `results/pure/`:
- `pure_benchmark.csv` — 18 rows (6 algorithms x 3 operations)
- `pure_system_info.txt` — system info + payload sizes + build config

Each algorithm gets a correctness self-test (round-trip + tamper detection) before timing. The CSV includes a `correctness` column (PASS/FAIL).

#### CSV columns (`results/pure/pure_benchmark.csv`)

```
algorithm, type, operation, correctness, iterations,
mean_ns, median_ns, min_ns, max_ns, stddev_ns, p95_ns, p99_ns,
ops_per_sec, pk_bytes, sk_bytes, ct_or_sig_bytes, ss_bytes,
nist_level
```

Use this to compare against the custom-backend results in `custom_benchmark.csv` — the pure benchmark shows what SHAKE performance looks like without any modifications, while the custom benchmark shows the effect of hash-backend substitution.

---

### kem_k_bench.sh — Variable k-Value ML-KEM Benchmark

Interactive script to benchmark ML-KEM with **non-standard module ranks** (k=1 through k=8).

Standard ML-KEM uses k=2 (ML-KEM-512), k=3 (ML-KEM-768), k=4 (ML-KEM-1024). This script lets you go beyond that range for research purposes.

For each k value, generates **both** benchmark types so you get side-by-side comparison at every k:
- **library** — standard default parameters for that k
- **custom** — user-selected parameters for that k

Standard NIST k values (k=2, 3, 4) are auto-included if not specified, so the k-scaling series is always complete.

```bash
bash kem_k_bench.sh
bash kem_k_bench.sh --iters 500 --warmup 50
```

#### How it works

1. Interactive menu to select backend (shake/turboshake/k12/blake3/xoodyak/haraka or ALL)
2. Enter k values (space-separated, e.g. `5 6 7 8` — standard k=2,3,4 auto-added)
3. For each k value, the script runs **both library and custom** benchmarks:
   - Copies ML-KEM source from the closest standard variant
   - Patches `params.h` with the requested k value and derived parameters
   - Patches `api.h` with computed key/ciphertext sizes
   - Recompiles and links the variant
   - Runs correctness check (keygen -> encaps -> decaps -> memcmp)
   - Times keygen, encaps, decaps
4. Results written to two separate CSVs in `results/`:
   - `custom_kem_k_benchmark.csv` — all k values (custom type)
   - `library_default_kem_k_benchmark.csv` — all k values (library type)

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

#### CSV columns (`custom_kem_k_benchmark.csv` / `library_default_kem_k_benchmark.csv`)

```
backend, k_value, algorithm, type, operation,
correctness, iterations,
mean_ns, median_ns, min_ns, max_ns,
stddev_ns, p95_ns, p99_ns, ops_per_sec,
pk_bytes, sk_bytes, ct_bytes, ss_bytes,
eta1, eta2, du_bits, dv_bits,
standard_level, fips_applicable
```

- `type`: `library` or `custom`
- `standard_level`: `ML-KEM-512` / `ML-KEM-768` / `ML-KEM-1024` for k=2/3/4, or `non-standard-research-only` for k=1/5-8
- `fips_applicable`: `1` for standard k values (2,3,4), `0` for research k values

---

### hyper_bench.sh — Hyperparameter Benchmark (ML-KEM + ML-DSA)

Interactive script to benchmark **ML-KEM** and **ML-DSA** with custom cryptographic hyperparameters. Recompiles PQClean source with patched parameters, runs correctness checks, and produces detailed CSV output.

For each parameter combination, generates **both** benchmark types at the **same** parameter values — giving side-by-side comparison:
- **library** — standard default run with those parameters
- **custom** — user-selected run with those parameters

The `type` column in the CSV distinguishes the two.

```bash
bash hyper_bench.sh
bash hyper_bench.sh --iters 500 --warmup 50
```

Results are written to two separate CSVs in `results/` per algorithm family.

#### ML-KEM mode

Tweak the **compression profile** and **module rank (k)**:

| Profile | eta1 | du | dv | Source template | Notes |
|---|---|---|---|---|---|
| A | 3 | 10 | 4 | ml-kem-512 | Aggressive compression, higher failure probability at large k |
| B | 2 | 11 | 5 | ml-kem-1024 | Conservative compression, lower failure probability |

k values: 1-8 (standard: 2/3/4; research: 1/5-8).

This lets you explore combinations that `kem_k_bench.sh` doesn't cover — e.g., k=5 with profile A (du=10/dv=4) vs. profile B (du=11/dv=5).

Output (in `results/`):
- `custom_kem_hyper_benchmark.csv` — all k values (custom type)
- `library_default_kem_hyper_benchmark.csv` — all k values (library type)

Columns: `backend, algorithm, profile, k, eta1, eta2, du, dv, type, operation, correctness, iterations, mean_ns, median_ns, min_ns, max_ns, stddev_ns, p95_ns, p99_ns, ops_per_sec, pk_bytes, sk_bytes, ct_bytes, ss_bytes`

The `type` column contains `library` (default k) or `custom` (user-selected k).

#### ML-DSA mode

Choose a **code base** (determines eta, gamma1, gamma2, packing code) then freely adjust **K, L, tau, omega**:

| Base | eta | gamma1 | gamma2 | ctildebytes | Source template |
|---|---|---|---|---|---|
| 44-base | 2 | 2^17 | (Q-1)/88 | 32 | ml-dsa-44 |
| 65-base | 4 | 2^19 | (Q-1)/32 | 48 | ml-dsa-65 |
| 87-base | 2 | 2^19 | (Q-1)/32 | 64 | ml-dsa-87 |

Tweakable parameters:

| Parameter | Range | Standard values | Effect |
|---|---|---|---|
| K (matrix rows) | 1-12 | 4 / 6 / 8 | Security level, key size |
| L (matrix cols) | 1-12 | 4 / 5 / 7 | Security level, signature size |
| tau (challenge weight) | 1-64 | 39 / 49 / 60 | Signing rejection rate |
| omega (hint budget) | 1-256 | 80 / 55 / 75 | Verification hint limit |

beta is auto-computed as `tau * eta`. The script validates that `beta < gamma1` (otherwise signing loops forever).

Output (in `results/`):
- `custom_dsa_hyper_benchmark.csv` — all parameter combos (custom type)
- `library_default_dsa_hyper_benchmark.csv` — all parameter combos (library type)

Columns: `backend, algorithm, base, K, L, eta, tau, beta, gamma1_bits, gamma2_div, omega, ctildebytes, type, operation, correctness, iterations, mean_ns, median_ns, min_ns, max_ns, stddev_ns, p95_ns, p99_ns, ops_per_sec, pk_bytes, sk_bytes, sig_bytes`

The `type` column contains `library` (default params) or `custom` (user-selected params).

---

### bench_controlled.sh — Controlled Multi-Round Benchmark

Runs the full custom benchmark multiple times with CPU noise controls for statistically rigorous results. Fixed backend order each round. Per-round CSVs saved for CI analysis.

```bash
sudo bash bench_controlled.sh                          # 10 rounds, 5000 iters
sudo bash bench_controlled.sh --rounds 20 --iters 10000 --core 2
```

| Option | Default | Description |
|---|---|---|
| `--rounds N` | 10 | Independent benchmark rounds |
| `--iters N` | 5000 | Iterations per operation per round |
| `--warmup N` | 500 | Warmup iterations |
| `--core N` | 0 | CPU core to pin to (`taskset -c N`) |
| `--no-lock` | — | Skip CPU governor and turbo controls |

**CPU controls applied:** frequency governor locked to `performance`, Intel turbo boost disabled, process pinned to a single core. 5-second cooldown between rounds.

Output:
- **`results/controlled_benchmark.csv`** — single combined file with `round` and `run_order` columns (all rounds in one file for easy analysis)
- **`results/replications/roundN_*.csv`** — individual per-round files (also kept)

Analyse with:
```bash
python3 compute_ci.py --shuffled results/controlled_benchmark.csv   # single file
python3 compute_ci.py --dir results/replications                     # per-round files
```

---

### bench_shuffled.sh — Shuffled-Order Multi-Round Benchmark

Same CPU controls as `bench_controlled.sh`, but **randomises the backend execution order** in each round. This eliminates systematic ordering bias — if SHAKE always runs first, it might benefit from cold caches while later backends hit thermal throttle, or vice versa.

```bash
sudo bash bench_shuffled.sh                            # 10 rounds, shuffled
sudo bash bench_shuffled.sh --rounds 20 --iters 10000
```

| Option | Default | Description |
|---|---|---|
| `--rounds N` | 10 | Independent benchmark rounds |
| `--iters N` | 5000 | Iterations per operation per round |
| `--warmup N` | 500 | Warmup iterations |
| `--core N` | 0 | CPU core to pin to |
| `--no-lock` | — | Skip CPU governor and turbo controls |
| `--no-haraka` | — | Skip Haraka backend |
| `--csv PATH` | `results/shuffled_benchmark.csv` | Output path |

Output: **single CSV file** with `round` and `run_order` columns:

```
round,run_order,backend_binary,algorithm,operation,hash_backend,...
1,1,bench_blake3,ML-KEM-512,KeyGen,"BLAKE3 ...",7,0,...
1,2,bench_shake,ML-KEM-512,KeyGen,"SHAKE ...",24,1,...
2,1,bench_xoodyak,ML-KEM-512,KeyGen,"Xoodyak ...",12,0,...
2,2,bench_turboshake,ML-KEM-512,KeyGen,"TurboSHAKE ...",12,0,...
...
```

Analyse with:
```bash
python3 compute_ci.py --shuffled results/shuffled_benchmark.csv
```

The `run_order` column lets you check whether running first vs last affects performance — if it does, you have an ordering-bias problem that only shuffling can detect.

---

### system_info.sh / pure_system_info.sh — Hardware + Build Information

Generated automatically by benchmark scripts. Produces `results/system_info.txt` (or `results/pure/pure_system_info.txt`):

| Section | Details |
|---|---|
| CPU | Model, architecture, physical cores, logical CPUs, threads/core, hyperthreading |
| Frequency | Current/min/max MHz, CPU governor |
| ISA Features | AES-NI, AVX2, AVX-512, SSE4.1, SHA-NI, NEON |
| Memory | Total RAM, available RAM |
| OS/Kernel | Kernel version, OS name, compiler version |
| Threading | Confirms single-threaded sequential execution, no CPU pinning |
| Build Matrix | SIMD tier per backend, compiler flags, parity documentation |
| Algorithm Capabilities | Backend features, algorithm XOF usage |
| Algorithm Payloads | PK, SK, CT/SIG, SS sizes in bytes per algorithm, NIST level, MTU notes |
| Active HW Capabilities | Which hardware features the current system actually has |

---

## Benchmark Design: Why Results Are Unbiased

| Property | How it's achieved |
|---|---|
| **Fixed iteration count** | `--iterations N` (not time-based), so results are the same regardless of CPU speed |
| **Wall-clock timing** | `clock_gettime(CLOCK_MONOTONIC)` — portable, no rdtsc, no architecture dependency |
| **Sequential** | All operations are single-threaded; no async, no parallel tasks |
| **Warmup** | `--warmup 20` discards first 20 calls (cache/branch-predictor warm-up) |
| **Median reported** | Median latency is reported (robust to OS scheduling outliers) |
| **Static linking** | Binaries statically link `liboqs.a` — no shared-lib lookup overhead |
| **Same compiler flags** | All backends compiled with `-O3` at matched scalar tier (no `-march=native` on x86\_64) |
| **System info captured** | `system_info.txt` records CPU model, cores, frequency, governor, ISA features alongside every benchmark run |

> **Note on CPU frequency:** For the most stable numbers, pin your CPU governor before running:
> ```bash
> cpupower frequency-set --governor performance   # bench.sh does this automatically if cpupower is installed
> ```

---

## CSV Output Format

All CSV files are written to the `results/` directory.

### `results/custom_benchmark.csv`

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

### `results/library_default_benchmark.csv`

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

### `results/custom_kem_k_benchmark.csv` / `results/library_default_kem_k_benchmark.csv`

Variable number of rows depending on chosen k values and backends. The custom CSV contains user-selected k values; the library CSV contains the default k=2 baseline. The `type` column distinguishes `library` from `custom`. See [kem_k_bench.sh](#kem_k_benchsh--variable-k-value-ml-kem-benchmark) for column details.

### `results/custom_*_hyper_benchmark.csv` / `results/library_default_*_hyper_benchmark.csv`

Variable number of rows depending on chosen parameter combinations and backends. Includes all hyperparameter values in each row for analysis. The `type` column distinguishes `library` from `custom`. See [hyper_bench.sh](#hyper_benchsh--hyperparameter-benchmark-ml-kem--ml-dsa) for column details.

### `results/pure/pure_benchmark.csv`

18 rows (6 algorithms x 3 operations). Stock liboqs implementations only — no custom backends. Columns: `algorithm, type, operation, correctness, iterations, mean_ns, median_ns, min_ns, max_ns, stddev_ns, p95_ns, p99_ns, ops_per_sec, pk_bytes, sk_bytes, ct_or_sig_bytes, ss_bytes, nist_level`. See [pure_bench.sh](#pure_benchsh--pure-stock-implementation-benchmark) for details.

### `results/controlled_benchmark.csv`

N×108 rows (N rounds × 6 backends × 6 algorithms × 3 operations). Same data as `custom_benchmark.csv` but with multiple rounds in fixed backend order. Extra columns: `round` (1..N), `run_order` (position within that round), `backend_binary` (which binary ran). See [bench_controlled.sh](#bench_controlledsh--controlled-multi-round-benchmark) for details.

### `results/shuffled_benchmark.csv`

Same structure as `controlled_benchmark.csv` but with **randomised** backend order each round. The `run_order` column differs between rounds — use it to detect ordering bias. See [bench_shuffled.sh](#bench_shuffledsh--shuffled-order-multi-round-benchmark) for details.

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
| `hyper_bench.sh` DSA signing very slow | Some parameter combos (e.g., 44-base with K=6, omega=55) cause high rejection rates — this is the expected research result |
| `hyper_bench.sh` CORRECTNESS FAILED | Non-standard parameters may break correctness; try parameters closer to standard values |

---

## Implementation Guide

See [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) for the full code walkthrough:
all `symmetric-<tag>.c` implementations, the `mldsa_refactor.py` patch script,
all 20 adapter files, the full benchmark harness source, build commands, and
design rationale for every decision.
