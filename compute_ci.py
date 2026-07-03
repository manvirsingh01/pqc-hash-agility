#!/usr/bin/env python3
"""
compute_ci.py — Compute confidence intervals and effect sizes from replicated
PQC benchmark data produced by bench_controlled.sh.

Usage:
    cd <build-dir>
    python3 /path/to/repo/compute_ci.py [--dir results/replications] [--alpha 0.05]

Output:
    results/summary_with_ci.csv       — per-operation summary with 95% CI
    results/effect_sizes.csv          — backend comparisons with significance
    Console output with flagged uncertain cells
"""

import argparse
import glob
import os
import re
import sys

import numpy as np

try:
    from scipy import stats as sp_stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
    print("[warn] scipy not installed — using t-value approximation for CI")


def t_ppf(alpha, df):
    if HAS_SCIPY:
        return sp_stats.t.ppf(1 - alpha / 2, df)
    if df >= 30:
        return 1.96
    t_table = {
        1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
        6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
        15: 2.131, 20: 2.086, 25: 2.060, 29: 2.045,
    }
    for k in sorted(t_table.keys()):
        if df <= k:
            return t_table[k]
    return 1.96


def load_replications(data_dir):
    """Load round CSV files from replications/ directory."""
    pattern = os.path.join(data_dir, "round*_bench_*.csv")
    files = sorted(glob.glob(pattern))
    if not files:
        pattern = os.path.join(data_dir, "round*_custom.csv")
        files = sorted(glob.glob(pattern))
    if not files:
        print(f"ERROR: No round CSV files found in {data_dir}")
        sys.exit(1)

    import csv as csvmod
    rows = []
    for f in files:
        m = re.search(r'round(\d+)', os.path.basename(f))
        round_num = int(m.group(1)) if m else 0
        with open(f) as fh:
            reader = csvmod.reader(fh)
            header = [h.strip() for h in next(reader)]
            for vals in reader:
                if len(vals) < len(header):
                    continue
                row = dict(zip(header, vals))
                row['round'] = round_num
                row['source_file'] = os.path.basename(f)
                rows.append(row)

    print(f"Loaded {len(rows)} data rows from {len(files)} files")
    return rows


def load_shuffled_csv(csv_path):
    """Load the single combined CSV from bench_shuffled.sh (has round column)."""
    import csv as csvmod
    rows = []
    with open(csv_path) as fh:
        reader = csvmod.reader(fh)
        header = next(reader)
        header = [h.strip() for h in header]
        for vals in reader:
            if len(vals) < len(header):
                continue
            row = dict(zip(header, vals))
            rows.append(row)

    n_rounds = len(set(row.get('round', '0') for row in rows))
    print(f"Loaded {len(rows)} data rows from {csv_path} ({n_rounds} rounds)")
    return rows


# Suffixes the PQClean-fork adapters append to algorithm names
# (e.g. "ML-KEM-512-TurboSHAKE"). Longest first so "-turboshake" is
# stripped before "-shake" gets a chance to match its tail.
BACKEND_SUFFIXES = ('-turboshake', '-xoodyak', '-haraka', '-blake3',
                    '-shake', '-k12')


def normalize_algo(name):
    """Strip the backend suffix from an algorithm name so rows from
    different backends group under the same algorithm key
    ("ML-KEM-512-TurboSHAKE" and "ML-KEM-512" both -> "ML-KEM-512")."""
    n = name.strip().strip('"')
    low = n.lower()
    for suf in BACKEND_SUFFIXES:
        if low.endswith(suf):
            return n[:-len(suf)]
    return n


def is_baseline_backend(backend_name, baseline):
    """True if backend_name's leading token equals the baseline name.
    Token match (not substring) so --baseline SHAKE matches
    "SHAKE (FIPS 202, ...)" but neither "TurboSHAKE (...)" nor the
    "SHAKE-liboqs (...)" production-reference series."""
    tok = backend_name.strip().strip('"').split(' ')[0].split('(')[0]
    return tok.lower() == baseline.lower()


def compute_summary(rows, alpha=0.05):
    """Compute per-(algorithm, operation, backend) summary with CI."""
    groups = {}
    for row in rows:
        algo = normalize_algo(row.get('algorithm', ''))
        op = row.get('operation', '')
        backend = row.get('hash_backend', '').strip('"')
        key = (backend, algo, op)

        median_val = float(row.get('median_cycles', row.get('median_ns', 0)))
        wall_val = float(row.get('wall_ns_mean', row.get('wall_ns', 0)))

        if key not in groups:
            groups[key] = {'medians': [], 'walls': []}
        groups[key]['medians'].append(median_val)
        groups[key]['walls'].append(wall_val)

    results = []
    for (backend, algo, op), data in sorted(groups.items()):
        medians = np.array(data['medians'])
        walls = np.array(data['walls'])
        n = len(medians)

        mean_med = np.mean(medians)
        std_med = np.std(medians, ddof=1) if n > 1 else 0
        ci_med = t_ppf(alpha, max(n - 1, 1)) * std_med / np.sqrt(n) if n > 1 else 0
        ci_pct = 100 * ci_med / mean_med if mean_med > 0 else 0

        mean_wall = np.mean(walls)
        std_wall = np.std(walls, ddof=1) if n > 1 else 0
        ci_wall = t_ppf(alpha, max(n - 1, 1)) * std_wall / np.sqrt(n) if n > 1 else 0

        results.append({
            'backend': backend,
            'algorithm': algo,
            'operation': op,
            'n_rounds': n,
            'mean_cycles': mean_med,
            'std_cycles': std_med,
            'median_cycles': np.median(medians),
            'ci95_cycles': ci_med,
            'ci95_pct': ci_pct,
            'mean_wall_ns': mean_wall,
            'std_wall_ns': std_wall,
            'ci95_wall_ns': ci_wall,
            'uncertain': ci_pct > 5.0,
        })

    return results


def compute_effects(summary, baseline='SHAKE', alpha=0.05):
    """Compute effect sizes (speedup) between baseline and each other backend."""
    baseline_map = {}
    for row in summary:
        if is_baseline_backend(row['backend'], baseline):
            key = (row['algorithm'], row['operation'])
            baseline_map[key] = row

    effects = []
    for row in summary:
        if is_baseline_backend(row['backend'], baseline):
            continue

        key = (row['algorithm'], row['operation'])
        b = baseline_map.get(key)
        if b is None:
            continue

        m1 = b['mean_cycles']
        m2 = row['mean_cycles']
        ci1 = b['ci95_cycles']
        ci2 = row['ci95_cycles']

        speedup_pct = 100 * (m1 - m2) / m1 if m1 > 0 else 0

        ci_overlap = (m2 - ci2) < (m1 + ci1) and (m1 - ci1) < (m2 + ci2)

        reportable = not ci_overlap and abs(speedup_pct) > 5

        effects.append({
            'algorithm': row['algorithm'],
            'operation': row['operation'],
            'backend': row['backend'],
            'baseline': b['backend'],
            'baseline_cycles': m1,
            'backend_cycles': m2,
            'speedup_pct': speedup_pct,
            'baseline_ci': ci1,
            'backend_ci': ci2,
            'ci_overlap': ci_overlap,
            'reportable': reportable,
        })

    return effects


def write_csv(filename, rows, columns):
    """Write a list of dicts to CSV. Uses the csv module so backend names
    containing commas (e.g. "SHAKE (FIPS 202, n_r=24, ...)") stay quoted
    and the columns stay aligned."""
    import csv as csvmod
    with open(filename, 'w', newline='') as f:
        w = csvmod.writer(f)
        w.writerow(columns)
        for row in rows:
            w.writerow([row.get(c, '') for c in columns])
    print(f"Wrote: {filename} ({len(rows)} rows)")


def main():
    parser = argparse.ArgumentParser(description='Compute CIs and effect sizes')
    parser.add_argument('--dir', default='results/replications',
                        help='Directory containing round CSV files')
    parser.add_argument('--alpha', type=float, default=0.05,
                        help='Significance level (default: 0.05 for 95%% CI)')
    parser.add_argument('--baseline', default='SHAKE',
                        help='Baseline backend name for effect comparison')
    parser.add_argument('--output', default='results',
                        help='Output directory for summary CSVs')
    parser.add_argument('--shuffled', default=None,
                        help='Path to shuffled_benchmark.csv (single-file mode)')
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    if args.shuffled:
        rows = load_shuffled_csv(args.shuffled)
    else:
        rows = load_replications(args.dir)
    summary = compute_summary(rows, args.alpha)

    summary_cols = [
        'backend', 'algorithm', 'operation', 'n_rounds',
        'mean_cycles', 'std_cycles', 'median_cycles',
        'ci95_cycles', 'ci95_pct',
        'mean_wall_ns', 'std_wall_ns', 'ci95_wall_ns',
        'uncertain',
    ]
    write_csv(os.path.join(args.output, 'summary_with_ci.csv'), summary, summary_cols)

    uncertain = [r for r in summary if r['uncertain']]
    if uncertain:
        print(f"\nStatistically uncertain cells (CI > 5% of median): {len(uncertain)}")
        for u in uncertain:
            print(f"  {u['backend']:30s}  {u['algorithm']:20s}  {u['operation']:10s}  "
                  f"CI={u['ci95_pct']:.1f}%")
    else:
        print("\nAll cells have CI < 5% of median — statistically stable.")

    effects = compute_effects(summary, args.baseline, args.alpha)
    if effects:
        effect_cols = [
            'algorithm', 'operation', 'backend', 'baseline',
            'baseline_cycles', 'backend_cycles', 'speedup_pct',
            'baseline_ci', 'backend_ci', 'ci_overlap', 'reportable',
        ]
        write_csv(os.path.join(args.output, 'effect_sizes.csv'), effects, effect_cols)

        reportable = [e for e in effects if e['reportable']]
        non_reportable = [e for e in effects if not e['reportable']]

        print(f"\nReportable effects (no CI overlap AND > 5%): {len(reportable)}")
        for e in reportable:
            print(f"  {e['backend']:30s}  {e['algorithm']:20s}  {e['operation']:10s}  "
                  f"speedup={e['speedup_pct']:+.1f}%")

        if non_reportable:
            print(f"\nNon-reportable (CI overlap or < 5%): {len(non_reportable)}")
            for e in non_reportable:
                reason = "CI overlap" if e['ci_overlap'] else f"|{e['speedup_pct']:.1f}%| < 5%"
                print(f"  {e['backend']:30s}  {e['algorithm']:20s}  {e['operation']:10s}  "
                      f"speedup={e['speedup_pct']:+.1f}%  ({reason})")


if __name__ == '__main__':
    main()
