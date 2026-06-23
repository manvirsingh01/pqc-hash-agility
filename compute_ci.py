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
    """Load all round CSV files and combine them."""
    pattern = os.path.join(data_dir, "round*_bench_*.csv")
    files = sorted(glob.glob(pattern))
    if not files:
        print(f"ERROR: No CSV files found matching {pattern}")
        sys.exit(1)

    rows = []
    for f in files:
        m = re.search(r'round(\d+)', os.path.basename(f))
        round_num = int(m.group(1)) if m else 0
        with open(f) as fh:
            header = None
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                if header is None:
                    header = [h.strip('"') for h in line.split(',')]
                    continue
                vals = line.split(',')
                row = dict(zip(header, vals))
                row['round'] = round_num
                row['source_file'] = os.path.basename(f)
                rows.append(row)

    print(f"Loaded {len(rows)} data rows from {len(files)} files")
    return rows


def compute_summary(rows, alpha=0.05):
    """Compute per-(algorithm, operation, backend) summary with CI."""
    groups = {}
    for row in rows:
        algo = row.get('algorithm', '')
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
        if baseline.lower() in row['backend'].lower():
            key = (row['algorithm'], row['operation'])
            baseline_map[key] = row

    effects = []
    for row in summary:
        if baseline.lower() in row['backend'].lower():
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
    """Write a list of dicts to CSV."""
    with open(filename, 'w') as f:
        f.write(','.join(columns) + '\n')
        for row in rows:
            vals = [str(row.get(c, '')) for c in columns]
            f.write(','.join(vals) + '\n')
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
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

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
