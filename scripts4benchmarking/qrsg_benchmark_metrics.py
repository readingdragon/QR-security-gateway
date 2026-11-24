#!/usr/bin/env python3
"""QRSG benchmark statistics: no network, labels from manifests, abstentions separately.

Three comparable classifiers on the same rows:
- local: SUSPICIOUS=positive, LOW_RISK=negative, UNVERIFIED=abstain
- reputation: KNOWN_THREAT=positive, NO_KNOWN_THREAT=negative, rest=abstain
- hybrid: HIGH_RISK/SUSPICIOUS=positive, LOW_RISK=negative, UNVERIFIED=abstain

Metrics are conditional on classified records; positive recall over ALL malicious
is also provided to expose coverage loss. This is a research benchmark, not proof
of universal phishing-detection accuracy.
"""
import argparse
import csv
import json
from collections import Counter
from pathlib import Path


def safe_ratio(n, d):
    return round(n / d, 5) if d else None


def prediction(row, model):
    if model == 'local':
        return {'SUSPICIOUS': True, 'LOW_RISK': False}.get(row['local_risk'])
    if model == 'reputation':
        return {'KNOWN_THREAT': True, 'NO_KNOWN_THREAT': False}.get(row['online_status'])
    if model == 'hybrid':
        return {'HIGH_RISK': True, 'SUSPICIOUS': True, 'LOW_RISK': False}.get(row['final_risk'])
    raise ValueError(model)


def measure(rows, model):
    matrix = Counter()
    for r in rows:
        actual = r['ground_truth'] == 'malicious'
        guess = prediction(r, model)
        if guess is None:
            matrix['ABSTAIN_M' if actual else 'ABSTAIN_B'] += 1
        elif actual:
            matrix['TP' if guess else 'FN'] += 1
        else:
            matrix['FP' if guess else 'TN'] += 1

    tp, fp, tn, fn = (matrix[k] for k in ('TP', 'FP', 'TN', 'FN'))
    classified = tp + fp + tn + fn
    predicted_positive = tp + fp
    malicious = tp + fn + matrix['ABSTAIN_M']
    benign = tn + fp + matrix['ABSTAIN_B']
    precision = safe_ratio(tp, predicted_positive)
    recall = safe_ratio(tp, tp + fn)
    f1 = safe_ratio(2 * tp, 2 * tp + fp + fn)
    return {
        'matrix': {k: matrix[k] for k in ('TP', 'FP', 'TN', 'FN', 'ABSTAIN_M', 'ABSTAIN_B')},
        'classified': classified, 'coverage': safe_ratio(classified, len(rows)),
        'malicious_coverage': safe_ratio(tp + fn, malicious),
        'benign_coverage': safe_ratio(fp + tn, benign),
        'precision_classified_only': precision,
        'recall_classified_only': recall,
        'f1_classified_only': f1,
        'fpr_classified_only': safe_ratio(fp, fp + tn),
        'malicious_detection_over_all_malicious': safe_ratio(tp, malicious),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--out', type=Path, help='Output JSON, default input with .summary.json suffix')
    a = p.parse_args()
    with a.input.open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        required = {'test_id', 'ground_truth', 'local_risk', 'online_status', 'final_risk', 'run_mode'}
        if not required.issubset(reader.fieldnames or []):
            p.error('Missing required result CSV columns')
        rows = list(reader)
    if not rows:
        p.error('No benchmark rows available')
    if len({r['test_id'] for r in rows}) != len(rows):
        p.error('Duplicate test_id in results: do not score until repaired')
    if any(r['ground_truth'] not in {'benign', 'malicious'} for r in rows):
        p.error('Invalid ground_truth')
    mode_set = {r['run_mode'] for r in rows}
    if len(mode_set) != 1:
        p.error('Mixed online and offline runs in one CSV')
    report = {
        'sample_count': len(rows),
        'mode': next(iter(mode_set)),
        'class_counts': dict(Counter(r['ground_truth'] for r in rows)),
        'warning': ('Class labels are dataset-supplied. Confusion matrix excludes '
                    'unverified/unchecked cases, which are counted as abstentions; '
                    'compare coverage and detection_over_all_malicious as well.'),
        'models': {name: measure(rows, name) for name in ('local', 'reputation', 'hybrid')},
    }
    out = a.out or a.input.with_suffix('.summary.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f"Cases={report['sample_count']} | mode={report['mode']} | classes={report['class_counts']}")
    for name, stats in report['models'].items():
        m = stats['matrix']
        print(f"{name:10} TP={m['TP']:3} FP={m['FP']:3} TN={m['TN']:3} FN={m['FN']:3} "
              f"ABSTAIN={m['ABSTAIN_M']+m['ABSTAIN_B']:3} "
              f"coverage={stats['coverage']} P={stats['precision_classified_only']} "
              f"R={stats['recall_classified_only']} F1={stats['f1_classified_only']} "
              f"FPR={stats['fpr_classified_only']}")
    print(f'Summary: {out}')


if __name__ == '__main__':
    main()
