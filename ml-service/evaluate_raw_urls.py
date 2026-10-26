"""Evaluate the saved URL models on a user-approved raw-URL CSV.

This script is read-only with respect to model artifacts. It never fetches URLs.
"""

import argparse
import hashlib
import json
import os
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import numpy as np
import pandas as pd
import sklearn
import torch
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit

from engine import (DEEP, DEEP_FEATURES, FEATURES, HGB, MODEL_DIR, RF, SCALER,
                    _url_features)


SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')
FEATURE_BATCH_SIZE = 2048


def label_token(value):
    text = str(value).strip()
    try:
        number = float(text)
        if np.isfinite(number) and number.is_integer():
            return str(int(number))
    except ValueError:
        pass
    return text


def prepare_url(value):
    if not isinstance(value, str) or not value.strip():
        return None
    url = value.strip()
    if not SCHEME_RE.match(url):
        url = 'https://' + url
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            return None
        return url
    except ValueError:
        return None


def canonical_url_key(url):
    parsed = urlparse(url)
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or '/', '', query, ''))


def _label_map(benign_label, phishing_label):
    benign = label_token(benign_label)
    phishing = label_token(phishing_label)
    if benign == phishing:
        raise ValueError('Benign and phishing label values must differ.')
    return {benign: 0, phishing: 1}


def load_raw_dataset(path, url_column, label_column, benign_label, phishing_label,
                     domain_column=None):
    frame = pd.read_csv(path)
    required = [url_column, label_column]
    if domain_column:
        required.append(domain_column)
    missing_columns = [column for column in required if column not in frame.columns]
    if missing_columns:
        raise ValueError(f'Missing required CSV columns: {", ".join(missing_columns)}')

    mapping = _label_map(benign_label, phishing_label)
    accepted = []
    dropped = {'missing_url': 0, 'invalid_url': 0, 'missing_label': 0, 'unknown_label': 0}
    for row_number, row in frame.iterrows():
        raw_url = row[url_column]
        if pd.isna(raw_url) or not str(raw_url).strip():
            dropped['missing_url'] += 1
            continue
        url = prepare_url(str(raw_url))
        if not url:
            dropped['invalid_url'] += 1
            continue
        raw_label = row[label_column]
        if pd.isna(raw_label):
            dropped['missing_label'] += 1
            continue
        label = mapping.get(label_token(raw_label))
        if label is None:
            dropped['unknown_label'] += 1
            continue
        parsed = urlparse(url)
        supplied_domain = row[domain_column] if domain_column else None
        if supplied_domain is not None and not pd.isna(supplied_domain) and str(supplied_domain).strip():
            group_domain = str(supplied_domain).strip().lower().rstrip('.')
        else:
            group_domain = (parsed.hostname or '').lower().rstrip('.')
        accepted.append({
            'url': url,
            'target': label,
            'url_group': canonical_url_key(url),
            'domain_group': group_domain,
            '_row_number': int(row_number),
        })

    data = pd.DataFrame(accepted)
    if data.empty:
        raise ValueError('No valid labeled HTTP URL records remain after validation.')

    grouped = data.groupby('url_group', sort=False, dropna=False)
    conflicts = grouped.target.nunique()
    conflicting_groups = set(conflicts[conflicts > 1].index)
    conflicting_rows = int(data.url_group.isin(conflicting_groups).sum())
    data = data[~data.url_group.isin(conflicting_groups)].copy()
    data = data.drop_duplicates('url_group', keep='first').reset_index(drop=True)
    if data.empty:
        raise ValueError('No unambiguous URL groups remain after conflicting labels are removed.')

    quality = {
        'input_rows': int(len(frame)),
        'accepted_rows_before_deduplication': len(accepted),
        'duplicate_rows_removed': len(accepted) - conflicting_rows - len(data),
        'conflicting_url_groups': len(conflicting_groups),
        'rows_in_conflicting_url_groups': conflicting_rows,
        'dropped': dropped,
        'remaining_rows': len(data),
        'class_counts': {str(key): int(value) for key, value in data.target.value_counts().sort_index().items()},
    }
    return data, quality


def split_dataset(data, test_size=0.2, seed=42, group_by='domain'):
    if not 0 < test_size < 1:
        raise ValueError('test_size must be between 0 and 1.')
    if group_by not in {'domain', 'url'}:
        raise ValueError("group_by must be 'domain' or 'url'.")
    group_column = 'domain_group' if group_by == 'domain' else 'url_group'
    groups = data[group_column].astype(str)
    if groups.nunique() < 2:
        raise ValueError(f'At least two distinct {group_by} groups are required for a holdout split.')
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_indices, test_indices = next(splitter.split(data, data.target, groups))
    train = data.iloc[train_indices].reset_index(drop=True)
    test = data.iloc[test_indices].reset_index(drop=True)
    overlap = set(train[group_column].astype(str)) & set(test[group_column].astype(str))
    if overlap:
        raise RuntimeError(f'{group_by} group leakage detected between train and test.')
    return train, test, {
        'method': 'GroupShuffleSplit; grouping by supplied domain column or parsed hostname' if group_by == 'domain'
                  else 'GroupShuffleSplit by normalized URL group',
        'group_column': group_column,
        'test_size_requested': test_size,
        'seed': seed,
        'train_rows': len(train),
        'test_rows': len(test),
        'train_class_counts': {str(key): int(value) for key, value in train.target.value_counts().sort_index().items()},
        'test_class_counts': {str(key): int(value) for key, value in test.target.value_counts().sort_index().items()},
        'train_groups': int(train[group_column].nunique()),
        'test_groups': int(test[group_column].nunique()),
        'group_overlap': len(overlap),
    }


def metric_report(labels, scores, threshold=0.5):
    labels = np.asarray(labels, dtype=int)
    scores = np.asarray(scores, dtype=float)
    predictions = (scores >= threshold).astype(int)
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    return {
        'accuracy': float(accuracy_score(labels, predictions)),
        'precision': float(precision_score(labels, predictions, zero_division=0)),
        'recall': float(recall_score(labels, predictions, zero_division=0)),
        'f1': float(f1_score(labels, predictions, zero_division=0)),
        'roc_auc': float(roc_auc_score(labels, scores)) if len(np.unique(labels)) == 2 else None,
        'false_positive_rate': float(false_positive / (false_positive + true_negative)) if false_positive + true_negative else None,
        'false_negative_rate': float(false_negative / (false_negative + true_positive)) if false_negative + true_positive else None,
        'confusion_matrix': matrix.tolist(),
        'threshold': threshold,
        'test_samples': int(len(labels)),
    }


def production_scores(urls):
    model_scores = {'randomForest': [], 'histGradientBoosting': [], 'deepLearning': []}
    expected_features = list(FEATURES)
    for start in range(0, len(urls), FEATURE_BATCH_SIZE):
        batch_urls = urls[start:start + FEATURE_BATCH_SIZE]
        records = [_url_features(url).iloc[0].to_dict() for url in batch_urls]
        features = pd.DataFrame(records, columns=expected_features)
        if list(features.columns) != expected_features:
            raise ValueError('Extracted feature schema does not match saved model feature order.')
        model_scores['randomForest'].extend(RF.predict_proba(features)[:, 1].tolist())
        model_scores['histGradientBoosting'].extend(HGB.predict_proba(features)[:, 1].tolist())
        scaled = SCALER.transform(features[DEEP_FEATURES].astype(float).values)
        with torch.no_grad():
            deep = torch.sigmoid(DEEP(torch.tensor(scaled, dtype=torch.float32))).cpu().numpy()
        model_scores['deepLearning'].extend(deep.reshape(-1).tolist())
    model_scores['weightedEnsemble'] = (
        0.8 * np.asarray(model_scores['histGradientBoosting'])
        + 0.1 * np.asarray(model_scores['randomForest'])
        + 0.1 * np.asarray(model_scores['deepLearning'])
    ).tolist()
    return model_scores


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def production_artifact_metadata():
    artifacts = ['phishing_model.pkl', 'hgb_model.pkl', 'deep_model.pt', 'deep_scaler.pkl', 'feature_names.pkl', 'deep_feature_names.pkl']
    return {
        'files': {name: sha256_file(os.path.join(MODEL_DIR, name)) for name in artifacts},
        'randomForestParameters': RF.get_params(deep=False),
        'histGradientBoostingParameters': HGB.get_params(deep=False),
        'deepLearning': {
            'architecture': '13 -> 64 -> 32 -> 1 logits',
            'hidden_activation': 'ReLU',
            'dropout': 0.15,
            'preprocessing': 'saved StandardScaler artifact',
        },
        'ensembleWeights': {'histGradientBoosting': 0.8, 'randomForest': 0.1, 'deepLearning': 0.1},
    }


def evaluate(args):
    data, quality = load_raw_dataset(
        args.csv, args.url_column, args.label_column,
        args.benign_label, args.phishing_label, args.domain_column,
    )
    train, test, split = split_dataset(data, args.test_size, args.seed, args.group_by)
    scores = production_scores(test.url.tolist())
    metrics = {name: metric_report(test.target, values) for name, values in scores.items()}
    source_file = os.path.abspath(args.csv)
    return {
        'runtime': {
            'python': os.sys.version.split()[0],
            'pandas': pd.__version__,
            'numpy': np.__version__,
            'scikit_learn': sklearn.__version__,
            'pytorch': torch.__version__,
        },
        'dataset': {
            'name': args.dataset_name,
            'source_url': args.source_url,
            'version_or_snapshot': args.dataset_version,
            'license_or_terms': args.dataset_license,
            'file_sha256': sha256_file(source_file),
            'url_column': args.url_column,
            'label_column': args.label_column,
            'domain_column': args.domain_column,
            'label_mapping': {str(args.benign_label): 0, str(args.phishing_label): 1},
            'quality': quality,
        },
        'protocol': {
            **split,
            'feature_extractor': 'ml-service/url_features.py via engine._url_features',
            'threshold': 0.5,
            'model_fit_performed': False,
            'complementary_partition_usage': 'Reserved and excluded from the test report; saved production models are evaluated without fitting or model selection.',
            'model_artifacts': production_artifact_metadata(),
            'production_artifacts_modified': False,
            'production_training_overlap': 'unknown; original training data provenance is unavailable',
            'trusted_domain_overrides_included_in_binary_metrics': False,
            'review_range_decisions_in_binary_metrics': False,
        },
        'models': metrics,
        'limitations': [
            'Production-model overlap with this dataset cannot be ruled out because original training URLs and provenance are unavailable.',
            'A model threshold of 0.5 is evaluated; displayed model scores are not calibrated probabilities.',
            'Domain grouping is only as reliable as the supplied domain column; parsed-hostname fallback does not apply a public suffix list.',
            'Trusted-domain and out-of-range REVIEW decisions are reported separately from binary model metrics.',
        ],
    }


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', required=True, help='Path to an already-approved raw-URL CSV; this script does not download it.')
    parser.add_argument('--dataset-name', required=True)
    parser.add_argument('--source-url', required=True)
    parser.add_argument('--dataset-version', required=True, help='Snapshot ID/date or documented release.')
    parser.add_argument('--dataset-license', required=True, help='License or terms verified by the user.')
    parser.add_argument('--url-column', default='URL')
    parser.add_argument('--label-column', default='label')
    parser.add_argument('--domain-column', default=None, help='Optional supplied registrable-domain grouping column.')
    parser.add_argument('--benign-label', required=True, help='Exact source label value for legitimate URLs.')
    parser.add_argument('--phishing-label', required=True, help='Exact source label value for phishing URLs.')
    parser.add_argument('--group-by', choices=['domain', 'url'], default='domain')
    parser.add_argument('--test-size', type=float, default=0.2)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--output', default=None, help='Optional report path; omitted means stdout only.')
    return parser


def main():
    args = build_parser().parse_args()
    report = evaluate(args)
    rendered = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, 'x', encoding='utf-8') as destination:
            destination.write(rendered + '\n')
    print(rendered)


if __name__ == '__main__':
    main()