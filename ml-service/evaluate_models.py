import json
import os

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch import nn


BASE = os.path.dirname(os.path.abspath(__file__))
FEATURES = joblib.load(os.path.join(BASE, 'feature_names.pkl'))


class MLP(nn.Module):
    def __init__(self, feature_count):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(feature_count, 64), nn.ReLU(), nn.Dropout(.15),
            nn.Linear(64, 32), nn.ReLU(), nn.Linear(32, 1),
        )

    def forward(self, values):
        return self.net(values).squeeze(1)


def score(y_true, probabilities):
    predictions = (probabilities >= .5).astype(int)
    return {
        'accuracy': round(accuracy_score(y_true, predictions), 4),
        'precision': round(precision_score(y_true, predictions, zero_division=0), 4),
        'recall': round(recall_score(y_true, predictions, zero_division=0), 4),
        'f1': round(f1_score(y_true, predictions, zero_division=0), 4),
        'roc_auc': round(roc_auc_score(y_true, probabilities), 4),
        'confusion_matrix': confusion_matrix(y_true, predictions, labels=[0, 1]).tolist(),
    }


def main():
    data = pd.read_csv(os.path.join(BASE, 'dataset.csv'))
    grouped = data.groupby(FEATURES, dropna=False).agg(
        label_count=('target', 'nunique'), label=('target', 'first'), rows=('target', 'size')
    ).reset_index()
    conflicting = grouped[grouped.label_count > 1]
    clean = grouped[grouped.label_count == 1].reset_index(drop=True)
    values = clean[FEATURES]
    labels = clean['label'].astype(int)
    train_indices, test_indices = train_test_split(
        np.arange(len(clean)), test_size=.2, random_state=42, stratify=labels
    )
    x_train, x_test = values.iloc[train_indices], values.iloc[test_indices]
    y_train, y_test = labels.iloc[train_indices], labels.iloc[test_indices]
    results = {
        'protocol': 'Group exact duplicate feature rows; exclude conflicting-label groups; stratified 80/20 split; random_state=42.',
        'dataset': {
            'rows': len(data),
            'features': len(FEATURES),
            'class_counts': data.target.value_counts().sort_index().to_dict(),
            'duplicate_rows': int(data.duplicated().sum()),
            'conflicting_feature_groups': len(conflicting),
            'rows_in_conflicting_feature_groups': int(conflicting.rows.sum()),
            'unique_unambiguous_vectors': len(clean),
        },
        'url_length_by_target': {
            str(label): {
                'min': int(group.url_length.min()),
                'median': float(group.url_length.median()),
                'mean': round(float(group.url_length.mean()), 4),
                'max': int(group.url_length.max()),
            }
            for label, group in data.groupby('target')
        },
        'models': {},
    }

    models = {
        'randomForest': RandomForestClassifier(
            n_estimators=800, max_features='sqrt', min_samples_leaf=1,
            class_weight='balanced_subsample', random_state=42, n_jobs=-1,
        ),
        'histGradientBoosting': HistGradientBoostingClassifier(
            max_iter=400, learning_rate=.04, max_leaf_nodes=15,
            l2_regularization=.5, random_state=42,
        ),
    }
    for name, model in models.items():
        model.fit(x_train, y_train)
        results['models'][name] = score(y_test, model.predict_proba(x_test)[:, 1])

    scaler = StandardScaler().fit(x_train.astype(np.float32))
    scaled_train = scaler.transform(x_train.astype(np.float32))
    scaled_test = scaler.transform(x_test.astype(np.float32))
    torch.manual_seed(42)
    model = MLP(scaled_train.shape[1])
    optimizer = torch.optim.Adam(model.parameters(), lr=.003, weight_decay=1e-4)
    loss_function = nn.BCEWithLogitsLoss()
    train_values = torch.tensor(scaled_train)
    train_labels = torch.tensor(y_train.to_numpy(), dtype=torch.float32)
    for _ in range(180):
        model.train()
        optimizer.zero_grad()
        loss = loss_function(model(train_values), train_labels)
        loss.backward()
        optimizer.step()
    model.eval()
    with torch.no_grad():
        probabilities = torch.sigmoid(model(torch.tensor(scaled_test))).numpy()
    results['models']['deepLearning'] = score(y_test.to_numpy(), probabilities)

    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()