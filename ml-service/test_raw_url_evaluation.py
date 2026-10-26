import os
import json
import tempfile
import unittest
from argparse import Namespace

import numpy as np
import pandas as pd

from engine import DEEP_FEATURES, FEATURES, MODEL_DIR
from evaluate_raw_urls import (evaluate, load_raw_dataset, metric_report,
                               production_artifact_metadata, sha256_file,
                               split_dataset)
from url_features import extract_features


class RawUrlEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.csv_path = os.path.join(self.temp_dir.name, 'raw_urls.csv')

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_csv(self, rows):
        pd.DataFrame(rows).to_csv(self.csv_path, index=False)

    def load(self, **overrides):
        options = {
            'path': self.csv_path,
            'url_column': 'URL',
            'label_column': 'Label',
            'benign_label': '1',
            'phishing_label': '0',
            'domain_column': 'Domain',
        }
        options.update(overrides)
        return load_raw_dataset(**options)

    def test_validation_maps_source_labels_and_reports_missing_or_invalid_rows(self):
        self.write_csv([
            {'URL': 'https://benign.example/', 'Label': 1, 'Domain': 'benign.example'},
            {'URL': 'http:///missing-host', 'Label': 0, 'Domain': 'missing-host'},
            {'URL': '', 'Label': 1, 'Domain': 'empty.example'},
            {'URL': 'https://unknown.example/', 'Label': 'other', 'Domain': 'unknown.example'},
            {'URL': 'https://null-label.example/', 'Label': None, 'Domain': 'null-label.example'},
        ])

        data, quality = self.load()

        self.assertEqual(data.target.tolist(), [0])
        self.assertEqual(quality['dropped']['invalid_url'], 1)
        self.assertEqual(quality['dropped']['missing_url'], 1)
        self.assertEqual(quality['dropped']['unknown_label'], 1)
        self.assertEqual(quality['dropped']['missing_label'], 1)

    def test_numeric_labels_still_validate_when_missing_rows_coerce_to_float(self):
        self.write_csv([
            {'URL': 'https://benign.example/', 'Label': 1, 'Domain': 'benign.example'},
            {'URL': 'https://phish.example/', 'Label': 0, 'Domain': 'phish.example'},
            {'URL': 'https://missing-label.example/', 'Label': None, 'Domain': 'missing-label.example'},
        ])
        data, quality = self.load()
        self.assertEqual(sorted(data.target.tolist()), [0, 1])
        self.assertEqual(quality['dropped']['missing_label'], 1)
        self.assertEqual(quality['dropped']['unknown_label'], 0)

    def test_exact_duplicates_are_removed_and_conflicting_groups_excluded(self):
        self.write_csv([
            {'URL': 'https://same.example/path?b=2&a=1', 'Label': 1, 'Domain': 'same.example'},
            {'URL': 'https://SAME.example/path?a=1&b=2#fragment', 'Label': 1, 'Domain': 'same.example'},
            {'URL': 'https://conflict.example/', 'Label': 1, 'Domain': 'conflict.example'},
            {'URL': 'https://conflict.example/#other', 'Label': 0, 'Domain': 'conflict.example'},
        ])

        data, quality = self.load()

        self.assertEqual(len(data), 1)
        self.assertEqual(quality['duplicate_rows_removed'], 1)
        self.assertEqual(quality['conflicting_url_groups'], 1)
        self.assertEqual(quality['rows_in_conflicting_url_groups'], 2)

    def test_domain_split_is_reproducible_and_has_no_domain_overlap(self):
        self.write_csv([
            {'URL': f'https://{domain}/path', 'Label': index % 2, 'Domain': domain}
            for index, domain in enumerate([
                'a.example', 'b.example', 'c.example', 'd.example',
                'e.example', 'f.example', 'g.example', 'h.example',
            ])
        ])
        data, _ = self.load()

        train_a, test_a, details_a = split_dataset(data, test_size=.25, seed=23, group_by='domain')
        train_b, test_b, details_b = split_dataset(data, test_size=.25, seed=23, group_by='domain')

        self.assertEqual(train_a.url.tolist(), train_b.url.tolist())
        self.assertEqual(test_a.url.tolist(), test_b.url.tolist())
        self.assertEqual(details_a, details_b)
        self.assertEqual(details_a['group_overlap'], 0)
        self.assertTrue(set(train_a.domain_group).isdisjoint(set(test_a.domain_group)))

    def test_url_group_split_is_reproducible(self):
        self.write_csv([
            {'URL': f'https://{domain}/unique/{index}', 'Label': index % 2, 'Domain': domain}
            for index, domain in enumerate(['a.example', 'b.example', 'c.example', 'd.example', 'e.example', 'f.example'])
        ])
        data, _ = self.load()
        train_a, test_a, details = split_dataset(data, test_size=.33, seed=7, group_by='url')
        train_b, test_b, _ = split_dataset(data, test_size=.33, seed=7, group_by='url')
        self.assertEqual(train_a.url.tolist(), train_b.url.tolist())
        self.assertEqual(test_a.url.tolist(), test_b.url.tolist())
        self.assertEqual(details['group_overlap'], 0)

    def test_production_feature_schema_and_metric_calculation(self):
        features = extract_features('https://example.test/path')
        self.assertEqual(list(features.columns), FEATURES)
        self.assertEqual(FEATURES, DEEP_FEATURES)

        result = metric_report([0, 0, 1, 1], np.array([.1, .8, .9, .4]))
        self.assertEqual(result['confusion_matrix'], [[1, 1], [1, 1]])
        self.assertEqual(result['false_positive_rate'], .5)
        self.assertEqual(result['false_negative_rate'], .5)
        self.assertEqual(result['accuracy'], .5)
        self.assertEqual(result['precision'], .5)
        self.assertEqual(result['recall'], .5)
        self.assertEqual(result['f1'], .5)
        self.assertEqual(result['roc_auc'], .75)

    def test_required_columns_and_label_map_are_validated(self):
        self.write_csv([{'URL': 'https://example.test', 'Label': 1}])
        with self.assertRaisesRegex(ValueError, 'Missing required CSV columns'):
            self.load(domain_column='Domain')
        with self.assertRaisesRegex(ValueError, 'must differ'):
            self.load(domain_column=None, benign_label='same', phishing_label='same')

    def test_evaluator_scores_saved_models_without_writing_artifacts(self):
        rows = [
            {'URL': f'https://site{index}.example/{"login" if index % 2 else "home"}',
             'Label': index % 2, 'Domain': f'site{index}.example'}
            for index in range(20)
        ]
        self.write_csv(rows)
        args = Namespace(
            csv=self.csv_path,
            url_column='URL',
            label_column='Label',
            benign_label='0',
            phishing_label='1',
            domain_column='Domain',
            dataset_name='temporary unit fixture',
            source_url='local test fixture',
            dataset_version='test-v1',
            dataset_license='test-only',
            group_by='domain',
            test_size=.25,
            seed=12,
        )
        artifact_hashes_before = production_artifact_metadata()['files']
        result = evaluate(args)
        json.dumps(result)
        artifact_hashes_after = production_artifact_metadata()['files']

        self.assertEqual(set(result['models']), {'randomForest', 'histGradientBoosting', 'deepLearning', 'weightedEnsemble'})
        self.assertEqual(result['protocol']['group_overlap'], 0)
        self.assertFalse(result['protocol']['production_artifacts_modified'])
        self.assertFalse(result['protocol']['model_fit_performed'])
        self.assertEqual(len(result['protocol']['model_artifacts']['files']['phishing_model.pkl']), 64)
        self.assertEqual(artifact_hashes_before['phishing_model.pkl'],
                         sha256_file(os.path.join(MODEL_DIR, 'phishing_model.pkl')))
        self.assertEqual(artifact_hashes_before, artifact_hashes_after)
        self.assertEqual(artifact_hashes_before, result['protocol']['model_artifacts']['files'])
        self.assertIn('python', result['runtime'])
        self.assertIn('false_positive_rate', result['models']['weightedEnsemble'])
        self.assertIn('false_negative_rate', result['models']['weightedEnsemble'])


if __name__ == '__main__':
    unittest.main()