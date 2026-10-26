import os
import json
import unittest
from http.client import HTTPConnection
from http.server import HTTPServer
from threading import Thread

import joblib
import pandas as pd

from engine import (DATASET_PATH, FEATURES, MODEL_DIR, _hostname_hyphen_count,
                    _is_trusted_host, _reasons, _training_range_violation,
                    _url_features, predict_url)
from url_features import extract_features
from api import Handler


CHATGPT_URL = 'https://chatgpt.com/g/g-p-6ac277d5e2a08191ab020e68a3a1ea3c-phishing-detection/c/6ac27b28-6d0c-83e8-b97d-54f985f60813'


class UrlFeatureRegressionTests(unittest.TestCase):
    def test_normal_https_url_has_expected_structural_features(self):
        features = extract_features('https://example.org/about').iloc[0]
        self.assertEqual(features['isHttps'], 1)
        self.assertEqual(features['nb_hyphens'], 0)
        self.assertEqual(features['at_symbol'], 0)

    def test_long_path_hyphens_do_not_create_hostname_warning(self):
        features = extract_features(CHATGPT_URL)
        self.assertGreater(features.iloc[0]['nb_hyphens'], 0)
        self.assertEqual(_hostname_hyphen_count(CHATGPT_URL), 0)
        self.assertFalse(any('hostname contains multiple hyphens' in reason.lower()
                             for reason in _reasons(CHATGPT_URL, features, 0, 0)))

    def test_hyphenated_hostname_is_measured_for_explanation(self):
        url = 'https://pay-pal-login.com/account'
        self.assertEqual(_hostname_hyphen_count(url), 2)
        self.assertEqual(extract_features(url).iloc[0]['nb_hyphens'], 2)

    def test_at_symbol_is_explained(self):
        url = 'https://trusted.example@evil.example/login'
        reasons = _reasons(url, extract_features(url), 0, 0)
        self.assertTrue(any('@ symbol' in reason for reason in reasons))

    def test_lookalike_hostname_does_not_match_trusted_domain(self):
        self.assertFalse(_is_trusted_host('paypa1.com'))
        self.assertFalse(_is_trusted_host('evilgoogle.com'))
        self.assertTrue(_is_trusted_host('accounts.google.com'))
        result = predict_url('https://evilgoogle.com')
        self.assertNotEqual(result['decisionSource'], 'trusted-domain-override')

    def test_trusted_domain_decision_is_separate_from_model_output(self):
        result = predict_url('https://google.com')
        self.assertEqual(result['decisionSource'], 'trusted-domain-override')
        self.assertEqual(result['type'], 'legitimate')
        self.assertIn(result['modelPrediction'], ('legitimate', 'phishing', 'suspicious'))
        self.assertIsNone(result['explanations']['model'])
        self.assertIsNotNone(result['explanations']['decision'])

    def test_suspicious_keywords_are_explained(self):
        url = 'http://secure-login-update.example/verify'
        reasons = _reasons(url, extract_features(url), 0, 0)
        self.assertTrue(any('security/account-related keywords' in reason for reason in reasons))

    def test_supplied_chatgpt_url_uses_trusted_domain_override(self):
        # chatgpt.com is an intentional trusted domain. The long path is outside
        # the training range, but the trusted override takes precedence and the
        # model prediction and ensemble score remain available separately.
        range_violation = _training_range_violation(_url_features(CHATGPT_URL))
        self.assertIsNotNone(range_violation)
        self.assertEqual(range_violation[0], 'url_length')
        self.assertEqual(range_violation[1], 116.0)
        result = predict_url(CHATGPT_URL)
        self.assertEqual(result['type'], 'legitimate')
        self.assertEqual(result['decisionSource'], 'trusted-domain-override')
        self.assertEqual(result['riskPercentage'], 1.0)
        self.assertEqual(result['modelPrediction'], 'phishing')
        self.assertEqual(result['modelRiskPercentage'], result['models']['ensemble'])
        self.assertIsNone(result['explanations']['model'])
        self.assertEqual(result['explanations']['heuristic'], [])
        self.assertTrue(any('trusted-domain' in reason.lower() for reason in result['reasons']))
        self.assertFalse(any('unusually long url' in reason.lower() for reason in result['reasons']))

    def test_predict_url_api_returns_trusted_domain_decision(self):
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = HTTPConnection('127.0.0.1', server.server_port, timeout=10)
        try:
            body = json.dumps({'url': CHATGPT_URL})
            connection.request('POST', '/predict-url', body, {'Content-Type': 'application/json'})
            response = connection.getresponse()
            result = json.loads(response.read())
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(response.status, 200)
        self.assertEqual(result['type'], 'legitimate')
        self.assertEqual(result['decisionSource'], 'trusted-domain-override')
        self.assertEqual(result['riskPercentage'], 1.0)
        self.assertEqual(result['modelPrediction'], 'phishing')
        self.assertEqual(result['modelRiskPercentage'], result['models']['ensemble'])
        self.assertTrue(any('trusted-domain' in reason.lower() for reason in result['reasons']))

    def test_training_and_inference_feature_schema_order_matches(self):
        train_columns = [name for name in pd.read_csv(DATASET_PATH, nrows=0).columns if name != 'target']
        self.assertEqual(list(extract_features('https://example.org').columns), train_columns)
        self.assertEqual(list(_url_features('https://example.org').columns), FEATURES)
        self.assertEqual(FEATURES, joblib.load(os.path.join(MODEL_DIR, 'deep_feature_names.pkl')))


if __name__ == '__main__':
    unittest.main()
