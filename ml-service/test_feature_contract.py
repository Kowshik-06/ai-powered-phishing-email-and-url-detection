"""Focused tests for the URL feature contract, extractor version, and validator.

Synthetic data only: no network access, no dataset downloads, no model loading.
Safe to run on its own:

    cd ml-service
    python -m unittest test_feature_contract -v
"""

from __future__ import annotations

import unittest

import pandas as pd

import extractor_version
import feature_contract
from feature_contract import FEATURE_NAMES, FEATURE_SPECS
from feature_validator import (
    CODE_ABOVE_MAXIMUM,
    CODE_ALLOWED_SET,
    CODE_AT_SYMBOL_BOOLEAN,
    CODE_BELOW_MINIMUM,
    CODE_COLUMN_ORDER,
    CODE_HTTPS_IMPLIES_VALID,
    CODE_LOOSE_LENGTH_BOUND,
    CODE_MISSING_COLUMNS,
    CODE_MISSING_VALUE,
    CODE_NON_FINITE,
    CODE_NON_INTEGER,
    CODE_NON_NUMERIC,
    CODE_STRICT_LENGTH_BOUND,
    CODE_UNEXPECTED_COLUMNS,
    CODE_UNVERIFIED_SEMANTICS,
    PROFILE_LEGACY,
    PROFILE_RUNTIME,
    validate_feature_table,
)
from url_features import extract_features


def make_row(**overrides):
    """A self-consistent synthetic feature row that satisfies the contract."""
    row = {
        "url_length": 25,
        "valid_url": 1,
        "at_symbol": 0,
        "sensitive_words_count": 0,
        "path_length": 1,
        "isHttps": 1,
        "nb_dots": 1,
        "nb_hyphens": 0,
        "nb_and": 0,
        "nb_or": 0,
        "nb_www": 0,
        "nb_com": 1,
        "nb_underscore": 0,
    }
    row.update(overrides)
    return row


def make_frame(**overrides):
    return pd.DataFrame([make_row(**overrides)])


def issues_with(report, code):
    return [issue for issue in report.issues if issue.code == code]


def codes(report):
    return [issue.code for issue in report.issues]


class FeatureContractTests(unittest.TestCase):
    def test_contract_matches_extractor_columns_and_order(self):
        emitted = list(extract_features("https://example.org/about").columns)
        self.assertEqual(list(FEATURE_NAMES), emitted)
        self.assertEqual(feature_contract.FEATURE_COUNT, 13)
        self.assertEqual(set(FEATURE_SPECS), set(FEATURE_NAMES))
        self.assertEqual(
            feature_contract.LEGACY_ALLOWED_EXTRA_COLUMNS, ("target",)
        )

    def test_documented_edge_cases_are_encoded(self):
        # path_length can be -1 for scheme-less input containing a slash.
        self.assertEqual(FEATURE_SPECS["path_length"].minimum, -1)
        self.assertIsNone(FEATURE_SPECS["path_length"].maximum)
        # Five keywords, each counted at most once.
        self.assertEqual(FEATURE_SPECS["sensitive_words_count"].maximum, 5)
        # Boolean-encoded columns.
        self.assertEqual(
            feature_contract.boolean_features(),
            ("valid_url", "at_symbol", "isHttps"),
        )
        self.assertEqual(
            feature_contract.scheme_dependent_features(),
            ("url_length", "valid_url", "path_length", "isHttps"),
        )

    def test_every_feature_declares_formula_and_semantic_status(self):
        for name in FEATURE_NAMES:
            spec = FEATURE_SPECS[name]
            self.assertTrue(spec.formula, msg=name)
            self.assertIn(
                spec.training_semantics, feature_contract.SEMANTIC_STATUSES, msg=name
            )
            self.assertTrue(spec.training_note, msg=name)
            self.assertTrue(spec.mismatch_risk, msg=name)

    def test_unverified_semantics_are_marked_provisional(self):
        for spec in feature_contract.unverified_semantics():
            self.assertTrue(spec.provisional, msg=spec.name)
        for name in ("nb_dots", "nb_hyphens", "nb_and", "nb_underscore"):
            self.assertFalse(FEATURE_SPECS[name].provisional, msg=name)

    def test_snapshot_is_serialisable_and_ordered(self):
        snapshot = feature_contract.contract_snapshot()
        self.assertEqual(snapshot["feature_order"], list(FEATURE_NAMES))
        self.assertEqual(snapshot["feature_count"], 13)
        self.assertEqual(
            snapshot["extractor_version"], extractor_version.EXTRACTOR_VERSION
        )
        self.assertEqual(len(snapshot["features"]), 13)


class ExtractorVersionTests(unittest.TestCase):
    def test_version_metadata_is_well_formed(self):
        self.assertRegex(extractor_version.EXTRACTOR_VERSION, r"^\d+\.\d+\.\d+$")
        self.assertIn("url_features", extractor_version.EXTRACTOR_MODULE)
        self.assertEqual(extractor_version.EXTRACTOR_FUNCTION, "extract_features")
        self.assertTrue(extractor_version.INCREMENT_POLICY)
        self.assertIn(extractor_version.EXTRACTOR_VERSION, extractor_version.VERSION_HISTORY)

    def test_compatibility_note_denies_model_compatibility(self):
        note = extractor_version.COMPATIBILITY_NOTE
        self.assertIn("NOT", note)
        self.assertIn("model", note.lower())

    def test_fingerprint_matches_recorded_pin(self):
        self.assertEqual(
            extractor_version.fingerprint(), extractor_version.EXTRACTOR_SHA256
        )

    def test_describe_exposes_identity_without_claiming_compatibility(self):
        described = extractor_version.describe()
        self.assertEqual(
            described["extractor_version"], extractor_version.EXTRACTOR_VERSION
        )
        self.assertIn("compatibility_note", described)


class ValidTableTests(unittest.TestCase):
    def test_valid_synthetic_row_passes_without_errors_or_warnings(self):
        report = validate_feature_table(make_frame(), profile=PROFILE_RUNTIME)
        self.assertTrue(report.ok)
        self.assertEqual(report.errors, ())
        self.assertEqual(report.warnings, ())
        self.assertEqual(report.rows, 1)

    def test_real_extractor_output_validates_under_runtime_profile(self):
        urls = [
            "https://example.org/about",
            "http://sub.example.co.uk/a/b?x=1&y=2",
            "https://login.secure.example.net/verify",
        ]
        frame = pd.concat([extract_features(url) for url in urls], ignore_index=True)
        report = validate_feature_table(frame, profile=PROFILE_RUNTIME)
        self.assertTrue(report.ok, msg=report.format_text())

    def test_path_length_minus_one_is_allowed_but_minus_two_is_not(self):
        # The extractor really returns -1 for scheme-less input with a slash.
        self.assertEqual(int(extract_features("a/b").iloc[0]["path_length"]), -1)
        self.assertTrue(validate_feature_table(make_frame(path_length=-1)).ok)

        report = validate_feature_table(make_frame(path_length=-2))
        self.assertFalse(report.ok)
        self.assertEqual(len(issues_with(report, CODE_BELOW_MINIMUM)), 1)

    def test_empty_table_with_correct_schema_passes(self):
        frame = pd.DataFrame({name: pd.Series(dtype="int64") for name in FEATURE_NAMES})
        report = validate_feature_table(frame)
        self.assertTrue(report.ok)
        self.assertEqual(report.rows, 0)
        self.assertEqual(report.errors, ())

    def test_legacy_profile_tolerates_target_column(self):
        frame = make_frame()
        frame["target"] = 1
        report = validate_feature_table(frame, profile=PROFILE_LEGACY)
        self.assertTrue(report.ok)
        self.assertEqual(issues_with(report, CODE_UNEXPECTED_COLUMNS), [])

    def test_runtime_profile_flags_target_column_as_unexpected(self):
        frame = make_frame()
        frame["target"] = 1
        report = validate_feature_table(frame, profile=PROFILE_RUNTIME)
        self.assertTrue(report.ok)  # warning only
        self.assertEqual(len(issues_with(report, CODE_UNEXPECTED_COLUMNS)), 1)


class SchemaTests(unittest.TestCase):
    def test_missing_column_is_an_error(self):
        frame = pd.DataFrame([make_row()]).drop(columns=["nb_com"])
        report = validate_feature_table(frame, profile=PROFILE_RUNTIME)
        self.assertFalse(report.ok)
        found = issues_with(report, CODE_MISSING_COLUMNS)
        self.assertEqual(len(found), 1)
        self.assertIn("nb_com", found[0].message)
        self.assertEqual(found[0].severity, "error")

    def test_unexpected_column_is_reported_without_failing(self):
        frame = make_frame()
        frame["unexpected_extra"] = "x"
        report = validate_feature_table(frame, profile=PROFILE_RUNTIME)
        self.assertTrue(report.ok)
        found = issues_with(report, CODE_UNEXPECTED_COLUMNS)
        self.assertEqual(len(found), 1)
        self.assertIn("unexpected_extra", found[0].message)

    def test_column_order_mismatch_is_a_warning_not_an_error(self):
        frame = pd.DataFrame([make_row()])[list(reversed(FEATURE_NAMES))]
        report = validate_feature_table(frame, profile=PROFILE_RUNTIME)
        self.assertTrue(report.ok)
        found = issues_with(report, CODE_COLUMN_ORDER)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "warning")

    def test_column_order_check_can_be_disabled(self):
        frame = pd.DataFrame([make_row()])[list(reversed(FEATURE_NAMES))]
        report = validate_feature_table(frame, require_order=False)
        self.assertEqual(issues_with(report, CODE_COLUMN_ORDER), [])


class CellValueTests(unittest.TestCase):
    def test_non_numeric_value_is_an_error(self):
        report = validate_feature_table(make_frame(url_length="not-a-number"))
        self.assertFalse(report.ok)
        found = issues_with(report, CODE_NON_NUMERIC)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].column, "url_length")
        self.assertEqual(found[0].count, 1)

    def test_missing_value_is_an_error(self):
        report = validate_feature_table(make_frame(nb_dots=None))
        self.assertFalse(report.ok)
        found = issues_with(report, CODE_MISSING_VALUE)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].column, "nb_dots")
        self.assertEqual(found[0].count, 1)

    def test_non_finite_value_is_an_error(self):
        report = validate_feature_table(make_frame(nb_hyphens=float("inf")))
        self.assertFalse(report.ok)
        found = issues_with(report, CODE_NON_FINITE)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].column, "nb_hyphens")

    def test_negative_value_is_an_error(self):
        report = validate_feature_table(make_frame(nb_and=-1))
        self.assertFalse(report.ok)
        found = issues_with(report, CODE_BELOW_MINIMUM)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].column, "nb_and")
        self.assertIn("negative", found[0].message.lower())

    def test_value_above_declared_maximum_is_an_error(self):
        report = validate_feature_table(make_frame(sensitive_words_count=6))
        self.assertFalse(report.ok)
        found = issues_with(report, CODE_ALLOWED_SET) + issues_with(
            report, CODE_ABOVE_MAXIMUM
        )
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].column, "sensitive_words_count")

    def test_non_integer_value_is_an_error(self):
        report = validate_feature_table(make_frame(sensitive_words_count=1.5))
        self.assertFalse(report.ok)
        found = issues_with(report, CODE_NON_INTEGER)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].column, "sensitive_words_count")

    def test_allowed_set_violation_is_reported_once(self):
        report = validate_feature_table(make_frame(valid_url=2))
        self.assertFalse(report.ok)
        found = issues_with(report, CODE_ALLOWED_SET)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].column, "valid_url")
        # The allowed set subsumes min/max, so no duplicate range error.
        self.assertEqual(issues_with(report, CODE_ABOVE_MAXIMUM), [])


class InvariantTests(unittest.TestCase):
    def test_ishttps_implies_valid_url_is_enforced(self):
        report = validate_feature_table(make_frame(valid_url=0, isHttps=1))
        self.assertFalse(report.ok)
        found = issues_with(report, CODE_HTTPS_IMPLIES_VALID)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].count, 1)
        self.assertEqual(found[0].column, "isHttps")

    def test_valid_url_zero_without_https_is_accepted(self):
        report = validate_feature_table(make_frame(valid_url=0, isHttps=0))
        self.assertTrue(report.ok)

    def test_at_symbol_outside_boolean_set_is_enforced(self):
        report = validate_feature_table(make_frame(at_symbol=9))
        self.assertFalse(report.ok)
        found = issues_with(report, CODE_AT_SYMBOL_BOOLEAN)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].column, "at_symbol")
        self.assertEqual(found[0].count, 1)
        # Reported once, never as a duplicate allowed-set error.
        self.assertEqual(issues_with(report, CODE_ALLOWED_SET), [])

    def test_loose_length_bound_is_a_warning_and_never_proof(self):
        report = validate_feature_table(make_frame(url_length=5, path_length=3))
        self.assertTrue(report.ok)  # warning does not fail the table
        found = issues_with(report, CODE_LOOSE_LENGTH_BOUND)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "warning")
        self.assertIn("NOT evidence", found[0].message)
        self.assertIn("NOT evidence", report.format_text())
        # The stricter, non-contract bound is reported only as info.
        strict = issues_with(report, CODE_STRICT_LENGTH_BOUND)
        self.assertEqual(len(strict), 1)
        self.assertEqual(strict[0].severity, "info")

    def test_legacy_bound_is_not_raised_for_consistent_rows(self):
        report = validate_feature_table(make_frame())
        self.assertEqual(issues_with(report, CODE_LOOSE_LENGTH_BOUND), [])
        self.assertEqual(issues_with(report, CODE_STRICT_LENGTH_BOUND), [])


class ProfileCategorisationTests(unittest.TestCase):
    def test_runtime_profile_categorises_violations_as_contract(self):
        report = validate_feature_table(make_frame(at_symbol=9), profile=PROFILE_RUNTIME)
        issue = issues_with(report, CODE_AT_SYMBOL_BOOLEAN)[0]
        self.assertEqual(issue.category, "contract")

    def test_legacy_profile_categorises_violations_as_legacy(self):
        report = validate_feature_table(make_frame(at_symbol=9), profile=PROFILE_LEGACY)
        issue = issues_with(report, CODE_AT_SYMBOL_BOOLEAN)[0]
        self.assertEqual(issue.category, "legacy")
        self.assertEqual(issue.severity, "error")

    def test_unverified_semantics_are_always_reported_as_info(self):
        for profile in (PROFILE_RUNTIME, PROFILE_LEGACY):
            report = validate_feature_table(make_frame(), profile=profile)
            semantic = issues_with(report, CODE_UNVERIFIED_SEMANTICS)
            self.assertEqual(
                len(semantic), len(feature_contract.unverified_semantics())
            )
            self.assertTrue(
                all(i.category == "unverified" for i in semantic), msg=profile
            )
            self.assertTrue(all(i.severity == "info" for i in semantic), msg=profile)
            self.assertEqual(
                {i.column for i in semantic},
                {s.name for s in feature_contract.unverified_semantics()},
            )
            self.assertTrue(report.ok, msg=profile)

    def test_unknown_profile_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_feature_table(make_frame(), profile="guess")


class ReadOnlyTests(unittest.TestCase):
    def test_validation_does_not_mutate_input(self):
        frame = pd.DataFrame(
            [
                make_row(),
                make_row(valid_url=0, isHttps=1, at_symbol=9),
                make_row(url_length="not-a-number"),
            ]
        )
        before = frame.copy(deep=True)
        before_columns = list(frame.columns)
        before_dtypes = [str(dtype) for dtype in frame.dtypes]

        validate_feature_table(frame, profile=PROFILE_RUNTIME)

        self.assertTrue(frame.equals(before))
        self.assertEqual(list(frame.columns), before_columns)
        self.assertEqual([str(dtype) for dtype in frame.dtypes], before_dtypes)

    def test_validation_of_list_input_does_not_touch_the_lists(self):
        rows = [make_row(), make_row(nb_dots=-1)]
        snapshot = [dict(row) for row in rows]
        validate_feature_table(rows)
        self.assertEqual(rows, snapshot)

    def test_report_text_does_not_echo_values(self):
        report = validate_feature_table(
            make_frame(url_length="https://private.example/secret-path")
        )
        rendered = report.format_text()
        self.assertIn(CODE_NON_NUMERIC, rendered)
        self.assertNotIn("private.example", rendered)
        self.assertNotIn("secret-path", rendered)


class ReportTests(unittest.TestCase):
    def test_report_serialises_to_expected_keys(self):
        report = validate_feature_table(make_frame(at_symbol=9))
        data = report.to_dict()
        for key in (
            "profile",
            "rows",
            "columns_checked",
            "ok",
            "error_count",
            "warning_count",
            "info_count",
            "issues",
            "caveat",
        ):
            self.assertIn(key, data)
        self.assertFalse(data["ok"])
        self.assertEqual(data["rows"], 1)
        self.assertEqual(len(data["columns_checked"]), 13)

    def test_report_text_contains_caveat(self):
        report = validate_feature_table(make_frame())
        self.assertIn("does NOT prove", report.format_text())


if __name__ == "__main__":
    unittest.main()
