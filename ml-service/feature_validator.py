"""Read-only validation of URL feature tables against ``feature_contract``.

The validator answers one narrow question: *is this table well-formed with
respect to the declared runtime contract?* It does not judge whether a model is
correct, whether labels are right, or whether training and runtime features mean
the same thing.

Guarantees
----------
* The input table is never modified. No column is added, dropped, renamed,
  coerced in place, filled, or reordered. All checks read columns and build new
  arrays.
* No row is repaired or removed.
* No URL or free-text value is printed. Issues report column names and row
  counts only; distinct *values* are never echoed.

Three categories are kept separate in the report
------------------------------------------------
``contract``
    A violation of the declared runtime contract (for example a value outside an
    allowed set, or a broken cross-feature invariant).
``legacy``
    A diagnostic that is meaningful for a legacy training table and shows that
    table cannot have been produced by the current extractor.
``unverified``
    A statement that a feature's training-time meaning cannot be established.
    Always emitted as ``info``; never affects pass/fail.

Profiles
--------
``runtime``
    The table is expected to be current extractor output: exactly the 13 feature
    columns. Contract violations are categorised ``contract``.
``legacy``
    The table is expected to be a historical training table. A trailing
    ``target`` column is tolerated. The same violations are categorised
    ``legacy`` because they say something about the training data rather than
    about the extractor.

A pass means "no contract errors were found". It does not mean the features are
trustworthy; see ``feature_contract`` for per-feature semantic status.
"""

from __future__ import annotations

import argparse
import textwrap
from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np
import pandas as pd

from feature_contract import (
    FEATURE_NAMES,
    FEATURE_SPECS,
    LEGACY_ALLOWED_EXTRA_COLUMNS,
    unverified_semantics,
)

PROFILE_RUNTIME = "runtime"
PROFILE_LEGACY = "legacy"
PROFILES: tuple[str, ...] = (PROFILE_RUNTIME, PROFILE_LEGACY)

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

CATEGORY_CONTRACT = "contract"
CATEGORY_LEGACY = "legacy"
CATEGORY_UNVERIFIED = "unverified"

#: Printed with every report so a clean result cannot be over-read.
PASS_CAVEAT = (
    "A pass means the table is well-formed under the declared runtime contract. "
    "It does NOT prove that the training-time meaning of each feature matches "
    "the runtime meaning, and it does NOT validate any model trained on it."
)

# Column-level checks.
CODE_MISSING_COLUMNS = "INV001"
CODE_UNEXPECTED_COLUMNS = "INV002"
CODE_COLUMN_ORDER = "INV003"
CODE_NON_NUMERIC = "INV004"
CODE_MISSING_VALUE = "INV005"
CODE_NON_FINITE = "INV006"
CODE_NON_INTEGER = "INV007"
CODE_BELOW_MINIMUM = "INV008"
CODE_ABOVE_MAXIMUM = "INV009"
CODE_ALLOWED_SET = "INV010"

# Cross-feature invariants.
CODE_HTTPS_IMPLIES_VALID = "INV011"
CODE_AT_SYMBOL_BOOLEAN = "INV012"
CODE_LOOSE_LENGTH_BOUND = "INV013"
CODE_STRICT_LENGTH_BOUND = "INV014"

# Informational semantic status.
CODE_UNVERIFIED_SEMANTICS = "SEM001"

#: ``at_symbol`` has a dedicated invariant (INV012) so the generic allowed-set
#: check must skip it, otherwise one bad value would be reported twice.
_DEDICATED_ALLOWED_SET = frozenset({"at_symbol"})


@dataclass(frozen=True)
class ValidationIssue:
    """One finding. ``count`` is a number of rows, or ``None`` when the finding
    is about the table/contract rather than about rows."""

    code: str
    category: str
    severity: str
    column: str | None
    count: int | None
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "category": self.category,
            "severity": self.severity,
            "column": self.column,
            "count": self.count,
            "message": self.message,
        }


@dataclass(frozen=True)
class ValidationReport:
    """Immutable result of :func:`validate_feature_table`."""

    profile: str
    rows: int
    columns_checked: tuple[str, ...]
    issues: tuple[ValidationIssue, ...]

    @property
    def errors(self) -> tuple[ValidationIssue, ...]:
        return tuple(i for i in self.issues if i.severity == SEVERITY_ERROR)

    @property
    def warnings(self) -> tuple[ValidationIssue, ...]:
        return tuple(i for i in self.issues if i.severity == SEVERITY_WARNING)

    @property
    def infos(self) -> tuple[ValidationIssue, ...]:
        return tuple(i for i in self.issues if i.severity == SEVERITY_INFO)

    @property
    def ok(self) -> bool:
        """True when no contract error was found. Informational findings do not
        affect this value."""
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        """Serialisable report. Contains no feature values."""
        return {
            "profile": self.profile,
            "rows": self.rows,
            "columns_checked": list(self.columns_checked),
            "ok": self.ok,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "info_count": len(self.infos),
            "caveat": PASS_CAVEAT,
            "issues": [issue.as_dict() for issue in self.issues],
        }

    def format_text(self, width: int = 100) -> str:
        """Human-readable report. Contains no feature values."""
        status = "PASS" if self.ok else "FAIL"
        lines = [
            "Feature-table validation",
            f"  profile              : {self.profile}",
            f"  rows                 : {self.rows}",
            f"  columns checked      : {len(self.columns_checked)}",
            f"  result               : {status}",
            f"  errors/warnings/info : {len(self.errors)}/{len(self.warnings)}/{len(self.infos)}",
            "",
        ]
        if not self.issues:
            lines.append("  No issues found.")
        for issue in self.issues:
            scope = issue.column if issue.column is not None else "(table)"
            suffix = "" if issue.count is None else f"  [{issue.count} row(s)]"
            lines.append(
                f"  {issue.severity.upper():<7} {issue.category:<10} "
                f"{issue.code}  {scope}{suffix}"
            )
            for chunk in textwrap.wrap(issue.message, width=max(40, width - 10)):
                lines.append(f"          {chunk}")
        lines.extend(["", "NOTE: " + PASS_CAVEAT])
        return "\n".join(lines)


def _issue_for_profile(
    profile: str,
    code: str,
    severity: str,
    column: str | None,
    count: int | None,
    message: str,
) -> ValidationIssue:
    """Contract/legacy checks share a code but are categorised by profile."""
    if code in {CODE_LOOSE_LENGTH_BOUND, CODE_STRICT_LENGTH_BOUND}:
        category = CATEGORY_LEGACY
    else:
        category = CATEGORY_CONTRACT if profile == PROFILE_RUNTIME else CATEGORY_LEGACY
    return ValidationIssue(code, category, severity, column, count, message)


def _numeric_array(frame: pd.DataFrame, name: str) -> np.ndarray | None:
    """Read-only numeric view of a column, or ``None`` if unconvertible."""
    try:
        coerced = pd.to_numeric(frame[name], errors="coerce")
        return coerced.astype("float64").to_numpy()
    except (TypeError, ValueError):
        return None


def validate_feature_table(
    table: Any,
    *,
    profile: str = PROFILE_RUNTIME,
    require_order: bool = True,
) -> ValidationReport:
    """Validate a feature table without changing it.

    Parameters
    ----------
    table:
        A :class:`pandas.DataFrame`, or anything ``pandas.DataFrame`` accepts
        (for example a list of dicts). A DataFrame is never modified; other
        inputs are copied into a new DataFrame.
    profile:
        ``"runtime"`` or ``"legacy"``. See the module docstring.
    require_order:
        When true, feature columns must appear in ``FEATURE_NAMES`` order. A
        mismatch is a warning, because this project selects model inputs by
        column name rather than by position.

    Returns
    -------
    ValidationReport
        Immutable; ``report.ok`` is true when no error-severity issue exists.
    """
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; expected one of {PROFILES}")

    frame = table if isinstance(table, pd.DataFrame) else pd.DataFrame(table)
    present = list(frame.columns)
    rows = int(len(frame))
    issues: list[ValidationIssue] = []

    extra_allowed = (
        set(LEGACY_ALLOWED_EXTRA_COLUMNS) if profile == PROFILE_LEGACY else set()
    )

    missing = [name for name in FEATURE_NAMES if name not in present]
    if missing:
        issues.append(
            _issue_for_profile(
                profile,
                CODE_MISSING_COLUMNS,
                SEVERITY_ERROR,
                None,
                None,
                "Missing required feature column(s): "
                + ", ".join(missing)
                + ". The table does not satisfy the declared 13-feature contract, "
                "so the remaining checks only cover the columns that are present.",
            )
        )

    unexpected = [c for c in present if c not in FEATURE_NAMES and c not in extra_allowed]
    if unexpected:
        issues.append(
            _issue_for_profile(
                profile,
                CODE_UNEXPECTED_COLUMNS,
                SEVERITY_WARNING,
                None,
                None,
                "Unexpected column(s) outside the feature contract: "
                + ", ".join(unexpected)
                + ". They are ignored by feature checks but mean this is not a "
                "bare feature table.",
            )
        )

    checked = tuple(name for name in FEATURE_NAMES if name in present)

    if require_order:
        canonical = [name for name in FEATURE_NAMES if name in present]
        if present_features_ordered(present, FEATURE_NAMES) != canonical:
            issues.append(
                _issue_for_profile(
                    profile,
                    CODE_COLUMN_ORDER,
                    SEVERITY_WARNING,
                    None,
                    None,
                    "Feature columns are not in the declared order. Expected order: "
                    + ", ".join(canonical)
                    + ". This project selects columns by name, so a mismatch is a "
                    "consistency signal rather than a runtime failure.",
                )
            )

    # ------------------------------------------------------------------ columns
    for name in checked:
        spec = FEATURE_SPECS[name]
        series = frame[name]

        missing_count = int(series.isna().sum())
        if missing_count:
            issues.append(
                _issue_for_profile(
                    profile,
                    CODE_MISSING_VALUE,
                    SEVERITY_ERROR,
                    name,
                    missing_count,
                    f"Missing (null/NaN) value(s) in '{name}'.",
                )
            )

        try:
            coerced = pd.to_numeric(series, errors="coerce")
        except (TypeError, ValueError):
            coerced = pd.Series(np.nan, index=series.index, dtype="float64")

        non_numeric_count = int((series.notna() & coerced.isna()).sum())
        if non_numeric_count:
            issues.append(
                _issue_for_profile(
                    profile,
                    CODE_NON_NUMERIC,
                    SEVERITY_ERROR,
                    name,
                    non_numeric_count,
                    f"Non-numeric value(s) in '{name}'. Contract dtype is "
                    f"{spec.dtype}.",
                )
            )

        try:
            values = coerced.astype("float64").to_numpy()
        except (TypeError, ValueError):
            values = None

        if values is None:
            continue

        observed = np.isfinite(values)
        non_finite_count = int((coerced.notna().to_numpy() & ~observed).sum())
        if non_finite_count:
            issues.append(
                _issue_for_profile(
                    profile,
                    CODE_NON_FINITE,
                    SEVERITY_ERROR,
                    name,
                    non_finite_count,
                    f"Non-finite value(s) (+/-inf) in '{name}'. NaN is reported "
                    "separately as a missing value.",
                )
            )

        non_integer_count = int(
            (np.mod(values[observed], 1.0) != 0.0).sum()
        )
        if non_integer_count:
            issues.append(
                _issue_for_profile(
                    profile,
                    CODE_NON_INTEGER,
                    SEVERITY_ERROR,
                    name,
                    non_integer_count,
                    f"Non-integer value(s) in '{name}'. Contract dtype is "
                    f"{spec.dtype}.",
                )
            )

        # For a feature with an allowed set the set fully subsumes its declared
        # minimum/maximum, so only one check runs to avoid double reporting.
        if spec.allowed_values is None:
            if spec.minimum is not None:
                below = int((observed & (values < spec.minimum)).sum())
                if below:
                    if spec.minimum == 0:
                        detail = (
                            " The current extractor cannot produce a negative "
                            "value here."
                        )
                    else:
                        detail = (
                            f" '{name}' is allowed to reach {spec.minimum} for "
                            "scheme-less input containing a slash, but nothing "
                            "lower."
                        )
                    issues.append(
                        _issue_for_profile(
                            profile,
                            CODE_BELOW_MINIMUM,
                            SEVERITY_ERROR,
                            name,
                            below,
                            f"Value(s) below the declared minimum {spec.minimum} in "
                            f"'{name}'.{detail}",
                        )
                    )

            if spec.maximum is not None:
                above = int((observed & (values > spec.maximum)).sum())
                if above:
                    issues.append(
                        _issue_for_profile(
                            profile,
                            CODE_ABOVE_MAXIMUM,
                            SEVERITY_ERROR,
                            name,
                            above,
                            f"Value(s) above the declared maximum {spec.maximum} in "
                            f"'{name}'.",
                        )
                    )

        if spec.allowed_values is not None and name not in _DEDICATED_ALLOWED_SET:
            invalid = int((observed & ~np.isin(values, spec.allowed_values)).sum())
            if invalid:
                issues.append(
                    _issue_for_profile(
                        profile,
                        CODE_ALLOWED_SET,
                        SEVERITY_ERROR,
                        name,
                        invalid,
                        f"Value(s) outside the allowed set "
                        f"{tuple(spec.allowed_values)} in '{name}'.",
                    )
                )

    # -------------------------------------------------------------- invariants
    if "at_symbol" in checked:
        values = _numeric_array(frame, "at_symbol")
        if values is not None:
            invalid = int(
                (np.isfinite(values) & ~np.isin(values, (0, 1))).sum()
            )
            if invalid:
                issues.append(
                    _issue_for_profile(
                        profile,
                        CODE_AT_SYMBOL_BOOLEAN,
                        SEVERITY_ERROR,
                        "at_symbol",
                        invalid,
                        "at_symbol value(s) are not 0 or 1. The current extractor "
                        "emits a boolean presence flag only. Legacy values such as "
                        "8 or 9 imply a count encoding that this extractor cannot "
                        "reproduce.",
                    )
                )

    if "isHttps" in checked and "valid_url" in checked:
        https = _numeric_array(frame, "isHttps")
        valid = _numeric_array(frame, "valid_url")
        if https is not None and valid is not None:
            both = np.isfinite(https) & np.isfinite(valid)
            broken = int((both & (https == 1) & (valid != 1)).sum())
            if broken:
                issues.append(
                    _issue_for_profile(
                        profile,
                        CODE_HTTPS_IMPLIES_VALID,
                        SEVERITY_ERROR,
                        "isHttps",
                        broken,
                        "Row(s) have isHttps == 1 while valid_url != 1. The current "
                        "extractor cannot produce this pair: isHttps == 1 means the "
                        "URL starts with 'https', which also satisfies "
                        "url.startswith('http'). In a legacy table this indicates a "
                        "different training-time encoding.",
                    )
                )

    if "url_length" in checked and "path_length" in checked:
        length = _numeric_array(frame, "url_length")
        path = _numeric_array(frame, "path_length")
        if length is not None and path is not None:
            both = np.isfinite(length) & np.isfinite(path)
            loose = int((both & (length < 9 + path)).sum())
            if loose:
                issues.append(
                    _issue_for_profile(
                        profile,
                        CODE_LOOSE_LENGTH_BOUND,
                        SEVERITY_WARNING,
                        "url_length",
                        loose,
                        "Row(s) violate the loose bound url_length >= 9 + "
                        "path_length. This is an arithmetic sanity check only and "
                        "assumes a scheme-bearing URL. Passing it is NOT evidence "
                        "that path_length has the same meaning as in training.",
                    )
                )
            strict = int((both & (length < 9 + 2 * path)).sum())
            if strict:
                issues.append(
                    _issue_for_profile(
                        profile,
                        CODE_STRICT_LENGTH_BOUND,
                        SEVERITY_INFO,
                        "url_length",
                        strict,
                        "Row(s) violate the stricter non-empty-segment bound "
                        "url_length >= 9 + 2*path_length. This is not a contract "
                        "rule (empty path segments are legal); it is advisory "
                        "evidence about how path_length was encoded.",
                    )
                )

    # ------------------------------------------------------- semantic honesty
    for spec in unverified_semantics():
        issues.append(
            ValidationIssue(
                CODE_UNVERIFIED_SEMANTICS,
                CATEGORY_UNVERIFIED,
                SEVERITY_INFO,
                spec.name,
                None,
                f"Training-time semantics are {spec.training_semantics}. "
                + spec.training_note,
            )
        )

    return ValidationReport(
        profile=profile,
        rows=rows,
        columns_checked=checked,
        issues=tuple(issues),
    )


def present_features_ordered(
    present: Sequence[str], expected: Sequence[str]
) -> list[str]:
    """Feature columns of ``present`` in the order they actually appear."""
    expected_set = set(expected)
    return [name for name in present if name in expected_set]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="feature_validator.py",
        description=(
            "Read-only validation of a URL feature table. The CSV is never "
            "modified and no feature values are printed."
        ),
    )
    parser.add_argument("csv", help="path to a feature table in CSV form")
    parser.add_argument(
        "--profile",
        choices=PROFILES,
        default=PROFILE_LEGACY,
        help="validation profile (default: legacy)",
    )
    parser.add_argument(
        "--no-order-check",
        action="store_true",
        help="skip the column-order consistency warning",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns 0 on pass, 1 on contract errors."""
    args = _build_parser().parse_args(argv)
    frame = pd.read_csv(args.csv)
    report = validate_feature_table(
        frame,
        profile=args.profile,
        require_order=not args.no_order_check,
    )
    print(report.format_text())
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    raise SystemExit(main())
