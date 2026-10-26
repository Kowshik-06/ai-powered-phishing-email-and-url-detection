"""The feature contract for the 13 URL features.

This module documents what ``url_features.extract_features`` actually does
today. It deliberately does **not** redefine, correct, or "fix" any feature, and
it does not change model input behaviour. Where the original training-time
semantics cannot be established, the contract says so instead of guessing.

Authoritative implementation
----------------------------
``ml-service/url_features.py`` :: ``extract_features(url) -> pandas.DataFrame``
(one row, 13 ``int64`` columns, in the order listed in ``FEATURE_NAMES``).

There is exactly one extractor. ``engine._url_features`` is a column selector
that wraps it; ``evaluate_raw_urls.py`` imports the same path. Version metadata
lives in ``extractor_version``.

Contract summary
----------------
==========================  =======  ============  =========  ==========================
feature                     dtype    allowed       scheme     training semantics
==========================  =======  ============  =========  ==========================
``url_length``              int64    >= 0          affected   unrecoverable
``valid_url``               int64    {0, 1}        affected   unrecoverable
``at_symbol``               int64    {0, 1}        no         unrecoverable
``sensitive_words_count``   int64    0..5          no         ambiguous
``path_length``             int64    >= -1         affected   unrecoverable
``isHttps``                 int64    {0, 1}        affected   unrecoverable
``nb_dots``                 int64    >= 0          no         verified
``nb_hyphens``              int64    >= 0          no         verified
``nb_and``                  int64    >= 0          no         verified
``nb_or``                   int64    >= 0          no         ambiguous
``nb_www``                  int64    >= 0          no         ambiguous
``nb_com``                  int64    >= 0          no         ambiguous
``nb_underscore``           int64    >= 0          no         verified
==========================  =======  ============  =========  ==========================

"Scheme affected" means that ``engine.py`` prepends ``https://`` to input with
no recognised scheme before calling the extractor (``engine.py:79``). The
extractor itself is a pure function of the string it is given.

Semantic status meanings
------------------------
``verified``
    The value's meaning is mechanically unambiguous and the runtime definition
    is consistent with what the training table appears to encode.

``ambiguous``
    The runtime definition is clear, but the training-time definition (for
    example a tokenisation or keyword list) cannot be confirmed.

``unrecoverable``
    The training-time meaning cannot be established, or the legacy values are
    provably impossible to reproduce with this extractor. Models trained on
    these columns are unvalidated for that reason. Do not treat agreement
    between training and runtime columns as evidence that they mean the same
    thing.

Important
---------
Passing validation does NOT make these features trustworthy. Validation proves
only that a table is well-formed with respect to the declared runtime contract.
Five features are ``unrecoverable`` and four more are ``ambiguous``; see
``unverified_semantics()``.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from extractor_version import EXTRACTOR_VERSION

#: Version of this contract document. Bump when a spec entry changes.
FEATURE_CONTRACT_VERSION = "1.0.0"

#: Ordered feature names, exactly as emitted by extract_features.
FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "valid_url",
    "at_symbol",
    "sensitive_words_count",
    "path_length",
    "isHttps",
    "nb_dots",
    "nb_hyphens",
    "nb_and",
    "nb_or",
    "nb_www",
    "nb_com",
    "nb_underscore",
)

FEATURE_COUNT = len(FEATURE_NAMES)

#: Columns a legacy training table may carry in addition to the features.
#: ``dataset.csv`` ends with this column; it is not a model input.
LEGACY_ALLOWED_EXTRA_COLUMNS: tuple[str, ...] = ("target",)

SEMANTIC_VERIFIED = "verified"
SEMANTIC_AMBIGUOUS = "ambiguous"
SEMANTIC_UNRECOVERABLE = "unrecoverable"
SEMANTIC_STATUSES = (SEMANTIC_VERIFIED, SEMANTIC_AMBIGUOUS, SEMANTIC_UNRECOVERABLE)


@dataclass(frozen=True)
class FeatureSpec:
    """Declared contract for one feature.

    ``minimum``/``maximum``/``allowed_values`` are contract bounds for the
    *runtime* extractor. ``None`` means "no declared bound". Bounds are chosen
    to describe current behaviour, not to express an opinion about what the
    feature should ideally be.
    """

    name: str
    formula: str
    dtype: str
    minimum: int | None
    maximum: int | None
    allowed_values: tuple[int, ...] | None
    scheme_dependent: bool
    scheme_note: str
    training_semantics: str
    training_note: str
    mismatch_risk: str
    provisional: bool

    @property
    def is_boolean(self) -> bool:
        return self.allowed_values == (0, 1)


_SPECS: dict[str, FeatureSpec] = {
    "url_length": FeatureSpec(
        name="url_length",
        formula="len(url)",
        dtype="int64",
        minimum=0,
        maximum=None,
        allowed_values=None,
        scheme_dependent=True,
        scheme_note=(
            "Pure length of the string passed in. engine.py:79 prepends "
            "'https://' to input with no scheme at all, adding exactly 8 "
            "characters before extraction, so runtime values include that "
            "prefix."
        ),
        training_semantics=SEMANTIC_UNRECOVERABLE,
        training_note=(
            "Legacy distribution is dominated by a suspected fixed-width "
            "truncation artefact: 1,277/2,488 rows (51.33%) sit at exactly "
            "{73, 74, 75}, with no rows in [77, 95]. The per-row value cannot "
            "be read as a real URL length."
        ),
        mismatch_risk=(
            "Has the highest Random Forest importance (0.2637 of 1.0) yet the "
            "training column is largely an artefact of an unknown generator."
        ),
        provisional=True,
    ),
    "valid_url": FeatureSpec(
        name="valid_url",
        formula='1 if url.startswith("http") else 0',
        dtype="int64",
        minimum=0,
        maximum=1,
        allowed_values=(0, 1),
        scheme_dependent=True,
        scheme_note=(
            "Case-sensitive prefix test: 'HTTP://...' and 'ftp://...' both "
            "yield 0. engine.py:79 prepends lowercase 'https://' only when the "
            "input has no scheme at all (its scheme regex is case-insensitive), "
            "so scheme-less input yields 1 while 'ftp://...' and 'HTTPS://...' "
            "keep their own text and yield 0."
        ),
        training_semantics=SEMANTIC_UNRECOVERABLE,
        training_note=(
            "71.99% of legacy rows are 0, and 486 rows combine valid_url=0 "
            "with isHttps=1. This extractor cannot produce that pair "
            "(isHttps=1 implies an 'https' prefix implies valid_url=1), so the "
            "legacy encoding has no reproducible meaning here."
        ),
        mismatch_risk=(
            "Constant 1 for every URL reaching the service (235,795 of "
            "235,795 corpus URLs) while carrying the second-highest Random "
            "Forest importance (0.1742)."
        ),
        provisional=True,
    ),
    "at_symbol": FeatureSpec(
        name="at_symbol",
        formula='1 if "@" in url else 0',
        dtype="int64",
        minimum=0,
        maximum=1,
        allowed_values=(0, 1),
        scheme_dependent=False,
        scheme_note=(
            "The prepended 'https://' contains no '@', so normalisation does "
            "not change this value."
        ),
        training_semantics=SEMANTIC_UNRECOVERABLE,
        training_note=(
            "Legacy values include 8 and 9 (2 rows). A boolean presence flag "
            "can never produce those, so the legacy feature was a count of "
            "'@' occurrences whose exact rules are unknown."
        ),
        mismatch_risk=(
            "Training encoded an unbounded count; runtime encodes a flag. "
            "Random Forest importance is the lowest of the 13 (0.0011), but "
            "the 0.8-weight HGB may still split on the column."
        ),
        provisional=True,
    ),
    "sensitive_words_count": FeatureSpec(
        name="sensitive_words_count",
        formula=(
            'sum(word in url.lower() for word in '
            '["login", "secure", "bank", "verify", "update"])'
        ),
        dtype="int64",
        minimum=0,
        maximum=5,
        allowed_values=None,
        scheme_dependent=False,
        scheme_note=(
            "The prepended 'https://' contains none of the five keywords, so "
            "normalisation does not change this value."
        ),
        training_semantics=SEMANTIC_AMBIGUOUS,
        training_note=(
            "Direction is preserved (phishing above legitimate) but magnitude "
            "is not: runtime means are 0.059 phishing / 0.003 legitimate "
            "against legacy means of 0.400 / 0.082. The legacy keyword list "
            "and matching rule are unknown."
        ),
        mismatch_risk=(
            "engine._reasons raises a keyword explanation at a count of 2 or "
            "more, an event far rarer under the runtime keyword set than the "
            "legacy distribution implies."
        ),
        provisional=True,
    ),
    "path_length": FeatureSpec(
        name="path_length",
        formula='len(url.split("/")) - 3 if "/" in url else 0',
        dtype="int64",
        minimum=-1,
        maximum=None,
        allowed_values=None,
        scheme_dependent=True,
        scheme_note=(
            "Counts '/'-separated tokens minus 3, assuming a scheme, '//' and "
            "a host. A scheme-less input containing a slash can yield -1 "
            "(for example 'a/b'). engine.py:79 prepending 'https://' adds two "
            "tokens, so normalisation changes this value by +2."
        ),
        training_semantics=SEMANTIC_UNRECOVERABLE,
        training_note=(
            "Legacy range 0-85, mean 16.21, p99 about 54 - consistent with a "
            "count of path *characters*, not path *segments*. 662 legacy rows "
            "(26.61%) violate the non-empty-segment bound "
            "url_length >= 9 + 2*path_length; 658 violate the slightly looser "
            "8 + 2*path_length bound used in the audit. The loose bound "
            "url_length >= 9 + path_length has 0 violations, which is why "
            "passing it proves nothing about path semantics."
        ),
        mismatch_risk=(
            "Runtime legitimate URLs always yield 0; phishing has mean 1.019. "
            "Feature-pair support against the corpus is 97.33% under character "
            "semantics but only 51.87% under segment semantics."
        ),
        provisional=True,
    ),
    "isHttps": FeatureSpec(
        name="isHttps",
        formula='1 if url.startswith("https") else 0',
        dtype="int64",
        minimum=0,
        maximum=1,
        allowed_values=(0, 1),
        scheme_dependent=True,
        scheme_note=(
            "Case-sensitive: 'HTTPS://...' yields 0. engine.py:79 prepends "
            "lowercase 'https://' only when the input has no scheme at all, so "
            "the value is synthesised (1) for scheme-less input; 'ftp://...' "
            "stays 0."
        ),
        training_semantics=SEMANTIC_UNRECOVERABLE,
        training_note=(
            "Legacy association is inverted: phishing mean 0.668 versus "
            "legitimate 0.213. The 486 rows combining isHttps=1 with "
            "valid_url=0 are unreachable here."
        ),
        mismatch_risk=(
            "Runtime legitimate is 1.000 and phishing 0.487, the opposite of "
            "the legacy direction. Random Forest importance is 0.0742."
        ),
        provisional=True,
    ),
    "nb_dots": FeatureSpec(
        name="nb_dots",
        formula='url.count(".")',
        dtype="int64",
        minimum=0,
        maximum=None,
        allowed_values=None,
        scheme_dependent=False,
        scheme_note=(
            "The prepended 'https://' contains no '.', so normalisation does "
            "not change this value."
        ),
        training_semantics=SEMANTIC_VERIFIED,
        training_note=(
            "Mechanically unambiguous: a count of '.' over the raw string, "
            "with the same direction in training and at runtime."
        ),
        mismatch_risk=(
            "Counts '.' anywhere, including the path and query, so it is not a "
            "subdomain-depth measure despite being used as one indirectly."
        ),
        provisional=False,
    ),
    "nb_hyphens": FeatureSpec(
        name="nb_hyphens",
        formula='url.count("-")',
        dtype="int64",
        minimum=0,
        maximum=None,
        allowed_values=None,
        scheme_dependent=False,
        scheme_note=(
            "The prepended 'https://' contains no '-', so normalisation does "
            "not change this value."
        ),
        training_semantics=SEMANTIC_VERIFIED,
        training_note=(
            "Definition is unambiguous: hyphens anywhere in the URL, including "
            "the path (see test_url_features.py:26-31)."
        ),
        mismatch_risk=(
            "Class association is inverted between populations: legacy "
            "legitimate 0.615 versus phishing 0.570, runtime legitimate 0.083 "
            "versus phishing 0.707. This is a data/population issue, not a "
            "definition ambiguity."
        ),
        provisional=False,
    ),
    "nb_and": FeatureSpec(
        name="nb_and",
        formula='url.count("&")',
        dtype="int64",
        minimum=0,
        maximum=None,
        allowed_values=None,
        scheme_dependent=False,
        scheme_note=(
            "The prepended 'https://' contains no '&', so normalisation does "
            "not change this value."
        ),
        training_semantics=SEMANTIC_VERIFIED,
        training_note=(
            "Definition is unambiguous: a count of '&' over the raw string."
        ),
        mismatch_risk=(
            "Class association is inverted: legacy legitimate 0.025 versus "
            "phishing 0.004, runtime legitimate 0.000 versus phishing 0.084."
        ),
        provisional=False,
    ),
    "nb_or": FeatureSpec(
        name="nb_or",
        formula='url.lower().count("or")',
        dtype="int64",
        minimum=0,
        maximum=None,
        allowed_values=None,
        scheme_dependent=False,
        scheme_note=(
            "The prepended 'https://' contains no 'or', so normalisation does "
            "not change this value."
        ),
        training_semantics=SEMANTIC_AMBIGUOUS,
        training_note=(
            "Runtime is a raw substring count over the whole lowercased URL, "
            "so it matches inside ordinary words (for, work, portal, or). "
            "Whether the legacy table used the same rule, tokens, or a "
            "host-only window is unknown."
        ),
        mismatch_risk=(
            "Direction agrees with the legacy table, but the substring rule "
            "makes the value a weak proxy for anything meaningful."
        ),
        provisional=True,
    ),
    "nb_www": FeatureSpec(
        name="nb_www",
        formula='url.lower().count("www")',
        dtype="int64",
        minimum=0,
        maximum=None,
        allowed_values=None,
        scheme_dependent=False,
        scheme_note=(
            "The prepended 'https://' contains no 'www', so normalisation does "
            "not change this value."
        ),
        training_semantics=SEMANTIC_AMBIGUOUS,
        training_note=(
            "Runtime counts 'www' as a substring anywhere, so a path or query "
            "containing 'www' also increments it. The legacy rule is unknown."
        ),
        mismatch_risk=(
            "Direction agrees with the legacy table, but a count of 0 or 2+ "
            "does not reliably indicate the absence of a host prefix."
        ),
        provisional=True,
    ),
    "nb_com": FeatureSpec(
        name="nb_com",
        formula='url.lower().count("com")',
        dtype="int64",
        minimum=0,
        maximum=None,
        allowed_values=None,
        scheme_dependent=False,
        scheme_note=(
            "The prepended 'https://' contains no 'com', so normalisation does "
            "not change this value."
        ),
        training_semantics=SEMANTIC_AMBIGUOUS,
        training_note=(
            "Runtime counts 'com' anywhere: the '.com' TLD, but also inside "
            "words such as computer, ecommerce, or .company. The legacy rule "
            "is unknown."
        ),
        mismatch_risk=(
            "A near-universal value for commercial domains makes the column "
            "poorly discriminative, and the substring rule inflates it "
            "further."
        ),
        provisional=True,
    ),
    "nb_underscore": FeatureSpec(
        name="nb_underscore",
        formula='url.count("_")',
        dtype="int64",
        minimum=0,
        maximum=None,
        allowed_values=None,
        scheme_dependent=False,
        scheme_note=(
            "The prepended 'https://' contains no '_', so normalisation does "
            "not change this value."
        ),
        training_semantics=SEMANTIC_VERIFIED,
        training_note=(
            "Definition is unambiguous: a count of '_' over the raw string."
        ),
        mismatch_risk=(
            "Class association is inverted: legacy legitimate 0.171 versus "
            "phishing 0.106, runtime legitimate 0.000 versus phishing 0.082."
        ),
        provisional=False,
    ),
}

#: Immutable mapping of feature name to its declared contract.
FEATURE_SPECS: Mapping[str, FeatureSpec] = MappingProxyType(_SPECS)


def spec_for(name: str) -> FeatureSpec:
    """Return the contract entry for ``name`` or raise ``KeyError``."""
    return FEATURE_SPECS[name]


def expected_columns() -> tuple[str, ...]:
    """The 13 feature columns, in the order the extractor emits them."""
    return FEATURE_NAMES


def boolean_features() -> tuple[str, ...]:
    """Features declared to take only the values 0 and 1."""
    return tuple(n for n in FEATURE_NAMES if FEATURE_SPECS[n].is_boolean)


def scheme_dependent_features() -> tuple[str, ...]:
    """Features whose value can change when a scheme is prepended."""
    return tuple(n for n in FEATURE_NAMES if FEATURE_SPECS[n].scheme_dependent)


def unverified_semantics() -> tuple[FeatureSpec, ...]:
    """Features whose training-time meaning is ambiguous or unrecoverable."""
    return tuple(
        FEATURE_SPECS[n]
        for n in FEATURE_NAMES
        if FEATURE_SPECS[n].training_semantics != SEMANTIC_VERIFIED
    )


def contract_snapshot() -> dict:
    """Serialisable form of the whole contract, for reports and tests."""
    return {
        "contract_version": FEATURE_CONTRACT_VERSION,
        "extractor_version": EXTRACTOR_VERSION,
        "feature_count": FEATURE_COUNT,
        "feature_order": list(FEATURE_NAMES),
        "legacy_allowed_extra_columns": list(LEGACY_ALLOWED_EXTRA_COLUMNS),
        "features": {
            n: {
                "formula": FEATURE_SPECS[n].formula,
                "dtype": FEATURE_SPECS[n].dtype,
                "minimum": FEATURE_SPECS[n].minimum,
                "maximum": FEATURE_SPECS[n].maximum,
                "allowed_values": (
                    list(FEATURE_SPECS[n].allowed_values)
                    if FEATURE_SPECS[n].allowed_values is not None
                    else None
                ),
                "scheme_dependent": FEATURE_SPECS[n].scheme_dependent,
                "training_semantics": FEATURE_SPECS[n].training_semantics,
                "provisional": FEATURE_SPECS[n].provisional,
            }
            for n in FEATURE_NAMES
        },
    }
