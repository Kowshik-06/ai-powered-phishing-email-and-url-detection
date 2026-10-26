"""Version metadata for the authoritative URL feature extractor.

This module is metadata only. It does not import, wrap, monkey-patch, or
otherwise change ``url_features.extract_features``. Importing it performs no
file writes and no model loading.

What this identifier *is*
-------------------------
A stable name for the behaviour of ``url_features.extract_features`` at the
moment it was reviewed. It lets a dataset, a model artifact, or an evaluation
report record *which* extractor produced its inputs.

What this identifier is *not*
-----------------------------
It does not prove that any existing model artifact was trained on features
produced by this version, and it does not assert compatibility with
``phishing_model.pkl``, ``hgb_model.pkl``, ``deep_model.pt``, the saved
scalers, or ``dataset.csv``. Those artifacts predate this metadata and their
training-time feature semantics remain unverified (see
``feature_contract.unverified_semantics``).
"""

from __future__ import annotations

import hashlib
import os

#: Semantic version of the feature-extraction contract. Bump this whenever the
#: behaviour of ``extract_features`` changes in any way that can alter a value
#: for any input.
EXTRACTOR_VERSION = "1.0.0"

#: Human-readable label for logs and reports.
EXTRACTOR_VERSION_LABEL = "url-features/1.0.0"

#: The module that owns feature extraction. There is exactly one implementation.
EXTRACTOR_MODULE = "ml-service/url_features.py"

#: The single authoritative function.
EXTRACTOR_FUNCTION = "extract_features"

#: SHA-256 of ``url_features.py`` with CRLF normalised to LF, so the pin is
#: stable across Git line-ending settings. Recorded at version 1.0.0.
#:
#: This is an *integrity pin for review*, not a compatibility claim. If the pin
#: no longer matches, the extractor file changed: decide whether the change is
#: a comment/format-only edit (update the pin) or a behavioural change (bump
#: ``EXTRACTOR_VERSION``, update the pin, update the contract, and re-validate
#: any dataset and model built from it).
EXTRACTOR_SHA256 = "5b449dd843eea58e7d199ddb011bc3763e552e7ef1b204047a574f3233199d89"

#: When the version must be incremented.
INCREMENT_POLICY = """
Increment EXTRACTOR_VERSION (and update EXTRACTOR_SHA256) when a change to
url_features.extract_features can alter any feature value for any input, or
when the emitted column set or column order changes. Examples:

  * changing a formula, operator, or substring list
  * changing case handling (for example making a prefix test case-insensitive)
  * adding, removing, renaming, or reordering a feature
  * changing the return type or dtypes

Do NOT increment for changes that cannot alter output values, such as comments,
whitespace, or type annotations. Those still change the file hash, so update
EXTRACTOR_SHA256 after confirming the output is byte-identical on a fixed
input corpus.

Version format is MAJOR.MINOR.PATCH:
  * MAJOR - an existing feature's meaning changes, an existing feature is
    removed, or an incompatible contract change occurs
  * MINOR - one or more features are added while existing feature meanings and
    definitions remain unchanged
  * PATCH - a value-changing correction that does not change the feature set or
    intended feature meanings

Any bump requires re-validating feature tables and reviewing whether dependent
models must be rebuilt. A version bump alone never makes an old model valid.
""".strip()

#: Caveat that must accompany any use of the version string.
COMPATIBILITY_NOTE = """
This version identifies the extractor contract only. It does NOT establish
that existing model artifacts were trained on features produced by this
version, and it does NOT make them compatible. Do not cite it as evidence of
model/feature agreement.
""".strip()

#: History of recorded versions.
VERSION_HISTORY = {
    "1.0.0": (
        "Baseline. Documents url_features.extract_features exactly as shipped. "
        "No behaviour change; this release only adds metadata, a contract, and "
        "a read-only validator."
    ),
}


def extractor_path() -> str:
    """Absolute path of the extractor module this metadata describes."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "url_features.py")


def fingerprint(path: str | None = None) -> str:
    """Return the newline-normalised SHA-256 of the extractor module.

    Reads the file only. Never writes.
    """
    target = path or extractor_path()
    with open(target, "rb") as handle:
        data = handle.read()
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def describe() -> dict:
    """Machine-readable summary of this metadata (no I/O beyond the path)."""
    return {
        "extractor_version": EXTRACTOR_VERSION,
        "extractor_version_label": EXTRACTOR_VERSION_LABEL,
        "extractor_module": EXTRACTOR_MODULE,
        "extractor_function": EXTRACTOR_FUNCTION,
        "extractor_sha256_pin": EXTRACTOR_SHA256,
        "compatibility_note": COMPATIBILITY_NOTE,
    }
