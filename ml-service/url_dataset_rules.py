"""Pure URL policy rules for the future dataset pipeline.

This module is intentionally isolated: it has no backend, frontend, model,
dataset, filesystem-write, subprocess, or network dependency. It does not
import ``engine.py`` and does not load model artifacts.

The policies below are *proposals for dataset preparation*. They are not
approved training policy, they do not change production preprocessing, and
they do not make any claim that two URLs are semantically equivalent.

Normalization policy
--------------------
``normalize_url`` performs only two transformations:

1. strip leading/trailing whitespace, and
2. prepend ``https://`` when the input has no scheme matching the runtime
   regex ``^[a-zA-Z][a-zA-Z0-9+.-]*://``.

It never lowercases path/query/fragment text, removes ``www``, decodes
percent escapes, sorts query parameters, or drops fragments. Scheme and host
casing are preserved exactly as supplied. A URL that cannot be parsed, has no
hostname, has an invalid port, or has a malformed host is rejected with a
stable reason code. That host validation is stricter than production runtime
preprocessing, which does not validate hostname characters.

Canonical identity policy
-------------------------
``canonicalize_url`` is a deduplication heuristic, not proof of equivalence.
It applies these documented rules after normalization:

* scheme and DNS hostname are lowercased; IDNs become their ASCII (IDNA) form;
* IPv4 and IPv6 literals are written in canonical ``ipaddress`` form;
* one trailing hostname dot is removed;
* default ports are removed only for ``http`` (80) and ``https`` (443);
* an empty path becomes ``/``;
* user information is preserved exactly;
* path, query, repeated query parameters, percent-encoding, query order, and
  fragment are preserved exactly.

Conservative consequences: ``?a=1&b=2`` and ``?b=2&a=1`` stay distinct;
``/A`` and ``/a`` stay distinct; ``%7E`` and ``~`` stay distinct; fragments
stay distinct. Empty fragment or query delimiters are indistinguishable from
absent delimiters because ``urlsplit`` does not retain that distinction.

Host classification policy
---------------------------
Hostnames are validated without DNS. IPv4/IPv6 literals are recognized with
``ipaddress``. A hostname consisting only of digits and dots is treated as an
IPv4 candidate and rejected if it is not a valid IPv4 literal, rather than
being accepted as a numeric DNS name. IDNs use the standard-library IDNA codec,
which implements IDNA 2003 rather than modern UTS #46; this is a documented
limitation.

This module deliberately does **not** implement a public-suffix-list (PSL)
algorithm. A registrable domain cannot be inferred safely from the last two
labels. ``resolve_registrable_domain`` requires an approved PSL-backed
resolver to be supplied later. Without one it returns
``dependency_required`` rather than guessing.

Shortener policy
----------------
``shortener_status`` checks a small, local, explicit hostname set. It performs
no DNS lookup and follows no redirects. A host is ``listed`` when it equals a
known shortener or is a subdomain of one. Valid unlisted hosts return
``not_listed``; this is **not** a safety or phishing verdict.

Template-key policy
-------------------
``template_key`` is a deterministic near-duplicate grouping key. It preserves
scheme, user information, hostname, port, path structure, query parameter
names/order, and fragment. Complete path segments or query values that are
all-numeric, UUID-shaped, or hexadecimal tokens of at least eight characters
are replaced with ``<num>``, ``<uuid>``, or ``<hex>``. Arbitrary alphabetic
tokens are preserved.

False positives are possible when a real word looks hexadecimal. False
negatives are possible when an identifier is embedded inside an alphanumeric
filename or uses percent-encoding. A template key is only a grouping
heuristic; it does not prove a shared phishing kit or identical behaviour.
Grouping by key is linear and this module performs no all-pairs comparison.

Safety
------
Every rejection is reported with a stable code. No public function prints,
logs, or embeds the input URL in an exception or rejection message. No public
function writes files, opens sockets, or reads environment state.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

# Same scheme-detection rule used by the existing runtime/evaluator code.
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

# Stable rejection codes. They never contain the rejected value.
REASON_NOT_A_STRING = "not_a_string"
REASON_EMPTY = "empty_input"
REASON_EMPTY_HOST = "empty_host"
REASON_WHITESPACE = "whitespace"
REASON_CONTROL_CHARACTER = "control_character"
REASON_MALFORMED_URL = "malformed_url"
REASON_MISSING_HOST = "missing_host"
REASON_INVALID_PORT = "invalid_port"
REASON_INVALID_HOST = "invalid_host"
REASON_INVALID_IPV4 = "invalid_ipv4"
REASON_HOST_TOO_LONG = "host_too_long"
REASON_LABEL_TOO_LONG = "label_too_long"
REASON_INVALID_LABEL = "invalid_label"

KIND_DNS = "dns"
KIND_IPV4 = "ipv4"
KIND_IPV6 = "ipv6"

SHORTENER_LISTED = "listed"
SHORTENER_NOT_LISTED = "not_listed"
SHORTENER_INVALID = "invalid"

REGISTRABLE_RESOLVED = "resolved"
REGISTRABLE_NOT_FOUND = "not_found"
REGISTRABLE_DEPENDENCY_REQUIRED = "dependency_required"
REGISTRABLE_IP_LITERAL = "ip_literal"
REGISTRABLE_INVALID_HOST = "invalid_host"
REGISTRABLE_RESOLVER_ERROR = "resolver_error"

# Deliberately small and local. No network lookup, no redirect following.
KNOWN_SHORTENER_HOSTS = frozenset(
    {
        "bit.ly",
        "bit.do",
        "buff.ly",
        "cutt.ly",
        "goo.gl",
        "is.gd",
        "lnkd.in",
        "mcaf.ee",
        "ow.ly",
        "rb.gy",
        "rebrand.ly",
        "s.id",
        "shorturl.at",
        "t.co",
        "t.ly",
        "tiny.cc",
        "tinyurl.com",
        "urlz.fr",
    }
)

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IPV4_SHAPE_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_NUMERIC_RE = re.compile(r"^[0-9]+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{8,}$")


@dataclass(frozen=True)
class RuleResult:
    """A successful string result or a stable rejection code.

    Exactly one of ``value``/``reason`` is expected to be meaningful. The
    class deliberately does not raise on construction so rejection handling
    stays explicit at call sites.
    """

    value: str | None
    reason: str | None

    @property
    def ok(self) -> bool:
        return self.reason is None

    @classmethod
    def accepted(cls, value: str) -> "RuleResult":
        return cls(value=value, reason=None)

    @classmethod
    def rejected(cls, reason: str) -> "RuleResult":
        return cls(value=None, reason=reason)


@dataclass(frozen=True)
class HostInfo:
    """Result of hostname validation/classification.

    ``host`` is the lowercased display form (Unicode for IDNs), while
    ``ascii_host`` is the IDNA/punycode form used for comparison. ``port`` is
    populated only by :func:`classify_url_host`.
    """

    host: str | None = None
    ascii_host: str | None = None
    kind: str | None = None
    port: int | None = None
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.reason is None

    @property
    def is_ip_literal(self) -> bool:
        return self.kind in (KIND_IPV4, KIND_IPV6)


@dataclass(frozen=True)
class ShortenerResult:
    """Shortener-list lookup result; not a phishing or safety verdict."""

    status: str
    matched_host: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class RegistrableDomainResult:
    """Registrable-domain resolution result.

    ``dependency_required`` means no approved public-suffix resolver was
    supplied. This module never guesses an eTLD+1 from the last two labels.
    """

    status: str
    domain: str | None = None
    reason: str | None = None

    @property
    def resolved(self) -> bool:
        return self.status == REGISTRABLE_RESOLVED


def _has_whitespace(value: str) -> bool:
    return any(character.isspace() for character in value)


def _has_control_character(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _read_port(parsed) -> tuple[int | None, str | None]:
    try:
        port = parsed.port
    except ValueError:
        return None, REASON_INVALID_PORT
    if port is not None and not 1 <= port <= 65535:
        return None, REASON_INVALID_PORT
    return port, None


def _to_ascii_hostname(host: str) -> str | None:
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def _classify_hostname(value: object) -> HostInfo:
    if not isinstance(value, str):
        return HostInfo(reason=REASON_NOT_A_STRING)
    if not value:
        return HostInfo(reason=REASON_EMPTY_HOST)
    if value != value.strip() or _has_whitespace(value):
        return HostInfo(reason=REASON_WHITESPACE)
    if _has_control_character(value):
        return HostInfo(reason=REASON_CONTROL_CHARACTER)

    host = value
    if host.startswith("["):
        if not host.endswith("]"):
            return HostInfo(reason=REASON_INVALID_HOST)
        host = host[1:-1]
    elif host.endswith("]"):
        return HostInfo(reason=REASON_INVALID_HOST)

    if not host:
        return HostInfo(reason=REASON_EMPTY_HOST)

    # One trailing dot denotes a fully qualified name. More than one is
    # malformed and is rejected rather than silently normalized away.
    if host.endswith("."):
        host = host[:-1]
        if not host or host.endswith("."):
            return HostInfo(reason=REASON_INVALID_HOST)

    if ":" in host:
        try:
            address = ipaddress.IPv6Address(host)
        except ValueError:
            return HostInfo(reason=REASON_INVALID_HOST)
        compressed = address.compressed
        return HostInfo(host=compressed, ascii_host=compressed, kind=KIND_IPV6)

    if _IPV4_SHAPE_RE.fullmatch(host):
        try:
            address = ipaddress.IPv4Address(host)
        except ValueError:
            return HostInfo(reason=REASON_INVALID_IPV4)
        canonical = str(address)
        return HostInfo(host=canonical, ascii_host=canonical, kind=KIND_IPV4)

    lowered = host.lower()
    # Check ASCII length limits before IDNA so an overlong ASCII label gets a
    # specific code instead of an IDNA codec failure.
    if lowered.isascii():
        if len(lowered) > 253:
            return HostInfo(reason=REASON_HOST_TOO_LONG)
        if any(len(label) > 63 for label in lowered.split(".")):
            return HostInfo(reason=REASON_LABEL_TOO_LONG)

    ascii_host = _to_ascii_hostname(lowered)
    if ascii_host is None:
        return HostInfo(reason=REASON_INVALID_HOST)
    if len(ascii_host) > 253:
        return HostInfo(reason=REASON_HOST_TOO_LONG)

    labels = ascii_host.split(".")
    if any(not label for label in labels):
        return HostInfo(reason=REASON_INVALID_HOST)
    for label in labels:
        if len(label) > 63:
            return HostInfo(reason=REASON_LABEL_TOO_LONG)
        if not _LABEL_RE.fullmatch(label):
            return HostInfo(reason=REASON_INVALID_LABEL)

    return HostInfo(host=lowered, ascii_host=ascii_host, kind=KIND_DNS)


def normalize_url(value: object) -> RuleResult:
    """Return a minimally normalized URL or a rejection code.

    Only whitespace stripping and conditional ``https://`` prepending are
    applied. The host is validated but its original casing is preserved.
    """

    if not isinstance(value, str):
        return RuleResult.rejected(REASON_NOT_A_STRING)

    url = value.strip()
    if not url:
        return RuleResult.rejected(REASON_EMPTY)
    if _has_whitespace(url):
        return RuleResult.rejected(REASON_WHITESPACE)
    if _has_control_character(url):
        return RuleResult.rejected(REASON_CONTROL_CHARACTER)

    if not SCHEME_RE.match(url):
        url = "https://" + url

    try:
        parsed = urlsplit(url)
        host = parsed.hostname
    except ValueError:
        return RuleResult.rejected(REASON_MALFORMED_URL)

    if not parsed.scheme or not host:
        return RuleResult.rejected(REASON_MISSING_HOST)

    _port, port_error = _read_port(parsed)
    if port_error is not None:
        return RuleResult.rejected(port_error)

    host_info = _classify_hostname(host)
    if not host_info.ok:
        return RuleResult.rejected(host_info.reason or REASON_INVALID_HOST)

    return RuleResult.accepted(url)


def canonicalize_url(value: object) -> RuleResult:
    """Return a conservative canonical comparison key or a rejection code.

    The transformations are listed in the module docstring. This is a
    deduplication heuristic, not proof of semantic equivalence.
    """

    normalized = normalize_url(value)
    if not normalized.ok:
        return normalized

    try:
        parsed = urlsplit(normalized.value or "")
    except ValueError:
        return RuleResult.rejected(REASON_MALFORMED_URL)

    host = parsed.hostname or ""
    host_info = _classify_hostname(host)
    if not host_info.ok:
        return RuleResult.rejected(host_info.reason or REASON_INVALID_HOST)

    port, port_error = _read_port(parsed)
    if port_error is not None:
        return RuleResult.rejected(port_error)

    scheme = parsed.scheme.lower()
    if port is not None and scheme in {"http", "https"}:
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None

    has_userinfo = "@" in parsed.netloc
    userinfo = parsed.netloc.rsplit("@", 1)[0] if has_userinfo else ""

    host_part = (
        f"[{host_info.ascii_host}]"
        if host_info.kind == KIND_IPV6
        else (host_info.ascii_host or "")
    )
    authority = (userinfo + "@" if has_userinfo else "") + host_part
    if port is not None:
        authority += f":{port}"

    path = parsed.path or "/"
    key = urlunsplit((scheme, authority, path, parsed.query, parsed.fragment))
    return RuleResult.accepted(key)


def classify_host(value: object) -> HostInfo:
    """Validate and classify a bare hostname (no port, no URL).

    Use :func:`classify_url_host` when the value is a URL or contains a port.
    """

    return _classify_hostname(value)


def classify_url_host(value: object) -> HostInfo:
    """Validate a URL and return its host, kind, and optional port."""

    normalized = normalize_url(value)
    if not normalized.ok:
        return HostInfo(reason=normalized.reason)

    try:
        parsed = urlsplit(normalized.value or "")
    except ValueError:
        return HostInfo(reason=REASON_MALFORMED_URL)

    port, port_error = _read_port(parsed)
    if port_error is not None:
        return HostInfo(reason=port_error)

    host_info = _classify_hostname(parsed.hostname or "")
    if not host_info.ok:
        return host_info

    return HostInfo(
        host=host_info.host,
        ascii_host=host_info.ascii_host,
        kind=host_info.kind,
        port=port,
    )


def _match_shortener(ascii_host: str) -> str | None:
    for known in sorted(KNOWN_SHORTENER_HOSTS):
        if ascii_host == known or ascii_host.endswith("." + known):
            return known
    return None


def shortener_status(host: object) -> ShortenerResult:
    """Look up a bare hostname in the local shortener set.

    Subdomains of a listed host are flagged. Unlisted valid hosts return
    ``not_listed``; this is not a claim that the host is safe.
    """

    host_info = classify_host(host)
    if not host_info.ok:
        return ShortenerResult(status=SHORTENER_INVALID, reason=host_info.reason)

    if host_info.kind != KIND_DNS or not host_info.ascii_host:
        return ShortenerResult(status=SHORTENER_NOT_LISTED)

    matched = _match_shortener(host_info.ascii_host)
    if matched is None:
        return ShortenerResult(status=SHORTENER_NOT_LISTED)
    return ShortenerResult(status=SHORTENER_LISTED, matched_host=matched)


def shortener_status_for_url(value: object) -> ShortenerResult:
    """Look up the host of a URL in the local shortener set."""

    host_info = classify_url_host(value)
    if not host_info.ok:
        return ShortenerResult(status=SHORTENER_INVALID, reason=host_info.reason)

    if host_info.kind != KIND_DNS or not host_info.ascii_host:
        return ShortenerResult(status=SHORTENER_NOT_LISTED)

    matched = _match_shortener(host_info.ascii_host)
    if matched is None:
        return ShortenerResult(status=SHORTENER_NOT_LISTED)
    return ShortenerResult(status=SHORTENER_LISTED, matched_host=matched)


def resolve_registrable_domain(
    host: object,
    resolver: Callable[[str], str | None] | None = None,
) -> RegistrableDomainResult:
    """Resolve a registrable domain through an approved PSL-backed resolver.

    ``resolver`` must accept an ASCII hostname and return a registrable domain
    (or ``None``). This module does not provide such a resolver and does not
    install one. Without it the result is ``dependency_required``. IP literals
    are reported separately and never passed to the resolver.

    The resolver's answer is checked only for being a non-empty suffix of the
    host; the resolver remains responsible for PSL correctness.
    """

    host_info = classify_host(host)
    if not host_info.ok:
        return RegistrableDomainResult(
            status=REGISTRABLE_INVALID_HOST,
            reason=host_info.reason,
        )

    if host_info.kind != KIND_DNS or not host_info.ascii_host:
        return RegistrableDomainResult(status=REGISTRABLE_IP_LITERAL)

    if resolver is None:
        return RegistrableDomainResult(status=REGISTRABLE_DEPENDENCY_REQUIRED)
    if not callable(resolver):
        return RegistrableDomainResult(status=REGISTRABLE_RESOLVER_ERROR)

    try:
        resolved = resolver(host_info.ascii_host)
    except Exception:
        return RegistrableDomainResult(status=REGISTRABLE_RESOLVER_ERROR)

    if resolved is None:
        return RegistrableDomainResult(status=REGISTRABLE_NOT_FOUND)
    if not isinstance(resolved, str):
        return RegistrableDomainResult(status=REGISTRABLE_RESOLVER_ERROR)

    domain = resolved.strip().lower().rstrip(".")
    if not domain:
        return RegistrableDomainResult(status=REGISTRABLE_NOT_FOUND)

    if host_info.ascii_host != domain and not host_info.ascii_host.endswith(
        "." + domain
    ):
        return RegistrableDomainResult(status=REGISTRABLE_RESOLVER_ERROR)

    return RegistrableDomainResult(
        status=REGISTRABLE_RESOLVED,
        domain=domain,
    )


def _mask_token(token: str) -> str:
    if _UUID_RE.fullmatch(token):
        return "<uuid>"
    if _NUMERIC_RE.fullmatch(token):
        return "<num>"
    if _HEX_RE.fullmatch(token):
        return "<hex>"
    return token


def _mask_query(query: str) -> str:
    if not query:
        return query

    masked_pairs: list[str] = []
    for pair in query.split("&"):
        if "=" in pair:
            name, value = pair.split("=", 1)
            masked_pairs.append(name + "=" + _mask_token(value))
        else:
            masked_pairs.append(pair)
    return "&".join(masked_pairs)


def template_key(value: object) -> RuleResult:
    """Return a deterministic near-duplicate template key or a rejection code.

    Only complete path segments and query values are masked. See the module
    docstring for false-positive and false-negative limitations.
    """

    canonical = canonicalize_url(value)
    if not canonical.ok:
        return canonical

    try:
        parsed = urlsplit(canonical.value or "")
    except ValueError:
        return RuleResult.rejected(REASON_MALFORMED_URL)

    path = "/".join(_mask_token(segment) for segment in parsed.path.split("/"))
    query = _mask_query(parsed.query)
    key = urlunsplit((parsed.scheme, parsed.netloc, path, query, parsed.fragment))
    return RuleResult.accepted(key)
