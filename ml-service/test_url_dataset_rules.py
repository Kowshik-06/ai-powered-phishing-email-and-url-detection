"""Synthetic tests for the pure URL-policy module.

No real dataset, network, DNS, public-suffix list, model artifact, or service
is used. Every hostname is from a reserved example range or an explicit
synthetic value.
"""

from __future__ import annotations

import contextlib
import io
import os
import socket
import tempfile
import unittest
from unittest import mock

import url_dataset_rules as rules


class NormalizationTests(unittest.TestCase):
    def assert_value(self, result, expected):
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.value, expected)

    def assert_reason(self, result, expected):
        self.assertFalse(result.ok)
        self.assertIsNone(result.value)
        self.assertEqual(result.reason, expected)

    def test_strips_surrounding_whitespace(self):
        self.assert_value(
            rules.normalize_url("  \t https://example.com/A?B=C#D \n "),
            "https://example.com/A?B=C#D",
        )
        self.assert_value(
            rules.normalize_url("  example.com/Path  "),
            "https://example.com/Path",
        )

    def test_preserves_existing_http_and_https_schemes(self):
        self.assert_value(
            rules.normalize_url("http://example.com/A?B=C#D"),
            "http://example.com/A?B=C#D",
        )
        self.assert_value(
            rules.normalize_url("https://example.org/a/b"),
            "https://example.org/a/b",
        )

    def test_prepends_https_only_when_scheme_is_absent(self):
        self.assert_value(
            rules.normalize_url("example.net/Path?Q=V#F"),
            "https://example.net/Path?Q=V#F",
        )
        self.assert_value(
            rules.normalize_url("example.net"),
            "https://example.net",
        )

    def test_uppercase_scheme_is_preserved_by_normalization(self):
        self.assert_value(
            rules.normalize_url("HTTP://EXAMPLE.COM/A"),
            "HTTP://EXAMPLE.COM/A",
        )
        self.assert_value(
            rules.normalize_url("HTTPS://EXAMPLE.COM/A"),
            "HTTPS://EXAMPLE.COM/A",
        )

    def test_non_http_scheme_is_accepted(self):
        self.assert_value(
            rules.normalize_url("ftp://example.com/file"),
            "ftp://example.com/file",
        )

    def test_empty_and_non_string_inputs_are_rejected_safely(self):
        self.assert_reason(rules.normalize_url(""), rules.REASON_EMPTY)
        self.assert_reason(rules.normalize_url("   \t "), rules.REASON_EMPTY)
        self.assert_reason(rules.normalize_url(None), rules.REASON_NOT_A_STRING)
        self.assert_reason(rules.normalize_url(123), rules.REASON_NOT_A_STRING)
        self.assert_reason(rules.normalize_url(b"https://example.com"), rules.REASON_NOT_A_STRING)
        self.assert_reason(rules.normalize_url([]), rules.REASON_NOT_A_STRING)

    def test_malformed_urls_are_rejected(self):
        self.assert_reason(rules.normalize_url("http://"), rules.REASON_MISSING_HOST)
        self.assert_reason(rules.normalize_url("https:///path"), rules.REASON_MISSING_HOST)
        self.assert_reason(
            rules.normalize_url("https://exa mple.com/"),
            rules.REASON_WHITESPACE,
        )
        self.assert_reason(
            rules.normalize_url("https://example.com:bad/"),
            rules.REASON_INVALID_PORT,
        )
        self.assert_reason(
            rules.normalize_url("https://example.com:0/"),
            rules.REASON_INVALID_PORT,
        )
        self.assert_reason(
            rules.normalize_url("https://999.999.999.999/"),
            rules.REASON_INVALID_IPV4,
        )
        self.assert_reason(
            rules.normalize_url("https://[2001:db8::1/"),
            rules.REASON_MALFORMED_URL,
        )
        self.assert_reason(
            rules.normalize_url("https://-bad.example/"),
            rules.REASON_INVALID_LABEL,
        )

    def test_does_not_lowercase_or_decode_or_reorder(self):
        value = "https://example.com/A%2FB?Z=1&a=2#Frag%20X"
        self.assert_value(rules.normalize_url(value), value)

    def test_normalization_is_idempotent(self):
        for value in (
            "https://example.com/A?B=C#D",
            "HTTP://EXAMPLE.COM/A",
            "ftp://example.com/file",
            "example.net/Path",
        ):
            first = rules.normalize_url(value)
            self.assertTrue(first.ok, first.reason)
            second = rules.normalize_url(first.value)
            self.assertTrue(second.ok, second.reason)
            self.assertEqual(first.value, second.value)

    def test_rejection_reason_does_not_echo_input(self):
        canary = "https://example.com/CANARY-TOKEN-9f3a bad"
        result = rules.normalize_url(canary)
        self.assertFalse(result.ok)
        self.assertNotIn("CANARY-TOKEN-9f3a", result.reason or "")
        self.assertNotIn(canary, result.reason or "")


class CanonicalizationTests(unittest.TestCase):
    def assert_value(self, result, expected):
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.value, expected)

    def value(self, url):
        result = rules.canonicalize_url(url)
        self.assertTrue(result.ok, result.reason)
        return result.value

    def test_lowercases_scheme_and_hostname_only(self):
        self.assert_value(
            rules.canonicalize_url("HTTP://EXAMPLE.COM/Path"),
            "http://example.com/Path",
        )
        self.assert_value(
            rules.canonicalize_url("https://EXAMPLE.COM/A/B"),
            "https://example.com/A/B",
        )

    def test_removes_default_ports_for_http_and_https(self):
        self.assertEqual(
            self.value("http://example.com:80/"),
            self.value("http://example.com/"),
        )
        self.assertEqual(
            self.value("https://example.com:443/"),
            self.value("https://example.com/"),
        )
        self.assertNotEqual(
            self.value("http://example.com:8080/"),
            self.value("http://example.com/"),
        )
        # 80 is not the default for https and must not be removed.
        self.assertEqual(
            self.value("https://example.com:80/"),
            "https://example.com:80/",
        )

    def test_preserves_non_default_ports(self):
        self.assertEqual(
            self.value("ftp://example.com:21/file"),
            "ftp://example.com:21/file",
        )
        self.assertEqual(
            self.value("https://example.com:8443/A"),
            "https://example.com:8443/A",
        )

    def test_removes_one_trailing_hostname_dot(self):
        self.assert_value(
            rules.canonicalize_url("https://example.com./A"),
            "https://example.com/A",
        )
        rejected = rules.canonicalize_url("https://example.com../A")
        self.assertFalse(rejected.ok)
        self.assertEqual(rejected.reason, rules.REASON_INVALID_HOST)

    def test_preserves_fragment_distinctions(self):
        self.assertNotEqual(
            self.value("https://example.com/A#One"),
            self.value("https://example.com/A#Two"),
        )
        # An empty fragment delimiter is not retained by urlsplit.
        self.assertEqual(
            self.value("https://example.com/A#"),
            self.value("https://example.com/A"),
        )
        # The same applies to an empty query delimiter.
        self.assertEqual(
            self.value("https://example.com/A?"),
            self.value("https://example.com/A"),
        )

    def test_preserves_query_order_and_repetition(self):
        self.assertNotEqual(
            self.value("https://example.com/search?a=1&b=2"),
            self.value("https://example.com/search?b=2&a=1"),
        )
        self.assertEqual(
            self.value("https://example.com/search?a=1&a=2"),
            "https://example.com/search?a=1&a=2",
        )
        self.assertNotEqual(
            self.value("https://example.com/search?a=1&a=2"),
            self.value("https://example.com/search?a=1"),
        )

    def test_preserves_percent_encoding(self):
        self.assertNotEqual(
            self.value("https://example.com/%7Euser"),
            self.value("https://example.com/~user"),
        )
        self.assertEqual(
            self.value("https://example.com/A%2FB"),
            "https://example.com/A%2FB",
        )

    def test_preserves_user_information(self):
        self.assert_value(
            rules.canonicalize_url("https://User:Pass@Example.com/A"),
            "https://User:Pass@example.com/A",
        )
        self.assertNotEqual(
            self.value("https://user:pass@example.com/A"),
            self.value("https://example.com/A"),
        )

    def test_canonicalizes_ip_literals(self):
        self.assert_value(
            rules.canonicalize_url("https://192.0.2.10:443/A"),
            "https://192.0.2.10/A",
        )
        self.assert_value(
            rules.canonicalize_url("https://[2001:DB8::1]:8443/a"),
            "https://[2001:db8::1]:8443/a",
        )

    def test_preserves_path_case_and_trailing_slash(self):
        self.assertNotEqual(
            self.value("https://example.com/A"),
            self.value("https://example.com/a"),
        )
        self.assertNotEqual(
            self.value("https://example.com/a"),
            self.value("https://example.com/a/"),
        )

    def test_empty_path_becomes_root(self):
        self.assert_value(
            rules.canonicalize_url("https://example.com"),
            "https://example.com/",
        )
        self.assert_value(
            rules.canonicalize_url("https://example.com?x=1"),
            "https://example.com/?x=1",
        )

    def test_canonicalization_is_idempotent(self):
        for value in (
            "https://example.com/A?B=C#D",
            "HTTP://User:Pass@EXAMPLE.COM:80/A",
            "https://[2001:DB8::1]:8443/a",
            "https://bücher.example/A",
        ):
            first = rules.canonicalize_url(value)
            self.assertTrue(first.ok, first.reason)
            second = rules.canonicalize_url(first.value)
            self.assertTrue(second.ok, second.reason)
            self.assertEqual(first.value, second.value)

    def test_scheme_less_canonicalization(self):
        self.assert_value(
            rules.canonicalize_url("example.com/X"),
            "https://example.com/X",
        )

    def test_idn_hostname_becomes_ascii(self):
        self.assert_value(
            rules.canonicalize_url("https://bücher.example/A"),
            "https://xn--bcher-kva.example/A",
        )

    def test_invalid_inputs_are_rejected(self):
        for value in (None, "", "   ", "https://example.com:bad/"):
            result = rules.canonicalize_url(value)
            self.assertFalse(result.ok)
            self.assertIsNone(result.value)
            self.assertIsNotNone(result.reason)


class HostClassificationTests(unittest.TestCase):
    def test_valid_dns_names(self):
        info = rules.classify_host("example.com")
        self.assertTrue(info.ok, info.reason)
        self.assertEqual(info.kind, rules.KIND_DNS)
        self.assertEqual(info.host, "example.com")
        self.assertEqual(info.ascii_host, "example.com")

        info = rules.classify_host("a.b.example.org")
        self.assertTrue(info.ok, info.reason)
        self.assertEqual(info.ascii_host, "a.b.example.org")

    def test_trailing_dot_and_case(self):
        info = rules.classify_host("Sub.Example.COM.")
        self.assertTrue(info.ok, info.reason)
        self.assertEqual(info.host, "sub.example.com")
        self.assertEqual(info.ascii_host, "sub.example.com")

    def test_invalid_and_empty_hosts(self):
        cases = {
            "": rules.REASON_EMPTY_HOST,
            "   ": rules.REASON_WHITESPACE,
            "exa mple.com": rules.REASON_WHITESPACE,
            "-bad.example": rules.REASON_INVALID_LABEL,
            "bad-.example": rules.REASON_INVALID_LABEL,
            "a..b": rules.REASON_INVALID_HOST,
            "_dmarc.example.com": rules.REASON_INVALID_LABEL,
            "example.com:80": rules.REASON_INVALID_HOST,
            "2001:db8:::1": rules.REASON_INVALID_HOST,
            "[2001:db8::1": rules.REASON_INVALID_HOST,
        }
        for value, reason in cases.items():
            info = rules.classify_host(value)
            self.assertFalse(info.ok, value)
            self.assertEqual(info.reason, reason, value)
            self.assertIsNone(info.host)

    def test_label_and_host_length_limits(self):
        info = rules.classify_host("a" * 64 + ".example")
        self.assertFalse(info.ok)
        self.assertEqual(info.reason, rules.REASON_LABEL_TOO_LONG)

        long_host = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 62])
        info = rules.classify_host(long_host)
        self.assertFalse(info.ok)
        self.assertEqual(info.reason, rules.REASON_HOST_TOO_LONG)

    def test_ipv4_literals(self):
        info = rules.classify_host("192.0.2.10")
        self.assertTrue(info.ok, info.reason)
        self.assertEqual(info.kind, rules.KIND_IPV4)
        self.assertEqual(info.host, "192.0.2.10")
        self.assertTrue(info.is_ip_literal)

    def test_invalid_numeric_hosts(self):
        for value in ("999", "999.1.1.1", "1.2.3.4.5", "192.0.2"):
            info = rules.classify_host(value)
            self.assertFalse(info.ok, value)
            self.assertEqual(info.reason, rules.REASON_INVALID_IPV4, value)

    def test_ipv6_literals(self):
        info = rules.classify_host("2001:DB8::1")
        self.assertTrue(info.ok, info.reason)
        self.assertEqual(info.kind, rules.KIND_IPV6)
        self.assertEqual(info.host, "2001:db8::1")
        self.assertEqual(info.ascii_host, "2001:db8::1")

        bracketed = rules.classify_host("[2001:db8::1]")
        self.assertTrue(bracketed.ok, bracketed.reason)
        self.assertEqual(bracketed.kind, rules.KIND_IPV6)
        self.assertEqual(bracketed.host, "2001:db8::1")

    def test_idn_and_ascii_form(self):
        info = rules.classify_host("bücher.example")
        self.assertTrue(info.ok, info.reason)
        self.assertEqual(info.kind, rules.KIND_DNS)
        self.assertEqual(info.host, "bücher.example")
        self.assertEqual(info.ascii_host, "xn--bcher-kva.example")

        ascii_info = rules.classify_host("xn--bcher-kva.example")
        self.assertTrue(ascii_info.ok, ascii_info.reason)
        self.assertEqual(ascii_info.ascii_host, "xn--bcher-kva.example")

    def test_hostname_with_port_via_url(self):
        info = rules.classify_url_host("https://example.com:8443/A")
        self.assertTrue(info.ok, info.reason)
        self.assertEqual(info.host, "example.com")
        self.assertEqual(info.port, 8443)

        ipv6_info = rules.classify_url_host("https://[2001:db8::1]:443/A")
        self.assertTrue(ipv6_info.ok, ipv6_info.reason)
        self.assertEqual(ipv6_info.kind, rules.KIND_IPV6)
        self.assertEqual(ipv6_info.port, 443)

        no_port = rules.classify_url_host("https://example.com/")
        self.assertTrue(no_port.ok, no_port.reason)
        self.assertIsNone(no_port.port)

    def test_invalid_url_port(self):
        info = rules.classify_url_host("https://example.com:bad/")
        self.assertFalse(info.ok)
        self.assertEqual(info.reason, rules.REASON_INVALID_PORT)

    def test_parsed_host_is_not_a_registrable_domain(self):
        info = rules.classify_host("a.b.example.com")
        self.assertTrue(info.ok, info.reason)
        self.assertEqual(info.ascii_host, "a.b.example.com")
        # There is no PSL in this module, so no eTLD+1 is fabricated here.


class RegistrableDomainTests(unittest.TestCase):
    def test_dependency_required_without_resolver(self):
        result = rules.resolve_registrable_domain("a.b.example.com")
        self.assertEqual(result.status, rules.REGISTRABLE_DEPENDENCY_REQUIRED)
        self.assertIsNone(result.domain)
        self.assertFalse(result.resolved)

    def test_ip_literals_are_separate(self):
        resolver = mock.Mock(return_value="example.com")
        ipv4 = rules.resolve_registrable_domain("192.0.2.10", resolver)
        self.assertEqual(ipv4.status, rules.REGISTRABLE_IP_LITERAL)
        self.assertIsNone(ipv4.domain)

        ipv6 = rules.resolve_registrable_domain("2001:db8::1", resolver)
        self.assertEqual(ipv6.status, rules.REGISTRABLE_IP_LITERAL)
        resolver.assert_not_called()

    def test_injected_resolver(self):
        result = rules.resolve_registrable_domain(
            "a.b.example.com", lambda host: "example.com"
        )
        self.assertEqual(result.status, rules.REGISTRABLE_RESOLVED)
        self.assertEqual(result.domain, "example.com")
        self.assertTrue(result.resolved)

        own_domain = rules.resolve_registrable_domain(
            "example.com", lambda host: "example.com"
        )
        self.assertEqual(own_domain.status, rules.REGISTRABLE_RESOLVED)

    def test_resolver_not_found(self):
        result = rules.resolve_registrable_domain(
            "a.b.example.com", lambda host: None
        )
        self.assertEqual(result.status, rules.REGISTRABLE_NOT_FOUND)
        self.assertIsNone(result.domain)

    def test_resolver_cannot_return_an_unrelated_suffix(self):
        result = rules.resolve_registrable_domain(
            "a.b.example.com", lambda host: "other.com"
        )
        self.assertEqual(result.status, rules.REGISTRABLE_RESOLVER_ERROR)

    def test_resolver_exception_is_contained(self):
        def exploding_resolver(host):
            raise RuntimeError("synthetic resolver failure")

        result = rules.resolve_registrable_domain(
            "a.b.example.com", exploding_resolver
        )
        self.assertEqual(result.status, rules.REGISTRABLE_RESOLVER_ERROR)
        self.assertIsNone(result.reason)

    def test_non_callable_resolver(self):
        result = rules.resolve_registrable_domain("a.b.example.com", "not-callable")
        self.assertEqual(result.status, rules.REGISTRABLE_RESOLVER_ERROR)

    def test_invalid_host(self):
        result = rules.resolve_registrable_domain("bad host")
        self.assertEqual(result.status, rules.REGISTRABLE_INVALID_HOST)


class ShortenerTests(unittest.TestCase):
    def test_exact_match(self):
        result = rules.shortener_status("bit.ly")
        self.assertEqual(result.status, rules.SHORTENER_LISTED)
        self.assertEqual(result.matched_host, "bit.ly")

    def test_documented_subdomain_match(self):
        result = rules.shortener_status("www.bit.ly")
        self.assertEqual(result.status, rules.SHORTENER_LISTED)
        self.assertEqual(result.matched_host, "bit.ly")

    def test_similar_looking_hosts_are_not_listed(self):
        for host in (
            "bit.ly.example.com",
            "notbit.ly",
            "bit.ly.evil.example",
            "example.com",
        ):
            result = rules.shortener_status(host)
            self.assertEqual(result.status, rules.SHORTENER_NOT_LISTED, host)
            self.assertIsNone(result.matched_host)

    def test_unknown_host_is_not_a_safety_claim(self):
        result = rules.shortener_status("example.org")
        self.assertEqual(result.status, rules.SHORTENER_NOT_LISTED)
        self.assertIsNone(result.matched_host)

    def test_malformed_host_is_invalid(self):
        result = rules.shortener_status("")
        self.assertEqual(result.status, rules.SHORTENER_INVALID)
        self.assertEqual(result.reason, rules.REASON_EMPTY_HOST)

    def test_url_helper(self):
        listed = rules.shortener_status_for_url("https://bit.ly/abc")
        self.assertEqual(listed.status, rules.SHORTENER_LISTED)
        self.assertEqual(listed.matched_host, "bit.ly")

        not_listed = rules.shortener_status_for_url(
            "https://bit.ly.example.com/abc"
        )
        self.assertEqual(not_listed.status, rules.SHORTENER_NOT_LISTED)

        invalid = rules.shortener_status_for_url("not a url")
        self.assertEqual(invalid.status, rules.SHORTENER_INVALID)

    def test_ip_literals_are_not_shorteners(self):
        self.assertEqual(
            rules.shortener_status("192.0.2.10").status,
            rules.SHORTENER_NOT_LISTED,
        )
        self.assertEqual(
            rules.shortener_status("2001:db8::1").status,
            rules.SHORTENER_NOT_LISTED,
        )


class TemplateKeyTests(unittest.TestCase):
    def value(self, url):
        result = rules.template_key(url)
        self.assertTrue(result.ok, result.reason)
        return result.value

    def test_numeric_path_segments(self):
        self.assertEqual(
            self.value("https://example.com/user/12345/profile"),
            "https://example.com/user/<num>/profile",
        )

    def test_uuid_path_segment(self):
        self.assertEqual(
            self.value(
                "https://example.com/item/"
                "123e4567-e89b-12d3-a456-426614174000/view"
            ),
            "https://example.com/item/<uuid>/view",
        )

    def test_hex_path_segment_boundaries(self):
        self.assertEqual(
            self.value("https://example.com/file/deadbeef/download"),
            "https://example.com/file/<hex>/download",
        )
        # Not a complete segment: do not mask.
        self.assertEqual(
            self.value("https://example.com/file/deadbeef.txt/download"),
            "https://example.com/file/deadbeef.txt/download",
        )
        self.assertEqual(
            self.value("https://example.com/file/abc/download"),
            "https://example.com/file/abc/download",
        )

    def test_alphabetic_tokens_are_preserved(self):
        self.assertEqual(
            self.value("https://example.com/report/alpha/beta"),
            "https://example.com/report/alpha/beta",
        )
        self.assertEqual(
            self.value("https://example.com/user123"),
            "https://example.com/user123",
        )
        self.assertEqual(
            self.value("https://example.com/2024-report"),
            "https://example.com/2024-report",
        )

    def test_different_hosts_remain_separate(self):
        self.assertNotEqual(
            self.value("https://example.com/123"),
            self.value("https://example.org/123"),
        )

    def test_query_names_and_values(self):
        self.assertEqual(
            self.value(
                "https://example.com/search?"
                "id=123&token=deadbeef&q=hello&"
                "uuid=123e4567-e89b-12d3-a456-426614174000"
            ),
            "https://example.com/search?"
            "id=<num>&token=<hex>&q=hello&uuid=<uuid>",
        )

    def test_query_order_and_repetition(self):
        self.assertEqual(
            self.value("https://example.com/s?a=1&a=2&b=hello"),
            "https://example.com/s?a=<num>&a=<num>&b=hello",
        )
        self.assertNotEqual(
            self.value("https://example.com/s?a=1&b=2"),
            self.value("https://example.com/s?b=2&a=1"),
        )

    def test_fragment_is_preserved(self):
        self.assertEqual(
            self.value("https://example.com/123#Section"),
            "https://example.com/<num>#Section",
        )

    def test_userinfo_is_preserved(self):
        self.assertEqual(
            self.value("https://User:Pass@example.com/123"),
            "https://User:Pass@example.com/<num>",
        )

    def test_template_is_deterministic(self):
        value = "https://example.com/a/123/b/deadbeef?x=9#F"
        first = rules.template_key(value)
        second = rules.template_key(value)
        self.assertEqual(first, second)

    def test_invalid_input_is_rejected(self):
        for value in (None, "", "   ", "https://example.com:bad/"):
            result = rules.template_key(value)
            self.assertFalse(result.ok)
            self.assertIsNotNone(result.reason)


class PrivacyAndSafetyTests(unittest.TestCase):
    def test_no_url_or_canary_in_stdout_stderr_or_reasons(self):
        canary = "https://example.com/CANARY-9f3a?token=CANARY-9f3a"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            results = [
                rules.normalize_url(canary),
                rules.canonicalize_url(canary),
                rules.template_key(canary),
                rules.classify_url_host(canary),
                rules.shortener_status_for_url(canary),
                rules.normalize_url("https://example.com/CANARY-9f3a bad"),
            ]
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn("CANARY-9f3a", combined)
        self.assertNotIn(canary, combined)
        for result in results:
            reason = getattr(result, "reason", None) or ""
            self.assertNotIn("CANARY-9f3a", reason)
            self.assertNotIn(canary, reason)

    def test_no_filesystem_writes_during_function_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.getcwd()
            os.chdir(directory)
            try:
                before = set(os.listdir(directory))
                rules.normalize_url("https://example.com/A")
                rules.canonicalize_url("https://example.com/123")
                rules.classify_url_host("https://example.com:8443/A")
                rules.classify_host("example.com")
                rules.resolve_registrable_domain("a.b.example.com")
                rules.shortener_status("bit.ly")
                rules.template_key("https://example.com/123")
                after = set(os.listdir(directory))
            finally:
                os.chdir(previous)
            self.assertEqual(before, after)

    def test_no_network_calls_during_function_calls(self):
        with mock.patch("socket.socket", side_effect=AssertionError("network")), \
                mock.patch("socket.create_connection", side_effect=AssertionError("network")):
            self.assertTrue(rules.normalize_url("https://example.com/A").ok)
            self.assertTrue(rules.canonicalize_url("https://example.com/123").ok)
            self.assertTrue(rules.template_key("https://example.com/123").ok)
            self.assertTrue(rules.classify_host("example.com").ok)
            self.assertTrue(rules.classify_url_host("https://example.com").ok)
            self.assertEqual(
                rules.shortener_status("bit.ly").status,
                rules.SHORTENER_LISTED,
            )
            self.assertEqual(
                rules.resolve_registrable_domain("a.b.example.com").status,
                rules.REGISTRABLE_DEPENDENCY_REQUIRED,
            )

    def test_results_are_deterministic(self):
        value = "https://Example.COM:443/A/123?b=2&a=1#F"
        self.assertEqual(rules.normalize_url(value), rules.normalize_url(value))
        self.assertEqual(rules.canonicalize_url(value), rules.canonicalize_url(value))
        self.assertEqual(rules.template_key(value), rules.template_key(value))
        self.assertEqual(rules.classify_host("example.com"), rules.classify_host("example.com"))

    def test_shortener_set_is_immutable(self):
        self.assertIsInstance(rules.KNOWN_SHORTENER_HOSTS, frozenset)


if __name__ == "__main__":
    unittest.main()
