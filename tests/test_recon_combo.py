import argparse
import unittest

import recon_combo


class ParsePortsTests(unittest.TestCase):
    def test_parse_single_ports_and_ranges(self):
        self.assertEqual(recon_combo.parse_ports("443,80,8000-8002"), [80, 443, 8000, 8001, 8002])

    def test_rejects_invalid_range_order(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            recon_combo.parse_ports("9000-8000")

    def test_rejects_out_of_range_port(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            recon_combo.parse_ports("65536")


class ParsePathsTests(unittest.TestCase):
    def test_normalizes_and_sorts_paths(self):
        self.assertEqual(
            recon_combo.parse_paths("robots.txt,/sitemap.xml, robots.txt"),
            ["/robots.txt", "/sitemap.xml"],
        )


class TargetTests(unittest.TestCase):
    def test_normalizes_domain_target(self):
        self.assertEqual(recon_combo.normalize_target("Example.COM"), ("example.com", None))

    def test_preserves_url_target(self):
        self.assertEqual(
            recon_combo.normalize_target("https://App.Example.com/login"),
            ("app.example.com", "https://App.Example.com/login"),
        )


class CandidateUrlTests(unittest.TestCase):
    def test_candidate_urls_use_scheme_defaults(self):
        self.assertEqual(
            recon_combo.candidate_urls(["example.com"], [80, 443, 8080], None, False, False),
            ["http://example.com/", "http://example.com:8080/", "https://example.com/"],
        )

    def test_base_url_short_circuits_candidates(self):
        self.assertEqual(
            recon_combo.candidate_urls(["example.com"], [80, 443], "https://app.example.com", False, False),
            ["https://app.example.com"],
        )


if __name__ == "__main__":
    unittest.main()
