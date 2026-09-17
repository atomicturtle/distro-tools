"""Tests for NVD / vuls timestamp parsing."""

import datetime
import unittest

from apollo.nvd import timestamps


class TestParseTs(unittest.TestCase):
    def test_go_short_fractional_seconds(self):
        # encoding/json emits variable-length fractions; fromisoformat rejects these.
        for raw, micro in (
            ("2010-04-08T17:30:00.36Z", 360000),
            ("2026-08-15T06:21:13.7Z", 700000),
            ("2026-08-15T06:21:13.70Z", 700000),
            ("2021-12-10T10:15:09.143Z", 143000),
        ):
            with self.subTest(raw=raw):
                got = timestamps.parse_ts(raw)
                self.assertIsNotNone(got)
                self.assertEqual(got.microsecond, micro)
                self.assertEqual(got.tzinfo, datetime.timezone.utc)

    def test_nvd_no_timezone_fraction(self):
        got = timestamps.parse_ts("2021-12-10T10:15:09.143")
        self.assertIsNotNone(got)
        self.assertEqual(got.year, 2021)
        self.assertEqual(got.microsecond, 143000)
        self.assertEqual(got.tzinfo, datetime.timezone.utc)

    def test_empty_and_invalid(self):
        self.assertIsNone(timestamps.parse_ts(None))
        self.assertIsNone(timestamps.parse_ts(""))
        self.assertIsNone(timestamps.parse_ts("not-a-date"))
