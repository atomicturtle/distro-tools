"""Tests that untrusted XML is parsed without entity expansion."""

import os
import sys
import unittest
from unittest.mock import patch

import defusedxml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.rpmworker.repomd import download_xml
from common.ssrf import UnsafeURLError


class _FakeResponse:
    def __init__(self, body: str, status: int = 200, headers=None):
        self.status = status
        self.headers = headers or {}
        self._body = body

    async def text(self):
        return self._body

    async def read(self):
        return self._body.encode("utf-8")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeSession:
    def __init__(self, responses):
        if not isinstance(responses, list):
            responses = [responses]
        self._responses = list(responses)

    def get(self, url, **kwargs):  # pylint: disable=unused-argument
        return self._responses.pop(0)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


_BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<lolz>&lol1;</lolz>
"""


class TestDownloadXmlDefused(unittest.IsolatedAsyncioTestCase):
    async def test_parses_plain_xml(self):
        body = '<repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision></repomd>'
        with patch(
            "apollo.rpmworker.repomd.assert_safe_http_url",
            side_effect=lambda url, **kwargs: url,
        ), patch(
            "apollo.rpmworker.repomd.aiohttp.ClientSession",
            return_value=_FakeSession(_FakeResponse(body)),
        ):
            root = await download_xml("https://example.test/repomd.xml")
        self.assertEqual(
            root.find("{http://linux.duke.edu/metadata/repo}revision").text, "1"
        )

    async def test_rejects_entity_expansion(self):
        with patch(
            "apollo.rpmworker.repomd.assert_safe_http_url",
            side_effect=lambda url, **kwargs: url,
        ), patch(
            "apollo.rpmworker.repomd.aiohttp.ClientSession",
            return_value=_FakeSession(_FakeResponse(_BILLION_LAUGHS)),
        ):
            with self.assertRaises(defusedxml.DefusedXmlException):
                await download_xml("https://example.test/bomb.xml")

    async def test_rejects_redirect_to_private_ip(self):
        redirect = _FakeResponse(
            "",
            status=302,
            headers={"Location": "http://169.254.169.254/latest"},
        )

        def safe(url, **kwargs):
            if "169.254.169.254" in url:
                raise UnsafeURLError("blocked")
            return url

        with patch(
            "apollo.rpmworker.repomd.assert_safe_http_url", side_effect=safe
        ), patch(
            "apollo.rpmworker.repomd.aiohttp.ClientSession",
            return_value=_FakeSession([redirect]),
        ):
            with self.assertRaises(UnsafeURLError):
                await download_xml("https://example.test/redirect.xml")


if __name__ == "__main__":
    unittest.main()
