"""Tests that repository YAML is parsed without PyYAML object construction."""

import os
import sys
import unittest
from unittest.mock import patch

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.rpmworker.repomd import download_yaml
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
    def __init__(self, response: _FakeResponse):
        self._response = response

    def get(self, url, **kwargs):  # pylint: disable=unused-argument
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class TestDownloadYamlSafeLoad(unittest.IsolatedAsyncioTestCase):
    async def test_parses_modulemd_documents(self):
        body = (
            "---\n"
            "document: modulemd\n"
            "data:\n"
            "  name: nginx\n"
            "---\n"
            "document: modulemd-defaults\n"
            "data:\n"
            "  module: nginx\n"
        )
        with patch(
            "apollo.rpmworker.repomd.assert_safe_http_url",
            side_effect=lambda url, **kwargs: url,
        ), patch(
            "apollo.rpmworker.repomd.aiohttp.ClientSession",
            return_value=_FakeSession(_FakeResponse(body)),
        ):
            docs = await download_yaml("https://example.test/modules.yaml")
        self.assertEqual(docs[0]["document"], "modulemd")
        self.assertEqual(docs[1]["data"]["module"], "nginx")

    async def test_rejects_python_object_tags(self):
        body = "!!python/object/apply:os.system ['id']\n"
        with patch(
            "apollo.rpmworker.repomd.assert_safe_http_url",
            side_effect=lambda url, **kwargs: url,
        ), patch(
            "apollo.rpmworker.repomd.aiohttp.ClientSession",
            return_value=_FakeSession(_FakeResponse(body)),
        ):
            with self.assertRaises(yaml.YAMLError):
                await download_yaml("https://example.test/evil.yaml")

    async def test_rejects_private_url(self):
        with self.assertRaises(UnsafeURLError):
            await download_yaml("http://127.0.0.1/modules.yaml")


if __name__ == "__main__":
    unittest.main()
