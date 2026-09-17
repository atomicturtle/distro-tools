import gzip
import lzma
import re
import defusedxml.ElementTree as ET
from urllib.parse import urljoin, urlparse
from os import path

from apollo.rpm_helpers import parse_nevra
from common.ssrf import assert_safe_http_url

import aiohttp
import yaml

NVRA_RE = re.compile(
    r"^(\S+)-([\w~%.+^]+)-([\w~^]+(?:\.[\w~%+^]+)+?)(?:\.(\w+))?(?:\.rpm)?$"
)
NEVRA_RE = re.compile(
    r"^(\S+)-(?:(\d)+:)([\w~%.+^]+)-([\w~^]+(?:\.[\w~%+^]+)+?)(?:\.(\w+))?(?:\.rpm)?$"
)
EPOCH_RE = re.compile(r"(\d+):")
DIST_RE = re.compile(r"(\.el\d+(?:_\d+|))")
MODULE_DIST_RE = re.compile(r"\.module.+$")

_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def clean_nvra_pkg(matching_pkg: ET.Element) -> tuple[str, str]:
    name = matching_pkg.find("{http://linux.duke.edu/metadata/common}name").text
    version = matching_pkg.find(
        "{http://linux.duke.edu/metadata/common}version"
    ).attrib["ver"]
    release = matching_pkg.find(
        "{http://linux.duke.edu/metadata/common}version"
    ).attrib["rel"]
    arch = matching_pkg.find("{http://linux.duke.edu/metadata/common}arch").text

    clean_release = MODULE_DIST_RE.sub("", DIST_RE.sub("", release))

    cleaned = f"{name}-{version}-{clean_release}.{arch}"
    raw = f"{name}-{version}-{release}.{arch}"
    if ".module+" in release:
        cleaned = f"module.{cleaned}"
        raw = f"module.{raw}"

    return cleaned, raw


def clean_nvra(nvra_raw: str) -> tuple[str, str]:
    try:
        results = parse_nevra(nvra_raw)
    except ValueError as e:
        return nvra_raw, nvra_raw
    name = results["name"]
    version = results["version"]
    release = results["release"]
    arch = results["arch"]

    clean_release = MODULE_DIST_RE.sub("", DIST_RE.sub("", release))

    cleaned = f"{name}-{version}-{clean_release}.{arch}"
    raw = f"{name}-{version}-{release}.{arch}"
    if ".module+" in release:
        cleaned = f"module.{cleaned}"
        raw = f"module.{raw}"

    return cleaned, raw


async def _fetch_bytes(url: str) -> bytes:
    """GET url after SSRF checks; re-validate every redirect hop."""
    current = assert_safe_http_url(url)
    async with aiohttp.ClientSession() as session:
        for _ in range(_MAX_REDIRECTS + 1):
            async with session.get(current, allow_redirects=False) as resp:
                if resp.status in _REDIRECT_STATUSES:
                    location = resp.headers.get("Location")
                    if not location:
                        raise Exception(
                            f"Redirect from {current} missing Location header"
                        )
                    current = assert_safe_http_url(urljoin(current, location))
                    continue
                if resp.status != 200:
                    raise Exception(f"Failed to get {current}: {resp.status}")
                return await resp.read()
    raise Exception(f"Too many redirects fetching {url}")


async def download_xml(
    url: str, gz: bool = False, xz: bool = False
) -> ET.Element:
    raw = await _fetch_bytes(url)
    if gz:
        return ET.fromstring(gzip.decompress(raw).decode("utf-8"))
    if xz:
        return ET.fromstring(lzma.decompress(raw).decode("utf-8"))
    return ET.fromstring(raw.decode("utf-8"))


async def download_yaml(url: str, gz: bool = False, xz: bool = False) -> any:
    raw = await _fetch_bytes(url)
    if gz:
        return list(yaml.safe_load_all(gzip.decompress(raw).decode("utf-8")))
    if xz:
        return list(yaml.safe_load_all(lzma.decompress(raw).decode("utf-8")))
    return list(yaml.safe_load_all(raw.decode("utf-8")))


async def get_data_from_repomd(
    url: str,
    data_type: str,
    el: ET.Element,
    is_yaml=False,
):
    # There is a top-most repomd element in repomd
    # Under there is revision and multiple data elements
    # We want the data element with type="data_type"
    # Under that is location with href
    # That href is the location of the data
    for data in el.findall("{http://linux.duke.edu/metadata/repo}data"):
        if data.attrib["type"] == data_type:
            location = data.find(
                "{http://linux.duke.edu/metadata/repo}location"
            )
            parsed_url = urlparse(url)
            new_path = path.abspath(
                path.join(parsed_url.path, "../..", location.attrib["href"])
            )
            data_url = parsed_url._replace(path=new_path).geturl()
            if is_yaml:
                return await download_yaml(
                    data_url,
                    gz=data_url.endswith(".gz"),
                    xz=data_url.endswith(".xz"),
                )
            return await download_xml(
                data_url,
                gz=data_url.endswith(".gz"),
                xz=data_url.endswith(".xz"),
            )

    return None
