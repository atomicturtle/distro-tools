"""
CWE (Common Weakness Enumeration) name lookup.

Provides official CWE names for CSAF 2.0 compliance.
CSAF mandatory test requires CWE name to match the official weakness name.

This module fetches CWE names from MITRE on-demand and caches them locally.
A small hardcoded set of common CWEs is included for offline fallback.
"""

import json
import logging
import os
import re
import html
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

# Track unknown CWEs to avoid duplicate warnings
_unknown_cwes_warned = set()

# Cache file location (defaults to ~/.cache/ciq-errata/cwe_cache.json)
_CACHE_DIR = Path(os.environ.get("CWE_CACHE_DIR", Path.home() / ".cache" / "ciq-errata"))
_CACHE_FILE = _CACHE_DIR / "cwe_cache.json"

# In-memory cache (loaded from file on first access)
_cwe_cache: Optional[dict] = None


def _load_cache() -> dict:
    """Load CWE cache from file."""
    global _cwe_cache
    if _cwe_cache is not None:
        return _cwe_cache

    _cwe_cache = {}
    if _CACHE_FILE.exists():
        try:
            with open(_CACHE_FILE, "r") as f:
                _cwe_cache = json.load(f)
            logger.debug(f"Loaded {len(_cwe_cache)} CWEs from cache")
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load CWE cache: {e}")
            _cwe_cache = {}
    return _cwe_cache


def _save_cache(cache: dict) -> None:
    """Save CWE cache to file."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with open(_CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except IOError as e:
        logger.warning(f"Failed to save CWE cache: {e}")


def _fetch_cwe_from_mitre(cwe_id: str) -> Optional[str]:
    """
    Fetch CWE name from MITRE website.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-416")

    Returns:
        Official CWE name if found, None otherwise
    """
    # Extract numeric ID from "CWE-XXX" format
    match = re.match(r"CWE-(\d+)", cwe_id)
    if not match:
        logger.warning(f"Invalid CWE format: {cwe_id}")
        return None

    cwe_num = match.group(1)
    url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "CIQ-Errata-Management/1.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode("utf-8")

        # Parse the title from HTML - MITRE uses format: "CWE - CWE-XXX: Name (version)"
        # The page title contains the official name
        title_match = re.search(r"<title>CWE\s*-\s*CWE-\d+:\s*(.+?)\s*\(\d", content)
        if title_match:
            name = html.unescape(title_match.group(1).strip())
            logger.info(f"Fetched CWE name from MITRE: {cwe_id} = {name}")
            return name

        # Alternative: try the h2 heading
        h2_match = re.search(r'<h2>CWE-\d+:\s*(.+?)</h2>', content)
        if h2_match:
            name = html.unescape(h2_match.group(1).strip())
            logger.info(f"Fetched CWE name from MITRE: {cwe_id} = {name}")
            return name

        logger.warning(f"Could not parse CWE name from MITRE page: {cwe_id}")
        return None

    except urllib.error.HTTPError as e:
        if e.code == 404:
            logger.warning(f"CWE not found on MITRE: {cwe_id}")
        else:
            logger.warning(f"HTTP error fetching {cwe_id} from MITRE: {e}")
        return None
    except urllib.error.URLError as e:
        logger.warning(f"Network error fetching {cwe_id} from MITRE: {e}")
        return None
    except Exception as e:
        logger.warning(f"Error fetching {cwe_id} from MITRE: {e}")
        return None

# CWE Categories (not Weaknesses) — the CSAF validator rejects these
# because CSAF 2.0 requires actual weakness entries, not organizational
# groupings. Red Hat enrichment data sometimes assigns categories.
CWE_CATEGORIES = frozenset({
    "CWE-310",   # Cryptographic Issues
    "CWE-388",   # Error Handling
    "CWE-438",   # Behavioral Change in New Version or Environment (deprecated)
    "CWE-1214",  # Data Integrity Issues
})

# Common CWE IDs and their official names from MITRE
# https://cwe.mitre.org/data/definitions/
# This is a subset of the most common CWEs for fast offline lookups.
# Unknown CWEs are fetched on-demand from MITRE and cached.
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-77": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-126": "Buffer Over-read",
    "CWE-127": "Buffer Under-read",
    "CWE-128": "Wrap-around Error",
    "CWE-129": "Improper Validation of Array Index",
    "CWE-131": "Incorrect Calculation of Buffer Size",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-170": "Improper Null Termination",
    "CWE-176": "Improper Handling of Unicode Encoding",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-191": "Integer Underflow (Wrap or Wraparound)",
    "CWE-193": "Off-by-one Error",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-252": "Unchecked Return Value",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-346": "Origin Validation Error",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
    "CWE-369": "Divide By Zero",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-401": "Missing Release of Memory after Effective Lifetime",
    "CWE-404": "Improper Resource Shutdown or Release",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-426": "Untrusted Search Path",
    "CWE-427": "Uncontrolled Search Path Element",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-552": "Files or Directories Accessible to External Parties",
    "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-617": "Reachable Assertion",
    "CWE-665": "Improper Initialization",
    "CWE-667": "Improper Locking",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-681": "Incorrect Conversion between Numeric Types",
    "CWE-682": "Incorrect Calculation",
    "CWE-704": "Incorrect Type Conversion or Cast",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
    "CWE-755": "Improper Handling of Exceptional Conditions",
    "CWE-763": "Release of Invalid Pointer or Reference",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-772": "Missing Release of Resource after Effective Lifetime",
    "CWE-776": "Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')",
    "CWE-787": "Out-of-bounds Write",
    "CWE-788": "Access of Memory Location After End of Buffer",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-824": "Access of Uninitialized Pointer",
    "CWE-835": "Loop with Unreachable Exit Condition ('Infinite Loop')",
    "CWE-843": "Access of Resource Using Incompatible Type ('Type Confusion')",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-908": "Use of Uninitialized Resource",
    "CWE-909": "Missing Initialization of Resource",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
    "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
    "CWE-1333": "Inefficient Regular Expression Complexity",
}


def get_cwe_name(cwe_id: str) -> str:
    """
    Get the official CWE name for a given CWE ID.

    Lookup order:
    1. Hardcoded lookup table (common CWEs, fast)
    2. File-based cache (previously fetched CWEs)
    3. Fetch from MITRE website (on-demand, cached for future)

    Args:
        cwe_id: CWE identifier (e.g., "CWE-416")

    Returns:
        Official CWE name if found, otherwise returns the CWE ID itself
        (which will fail CSAF mandatory validation but won't break the document)
    """
    if not cwe_id:
        return ""

    # 1. Check hardcoded lookup (fastest)
    name = CWE_NAMES.get(cwe_id)
    if name:
        return name

    # 2. Check file cache
    cache = _load_cache()
    if cwe_id in cache:
        return cache[cwe_id]

    # 3. Fetch from MITRE and cache
    name = _fetch_cwe_from_mitre(cwe_id)
    if name:
        cache[cwe_id] = name
        _save_cache(cache)
        return name

    # Log warning for unfetchable CWE (only once per CWE)
    if cwe_id not in _unknown_cwes_warned:
        _unknown_cwes_warned.add(cwe_id)
        logger.warning(
            f"Could not resolve CWE name: {cwe_id} - CSAF validation will fail"
        )

    return cwe_id


def is_cwe_known(cwe_id: str) -> bool:
    """
    Check if a CWE ID has a known official name.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-416")

    Returns:
        True if the CWE is in our lookup table or cache, False otherwise
    """
    if cwe_id in CWE_NAMES:
        return True
    cache = _load_cache()
    return cwe_id in cache


def clear_cache() -> None:
    """Clear the in-memory and file cache (useful for testing)."""
    global _cwe_cache
    _cwe_cache = None
    if _CACHE_FILE.exists():
        _CACHE_FILE.unlink()
