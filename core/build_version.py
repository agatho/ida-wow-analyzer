"""
Resolve a WoW build number to its (major, minor, patch, build) version tuple.

WHY THIS EXISTS
---------------
Two independent places guessed the version from the build number:

    analyzers/db2_loadinfo_codegen.py:  TARGET_BUILD = (12, 0, 5, 67186)
    analyzers/idb_enrichment.py:        if build_num >= 67000: (12, 0, 5, build)

Both are used to pick a DBD layout via ``find_layout_for_build``. On build
69382 — which is 12.1.0 — they selected the 12.0.5 layout, so every DB2 table
whose schema changed in 12.1 got the wrong field widths and order, in code that
otherwise looked like it had worked.

AutoDump already records the exact version string
(``wow_manifest_<build>.json`` -> ``"build": "12.1.0.69382"``), so there is no
need to guess at all. The heuristic remains only as a last resort, and it now
knows about 12.1.
"""

import json
import os
import re


_MANIFEST_CACHE = {}


def _manifest_version(build):
    """(major, minor, patch) from wow_manifest_<build>.json, or None."""
    if build in _MANIFEST_CACHE:
        return _MANIFEST_CACHE[build]

    version = None
    try:
        from tc_wow_analyzer.core.utils import dumps_dir
        path = os.path.join(dumps_dir(), f"wow_manifest_{build}.json")
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            text = str(data.get("build") or "")
            match = re.match(r"(\d+)\.(\d+)\.(\d+)", text)
            if match:
                version = tuple(int(g) for g in match.groups())
    except Exception:
        version = None

    _MANIFEST_CACHE[build] = version
    return version


# Fallback only. Ranges are inclusive lower bounds, highest first.
_HEURISTIC = (
    (69000, (12, 1, 0)),
    (68000, (12, 0, 7)),
    (67000, (12, 0, 5)),
    (65000, (11, 1, 5)),
    (60000, (11, 0, 5)),
)


def build_tuple(build, default=(12, 1, 0)):
    """Return ``(major, minor, patch, build)`` for *build*.

    Prefers the AutoDump manifest; falls back to the range heuristic.
    """
    try:
        build = int(build or 0)
    except (TypeError, ValueError):
        build = 0
    if not build:
        return default + (0,)

    version = _manifest_version(build)
    if version:
        return version + (build,)

    for threshold, version in _HEURISTIC:
        if build >= threshold:
            return version + (build,)
    return (10, 2, 7, build)


def version_string(build):
    """e.g. "12.1.0.69382"."""
    return ".".join(str(part) for part in build_tuple(build))
