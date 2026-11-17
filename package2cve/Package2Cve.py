#!/usr/bin/env python
"""Match Debian packages against the Debian Security Tracker.

The tracker JSON (https://security-tracker.debian.org/tracker/data/json) is
keyed by *source* package name, and every fixed version in it is a *source*
version. Installed binary packages are therefore resolved to their source
package/version before being compared.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

import requests
from debian.debian_support import version_compare

from package2cve.remote import Executor, executor_for

TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"

# Numeric release -> codename. Only used to translate "12" -> "bookworm" or
# VERSION_ID from /etc/os-release; the set of *valid* releases is taken from
# the tracker data itself, so new releases work without touching this table.
DEBIAN_CODENAMES = {
    7: "wheezy",
    8: "jessie",
    9: "stretch",
    10: "buster",
    11: "bullseye",
    12: "bookworm",
    13: "trixie",
    14: "forky",
    15: "duke",
    "unstable": "sid",
}

# dpkg-query is stable across Debian releases (unlike `apt list`, which warns
# that its CLI is not stable) and gives us the Source field we need.
DPKG_QUERY_CMD = (
    "dpkg-query -W -f='${Status}\\t${Package}\\t${Version}\\t${Source}\\n'"
)
OS_RELEASE_CMD = "cat /etc/os-release"


class Package2CveError(Exception):
    pass


class Package2Cve:

    def __init__(self, data: Optional[Dict[str, Any]] = None,
                 tracker_file: Optional[str] = None,
                 url: str = TRACKER_URL, timeout: int = 300):
        if data is not None:
            self.data = data
        elif tracker_file:
            with open(tracker_file, encoding="utf-8") as fh:
                self.data = json.load(fh)
        else:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            self.data = response.json()
        self.releases = sorted({
            release
            for cves in self.data.values()
            for cve in cves.values()
            for release in cve.get("releases", {})
        })

    # ------------------------------------------------------------------ #
    # Release handling
    # ------------------------------------------------------------------ #
    def normalize_release(self, release: Any) -> str:
        """Accept 'trixie', 13, '13' or 'unstable' and return the codename."""
        value = str(release).strip().lower()
        if value.isdigit():
            value = DEBIAN_CODENAMES.get(int(value), value)
        elif value in DEBIAN_CODENAMES:
            value = DEBIAN_CODENAMES[value]
        if value not in self.releases:
            raise Package2CveError(
                "Debian release '{0}' is not tracked by the security tracker "
                "(tracked: {1})".format(release, ", ".join(self.releases)))
        return value

    # ------------------------------------------------------------------ #
    # Single package
    # ------------------------------------------------------------------ #
    def package_cve(self, os: Any, package: str, version: str,
                    include_unfixed: bool = False) -> Optional[Dict[str, Any]]:
        """Return the CVEs affecting a *source* package at a given version.

        :param os: Debian codename or number (``"trixie"``, ``13``...).
        :param package: source package name (``openssl``, not ``libssl3``).
        :param version: installed source version.
        :param include_unfixed: also report CVEs without a fix released yet.
        :return: dict with the findings, or ``None`` if nothing applies.
        """
        release = self.normalize_release(os)
        entries = self.data.get(package)
        if not entries:
            return None

        cves = []
        latest_available = None
        fixed_version = None
        for cve_id, cve in entries.items():
            info = cve.get("releases", {}).get(release)
            if not info:
                continue
            for repo_version in info.get("repositories", {}).values():
                latest_available = _max_version(latest_available, repo_version)
            if cve_id.startswith("TEMP-"):
                continue

            fixed = info.get("fixed_version")
            if info.get("status") == "resolved" and fixed:
                # fixed_version "0" means the release was never affected.
                if fixed == "0" or version_compare(version, fixed) >= 0:
                    continue
                fixed_version = _max_version(fixed_version, fixed)
            elif not include_unfixed:
                continue
            else:
                fixed = None

            cves.append({
                "cve": cve_id,
                "status": info.get("status"),
                "fixed_version": fixed,
                "urgency": info.get("urgency"),
            })

        if not cves:
            return None
        return {
            "package_name": package,
            "release": release,
            "current_version": version,
            "fixed_version": fixed_version,
            "latest_available": latest_available,
            "cves": sorted(cves, key=lambda c: c["cve"]),
        }

    # ------------------------------------------------------------------ #
    # Hosts
    # ------------------------------------------------------------------ #
    def host_packages_cve(self, executor: Executor,
                          release: Optional[str] = None,
                          include_unfixed: bool = False) -> List[Dict[str, Any]]:
        """Scan the host behind ``executor`` and return its vulnerable packages."""
        if release is None:
            release = detect_release(executor.run(OS_RELEASE_CMD))
        release = self.normalize_release(release)

        installed = parse_dpkg_query(executor.run(DPKG_QUERY_CMD))
        results = []
        for (source, source_version), binaries in sorted(installed.items()):
            found = self.package_cve(release, source, source_version,
                                     include_unfixed=include_unfixed)
            if not found:
                continue
            found["binary_packages"] = sorted(binaries)
            results.append(found)
        return results

    def remote_host_packages_cve(self, hostname: str, user: Optional[str] = None,
                                 password: Optional[str] = None,
                                 transport: str = "ssh",
                                 release: Optional[str] = None,
                                 include_unfixed: bool = False,
                                 **transport_options: Any) -> List[Dict[str, Any]]:
        """Connect to ``hostname`` over SSH or Teleport and scan it.

        ``transport`` is ``"ssh"`` (default), ``"teleport"`` or ``"local"``.
        Extra keyword arguments go to the transport (``port``,
        ``key_filename``, ``proxy``, ``cluster``, ``tsh_bin``...).
        """
        with executor_for(transport, hostname=hostname, user=user,
                          password=password, **transport_options) as executor:
            return self.host_packages_cve(executor, release=release,
                                          include_unfixed=include_unfixed)


# ---------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------- #
def _max_version(current: Optional[str], candidate: str) -> str:
    if current is None or version_compare(candidate, current) > 0:
        return candidate
    return current


def parse_os_release(text: str) -> Dict[str, str]:
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"').strip("'")
    return values


def detect_release(os_release_text: str) -> str:
    values = parse_os_release(os_release_text)
    distro = values.get("ID", "")
    if distro != "debian":
        raise Package2CveError(
            "Host is not Debian (ID={0!r}); the Debian security tracker "
            "only covers Debian".format(distro))
    codename = values.get("VERSION_CODENAME")
    if codename:
        return codename
    version_id = values.get("VERSION_ID", "")
    if version_id.isdigit() and int(version_id) in DEBIAN_CODENAMES:
        return DEBIAN_CODENAMES[int(version_id)]
    raise Package2CveError("Could not determine the Debian release of the host")


def parse_dpkg_query(text: str) -> Dict[Tuple[str, str], List[str]]:
    """Group installed binary packages by (source package, source version)."""
    installed: Dict[Tuple[str, str], List[str]] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or not parts[0].endswith(" installed"):
            continue
        status, package, version, source = parts[:4]
        source = source.strip()
        if not source:
            source_name, source_version = package, version
        elif "(" in source:
            # "openssl (3.0.11-1~deb12u2)" when the source version differs
            source_name, _, rest = source.partition(" (")
            source_version = rest.rstrip(")")
        else:
            source_name, source_version = source, version
        if source_name.startswith("linux-signed-"):
            # Signed kernel images (linux-signed-amd64 "6.1.55+1") are not in
            # the tracker; the binary version is the version of source "linux".
            source_name, source_version = "linux", version
        installed.setdefault((source_name, source_version), []).append(package)
    return installed

