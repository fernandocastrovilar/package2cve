# package2cve

![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.txt)

## Description

`package2cve` checks the packages installed on a Debian host (over SSH, over
Teleport, or locally) against the [Debian Security Tracker](https://security-tracker.debian.org/tracker/)
and reports the CVEs that affect them together with the version that fixes them.

It works with any release the tracker covers (currently bookworm, trixie,
forky and sid). New releases are picked up from the tracker data
automatically.

## How it works

- Installed packages are read with `dpkg-query` and the release from
  `/etc/os-release` (no `lsb_release` needed).
- Binary packages are mapped to their **source** package and version
  (`libssl3t64` -> `openssl`), which is what the tracker uses.
- Versions are compared with Debian semantics (epochs, `~`, `+bN`) via
  `python-debian`.
- By default only CVEs with a released fix are reported. Use
  `--include-unfixed` / `include_unfixed=True` to also get open ones.

## Install

```bash
pip install package2cve
```

For Teleport you need `tsh` in your `PATH` and an active `tsh login`.

## CLI

```bash
# Over SSH (uses ssh-agent / ~/.ssh keys; --ask-password to prompt for one)
package2cve host myserver.example.com -u admin
package2cve host myserver.example.com -u admin -i ~/.ssh/id_ed25519 -p 2222

# Over Teleport (tsh ssh). -u is the node login
package2cve host mynode -u root --teleport
package2cve host mynode -u root --teleport --proxy teleport.example.com:443 --cluster leaf

# This machine
package2cve local

# A single source package version
package2cve package trixie openssl 3.5.7-1~deb13u2

# Reuse a downloaded tracker file (it is ~90 MB)
curl -o tracker.json https://security-tracker.debian.org/tracker/data/json
package2cve --tracker-file tracker.json host mynode -u root --teleport
```

Output is JSON on stdout. Add `-s` / `--short` (anywhere in the command) to
get a readable table instead, with what is installed, the version that fixes
it and the latest one available:

```
$ package2cve host myserver -u root --short
PACKAGE   INSTALLED         FIXED IN          LATEST            CVES
openssl   3.0.15-1~deb12u1  3.0.22-1~deb12u2  3.0.22-1~deb12u2    38
expat     2.5.0-1+deb12u1   2.5.0-1+deb12u5   2.5.0-1+deb12u5     30

2 packages, 68 CVEs (bookworm)
```

`FIXED IN` is `-` for CVEs without a fix yet (only shown with
`--include-unfixed`).

Exit code is `0` when nothing is found, `1` when
vulnerabilities are found and `2` on errors.

## Library

```python
from package2cve import Package2Cve

p2c = Package2Cve()  # or Package2Cve(tracker_file="tracker.json")

# SSH (default transport)
p2c.remote_host_packages_cve("myserver", "admin", password=None)

# Teleport
p2c.remote_host_packages_cve("mynode", "root", transport="teleport",
                             proxy="teleport.example.com:443")

# Single package: release (codename or number), source package, version
p2c.package_cve("trixie", "openssl", "3.5.7-1~deb13u2")
```

Each finding looks like:

```json
{
  "package_name": "openssl",
  "release": "trixie",
  "current_version": "3.5.7-1~deb13u2",
  "fixed_version": "3.5.7-1~deb13u3",
  "latest_available": "3.5.7-1~deb13u3",
  "cves": [
    {"cve": "CVE-2026-35189", "status": "resolved",
     "fixed_version": "3.5.7-1~deb13u3", "urgency": "not yet assigned"}
  ],
  "binary_packages": ["libssl3t64", "openssl"]
}
```

`binary_packages` only appears in host scans. `fixed_version` is the version
that fixes every reported (fixed) CVE.

### Upgrading from 0.x

1.0 changes the return values: methods return Python lists/dicts instead of
JSON strings, errors are raised instead of returned, and the result format
above replaces the old `cve_list` structure. `package_cve` expects the
**source** package name.

## License

MIT. See [LICENSE.txt](LICENSE.txt).

## Contact

Email: whit3bl0cker@gmail.com · Issues on GitHub.
