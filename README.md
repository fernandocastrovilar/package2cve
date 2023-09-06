# package2cve

![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Description

`package2cve` is a tool that allows you to analyze installed packages on a Debian server and provides information about known vulnerabilities associated with those packages. It also offers details about the versions that fix these vulnerabilities, making system security management easier.

## Features

- Scanning of installed packages on a Debian server.
- Searching for known vulnerabilities in the CVE (Common Vulnerabilities and Exposures) database.
- Detailed information about the discovered vulnerabilities, including CVE ID and fixed version.
- User-friendly and readable results in json.

## Requirements

- Python 3.11 or higher.
- Internet access to query the CVE database.

## Usage

```bash
pip install package2cve
```
```python
from package2cve.Package2Cve import Package2Cve
op = Package2Cve()
# Get remote host package cve. It use ssh connection so password can be "password" or None
op.remote_host_packages_cve("HOSTNAME", "user", "password/None")
# Get package version cve
op.package_cve("os_codename", "package_name", "version")
```

## License
This project is licensed under the MIT License. See the LICENSE file for more details.

## Contributions
Contributions are welcome.

## Contact
If you have questions, comments, or suggestions, feel free to get in touch with us:

Email: whit3bl0cker@gmail.com
Report issues: GitHub Issues



Thank you for using package2cve!