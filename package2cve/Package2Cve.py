#!/usr/bin/env python

from version_utils import rpm
import json
import paramiko
import requests


DEBIAN_CODENAMES = {
    7: "wheezy",
    8: "jessie",
    9: "stretch",
    10: "buster",
    11: "bullseye",
    12: "bookworm",
    "unstable": "sid"
}


class Package2Cve:

    def __init__(self):
        url = "https://security-tracker.debian.org/tracker/data/json"
        response = requests.get(url)
        self.data = response.json()

    def _determine_cve(self, package, version, os):
        vulnerabilities = []
        try:
            if package in self.data:
                cves = self.data[package]

                for cve in cves:
                    if os in cves[cve]["releases"].keys():
                        if "fixed_version" in cves[cve]["releases"][os]:
                            fixed = cves[cve]["releases"][os]["fixed_version"]
                            vulnerable = rpm.compare_versions(fixed, version) > 0
                        else:
                            fixed = False
                            vulnerable = True
                        if vulnerable:
                            latest = cves[cve]["releases"][os]["repositories"][os]
                            vulnerability = {
                                "cve": cve,
                                "fixed": fixed,
                                "latest": latest,
                            }
                            vulnerabilities.append(vulnerability)
            return vulnerabilities
        except Exception as error:
            return error

    def package_cve(self, os, package, version):
        if os not in DEBIAN_CODENAMES:
            raise Exception("Debian codename not valid")
        vulnerabilities = self._determine_cve(package, version, os)
        if not vulnerabilities:
            """
            If no CVE, return None to continue
            """
            return None
        latest_version = vulnerabilities[0]["latest"]
        cve_list = []
        cve_num_flag = False
        for vuln in vulnerabilities:
            if not vuln["fixed"]:
                """
                Only return CVEs fixed
                """
                continue
            if not vuln["cve"] or "TEMP-" in vuln["cve"]:
                continue
            else:
                cve_num_flag = True
                cve_num = vuln["cve"]
                cves = {
                    "cve_num": f"{cve_num}"
                }
            cve_list.append(cves)
        cve_str = json.dumps(cve_list)
        if cve_num_flag is False:
            return None
        return latest_version, cve_str

    def remote_host_packages_cve(self, hostname, user, password):
        cmd1 = "apt list --installed"
        cmd2 = "lsb_release -c"
        remote_list = []
        try:
            client = paramiko.client.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if password:
                client.connect(hostname, username=user, password=password, timeout=60)
            else:
                client.connect(hostname, username=user, timeout=60)
            _stdin, _stdout, _stderr = client.exec_command(cmd1)
            packages = _stdout.readlines()
            _stdin, _stdout, _stderr = client.exec_command(cmd2)
            os_version = _stdout.readlines()[0].split("\t")[1].strip()
            client.close()
            for line in packages:
                if "Listing" in line or not line:
                    continue
                package_data = str(line).split(" ", 3)
                package_name = package_data[0].split("/")[0]
                package_version = package_data[1]
                out = self.package_cve(os_version, package_name, package_version)
                if not out:
                    continue
                cve_list = out[1]
                cve_list = json.loads(cve_list)
                latest_fixed_version = out[0]
                package = {
                            "package_name": f"{package_name}",
                            "cve_list": {
                                "cve": f"{str(cve_list)}"
                            },
                            "current_version": f"{package_version}",
                            "latest_fixed_version": f"{latest_fixed_version}"
                            }
                remote_list.append(package)
            if not remote_list:
                return "{'no vulnerabilities found'}"
            list_str = json.dumps(remote_list)
            return list_str
        except Exception as error:
            return error
