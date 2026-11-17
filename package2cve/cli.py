"""Command line interface: ``package2cve host|package|local ...``."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from package2cve.Package2Cve import Package2Cve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="package2cve",
        description="Find CVEs in Debian packages using the Debian Security Tracker")
    parser.add_argument("--tracker-file",
                        help="use a local copy of the tracker JSON instead of downloading it")
    parser.add_argument("--include-unfixed", action="store_true",
                        help="also report CVEs that have no fixed version yet")
    sub = parser.add_subparsers(dest="command", required=True)

    host = sub.add_parser("host", help="scan the packages installed on a remote host")
    host.add_argument("hostname")
    host.add_argument("-u", "--user", help="SSH user / Teleport node login")
    host.add_argument("--teleport", action="store_true",
                      help="connect with 'tsh ssh' instead of SSH (needs 'tsh login')")
    host.add_argument("--proxy", help="Teleport proxy (tsh --proxy)")
    host.add_argument("--cluster", help="Teleport cluster (tsh --cluster)")
    host.add_argument("-p", "--port", type=int, default=22, help="SSH port")
    host.add_argument("-i", "--identity", help="SSH private key file")
    host.add_argument("--ask-password", action="store_true",
                      help="prompt for the SSH password")
    host.add_argument("--release",
                      help="Debian release of the host (autodetected if omitted)")

    local = sub.add_parser("local", help="scan the packages installed on this machine")
    local.add_argument("--release",
                       help="Debian release (autodetected if omitted)")

    pkg = sub.add_parser("package", help="check a single source package version")
    pkg.add_argument("release", help="codename or number, e.g. trixie or 13")
    pkg.add_argument("package", help="source package name, e.g. openssl")
    pkg.add_argument("version", help="source package version")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "host" and args.teleport:
            if args.ask_password or args.identity or args.port != 22:
                raise SystemExit("--ask-password, --identity and --port are SSH-only options")
        if args.command == "host" and not args.teleport and (args.proxy or args.cluster):
            raise SystemExit("--proxy and --cluster need --teleport")

        p2c = Package2Cve(tracker_file=args.tracker_file)

        if args.command == "package":
            result = p2c.package_cve(args.release, args.package, args.version,
                                     include_unfixed=args.include_unfixed)
        elif args.command == "local":
            result = p2c.remote_host_packages_cve(
                None, transport="local", release=args.release,
                include_unfixed=args.include_unfixed)
        else:
            if args.teleport:
                options = {"proxy": args.proxy, "cluster": args.cluster}
                transport = "teleport"
                password = None
            else:
                options = {"port": args.port, "key_filename": args.identity}
                transport = "ssh"
                password = getpass.getpass("SSH password: ") if args.ask_password else None
            result = p2c.remote_host_packages_cve(
                args.hostname, user=args.user, password=password,
                transport=transport, release=args.release,
                include_unfixed=args.include_unfixed, **options)
    except Exception as error:  # paramiko, requests, tsh... -> clean message
        print("error: {0}".format(error), file=sys.stderr)
        return 2

    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 1 if result else 0


if __name__ == "__main__":
    sys.exit(main())
