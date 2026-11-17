"""Ways of running a command on the host being scanned."""

from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional


class RemoteCommandError(Exception):
    pass


class Executor:
    """Runs a shell command on the target host and returns its stdout."""

    def run(self, command: str) -> str:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self) -> "Executor":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _check(cmd_desc: str, returncode: int, stdout: str, stderr: str) -> str:
    if returncode != 0:
        raise RemoteCommandError("{0} failed (exit {1}): {2}".format(
            cmd_desc, returncode, stderr.strip() or stdout.strip()))
    return stdout


class LocalExecutor(Executor):
    """Scan the machine package2cve is running on."""

    def run(self, command: str) -> str:
        proc = subprocess.run(["sh", "-c", command], capture_output=True,
                              text=True)
        return _check(command, proc.returncode, proc.stdout, proc.stderr)


class SSHExecutor(Executor):
    """Plain SSH through paramiko (password, key file or ssh-agent)."""

    def __init__(self, hostname: str, user: Optional[str] = None,
                 password: Optional[str] = None, port: int = 22,
                 key_filename: Optional[str] = None, timeout: int = 60):
        import paramiko  # only needed for this transport

        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(hostname, port=port, username=user,
                            password=password or None,
                            key_filename=key_filename, timeout=timeout)

    def run(self, command: str) -> str:
        _stdin, stdout, stderr = self.client.exec_command(command)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        return _check(command, stdout.channel.recv_exit_status(), out, err)

    def close(self) -> None:
        self.client.close()


class TeleportExecutor(Executor):
    """Run commands through ``tsh ssh``.

    Requires a valid ``tsh login`` session. ``user`` is the node login
    (e.g. ``root``); ``proxy`` and ``cluster`` map to the tsh flags of the
    same name.
    """

    def __init__(self, hostname: str, user: Optional[str] = None,
                 proxy: Optional[str] = None, cluster: Optional[str] = None,
                 tsh_bin: str = "tsh", timeout: int = 300):
        self.tsh = shutil.which(tsh_bin)
        if not self.tsh:
            raise RemoteCommandError(
                "'{0}' not found in PATH; install Teleport's tsh".format(tsh_bin))
        self.target = "{0}@{1}".format(user, hostname) if user else hostname
        self.flags: List[str] = []
        if proxy:
            self.flags.append("--proxy={0}".format(proxy))
        if cluster:
            self.flags.append("--cluster={0}".format(cluster))
        self.timeout = timeout

    def run(self, command: str) -> str:
        args = [self.tsh, "ssh", *self.flags, self.target, command]
        try:
            proc = subprocess.run(args, capture_output=True, text=True,
                                  stdin=subprocess.DEVNULL,
                                  timeout=self.timeout)
        except subprocess.TimeoutExpired:
            raise RemoteCommandError("tsh ssh {0} timed out".format(self.target))
        return _check("tsh ssh {0}".format(self.target), proc.returncode,
                      proc.stdout, proc.stderr)


def executor_for(transport: str, hostname: Optional[str] = None,
                 user: Optional[str] = None, password: Optional[str] = None,
                 **options) -> Executor:
    transport = transport.lower()
    if transport == "local":
        return LocalExecutor()
    if not hostname:
        raise ValueError("hostname is required for transport '{0}'".format(transport))
    if transport == "ssh":
        return SSHExecutor(hostname, user=user, password=password, **options)
    if transport in ("teleport", "tsh"):
        if password:
            raise ValueError("Teleport does not use passwords; run 'tsh login' first")
        return TeleportExecutor(hostname, user=user, **options)
    raise ValueError("Unknown transport '{0}' (ssh, teleport, local)".format(transport))
