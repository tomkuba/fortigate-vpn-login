# -*- coding: utf-8 -*-
"""
    fortigate_vpn_login.utils
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Helper methods for fortigate_vpn_login
"""
import os
import base64
import hashlib
import psutil
import socket
import ssl
import subprocess
import re
from typing import Optional
from shutil import which
from pathlib import Path
from enum import Enum, auto
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fortigate_vpn_login import logger


class VPNStatus(Enum):
    UNKNOWN = auto()
    DISCONNECTED = auto()
    CONNECTED_FOREGROUND = auto()
    CONNECTED_BACKGROUND = auto()


def get_default_config_filepath() -> Path:
    """
    Gets the default path for storing configuration files for this program. On UNIX, this will follow the
    XDG standard: `~/.config/fortigate_vpn_login`. On Windows, there's no standard, so we'll use
    `%APPDIR%/fortigate_vpn_login`.

    Returns:
        obj(Path): the path to store configuration files

    """
    if is_windows():
        return Path(os.getenv('APPDATA')) / 'fortigate_vpn_login'
    else:
        return Path(os.path.expanduser('~/.config/fortigate_vpn_login'))


def is_windows() -> bool:
    """
    Detects if the application is running on windows or not.

    Returns:
        bool: True if it's on Windows. False if not.
    """
    return os.name == 'nt'


def find_openconnect() -> Optional[Path]:
    """
    Checks openconnect presence on the system/path

    Returns:
        obj(Path)|Optional: path of the openconnect executable
    """
    if not is_windows():
        openconnect_path = which('openconnect')

    else:
        try_paths = [
            'c:\\Progra~1\\OpenConnect\\openconnect.exe',
            'c:\\Progra~2\\OpenConnect\\openconnect.exe',
            'c:\\Progra~3\\OpenConnect\\openconnect.exe',
        ]
        openconnect_path = which('openconnect.exe')

        if not openconnect_path:
            for try_path in try_paths:
                if os.path.exists(try_path) and os.access(try_path, os.X_OK) and os.path.isfile(try_path):
                    openconnect_path = try_path
                    break

    if not openconnect_path:
        return None
    else:
        logger.debug(f"Found openconnect path: {openconnect_path}")
        return Path(openconnect_path)


def is_openconnect_running_windows():
    """
    Detects if openconnect is running on windows or not.

    Returns:
        bool: True if running on Windows. False if not.
    """
    running = 'openconnect.exe' in (p.name() for p in psutil.process_iter(["name"]))
    logger.debug(f"is openconnect running on windows? {running}")
    if running:
        return True
    else:
        return False


def get_openconnect_pid(pid_file: str) -> int:
    """
    If it's running and has a pid file, gets the PID number

    Args:
        pid_file (str): Location of the file containing the PID number

    Returns:
        int: the PID number
    """
    pid = None
    with open(pid_file, 'r') as fp:
        pid = int(fp.read())

    logger.debug(f"get openconnect pid: {pid}")
    if pid and not psutil.pid_exists(pid):
        pid = None

    return pid


def get_gateway_cert_hash(host: str, port: int = 443) -> Optional[str]:
    """
    Fetches the TLS certificate presented by the VPN gateway and returns its public-key
    fingerprint in the `pin-sha256:` form understood by `openconnect --servercert` (and
    NetworkManager's `vpn.secrets.gwcert`).

    Computing this at runtime avoids shipping a hardcoded pin that breaks whenever the gateway
    certificate is renewed.

    Args:
        host (str): The gateway hostname.
        port (int): The gateway TLS port. Defaults to 443.

    Returns:
        str|Optional: `pin-sha256:<base64>` digest of the certificate's SubjectPublicKeyInfo,
        or None on failure.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # we only want to read the presented certificate, not validate the chain
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
    except OSError as e:
        logger.debug(f"Could not fetch gateway certificate from {host}:{port}: {e}")
        return None

    if not der_cert:
        logger.debug(f"No certificate returned by {host}:{port}")
        return None

    spki = x509.load_der_x509_certificate(der_cert).public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pin = base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
    cert_hash = f"pin-sha256:{pin}"
    logger.debug(f"Gateway certificate hash for {host}:{port}: {cert_hash}")
    return cert_hash


def check_openconnect_version(openconnect_path: Path) -> bool:
    """
    Checks if the openconnect version is compatible with this program, mainly checking for the
    'fortinet' protocol support.

    Args:
        openconnect_path (Path): path of the openconnect executable

    Returns:
        bool: True if compatible. False if not.
    """
    env = os.environ.copy()
    env['LC_ALL'] = 'C'
    process = subprocess.run([openconnect_path, '--version'], env=env, capture_output=True)
    output = process.stdout.decode("utf-8")
    logger.debug(f"Checking openconnect version: {output}")

    if not process.returncode == 0:
        return False

    # openconnect version
    # match = re.search(r'^OpenConnect version v(.*?)[\r\n]*$', output, re.MULTILINE)
    # openconnect_version = match.group(1)

    # openconnect fortinet support
    match = re.search(r'^Supported protocols: (.*?)$', output, re.MULTILINE)
    openconnect_supported_protocols = match.group(1)
    openconnect_supported_protocols = openconnect_supported_protocols.replace("(default)", "")
    openconnect_supported_protocols = [x.strip() for x in openconnect_supported_protocols.split(',')]
    logger.debug(f"Openconnect supported protocols: {openconnect_supported_protocols}")

    if 'fortinet' not in openconnect_supported_protocols:
        return False

    return True
