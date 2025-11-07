import ssl
import socket
import idna
from datetime import datetime
from .parser import parse_certificate

def scan_ssl(host, port=443):
    """
    Establish SSL/TLS connection and retrieve certificate + connection details.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    hostname = idna.encode(host).decode()

    with socket.create_connection((hostname, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            cert_info = parse_certificate(cert_bin)
            protocol = ssock.version()
            cipher = ssock.cipher()

    return {
        "target": host,
        "port": port,
        "protocol": protocol,
        "cipher": cipher,
        "certificate": cert_info,
        "scanned_at": datetime.utcnow().isoformat() + "Z"
    }

