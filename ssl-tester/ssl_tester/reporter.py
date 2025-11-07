# ssl_tester/reporter.py
import json

def format_cipher(cipher_tuple):
    """
    ssock.cipher() usually returns (name, protocol/version, bits).
    Be defensive in case some items are None or ordering differs.
    """
    if not cipher_tuple:
        return "unknown"
    # Common order: (name, version, bits)
    name = cipher_tuple[0] if len(cipher_tuple) > 0 else "unknown"
    maybe_bits = None
    maybe_version = None
    if len(cipher_tuple) == 3:
        maybe_version = cipher_tuple[1]
        maybe_bits = cipher_tuple[2]
    elif len(cipher_tuple) == 2:
        # some platforms return (name, bits) — guess
        maybe_bits = cipher_tuple[1]
    parts = [name]
    if maybe_version:
        parts.append(f"{maybe_version}")
    if maybe_bits:
        parts.append(f"{maybe_bits} bits")
    return " / ".join(parts)

def print_report(report, verbose=False):
    cert = report.get("certificate", {})
    cipher_repr = format_cipher(report.get("cipher"))

    print(f"\n[+] Target: {report.get('target')}:{report.get('port')}")
    print(f"    Protocol: {report.get('protocol')}")
    print(f"    Cipher: {cipher_repr}")
    print(f"    Issuer: {cert.get('issuer')}")
    print(f"    Subject: {cert.get('subject')}")
    print(f"    Validity: {cert.get('not_before')} → {cert.get('not_after')}")

    if verbose:
        san = ", ".join(cert.get("san") or []) or "None"
        print(f"    SANs: {san}")
        print(f"    Serial: {cert.get('serial_number')}")
        print(f"    Expired (sanity): {cert.get('expired')}")
        print(f"    Days until expiry: {cert.get('days_until_expiry')}")

def save_json(report, path):
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

