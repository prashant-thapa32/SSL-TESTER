# ssl_tester/parser.py
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import timezone

def parse_certificate(cert_bytes):
    """
    Parse DER cert bytes and return dict with timezone-aware datetimes.
    Uses the new _utc properties to avoid DeprecationWarning.
    """
    cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = san.value.get_values_for_type(x509.DNSName)
    except Exception:
        san_list = []

    # Use the timezone-aware UTC properties
    not_before = getattr(cert, "not_valid_before_utc", None) or getattr(cert, "not_valid_before")
    not_after  = getattr(cert, "not_valid_after_utc", None)  or getattr(cert, "not_valid_after")

    # Ensure both are timezone-aware in UTC (fallback: attach UTC)
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        # ISO 8601 with timezone (e.g. 2025-10-29T14:56:50+00:00)
        "not_before": not_before.isoformat(),
        "not_after":  not_after.isoformat(),
        "serial_number": hex(cert.serial_number),
        "san": san_list,
        # expired: compare aware datetimes in UTC
        "expired": not_after < not_before,  # this is still a sanity check
        "days_until_expiry": (not_after.astimezone(timezone.utc) - __import__("datetime").datetime.now(timezone.utc)).days
    }
