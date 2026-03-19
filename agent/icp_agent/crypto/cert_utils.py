"""Certificate parsing and utility functions."""

from datetime import datetime
from typing import Optional

import structlog
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID


logger = structlog.get_logger(__name__)


def parse_certificate(cert_pem: str) -> x509.Certificate:
    """
    Parse PEM-encoded certificate.

    Args:
        cert_pem: PEM-encoded certificate

    Returns:
        Parsed X.509 certificate

    Raises:
        ValueError: If certificate parsing fails
    """
    try:
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode("utf-8"),
            backend=default_backend(),
        )
        return cert
    except Exception as e:
        logger.error("Failed to parse certificate", error=str(e))
        raise ValueError(f"Invalid certificate: {e}")


def get_certificate_expiry(cert_pem: str) -> datetime:
    """
    Get certificate expiration time.

    Args:
        cert_pem: PEM-encoded certificate

    Returns:
        Certificate expiration datetime (UTC)
    """
    cert = parse_certificate(cert_pem)
    return cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after


def get_spiffe_id_from_cert(cert_pem: str) -> Optional[str]:
    """
    Extract SPIFFE ID from certificate SAN extension.

    Args:
        cert_pem: PEM-encoded certificate

    Returns:
        SPIFFE ID if found, None otherwise
    """
    cert = parse_certificate(cert_pem)

    try:
        # Get Subject Alternative Name extension
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )

        # Look for URI with spiffe:// scheme
        for san in san_ext.value:
            if isinstance(san, x509.UniformResourceIdentifier):
                uri = san.value
                if uri.startswith("spiffe://"):
                    return uri

    except x509.ExtensionNotFound:
        logger.warning("Certificate does not have SAN extension")

    return None


def get_certificate_serial(cert_pem: str) -> str:
    """
    Get certificate serial number.

    Args:
        cert_pem: PEM-encoded certificate

    Returns:
        Certificate serial number as hex string
    """
    cert = parse_certificate(cert_pem)
    return format(cert.serial_number, 'x')


def is_certificate_expired(cert_pem: str) -> bool:
    """
    Check if certificate has expired.

    Args:
        cert_pem: PEM-encoded certificate

    Returns:
        True if expired, False otherwise
    """
    expiry = get_certificate_expiry(cert_pem)
    return datetime.utcnow() >= expiry


def is_certificate_expiring_soon(
    cert_pem: str,
    threshold_seconds: int = 21600,
) -> bool:
    """
    Check if certificate is expiring soon.

    Args:
        cert_pem: PEM-encoded certificate
        threshold_seconds: Time threshold in seconds (default: 6 hours)

    Returns:
        True if expiring within threshold, False otherwise
    """
    expiry = get_certificate_expiry(cert_pem)
    remaining = (expiry - datetime.utcnow()).total_seconds()
    return remaining <= threshold_seconds
