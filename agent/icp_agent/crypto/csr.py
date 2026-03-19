"""
Certificate Signing Request (CSR) generation utilities.

Provides functions to generate private keys and CSRs for SPIFFE SVIDs.
"""

from typing import Optional, List, Tuple

import structlog
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


logger = structlog.get_logger(__name__)


def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """
    Generate RSA private key.

    Args:
        key_size: Key size in bits (default: 2048)

    Returns:
        RSA private key
    """
    logger.debug("Generating private key", key_size=key_size)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )

    logger.debug("Private key generated successfully")
    return private_key


def generate_csr(
    private_key: rsa.RSAPrivateKey,
    spiffe_id: str,
    common_name: Optional[str] = None,
    dns_names: Optional[List[str]] = None,
    ip_addresses: Optional[List[str]] = None,
) -> str:
    """
    Generate Certificate Signing Request (CSR) for SPIFFE SVID.

    Args:
        private_key: RSA private key
        spiffe_id: SPIFFE ID to include in URI SAN
        common_name: Optional common name (defaults to spiffe_id)
        dns_names: Optional DNS SANs
        ip_addresses: Optional IP SANs

    Returns:
        PEM-encoded CSR
    """
    logger.info("Generating CSR", spiffe_id=spiffe_id)

    # Build subject with CN
    cn = common_name or spiffe_id
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    # Build Subject Alternative Names (SAN)
    san_list = [
        x509.UniformResourceIdentifier(spiffe_id),
    ]

    if dns_names:
        for dns_name in dns_names:
            san_list.append(x509.DNSName(dns_name))

    if ip_addresses:
        from ipaddress import ip_address
        for ip_addr in ip_addresses:
            san_list.append(x509.IPAddress(ip_address(ip_addr)))

    # Create CSR
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(subject)
    csr_builder = csr_builder.add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
    )

    # Sign CSR with private key
    csr = csr_builder.sign(private_key, hashes.SHA256(), backend=default_backend())

    # Encode to PEM
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    logger.info("CSR generated successfully", spiffe_id=spiffe_id)
    return csr_pem


def generate_key_and_csr(
    spiffe_id: str,
    common_name: Optional[str] = None,
    dns_names: Optional[List[str]] = None,
    ip_addresses: Optional[List[str]] = None,
    key_size: int = 2048,
) -> Tuple[str, str]:
    """
    Generate private key and CSR in one step.

    Args:
        spiffe_id: SPIFFE ID to include in URI SAN
        common_name: Optional common name
        dns_names: Optional DNS SANs
        ip_addresses: Optional IP SANs
        key_size: Key size in bits (default: 2048)

    Returns:
        Tuple of (PEM-encoded private key, PEM-encoded CSR)
    """
    # Generate private key
    private_key = generate_private_key(key_size)

    # Encode private key to PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    # Generate CSR
    csr_pem = generate_csr(
        private_key,
        spiffe_id,
        common_name,
        dns_names,
        ip_addresses,
    )

    return private_key_pem, csr_pem
