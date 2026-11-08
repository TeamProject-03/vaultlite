"""Private Certificate Authority (CA) and TLS 1.3 Certificate Generator.
OWNER: Mohammed Siraj.

This script generates a local private Root CA and issues a TLS server
certificate with Subject Alternative Names (SAN) for localhost and 127.0.0.1.

Security properties:
- Generates 2048-bit RSA keys and SHA-256 self-signed Root CA.
- Issues a server certificate signed by the private Root CA.
- Includes SubjectAlternativeName for 'localhost' and '127.0.0.1' so modern
  browsers, curl, and httpx validate TLS without insecure flags when the CA
  is trusted.
- Output files are saved to certs/ (which is ignored by .gitignore).
"""
import datetime
import ipaddress
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_ca_and_cert(output_dir: Path) -> tuple[Path, Path, Path, Path]:
    """Generate Root CA and Server TLS certificates in `output_dir`."""
    output_dir.mkdir(parents=True, exist_ok=True)

    ca_key_file = output_dir / "ca.key"
    ca_crt_file = output_dir / "ca.crt"
    server_key_file = output_dir / "server.key"
    server_crt_file = output_dir / "server.crt"

    # 1. Generate Root CA Key and Certificate
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VaultLite MACS902"),
        x509.NameAttribute(NameOID.COMMON_NAME, "VaultLite Private Root CA"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # 2. Generate Server Key and Certificate (with SAN for localhost)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VaultLite Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ])

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # 3. Write private keys (unencrypted on local dev machine)
    ca_key_file.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    server_key_file.write_bytes(
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # 4. Write certificates
    ca_crt_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    server_crt_file.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

    return ca_key_file, ca_crt_file, server_key_file, server_crt_file


if __name__ == "__main__":
    certs_dir = Path(__file__).resolve().parent.parent / "certs"
    ca_k, ca_c, srv_k, srv_c = generate_ca_and_cert(certs_dir)
    print(f"Generated Private CA and Server TLS Certificates in: {certs_dir}")
    print(f"  CA Certificate    : {ca_c.name}")
    print(f"  CA Private Key    : {ca_k.name}")
    print(f"  Server Certificate: {srv_c.name}")
    print(f"  Server Private Key: {srv_k.name}")
