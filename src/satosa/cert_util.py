import datetime

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.jwk.rsa import RSAKey


def create_certificate(cert_info):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, cert_info['cn']),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, cert_info['state']),
        x509.NameAttribute(NameOID.LOCALITY_NAME, cert_info['state']),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, cert_info['organization']),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, cert_info['organization_unit']),
    ])
    item = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    )

    if 'dns_name' in cert_info:
        item.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cert_info['dns_name'])]), critical=False
        )

    cert = item.sign(key, hashes.SHA256())
    cert_str = cert.public_bytes(serialization.Encoding.PEM)

    key_str = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_str, key_str


def generate_cert():
    cert_info = {
        "cn": "SE",
        "country_code": "se",
        "state": "ac",
        "city": "Umea",
        "organization": "ITS",
        "organization_unit": "DIRG"
    }
    cert_str, key_str = create_certificate(cert_info)
    return cert_str, key_str


def write_cert(cert_path, key_path):
    cert, key = generate_cert()
    with open(cert_path, "wb") as cert_file:
        cert_file.write(cert)
    with open(key_path, "wb") as key_file:
        key_file.write(key)

def rsa_key_from_pem(file_name, **kwargs):
    _key = RSAKey(**kwargs)
    _key.load_key(import_private_rsa_key_from_file(file_name))
    return _key
