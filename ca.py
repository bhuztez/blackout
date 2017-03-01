#!/usr/bin/env python3

from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generate_key(bits=2048):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend())


def write_private(obj, filename):
    data = obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    with open(filename, 'wb') as f:
       f.write(data)


def write_public(obj, filename):
    data = obj.public_bytes(serialization.Encoding.PEM)
    with open(filename, 'wb') as f:
        f.write(data)


def read_private_key(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    return serialization.load_pem_private_key(data, None, default_backend())


def read_cert(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    return x509.load_pem_x509_certificate(data, default_backend())


def read_crl(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    return x509.load_pem_x509_crl(data, default_backend())


def create_cert_builder(key, subject, issuer, serial_number, is_cacert = False):
    now = datetime.utcnow()

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(is_cacert, None),
            critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not is_cacert,
                content_commitment=not is_cacert,
                key_encipherment=not is_cacert,
                data_encipherment=not is_cacert,
                key_agreement=not is_cacert,
                key_cert_sign=is_cacert,
                crl_sign=is_cacert,
                encipher_only=False,
                decipher_only=False),
            critical=True)
    )



def create_ca(cn, serial_number, key_path, cert_path):
    key = generate_key()
    write_private(key, key_path)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    cert = (
        create_cert_builder(key, subject, subject, serial_number, True)
        .add_extension(
            x509.AuthorityKeyIdentifier. from_issuer_public_key(key.public_key()),
            critical=False
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    write_public(cert, cert_path)


def create_cert(cn, serial_number, key_path, cert_path, ca_key, ca_cert):
    key = generate_key()
    write_private(key, key_path)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    cert = (
        create_cert_builder(key, subject, ca_cert.subject, serial_number, False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            ),
            critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                 x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                 x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION
                ]
            ),
            critical=True
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    write_public(cert, cert_path)


def create_crl(crl_path, ca_key, ca_cert):
    now = datetime.utcnow()

    builder = (
        x509.CertificateRevocationListBuilder()
        .last_update(now)
        .next_update(now + timedelta(days=1))
        .issuer_name(ca_cert.subject)
    )

    for i in [3,4,5]:
        cert = (
            x509.RevokedCertificateBuilder()
            .revocation_date(now)
            .serial_number(i)
            .add_extension(
                x509.CRLReason(x509.ReasonFlags.key_compromise),
                critical=False)
            .build(default_backend())
        )
        builder = builder.add_revoked_certificate(cert)

    cert = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend())

    write_public(cert, crl_path)


def validate_cert(cert, ca_cert):
    v = ca_cert.public_key().verifier(
        cert.signature,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    v.update(cert.tbs_certificate_bytes)
    v.verify()


def validate_crl(crl, ca_cert):
    v = ca_cert.public_key().verifier(
        crl.signature,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    v.update(crl.tbs_certlist_bytes)
    v.verify()


def main():
    import os.path

    ROOT = os.path.dirname(os.path.abspath(__file__))
    CA_CERT_PATH = os.path.join(ROOT, 'ca.crt')
    CA_KEY_PATH = os.path.join(ROOT, 'ca.key')
    CA_COMMON_NAME = 'Example CA'

    COMMON_NAME = 'peer'
    KEY_PATH = os.path.join(ROOT, COMMON_NAME + '.key')
    CERT_PATH = os.path.join(ROOT, COMMON_NAME + '.crt')
    CRL_PATH = os.path.join(ROOT, 'crl.pem')

    create_ca(CA_COMMON_NAME, 1, CA_KEY_PATH, CA_CERT_PATH)
    create_cert(COMMON_NAME, 2, KEY_PATH, CERT_PATH,
                read_private_key(CA_KEY_PATH),
                read_cert(CA_CERT_PATH))

    validate_cert(read_cert(CERT_PATH), read_cert(CA_CERT_PATH))
    create_crl(CRL_PATH,
               read_private_key(CA_KEY_PATH),
               read_cert(CA_CERT_PATH))
    validate_crl(read_crl(CRL_PATH), read_cert(CA_CERT_PATH))


if __name__ == '__main__':
    main()
