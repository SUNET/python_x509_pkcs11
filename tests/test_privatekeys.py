import asyncio
import datetime
import os
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import ObjectIdentifier
from cryptography.x509.oid import NameOID

from src.python_x509_pkcs11.lib import KEYTYPES
from src.python_x509_pkcs11.pkcs11_handle import PKCS11Session
from src.python_x509_pkcs11.privatekeys import (
    PKCS11ECPrivateKey,
    PKCS11ED448PrivateKey,
    PKCS11ED25519PrivateKey,
    PKCS11RSAPrivateKey,
)

not_valid_before = datetime.datetime.now()
not_valid_after = not_valid_before + datetime.timedelta(days=90)
subject_private_key = rsa.generate_private_key(65537, 2048)
name = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Stockholm"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Stockholm"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sunet"),
        x509.NameAttribute(NameOID.COMMON_NAME, "sunet.se"),
    ]
)


def get_builder() -> x509.CertificateBuilder:
    "Helper function for test"
    builder = (
        x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .issuer_name(name)
        .subject_name(name)
        .public_key(subject_private_key.public_key())
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("sunet.se")]),
            critical=False,
        )
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )
    return builder


class TestPrivateKeys(unittest.TestCase):

    def test_rsa_private_key(self) -> None:
        "Tests HSM based RSA private key usage."
        key_label = "testpkcs" + hex(int.from_bytes(os.urandom(8), "big") >> 1)
        # First let us create an RSA4096 private key.
        asyncio.run(PKCS11Session().create_keypair(key_label, key_type=KEYTYPES.RSA4096))

        issuer_private_key = PKCS11RSAPrivateKey(key_label, KEYTYPES.RSA4096)
        # This is the issuer public key
        issuer_public_key = issuer_private_key.public_key()

        builder = get_builder()
        cert = builder.sign(issuer_private_key, hashes.SHA512())

        # "1.2.840.113549.1.1.13"
        # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA512
        oid = ObjectIdentifier("1.2.840.113549.1.1.13")
        self.assertEqual(cert.signature_algorithm_oid, oid)

        # Now verify the signature of the certificate
        issuer_public_key.verify(
            cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm
        )

    def test_ec_private_key(self) -> None:
        "Tests HSM based ec private key usage."
        key_label = "testpkcs" + hex(int.from_bytes(os.urandom(20), "big") >> 1)
        # First let us create an SECP521r1 private key.
        asyncio.run(PKCS11Session().create_keypair(key_label, key_type=KEYTYPES.SECP521r1))

        issuer_private_key = PKCS11ECPrivateKey(key_label, KEYTYPES.SECP521r1)
        # This is the issuer public key
        issuer_public_key = issuer_private_key.public_key()

        builder = get_builder()
        cert = builder.sign(issuer_private_key, hashes.SHA512())

        # "1.2.840.10045.4.3.4" is for ECDSA wtih SHA512 hash
        # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA512
        oid = ObjectIdentifier("1.2.840.10045.4.3.4")
        self.assertEqual(cert.signature_algorithm_oid, oid)

        # Now verify the signature of the certificate
        issuer_public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))

    def test_ed25519_private_key(self) -> None:
        "Tests HSM based ed25519 private key usage."
        key_label = "testpkcs" + hex(int.from_bytes(os.urandom(20), "big") >> 1)
        # First let us create an ED25519 private key.
        asyncio.run(PKCS11Session().create_keypair(key_label, key_type=KEYTYPES.ED25519))

        issuer_private_key = PKCS11ED25519PrivateKey(key_label, KEYTYPES.ED25519)
        # This is the issuer public key
        issuer_public_key = issuer_private_key.public_key()

        builder = get_builder()
        cert = builder.sign(issuer_private_key, None)

        # "1.3.101.112" is for ED25519 keys
        # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.oid.SignatureAlgorithmOID.ED25519
        oid = ObjectIdentifier("1.3.101.112")
        self.assertEqual(cert.signature_algorithm_oid, oid)

        # Now verify the signature of the certificate
        issuer_public_key.verify(cert.signature, cert.tbs_certificate_bytes)

    def test_ed448_private_key(self) -> None:
        "Tests HSM based ed448 private key usage."
        key_label = "testpkcs" + hex(int.from_bytes(os.urandom(20), "big") >> 1)
        # First let us create an ED25519 private key.
        asyncio.run(PKCS11Session().create_keypair(key_label, key_type=KEYTYPES.ED448))

        issuer_private_key = PKCS11ED448PrivateKey(key_label, KEYTYPES.ED448)
        # This is the issuer public key
        issuer_public_key = issuer_private_key.public_key()

        builder = get_builder()
        cert = builder.sign(issuer_private_key, None)

        # "1.3.101.113" is for ED448 keys
        # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.oid.SignatureAlgorithmOID.ED448
        oid = ObjectIdentifier("1.3.101.113")
        self.assertEqual(cert.signature_algorithm_oid, oid)

        # Now verify the signature of the certificate
        issuer_public_key.verify(cert.signature, cert.tbs_certificate_bytes)
