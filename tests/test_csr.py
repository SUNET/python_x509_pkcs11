"""
Test to sign a csr

# Remeber to set PKCS11 env variables
export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_TOKEN='my_test_token_1'
export PKCS11_PIN='1234'

# Delete a previous pkcs11 token if exists
softhsm2-util --delete-token --token my_test_token_1

# Create a new pkcs11 token
softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN \
--pin $PKCS11_PIN --so-pin $PKCS11_PIN

"""
import unittest
from asn1crypto import x509 as asn1_x509
from asn1crypto import csr as asn1_csr
from asn1crypto import pem as asn1_pem

from src.python_x509_pkcs11 import csr
from src.python_x509_pkcs11.pkcs11_handle import PKCS11Session
from src.python_x509_pkcs11.error import DuplicateExtensionException

# Replace the above with this should you use this code
# from python_x509_pkcs11 import csr
# from python_x509_pkcs11.pkcs11_handle import PKCS11Session
# from python_x509_pkcs11.error import DuplicateExtensionException

CSR_PEM = """-----BEGIN CERTIFICATE REQUEST-----
MIIDOTCCAiECAQAwRDELMAkGA1UEBhMCU0UxGzAZBgNVBAoMEkV4YW1wbGUgVW5p
dmVyc2l0eTEYMBYGA1UEAwwPZm9vLmV4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA0gTQK7ogA8Lu+z2ygADguk49XZe6bL7WMfto4Fi+
1hQX04V/zJzfCRp8qBTgm8VD1ZuXDI7p5vZ1fXv7/d0EQoSpYEz30BKxsP3tD+4z
AMv/11++V/X4nD4+RnXtWmGnTHIm+FbvNUU6hdBShzjVuHbkj/dSZHAc8G1x9woV
aVCLaeJj1mWj4u+3jvUiDQiyMPLxB024kxQvHhRf7LnAk6OFI7E8upAOjNVGuZ+R
m7NujaZYaZQ0SV0brbRpN+apFwYGrq8fvaUqMY9v42j5D3ik/gGGBjcY1L/WQmu/
UwtZPNouLUwY0rBIKZH66fsOUirGdGfvuS9Fi9cRwAWReQIDAQABoIGvMIGsBgkq
hkiG9w0BCQ4xgZ4wgZswQAYDVR0RBDkwN4IPZm9vLmV4YW1wbGUub3Jngg9iYXIu
ZXhhbXBsZS5vcmeCE3d3dy5mb28uZXhhbXBsZS5vcmcwCQYDVR0TBAIwADALBgNV
HQ8EBAMCBeAwIAYJYIZIAYb4QgENBBMWEVRoaXMgaXMgYSBDb21tZW50MB0GA1Ud
DgQWBBQ3pFRw1eO/rsU8dfFlObL2GoE+hDANBgkqhkiG9w0BAQsFAAOCAQEAdxKD
/ugiLarTyb1qnDvPYUg3lBnIEpPKXLb/2JTocd26AfrdzCD2DQAG57A17jICiETJ
Twbw+OPxPxMJ+/qtNUTYBYi6A4Sb+kccnOALvMtWGerG4oQEpnk6xx5dvBPrYr62
aEyGQeuk1ird8R/OKKWxvdSxXWqVFFO6ikh59Cu+w2NxawD4A0XsveBYzpudw8MN
+ljg6anm8g+ajLm4F5aDu0+Du3blJU1fZhZ0sQM0Koa1hxTYs+9ZJFzqAu4SzISl
+L9/hVi/34Q8kBz05pp1ZBX9Mp+r9R0+n/PFSh1QNBB3wzFE+mjGDi0M/ElLksCx
C+FhkjWYaDrKJDYh2Q==
-----END CERTIFICATE REQUEST-----
"""

issuer_name = {
    "country_name": "SE",
    "state_or_province_name": "Stockholm",
    "locality_name": "Stockholm",
    "organization_name": "SUNET",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test.sunet.se",
    "email_address": "soc@sunet.se",
}


class TestCsr(unittest.TestCase):
    """
    Test our csr module.
    """

    def test_sign_csr_keep_extensions(self) -> None:
        """
        Sign a CSR with the key with the key_label in the pkcs11 device.
        """

        PKCS11Session.create_keypair("test_3", 4096)
        cert_pem = csr.sign_csr("test_3", issuer_name, CSR_PEM)

        data = cert_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))

        exts = test_cert["tbs_certificate"]["extensions"]
        # CSR exts + authority and subject key identifier = 6
        self.assertTrue(len(exts) == 6)

        # Assert its value is a string
        self.assertTrue(isinstance(exts[0]["extn_value"].native[0], str))

        # Assert its correct value
        self.assertTrue(exts[0]["extn_value"].native[0] == "foo.example.org")

    def test_sign_csr_no_keep_extensions(self) -> None:
        """
        Sign a CSR with the key with the key_label in the pkcs11 device.
        """

        PKCS11Session.create_keypair("test_3", 4096)
        cert_pem = csr.sign_csr(
            "test_3", issuer_name, CSR_PEM, keep_csr_extensions=False
        )

        data = cert_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))

        exts = test_cert["tbs_certificate"]["extensions"]
        # CSR exts + authority and subject key identifier = 2
        self.assertTrue(len(exts) == 2)

        # Test Subject key identifier
        self.assertTrue(isinstance(exts[0]["extn_value"].native, bytes))
        self.assertTrue(
            exts[0]["extn_value"].native
            == b"7\xa4Tp\xd5\xe3\xbf\xae\xc5<u\xf1e9\xb2\xf6\x1a\x81>\x84"
        )
        self.assertTrue(isinstance(exts[0]["extn_id"].native, str))
        self.assertTrue(exts[0]["extn_id"].native == "key_identifier")

        # Test authority key identifier
        self.assertTrue(
            isinstance(exts[1]["extn_value"].native["key_identifier"], bytes)
        )
        self.assertTrue(isinstance(exts[1]["extn_id"].native, str))
        self.assertTrue(exts[1]["extn_id"].native == "authority_key_identifier")

    def test_sign_csr_new_extensions(self) -> None:
        """
        Sign a CSR with the key with the key_label in the pkcs11 device.
        """

        exts = asn1_csr.Extensions()

        k_u = asn1_x509.KeyUsage(("100001100",))
        ext1 = asn1_x509.Extension()
        ext1["extn_id"] = asn1_x509.ExtensionId("2.5.29.15")
        ext1["critical"] = True
        ext1["extn_value"] = k_u
        exts.append(ext1)

        b_c = asn1_x509.BasicConstraints()
        b_c["ca"] = True

        ext2 = asn1_x509.Extension()
        ext2["extn_id"] = asn1_x509.ExtensionId("2.5.29.19")
        ext2["critical"] = True
        ext2["extn_value"] = b_c
        exts.append(ext2)

        PKCS11Session.create_keypair("test_3", 4096)
        cert_pem = csr.sign_csr(
            "test_3",
            issuer_name,
            CSR_PEM,
            keep_csr_extensions=False,
            extra_extensions=exts,
        )

        data = cert_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))

        exts = test_cert["tbs_certificate"]["extensions"]
        # CSR exts (key usage and basic constraints
        # + authority and subject key identifier = 4
        self.assertTrue(len(exts) == 4)

        # Test key Usage
        self.assertTrue(isinstance(exts[0].native["extn_id"], str))
        self.assertTrue(
            exts[0]["extn_value"].native
            == {"crl_sign", "key_cert_sign", "digital_signature"}
        )

        # Test Basic constraints
        self.assertTrue(isinstance(exts[1]["extn_id"].native, str))
        self.assertTrue(exts[1]["extn_id"].native == "basic_constraints")

        self.assertTrue(isinstance(exts[1]["extn_value"].native["ca"], bool))
        self.assertTrue(exts[1]["extn_value"].native["ca"])

    def test_sign_csr_duplicate_extensions(self) -> None:
        """
        Sign a CSR with the key with the key_label in the pkcs11 device.
        """

        exts = asn1_csr.Extensions()

        k_u = asn1_x509.KeyUsage(("100001100",))
        ext1 = asn1_x509.Extension()
        ext1["extn_id"] = asn1_x509.ExtensionId("2.5.29.15")
        ext1["critical"] = True
        ext1["extn_value"] = k_u
        exts.append(ext1)
        exts.append(ext1)

        with self.assertRaises(DuplicateExtensionException):
            _ = csr.sign_csr(
                "test_3",
                issuer_name,
                CSR_PEM,
                keep_csr_extensions=False,
                extra_extensions=exts,
            )
