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
from asn1crypto import pem as asn1_pem

from src.python_x509_pkcs11 import csr
from src.python_x509_pkcs11.pkcs11_handle import PKCS11Session


class TestCsr(unittest.TestCase):
    """
    Test our csr module.
    """
    def test_sign_csr(self
                      ) -> None:
        """
        Sign a CSR with the key with the key_label in the pkcs11 device.
        """

        csr_pem = """-----BEGIN CERTIFICATE REQUEST-----
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

        issuer_name = {"country_name": "SE",
                       "state_or_province_name": "Stockholm",
                       "locality_name": "Stockholm",
                       "organization_name": "SUNET",
                       "organizational_unit_name": "SUNET Infrastructure",
                       "common_name": "ca-test.sunet.se",
                       "email_address": "soc@sunet.se"}

        PKCS11Session.create_keypair_if_not_exists("test_3", 4096)
        cert_pem = csr.sign_csr("test_3", issuer_name, csr_pem)

        data = cert_pem.encode('utf-8')
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)

        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))
