"""
Test to create and sign a crl

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
from asn1crypto import crl as asn1_crl
from asn1crypto import pem as asn1_pem

from src.python_x509_pkcs11 import crl
from src.python_x509_pkcs11.pkcs11_handle import PKCS11Session

# Replace the above with this should you use this code
# from python_x509_pkcs11 import crl
# from python_x509_pkcs11.pkcs11_handle import PKCS11Session

subject_name = {
    "country_name": "SE",
    "state_or_province_name": "Stockholm",
    "locality_name": "Stockholm",
    "organizational_unit_name": "SUNET Infrastructure",
    "organization_name": "SUNET",
    "common_name": "ca-test.sunet.se",
    "email_address": "soc@sunet.se",
}

OLD_CRL_PEM = """-----BEGIN X509 CRL-----
MIIDQjCCASoCAQIwDQYJKoZIhvcNAQELBQAwgZwxCzAJBgNVBAYTAlNFMRIwEAYD
VQQIDAlTdG9ja2hvbG0xEjAQBgNVBAcMCVN0b2NraG9sbTEOMAwGA1UECgwFU1VO
RVQxHTAbBgNVBAsMFFNVTkVUIEluZnJhc3RydWN0dXJlMRkwFwYDVQQDDBBjYS10
ZXN0LnN1bmV0LnNlMRswGQYJKoZIhvcNAQkBFgxzb2NAc3VuZXQuc2UXDTIyMDcw
NTExMzEwOFoXDTI1MDcwNDExMzMwOFowKDAmAgcIUlkTQfsgFw0yMjA3MDMxMTMz
MDhaMAwwCgYDVR0VBAMKAQOgLzAtMAoGA1UdFAQDAgEBMB8GA1UdIwQYMBaAFMz8
c+Hp0qtdoxW9LEqBdA/HvFatMA0GCSqGSIb3DQEBCwUAA4ICAQAIzW9la/iU9MmD
sBCyxqd+tgtQAUUPsMmSGxvVx4OZof2MaL22K5btQiMp7oEh/+p0tln/ccmHwOqS
GLjbCWVkVGglV5nycnkDZWCBFsdv4nJSXe4/FEhHey4ki6Nq0P++GKHQAgqck7sM
bVJ7tTP3bxXzG/Fw9EQW4CydhNapTkTYlHVr0J02M8LLNJe1NN9ta+XZva9KMDBI
91pY6tJnd6cFroypFUUsGib44weByfjavy6zFCMXhXCkNDJzkoab7RHCikoTcxvw
mgi5o9bl9iOu264ejId4wnj+APunzkfRxLL8SMS5fGqq3CMtoBV0Lg9QPHzSSPgX
mKOccXyu4DGDU7rtgIyeN62YCHAmto6dtYuUubzZyYNsW7oHqSMyPDx2jL0N+OX3
VQEEmMqhmic66m/HYwphXOydIOqDqjtxLX2qasLN3msWLXoX5BuQNxh9SmprmbkU
+wfTXtOgLMtt09t01auaFtuPlujT3gWcV6vtj19v8UUnJdQkxc8JNhC+7Kjj6d3j
gr/JLfZWbMdXA2ldc2f67gBX/AQ8BdayBy4QZDG+tEeIWjsIlaZNZuGZ9M4GpqeS
7DNwgiPyOZREXjmE2ci2iYaffA+x+z/bXHCbSKtfJ9RfqPfLThQujR8XlkXxn4DX
wPJMBBDuchfFtgit0yJr2V/BD8Iadw==
-----END X509 CRL-----"""


class TestCrl(unittest.TestCase):
    """
    Test our crl module.
    """

    def test_create_new_crl(self) -> None:
        """
        Create and sign a CRL with the key_label in the pkcs11 device.
        """

        PKCS11Session.create_keypair("test_3", 4096)

        crl_pem = crl.create("test_3", subject_name)

        data = crl_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_crl = asn1_crl.CertificateList.load(data)

        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))

    def test_add_none_to_old_crl(self) -> None:
        """
        Create and sign a CRL with the key_label in the pkcs11 device.
        """

        PKCS11Session.create_keypair("test_3", 4096)

        crl_pem = crl.create("test_3", subject_name, old_crl_pem=OLD_CRL_PEM)

        data = crl_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_crl = asn1_crl.CertificateList.load(data)

        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))

    def test_add_serial_to_empty_crl(self) -> None:
        """
        Create and sign a CRL with the key_label in the pkcs11 device.
        """

        PKCS11Session.create_keypair("test_3", 4096)

        crl_pem = crl.create(
            "test_3", subject_name, serial_number=2342342342343456, reason=3
        )

        data = crl_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_crl = asn1_crl.CertificateList.load(data)

        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))

    def test_add_serial_to_old_crl(self) -> None:
        """
        Create and sign a CRL with the key_label in the pkcs11 device.
        """

        PKCS11Session.create_keypair("test_3", 4096)

        crl_pem = crl.create(
            "test_3",
            subject_name,
            old_crl_pem=OLD_CRL_PEM,
            serial_number=2342348342341456,
            reason=2,
        )

        data = crl_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_crl = asn1_crl.CertificateList.load(data)

        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))
