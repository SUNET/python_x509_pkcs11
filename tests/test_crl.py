"""
Test to create and sign a crl
"""
import asyncio
import datetime
import os
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

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))

        crl_pem = asyncio.run(crl.create(new_key_label, subject_name))

        data = crl_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_crl = asn1_crl.CertificateList.load(data)
        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))
        tbs = test_crl["tbs_cert_list"]
        for _, extension in enumerate(tbs["crl_extensions"]):
            if extension["extn_id"].dotted == "2.5.29.20":
                self.assertTrue(extension["extn_value"].native == 1)
        self.assertTrue(len(tbs["revoked_certificates"]) == 0)
        self.assertTrue(tbs["issuer"].native == subject_name)
        self.assertTrue(tbs["version"].native == "v2")

        crl_pem = asyncio.run(crl.create(new_key_label, subject_name, old_crl_pem=OLD_CRL_PEM))
        data = crl_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_crl = asn1_crl.CertificateList.load(data)
        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))
        tbs = test_crl["tbs_cert_list"]
        for _, extension in enumerate(tbs["crl_extensions"]):
            if extension["extn_id"].dotted == "2.5.29.20":
                self.assertTrue(extension["extn_value"].native == 2)
        self.assertTrue(len(tbs["revoked_certificates"]) == 1)

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(new_key_label))

    def test_add_serial_crl(self) -> None:
        """
        Create and sign a CRL with the key_label in the pkcs11 device.
        """

        # Revoke first
        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))
        crl_pem1 = asyncio.run(crl.create(new_key_label, subject_name, serial_number=2342342342343456, reason=3))
        data = crl_pem1.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_crl = asn1_crl.CertificateList.load(data)
        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))
        self.assertTrue(len(test_crl["tbs_cert_list"]["revoked_certificates"]) == 1)

        # Revoke second
        crl_pem2 = asyncio.run(
            crl.create(
                new_key_label,
                subject_name,
                old_crl_pem=crl_pem1,
                serial_number=2342348342341456,
                reason=2,
            )
        )
        data = crl_pem2.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_crl = asn1_crl.CertificateList.load(data)
        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))
        self.assertTrue(len(test_crl["tbs_cert_list"]["revoked_certificates"]) == 2)

        # Revoke third
        crl_pem3 = asyncio.run(
            crl.create(
                new_key_label,
                subject_name,
                old_crl_pem=crl_pem2,
                serial_number=2342342342341457,
                reason=2,
            )
        )
        data = crl_pem3.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_crl = asn1_crl.CertificateList.load(data)
        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))
        self.assertTrue(len(test_crl["tbs_cert_list"]["revoked_certificates"]) == 3)

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(new_key_label))

    def test_aki(self) -> None:
        """
        Create and sign a CRL with AKI.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))
        _, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label))
        crl_pem1 = asyncio.run(crl.create(new_key_label, subject_name))
        data = crl_pem1.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_crl = asn1_crl.CertificateList.load(data)
        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))

        tbs = test_crl["tbs_cert_list"]

        # AKI
        found = False
        for _, extension in enumerate(tbs["crl_extensions"]):
            if extension["extn_id"].dotted == "2.5.29.35":
                self.assertTrue(extension["extn_value"].native["key_identifier"] == identifier)
                found = True
        self.assertTrue(found)

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(new_key_label))

    def test_next_update_this_update(self) -> None:
        """
        Create and sign a CRL with next_update and/or this_update.
        """

        # Both
        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        next_update = datetime.datetime(2022, 1, 1, tzinfo=datetime.timezone.utc)
        this_update = datetime.datetime(2022, 1, 3, tzinfo=datetime.timezone.utc)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))
        crl_pem = asyncio.run(crl.create(new_key_label, subject_name, next_update=next_update, this_update=this_update))
        data = crl_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_crl = asn1_crl.CertificateList.load(data)
        tbs = test_crl["tbs_cert_list"]
        self.assertTrue(tbs["next_update"].native == next_update)
        self.assertTrue(tbs["this_update"].native == this_update)
        self.assertTrue(tbs["next_update"].native != tbs["this_update"].native)

        # Only next_update
        crl_pem = asyncio.run(crl.create(new_key_label, subject_name, next_update=next_update))
        data = crl_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_crl = asn1_crl.CertificateList.load(data)
        tbs = test_crl["tbs_cert_list"]
        self.assertTrue(tbs["next_update"].native == next_update)
        self.assertTrue(tbs["this_update"].native != this_update)
        self.assertTrue(tbs["next_update"].native != tbs["this_update"].native)

        # Only this_update
        crl_pem = asyncio.run(crl.create(new_key_label, subject_name, this_update=this_update))
        data = crl_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_crl = asn1_crl.CertificateList.load(data)
        tbs = test_crl["tbs_cert_list"]
        self.assertTrue(tbs["next_update"].native != next_update)
        self.assertTrue(tbs["this_update"].native == this_update)
        self.assertTrue(tbs["next_update"].native != tbs["this_update"].native)

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(new_key_label))
