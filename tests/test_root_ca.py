"""
Test to create a new root CA

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
import datetime
import os

from asn1crypto.core import GeneralizedTime
from asn1crypto import x509 as asn1_x509
from asn1crypto import csr as asn1_csr
from asn1crypto import pem as asn1_pem

from src.python_x509_pkcs11.root_ca import create

# Replace the above with this should you use this code
# from python_x509_pkcs11.root_ca import create

name_dict = {
    "country_name": "SE",
    "state_or_province_name": "Stockholm",
    "locality_name": "Stockholm",
    "organization_name": "SUNET",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test.sunet.se",
    "email_address": "soc@sunet.se",
}

new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)


class TestRootCa(unittest.TestCase):
    """
    Test our root ca module.
    """

    def test_create_root_ca(self) -> None:
        """
        Create and selfsign a CSR with the key_label in the pkcs11 device.
        """

        root_cert_pem = create(new_key_label[:-1], 4096, name_dict)

        data = root_cert_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))

        cert_exts = test_cert["tbs_certificate"]["extensions"]
        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))
        # CSR exts (key usage and basic constraints
        # + authority and subject key identifier = 4
        self.assertTrue(len(cert_exts) == 4)

    def test_create_root_ca_with_extensions(self) -> None:
        """
        Create and selfsign a CSR with the key_label in the pkcs11 device.
        """

        exts = asn1_csr.Extensions()

        pkup = asn1_x509.PrivateKeyUsagePeriod()
        pkup["not_before"] = GeneralizedTime(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(2)
        )
        pkup["not_after"] = GeneralizedTime(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(365 * 10, 0, 0)
        )

        ext = asn1_x509.Extension()
        ext["extn_id"] = asn1_x509.ExtensionId("2.5.29.16")
        ext["critical"] = False
        ext["extn_value"] = pkup
        exts.append(ext)

        root_cert_pem = create(new_key_label[:-2], 4096, name_dict, exts)

        data = root_cert_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)

        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))

        test_cert = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))

        cert_exts = test_cert["tbs_certificate"]["extensions"]
        # test pkup ext + CSR exts (key usage and basic constraints
        # + authority and subject key identifier = 5
        self.assertTrue(len(cert_exts) == 5)
