"""
Test to create and sign a crl

# Remeber to set PKCS11 env variables
export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_TOKEN='my_test_token_1'
export PKCS11_PIN='1234'

# Delete a previous pkcs11 token if exists
softhsm2-util --delete-token --token my_test_token_1

# Create a new pkcs11 token
softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN

"""
import unittest
from asn1crypto import crl as asn1_crl
from asn1crypto import pem as asn1_pem

import python_x509_pkcs11.crl as crl
from python_x509_pkcs11.PKCS11Handle import PKCS11Session

class TestCrl(unittest.TestCase):
    """
    Test our crl module.
    """
    def test_create_crl(self) -> None:
        """
        Create and sign a CRL with the key with the key_label in the pkcs11 device.
        """

        subject_name = {"country_name": "SE",
                        "state_or_province_name": "Stockholm",
                        "locality_name": "Stockholm",
                        "organizational_unit_name": "SUNET Infrastructure",
                        "organization_name": "SUNET",
                        "common_name": "ca-test.sunet.se",
                        "email_address": "soc@sunet.se"}

        PKCS11Session.create_keypair_if_not_exists(4096, "test_3")

        crl_pem = crl.create("test_3", subject_name)

        data = crl_pem.encode('utf-8')
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_crl = asn1_crl.CertificateList.load(data)

        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))
