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
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem

from src.python_x509_pkcs11.root_ca import create
from src.python_x509_pkcs11.pkcs11_handle import PKCS11Session


class TestRootCa(unittest.TestCase):
    """
    Test our root ca module.
    """
    def test_create_root_ca(self
                            ) -> asn1_x509.Certificate:
        """
        Create and selfsign a CSR with the key_label in the pkcs11 device.
        """
        name_dict = {"country_name": "SE",
                     "state_or_province_name": "Stockholm",
                     "locality_name": "Stockholm",
                     "organization_name": "SUNET",
                     "organizational_unit_name": "SUNET Infrastructure",
                     "common_name": "ca-test.sunet.se",
                     "email_address": "soc@sunet.se"}

        PKCS11Session.create_keypair_if_not_exists("test_3", 4096)
        root_cert_pem = create("test_3", 4096, name_dict)

        data = root_cert_pem.encode('utf-8')
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)

        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))
