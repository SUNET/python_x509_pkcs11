"""
Test our PKCS11 session handler

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
import os

from src.python_x509_pkcs11.pkcs11_handle import PKCS11Session


class TestPKCS11Handle(unittest.TestCase):
    """
    Test our PKCS11 session handler.
    """
    def test_create_keypair(self
                            ) -> None:
        """
        Create keypair with key_label in the PKCS11 device.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        PKCS11Session.create_keypair(new_key_label, 4096)
        identifier = PKCS11Session.key_identifier(new_key_label)

        self.assertTrue(isinstance(identifier, bytes))

    def test_create_keypair_if_not_exists(self
                                          ) -> None:
        """
        Create keypair with key_label in the PKCS11 device.
        """

        PKCS11Session.create_keypair_if_not_exists("test_4", 4096)
        identifier = PKCS11Session.key_identifier("test_4")

        self.assertTrue(isinstance(identifier, bytes))

    def test_get_identifier(self
                            ) -> None:
        """
        Get key identifier from public key with key_label in the PKCS11 device.
        """
        identifier = PKCS11Session.key_identifier("test_4")

        self.assertTrue(isinstance(identifier, bytes))

    def test_sign_data(self
                       ) -> None:
        """
        Sign bytes with key_label in the PKCS11 device.
        """

        data_to_be_signed = b'MY TEST DATA TO BE SIGNED HERE'
        signature = PKCS11Session.sign("test_4", data_to_be_signed)

        self.assertTrue(isinstance(signature, bytes))
