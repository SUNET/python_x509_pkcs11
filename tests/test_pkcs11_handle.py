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

from pkcs11 import Mechanism
from pkcs11.exceptions import NoSuchKey, MultipleObjectsReturned
from asn1crypto.keys import PublicKeyInfo

from src.python_x509_pkcs11.pkcs11_handle import PKCS11Session

# Replace the above with this should you use this code
# from python_x509_pkcs11.pkcs11_handle import PKCS11Session


class TestPKCS11Handle(unittest.TestCase):
    """
    Test our PKCS11 session handler.
    """

    def test_create_keypair(self) -> None:
        """
        Create keypair with key_label in the PKCS11 device.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        PKCS11Session.create_keypair(new_key_label, 4096, False)
        pk_info, identifier = PKCS11Session.public_key_data(new_key_label)
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(isinstance(pk_info, PublicKeyInfo))

        with self.assertRaises(MultipleObjectsReturned):
            PKCS11Session.create_keypair(new_key_label, 4096, False)
            pk_info, identifier = PKCS11Session.public_key_data(new_key_label)

    def test_get_public_key_data(self) -> None:
        """
        Get key identifier from public key with key_label in the PKCS11 device.
        """
        PKCS11Session.create_keypair("test_4", 4096)
        pk_info, identifier = PKCS11Session.public_key_data("test_4")
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(isinstance(pk_info, PublicKeyInfo))

        with self.assertRaises(NoSuchKey):
            pk_info, identifier = PKCS11Session.public_key_data("test_4"[:-2])

    def test_sign_and_verify_data(self) -> None:
        """
        Sign bytes with key_label in the PKCS11 device.
        """

        PKCS11Session.create_keypair("test_4", 4096)
        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"

        signature = PKCS11Session.sign("test_4", data_to_be_signed)
        self.assertTrue(isinstance(signature, bytes))

        signature = PKCS11Session.sign(
            "test_4", data_to_be_signed, Mechanism.SHA512_RSA_PKCS
        )
        self.assertTrue(isinstance(signature, bytes))

        self.assertTrue(PKCS11Session.verify("test_4", data_to_be_signed, signature))

        self.assertFalse(
            PKCS11Session.verify(
                "test_4", data_to_be_signed, b"NOT VALID SIGNATURE HERE"
            )
        )

        self.assertFalse(
            PKCS11Session.verify(
                "test_4",
                data_to_be_signed,
                b"NOT VALID SIGNATURE HERE",
                Mechanism.SHA512_RSA_PKCS,
            )
        )

        self.assertFalse(
            PKCS11Session.verify(
                "test_4", data_to_be_signed, signature, Mechanism.SHA512_RSA_PKCS
            )
        )
