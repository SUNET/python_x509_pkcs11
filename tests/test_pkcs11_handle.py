"""
Test our PKCS11 session handler
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

    def test_key_labels(self) -> None:
        """Create keypair with key_label in the PKCS11 device."""

        PKCS11Session.key_labels()

    def test_create_keypair(self) -> None:
        """
        Create keypair with key_label in the PKCS11 device.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        PKCS11Session.create_keypair(new_key_label, 2048)
        pk_info, identifier = PKCS11Session.public_key_data(new_key_label)
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(isinstance(pk_info, PublicKeyInfo))

        with self.assertRaises(MultipleObjectsReturned):
            PKCS11Session.create_keypair(new_key_label, 2048)
            pk_info, identifier = PKCS11Session.public_key_data(new_key_label)

        PKCS11Session.create_keypair(new_key_label[:-1], 2048)
        pk_info2, identifier2 = PKCS11Session.public_key_data(new_key_label[:-1])
        self.assertTrue(isinstance(identifier2, bytes))
        self.assertTrue(isinstance(pk_info2, PublicKeyInfo))

        self.assertTrue(identifier != identifier2)
        self.assertTrue(pk_info.native != pk_info2.native)

        PKCS11Session.create_keypair(new_key_label[:-2], 4096)
        pk_info2, identifier2 = PKCS11Session.public_key_data(new_key_label[:-2])
        self.assertTrue(isinstance(identifier2, bytes))
        self.assertTrue(isinstance(pk_info2, PublicKeyInfo))

        # Test key_labels
        PKCS11Session.create_keypair(new_key_label[:-3], 4096)
        pk_info3, identifier3 = PKCS11Session.public_key_data(new_key_label[:-3])
        key_labels = PKCS11Session.key_labels()
        self.assertTrue(isinstance(key_labels, list))
        for label in key_labels:
            self.assertTrue(isinstance(label, str))
        self.assertTrue(new_key_label[:-3] in key_labels)
        self.assertFalse("should_not_exists_1232353523" in key_labels)
        pk_info3_1, identifier3_1 = PKCS11Session.public_key_data(new_key_label[:-3])
        self.assertTrue(pk_info3.dump() == pk_info3_1.dump())
        self.assertTrue(identifier3 == identifier3_1)

    def test_get_public_key_data(self) -> None:
        """
        Get key identifier from public key with key_label in the PKCS11 device.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        PKCS11Session.create_keypair(new_key_label)
        pk_info, identifier = PKCS11Session.public_key_data(new_key_label)
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(isinstance(pk_info, PublicKeyInfo))

        with self.assertRaises(NoSuchKey):
            pk_info, identifier = PKCS11Session.public_key_data(new_key_label[:-2])

    def test_sign_and_verify_data(self) -> None:
        """
        Sign bytes with key_label in the PKCS11 device.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        PKCS11Session.create_keypair(new_key_label)
        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"

        signature = PKCS11Session.sign(new_key_label, data_to_be_signed)
        self.assertTrue(isinstance(signature, bytes))

        signature = PKCS11Session.sign(new_key_label, data_to_be_signed, Mechanism.SHA512_RSA_PKCS)
        self.assertTrue(isinstance(signature, bytes))

        self.assertTrue(PKCS11Session.verify(new_key_label, data_to_be_signed, signature))

        self.assertFalse(
            PKCS11Session.verify(new_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE")
        )

        self.assertFalse(
            PKCS11Session.verify(
                new_key_label,
                data_to_be_signed,
                b"NOT VALID SIGNATURE HERE",
                Mechanism.SHA512_RSA_PKCS,
            )
        )

        self.assertFalse(
            PKCS11Session.verify(
                new_key_label, data_to_be_signed, signature, Mechanism.SHA512_RSA_PKCS
            )
        )
