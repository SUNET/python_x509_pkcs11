"""
Test our PKCS11 session handler
"""
import unittest
import os
import asyncio

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

    def test_import_keypair(self) -> None:
        """Import keypair with key_label in the PKCS11 device.

        Generate pub and priv with
        openssl genrsa -out rsaprivkey.pem 2048
        openssl rsa -inform pem -in rsaprivkey.pem -outform der -out PrivateKey.der
        openssl rsa -in rsaprivkey.pem -RSAPublicKey_out -outform DER -out PublicKey.der
        """

        pub = b"0\x82\x01\n\x02\x82\x01\x01\x00\xd9\xb6C,O\xc0\x83\xca\xa5\xcc\xa7<_\xbf$\xdd-YJ0m\xbf\xa8\xf9[\xe7\xcb\x14W6G\n\x13__\xea\xb4Z\xab2\x01\x0f\xa4\xd3\x1c\xbb\xa6\x98\x9d\xcdf\xaa\x07\xcb\xff\xd8\x80\xa9\\\xa1\xf44\x01\xdbY\xa6\xcf\x83\xd2\x83Z\x8a<\xc1\x18\xe5\x8d\xff\xbfzU\x03\x01\x11\xa1\xa1\x98\xcf\xcaVu\xf9\xf3\xa7+ \xe7N9\x07\xfd\xc6\xd0\x7f\xa0\xba&\xef\xb2a\xc6\xa5d\x1c\x93\xe6\xc3\x80\xd1*;\xc8@7\x0fm)\xf93\xe4\x1f\x91\xf4=\xa6\xf8\xed\x9cN\x84\x9b\xf2\xc5\x9f\x9f\x82E\xa5Tm\xb9\xb3:T\xc7_\xb1^[\xf4\x0b\xd8\x0b\xd2\xfb\xe1\x13\x1e,L\xd9\xdc\xed]_#\xca\xa0r\xc2\xc5F \xec\xae\x8d\x08v\x059\x062\xe1\xf7%\x9e\xfd\xfb9\x11(\xa4\x86v\x90\x01\x1c\xbeP\x04\xa3%\x91\x08\xc5\xd5\xc1U\xf6\xd3\x7f\x1f\x9f7`\xce\xc9\xa1\xd9\x8f\\Z\xa8\x1cmz\x19x\xa4'F\xdf\xb2\xb2\x87\xba\xf7\n>]\x9f\xc0K@\xd9\xdb\x02\x03\x01\x00\x01"

        priv = b"0\x82\x04\xa4\x02\x01\x00\x02\x82\x01\x01\x00\xd9\xb6C,O\xc0\x83\xca\xa5\xcc\xa7<_\xbf$\xdd-YJ0m\xbf\xa8\xf9[\xe7\xcb\x14W6G\n\x13__\xea\xb4Z\xab2\x01\x0f\xa4\xd3\x1c\xbb\xa6\x98\x9d\xcdf\xaa\x07\xcb\xff\xd8\x80\xa9\\\xa1\xf44\x01\xdbY\xa6\xcf\x83\xd2\x83Z\x8a<\xc1\x18\xe5\x8d\xff\xbfzU\x03\x01\x11\xa1\xa1\x98\xcf\xcaVu\xf9\xf3\xa7+ \xe7N9\x07\xfd\xc6\xd0\x7f\xa0\xba&\xef\xb2a\xc6\xa5d\x1c\x93\xe6\xc3\x80\xd1*;\xc8@7\x0fm)\xf93\xe4\x1f\x91\xf4=\xa6\xf8\xed\x9cN\x84\x9b\xf2\xc5\x9f\x9f\x82E\xa5Tm\xb9\xb3:T\xc7_\xb1^[\xf4\x0b\xd8\x0b\xd2\xfb\xe1\x13\x1e,L\xd9\xdc\xed]_#\xca\xa0r\xc2\xc5F \xec\xae\x8d\x08v\x059\x062\xe1\xf7%\x9e\xfd\xfb9\x11(\xa4\x86v\x90\x01\x1c\xbeP\x04\xa3%\x91\x08\xc5\xd5\xc1U\xf6\xd3\x7f\x1f\x9f7`\xce\xc9\xa1\xd9\x8f\\Z\xa8\x1cmz\x19x\xa4'F\xdf\xb2\xb2\x87\xba\xf7\n>]\x9f\xc0K@\xd9\xdb\x02\x03\x01\x00\x01\x02\x82\x01\x00a5\x1e=\x14\xc6\xf2\x91s\x023\xd1\xa36\xa7q\x12$\x82\x19\xa9\x87 \x1df\xc9\xd2E\x1c\xc3\xa1h\x80I\xdf{\xdeWu\x84\xf80Q\xf9\xe9$h8P\x8d;\xbf\xc3\x87t\x8e\xe8\xb3\xb6&\xa1\xf0\xee\xbbP\x06I5\xa4\xb2\xfd\xa4'\x88Xcv\xc9\xb0g \xba\x1c\xaa\x10\xaf$\x99\xf2\xd04\x11\x0c\x97\xa1\x8c){%\xbf\xc9\xb2\x11\xbaJ\xbb\x93S\x07$\xdd\x1bO\xdd\xea\xb3\xe8\xab\x05\xb9\x83\xc3\xdf\xd85\xcd\x1a%\xd5\xd9\xc4\x933\x83\t\xd3\xea\xcdb\xcb\xec\x9eGqk\x1c\x8c\x06\x8a\\\xae\xbe\xd3+\x0b\xd0R\xbd:\x8a\xf5\xf4\x0f\x0b\xd4\xfa@P=\xe5\xb2\xa1\xb2\x01\x00\x08\xc7\x11?M\x84-\x1e\xbc\xa9\xbf|\x87\x98\xd7\x0e\xf6\xa9\xa6\xcd\x8c8\xa5F8\xacM\x82\xade[\xa9_\xa7Biv\x9c\x06\xa6\x001\xc3I\x1f\xc4\x9by\xd7\xe0\x9e\xb9\n\xbb\x19\\o\xc5i\xd90r\xd4\x1e(\x05\xdd\xedF\xe9\xaa\xbd\x91\xe5\x08\x8f4-\xb6\xd1Q\x02\x81\x81\x00\xf7\x076\xd8i\x87\x12\xf1\xd0$\x07\x1f\xab\xb7^\x0e\xa5\xfb\x83\x98\x00\x0b\\\x1d\xe8s\x15r\x96/\x0e\x0ezB\xc8\xf6\xf3Zmj?\xa0\xc1\x11r\xaf3\x11a\xcd\xa3\xfc\xa0\x03\x04E\x05\x99\x9a\xd9\xff\x8e+\xdcfM\xa8\xe8&\x84\x85\xc5\x11O\x9d4\x1f\xc3\x1f\xef\xed\x13BW\xaa\x93\xc3\x08(v]\xbc\x93V\xb6s\xce\xb1\xa8\xe2\x94\xa5'\xf3\x7f\x90,G[\xfeI\x16\xbe\xb0\xf8J\xca9n\xb5\xfc\x8a\xe2[\xc5\x0c\x95\xd5\x02\x81\x81\x00\xe1\x9ey\xc8\xe2\xd3\x93\xa2nj\xe1.\xaa\xe3\xa7\xf5P\xd1\xd8yM\x01\xdc\x01\x0c\xdbQG\x1b=\xbe\xe4.\x9cM\xc2\xda\xd2\xa4\xb3\x80\xb2\xbd\xbaO\x1bD&]0\x0b\xe6\xf5\x08\xdb*I\xfe+@Aa\x16;\x9a%\x8cof:\x156 \xb0\xe6\xfe\x95\x9bO\x85]\x96\x94S\x05\xc8\x8a\xb6\x92\xb3\x95\xc5\xfbX\xa9S<@\x12\x94K\x8b\xa3\x0f\xebO\xb5\x9f\x0c\x08\xf2\xccS\xfd8\x06\xeb\xaa\x96_\xadm&L~!\x18\xef\x02\x81\x80@.\x04\xa6\xd7K\xfb\xb5\r\xb1\xbe\x94\x10\xe6\x14.\xd4\x1a\xf3\x86\x93D`Kx\xf0%{^\xdf\x9c\xd4P\x19w\xe3\t8\xceB\x93\x83m\x85\xdd\xf8\xfc\xd8\xa0Cp>\x9bH\r\\\xedf\x8a\x1f\xe7P\x85\xbe\xbei\xa0\xdf\xa7\xda8s\t\xdbXi\x89s\x05\xa2-C\x1a\xb2r#\xef\xc0\xf7\xda@\xe2T\x99k\xcf\xcc\xbc\xc5\xb7\x10\x8d\x94B\xa4:\xcd\xf6@Ea\xb1\xe2\x1bRw\x03\xf1E\xfdL>\xbd.\xc0\x94S}\x02\x81\x81\x00\xa2\xce\x13}EH}a\x19\xa2`I\xa7\xa0\xcdc4\xe5\xa7\xfa\xa7\xf9\xee\x82\x87\x7f\x7f\x1f\xfbeK\xe9&E=\xcb\x9c\xd1\xa1m\xb21\xc8\xbc\xb76\xaa\xaf\xb0P\xeaU\xc7}\x93\x80\xe9\x91\xd2-\xf4\xbf\x95&\x7f.\x17/\x8f\xa9\xdc\x02\x8a\x06}9:E\xafUBZU?\xaf\x8d\xad\xa2\xdf+]\xa9V\x9c\xfc\xda\x86@\x89\xe7\x9e\xb7\xed{\xa0F\x8d}nV\xca\xb5l\xe9\xedR\xf9\x1d\xc8\x92\xd3\xf7NJ\xa6=E\xdb\x02\x81\x81\x00\xf5\xa8\xec\x00k\x18\x10KK\xd0D\xa9\xeb\x87==X\xa2\xaa)\xeb\x92\xfa\xf8f\xa6W\xaa\x94\x92\xa1F\t\xc1\x01\xd8%-\x1f\xb71\xefg\x95q\xb3\xa5J[k\xe3\x17\xac\xfd\xbfU\x02\x95\xa4\xf9\xcd\x80!E\x9d\x7f\x9c\xcd\x89uV\x1df\xee\xab\xd3\x1f7$&\x014\xd2\xdd\xc2\xe4?\x1bh*\xb6\x00\x1a\x1fz^\xbc\x97\xde\x9cK\xc8\xf5\xcf0\"\x8c\x8bm\xecUv\xefu\xd9YD\x05\xe8?9J\x8c\x18\x90\x0e\xc4\x88"

        imported_key_label = "imported_keypair_label"

        signature_val = b"\xd4\x94'N(\x1c\x16\xc11\xf0#\xe0\xb0\x0b\xc4L[D\xed6<-\xb53\xa0\x9fm\xdd\xfd_\xd7\xb5\xbe]KAu\xb5\x99\x11z@-6/-\xc9_\xde\x05\xba\xb6\x81\xad|\x95\xd8*\xc4\xa4<\xcfE\xaaE\x922e\xa1\x81\xa6\xe9\x94:M\x17_\x0ba\xdd\x94|1\x15|;%z\xc2\x9c\xe4b\xf9\x06es@U\xcd\x83x\xb4\x08&\xb7\xc1\xe9\xc8\x04c\x7f\x9b\x0e\xff\xe3\xb68\xbd\xb6\x05\r\xe86\x17L\x1e\xeb\xd7R\xaf\xa2\x7fU\x8e]\x9e\x93\x8f\x17\xed\xa4\x15\xcb\xc5\x84)\xe0\xec\xbe\x90\xba\x1d0jgEY^r\xe8\x18{Q\n\xab\xfe\xf9\xb3#R*8\xc8\x06\xdb\x81\xaf\xd1q\n\xef~S\x9d\xb0\x1f\n\x81@}\xba\xdcL?\xf9\"\xddN|\xb9\x828\x96\x89P\x92&$O\x16P\xbe\xd7\x06\xcc\xd5*P\xcd\x92\x82\xc2\xcf\x94\xf0\x1e\xe3\xc1\xd6\xf9\x1b\xccE!tE\x87\x05o'|\xab\x9b!5ua\xed\xe0\x7f\x15\xc8t;.\xf5"

        pk_info, identifier = asyncio.run(
            PKCS11Session.import_keypair(imported_key_label, pub, priv)
        )
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(identifier == b'\xf0c\xd5\xe2X\xdc\x19@\xa2\xbc#\x13\x0c_\xaae\x16\xde"f')
        self.assertTrue(isinstance(pk_info, PublicKeyInfo))

        self.assertTrue(imported_key_label in asyncio.run(PKCS11Session.key_labels()))
        with self.assertRaises(MultipleObjectsReturned):
            pk_info, identifier = asyncio.run(
                PKCS11Session.import_keypair(imported_key_label, pub, priv)
            )

        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"
        signature = asyncio.run(PKCS11Session.sign(imported_key_label, data_to_be_signed))
        self.assertTrue(isinstance(signature, bytes))
        self.assertTrue(signature == signature_val)
        self.assertTrue(
            asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature))
        )
        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE"
                )
            )
        )

    def test_create_keypair(self) -> None:
        """Create keypair with key_label in the PKCS11 device."""

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label, 2048))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label))
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(isinstance(pk_info, PublicKeyInfo))

        with self.assertRaises(MultipleObjectsReturned):
            asyncio.run(PKCS11Session.create_keypair(new_key_label, 2048))
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label))

        asyncio.run(PKCS11Session.create_keypair(new_key_label[:-1], 2048))
        pk_info2, identifier2 = asyncio.run(PKCS11Session.public_key_data(new_key_label[:-1]))
        self.assertTrue(isinstance(identifier2, bytes))
        self.assertTrue(isinstance(pk_info2, PublicKeyInfo))

        self.assertTrue(identifier != identifier2)
        self.assertTrue(pk_info.native != pk_info2.native)

        asyncio.run(PKCS11Session.create_keypair(new_key_label[:-2], 4096))
        pk_info2, identifier2 = asyncio.run(PKCS11Session.public_key_data(new_key_label[:-2]))
        self.assertTrue(isinstance(identifier2, bytes))
        self.assertTrue(isinstance(pk_info2, PublicKeyInfo))

        # Test key_labels
        pk_info3, identifier3 = asyncio.run(PKCS11Session.create_keypair(new_key_label[:-3], 4096))
        key_labels = asyncio.run(PKCS11Session.key_labels())
        self.assertTrue(isinstance(key_labels, list))
        self.assertTrue(len(key_labels) > 0)
        for label in key_labels:
            self.assertTrue(isinstance(label, str))
        self.assertTrue(new_key_label[:-3] in key_labels)
        self.assertFalse("should_not_exists_1232353523" in key_labels)

        pk_info3_1, identifier3_1 = asyncio.run(PKCS11Session.public_key_data(new_key_label[:-3]))
        self.assertTrue(pk_info3.dump() == pk_info3_1.dump())
        self.assertTrue(identifier3 == identifier3_1)

    def test_get_public_key_data(self) -> None:
        """
        Get key identifier from public key with key_label in the PKCS11 device.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label))
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(isinstance(pk_info, PublicKeyInfo))

        with self.assertRaises(NoSuchKey):
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label[:-2]))

    def test_sign_and_verify_data(self) -> None:
        """
        Sign bytes with key_label in the PKCS11 device.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))
        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"

        signature = asyncio.run(PKCS11Session.sign(new_key_label, data_to_be_signed))
        self.assertTrue(isinstance(signature, bytes))

        signature = asyncio.run(
            PKCS11Session.sign(new_key_label, data_to_be_signed, Mechanism.SHA512_RSA_PKCS)
        )
        self.assertTrue(isinstance(signature, bytes))

        self.assertTrue(
            asyncio.run(PKCS11Session.verify(new_key_label, data_to_be_signed, signature))
        )

        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(new_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE")
            )
        )

        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    new_key_label,
                    data_to_be_signed,
                    b"NOT VALID SIGNATURE HERE",
                    Mechanism.SHA512_RSA_PKCS,
                )
            )
        )

        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    new_key_label, data_to_be_signed, signature, Mechanism.SHA512_RSA_PKCS
                )
            )
        )
