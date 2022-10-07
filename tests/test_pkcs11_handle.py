"""
Test our PKCS11 session handler
"""
import unittest
import os
import asyncio

from pkcs11 import Mechanism
from pkcs11.exceptions import NoSuchKey, MultipleObjectsReturned

from src.python_x509_pkcs11.pkcs11_handle import PKCS11Session

# Replace the above with this should you use this code
# from python_x509_pkcs11.pkcs11_handle import PKCS11Session


class TestPKCS11Handle(unittest.TestCase):
    """
    Test our PKCS11 session handler.
    """

    def test_import_keypair_rsa(self) -> None:
        """Import keypair with key_label in the PKCS11 device.

        Generate pub and priv with
        openssl genrsa -out rsaprivkey.pem 2048
        openssl rsa -inform pem -in rsaprivkey.pem -outform der -out PrivateKey.der
        openssl rsa -in rsaprivkey.pem -RSAPublicKey_out -outform DER -out PublicKey.der
        """

        pub = b"0\x82\x01\n\x02\x82\x01\x01\x00\xd9\xb6C,O\xc0\x83\xca\xa5\xcc\xa7<_\xbf$\xdd-YJ0m\xbf\xa8\xf9[\xe7\xcb\x14W6G\n\x13__\xea\xb4Z\xab2\x01\x0f\xa4\xd3\x1c\xbb\xa6\x98\x9d\xcdf\xaa\x07\xcb\xff\xd8\x80\xa9\\\xa1\xf44\x01\xdbY\xa6\xcf\x83\xd2\x83Z\x8a<\xc1\x18\xe5\x8d\xff\xbfzU\x03\x01\x11\xa1\xa1\x98\xcf\xcaVu\xf9\xf3\xa7+ \xe7N9\x07\xfd\xc6\xd0\x7f\xa0\xba&\xef\xb2a\xc6\xa5d\x1c\x93\xe6\xc3\x80\xd1*;\xc8@7\x0fm)\xf93\xe4\x1f\x91\xf4=\xa6\xf8\xed\x9cN\x84\x9b\xf2\xc5\x9f\x9f\x82E\xa5Tm\xb9\xb3:T\xc7_\xb1^[\xf4\x0b\xd8\x0b\xd2\xfb\xe1\x13\x1e,L\xd9\xdc\xed]_#\xca\xa0r\xc2\xc5F \xec\xae\x8d\x08v\x059\x062\xe1\xf7%\x9e\xfd\xfb9\x11(\xa4\x86v\x90\x01\x1c\xbeP\x04\xa3%\x91\x08\xc5\xd5\xc1U\xf6\xd3\x7f\x1f\x9f7`\xce\xc9\xa1\xd9\x8f\\Z\xa8\x1cmz\x19x\xa4'F\xdf\xb2\xb2\x87\xba\xf7\n>]\x9f\xc0K@\xd9\xdb\x02\x03\x01\x00\x01"  # pylint: disable=C0301

        priv = b"0\x82\x04\xa4\x02\x01\x00\x02\x82\x01\x01\x00\xd9\xb6C,O\xc0\x83\xca\xa5\xcc\xa7<_\xbf$\xdd-YJ0m\xbf\xa8\xf9[\xe7\xcb\x14W6G\n\x13__\xea\xb4Z\xab2\x01\x0f\xa4\xd3\x1c\xbb\xa6\x98\x9d\xcdf\xaa\x07\xcb\xff\xd8\x80\xa9\\\xa1\xf44\x01\xdbY\xa6\xcf\x83\xd2\x83Z\x8a<\xc1\x18\xe5\x8d\xff\xbfzU\x03\x01\x11\xa1\xa1\x98\xcf\xcaVu\xf9\xf3\xa7+ \xe7N9\x07\xfd\xc6\xd0\x7f\xa0\xba&\xef\xb2a\xc6\xa5d\x1c\x93\xe6\xc3\x80\xd1*;\xc8@7\x0fm)\xf93\xe4\x1f\x91\xf4=\xa6\xf8\xed\x9cN\x84\x9b\xf2\xc5\x9f\x9f\x82E\xa5Tm\xb9\xb3:T\xc7_\xb1^[\xf4\x0b\xd8\x0b\xd2\xfb\xe1\x13\x1e,L\xd9\xdc\xed]_#\xca\xa0r\xc2\xc5F \xec\xae\x8d\x08v\x059\x062\xe1\xf7%\x9e\xfd\xfb9\x11(\xa4\x86v\x90\x01\x1c\xbeP\x04\xa3%\x91\x08\xc5\xd5\xc1U\xf6\xd3\x7f\x1f\x9f7`\xce\xc9\xa1\xd9\x8f\\Z\xa8\x1cmz\x19x\xa4'F\xdf\xb2\xb2\x87\xba\xf7\n>]\x9f\xc0K@\xd9\xdb\x02\x03\x01\x00\x01\x02\x82\x01\x00a5\x1e=\x14\xc6\xf2\x91s\x023\xd1\xa36\xa7q\x12$\x82\x19\xa9\x87 \x1df\xc9\xd2E\x1c\xc3\xa1h\x80I\xdf{\xdeWu\x84\xf80Q\xf9\xe9$h8P\x8d;\xbf\xc3\x87t\x8e\xe8\xb3\xb6&\xa1\xf0\xee\xbbP\x06I5\xa4\xb2\xfd\xa4'\x88Xcv\xc9\xb0g \xba\x1c\xaa\x10\xaf$\x99\xf2\xd04\x11\x0c\x97\xa1\x8c){%\xbf\xc9\xb2\x11\xbaJ\xbb\x93S\x07$\xdd\x1bO\xdd\xea\xb3\xe8\xab\x05\xb9\x83\xc3\xdf\xd85\xcd\x1a%\xd5\xd9\xc4\x933\x83\t\xd3\xea\xcdb\xcb\xec\x9eGqk\x1c\x8c\x06\x8a\\\xae\xbe\xd3+\x0b\xd0R\xbd:\x8a\xf5\xf4\x0f\x0b\xd4\xfa@P=\xe5\xb2\xa1\xb2\x01\x00\x08\xc7\x11?M\x84-\x1e\xbc\xa9\xbf|\x87\x98\xd7\x0e\xf6\xa9\xa6\xcd\x8c8\xa5F8\xacM\x82\xade[\xa9_\xa7Biv\x9c\x06\xa6\x001\xc3I\x1f\xc4\x9by\xd7\xe0\x9e\xb9\n\xbb\x19\\o\xc5i\xd90r\xd4\x1e(\x05\xdd\xedF\xe9\xaa\xbd\x91\xe5\x08\x8f4-\xb6\xd1Q\x02\x81\x81\x00\xf7\x076\xd8i\x87\x12\xf1\xd0$\x07\x1f\xab\xb7^\x0e\xa5\xfb\x83\x98\x00\x0b\\\x1d\xe8s\x15r\x96/\x0e\x0ezB\xc8\xf6\xf3Zmj?\xa0\xc1\x11r\xaf3\x11a\xcd\xa3\xfc\xa0\x03\x04E\x05\x99\x9a\xd9\xff\x8e+\xdcfM\xa8\xe8&\x84\x85\xc5\x11O\x9d4\x1f\xc3\x1f\xef\xed\x13BW\xaa\x93\xc3\x08(v]\xbc\x93V\xb6s\xce\xb1\xa8\xe2\x94\xa5'\xf3\x7f\x90,G[\xfeI\x16\xbe\xb0\xf8J\xca9n\xb5\xfc\x8a\xe2[\xc5\x0c\x95\xd5\x02\x81\x81\x00\xe1\x9ey\xc8\xe2\xd3\x93\xa2nj\xe1.\xaa\xe3\xa7\xf5P\xd1\xd8yM\x01\xdc\x01\x0c\xdbQG\x1b=\xbe\xe4.\x9cM\xc2\xda\xd2\xa4\xb3\x80\xb2\xbd\xbaO\x1bD&]0\x0b\xe6\xf5\x08\xdb*I\xfe+@Aa\x16;\x9a%\x8cof:\x156 \xb0\xe6\xfe\x95\x9bO\x85]\x96\x94S\x05\xc8\x8a\xb6\x92\xb3\x95\xc5\xfbX\xa9S<@\x12\x94K\x8b\xa3\x0f\xebO\xb5\x9f\x0c\x08\xf2\xccS\xfd8\x06\xeb\xaa\x96_\xadm&L~!\x18\xef\x02\x81\x80@.\x04\xa6\xd7K\xfb\xb5\r\xb1\xbe\x94\x10\xe6\x14.\xd4\x1a\xf3\x86\x93D`Kx\xf0%{^\xdf\x9c\xd4P\x19w\xe3\t8\xceB\x93\x83m\x85\xdd\xf8\xfc\xd8\xa0Cp>\x9bH\r\\\xedf\x8a\x1f\xe7P\x85\xbe\xbei\xa0\xdf\xa7\xda8s\t\xdbXi\x89s\x05\xa2-C\x1a\xb2r#\xef\xc0\xf7\xda@\xe2T\x99k\xcf\xcc\xbc\xc5\xb7\x10\x8d\x94B\xa4:\xcd\xf6@Ea\xb1\xe2\x1bRw\x03\xf1E\xfdL>\xbd.\xc0\x94S}\x02\x81\x81\x00\xa2\xce\x13}EH}a\x19\xa2`I\xa7\xa0\xcdc4\xe5\xa7\xfa\xa7\xf9\xee\x82\x87\x7f\x7f\x1f\xfbeK\xe9&E=\xcb\x9c\xd1\xa1m\xb21\xc8\xbc\xb76\xaa\xaf\xb0P\xeaU\xc7}\x93\x80\xe9\x91\xd2-\xf4\xbf\x95&\x7f.\x17/\x8f\xa9\xdc\x02\x8a\x06}9:E\xafUBZU?\xaf\x8d\xad\xa2\xdf+]\xa9V\x9c\xfc\xda\x86@\x89\xe7\x9e\xb7\xed{\xa0F\x8d}nV\xca\xb5l\xe9\xedR\xf9\x1d\xc8\x92\xd3\xf7NJ\xa6=E\xdb\x02\x81\x81\x00\xf5\xa8\xec\x00k\x18\x10KK\xd0D\xa9\xeb\x87==X\xa2\xaa)\xeb\x92\xfa\xf8f\xa6W\xaa\x94\x92\xa1F\t\xc1\x01\xd8%-\x1f\xb71\xefg\x95q\xb3\xa5J[k\xe3\x17\xac\xfd\xbfU\x02\x95\xa4\xf9\xcd\x80!E\x9d\x7f\x9c\xcd\x89uV\x1df\xee\xab\xd3\x1f7$&\x014\xd2\xdd\xc2\xe4?\x1bh*\xb6\x00\x1a\x1fz^\xbc\x97\xde\x9cK\xc8\xf5\xcf0\"\x8c\x8bm\xecUv\xefu\xd9YD\x05\xe8?9J\x8c\x18\x90\x0e\xc4\x88"  # pylint: disable=C0301

        imported_key_label = "imported_keypair_label_RSA"

        signature_val = b"\xd4\x94'N(\x1c\x16\xc11\xf0#\xe0\xb0\x0b\xc4L[D\xed6<-\xb53\xa0\x9fm\xdd\xfd_\xd7\xb5\xbe]KAu\xb5\x99\x11z@-6/-\xc9_\xde\x05\xba\xb6\x81\xad|\x95\xd8*\xc4\xa4<\xcfE\xaaE\x922e\xa1\x81\xa6\xe9\x94:M\x17_\x0ba\xdd\x94|1\x15|;%z\xc2\x9c\xe4b\xf9\x06es@U\xcd\x83x\xb4\x08&\xb7\xc1\xe9\xc8\x04c\x7f\x9b\x0e\xff\xe3\xb68\xbd\xb6\x05\r\xe86\x17L\x1e\xeb\xd7R\xaf\xa2\x7fU\x8e]\x9e\x93\x8f\x17\xed\xa4\x15\xcb\xc5\x84)\xe0\xec\xbe\x90\xba\x1d0jgEY^r\xe8\x18{Q\n\xab\xfe\xf9\xb3#R*8\xc8\x06\xdb\x81\xaf\xd1q\n\xef~S\x9d\xb0\x1f\n\x81@}\xba\xdcL?\xf9\"\xddN|\xb9\x828\x96\x89P\x92&$O\x16P\xbe\xd7\x06\xcc\xd5*P\xcd\x92\x82\xc2\xcf\x94\xf0\x1e\xe3\xc1\xd6\xf9\x1b\xccE!tE\x87\x05o'|\xab\x9b!5ua\xed\xe0\x7f\x15\xc8t;.\xf5"  # pylint: disable=C0301

        asyncio.run(PKCS11Session.import_keypair(pub, priv, imported_key_label, key_type="rsa"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type="rsa"))

        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(identifier == b'\xf0c\xd5\xe2X\xdc\x19@\xa2\xbc#\x13\x0c_\xaae\x16\xde"f')
        self.assertTrue(isinstance(pk_info, str))

        self.assertTrue(imported_key_label in asyncio.run(PKCS11Session.key_labels()))
        with self.assertRaises(MultipleObjectsReturned):
            asyncio.run(PKCS11Session.import_keypair(pub, priv, imported_key_label, key_type="rsa"))

        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"
        signature = asyncio.run(PKCS11Session.sign(imported_key_label, data_to_be_signed, key_type="rsa"))
        self.assertTrue(isinstance(signature, bytes))
        self.assertTrue(signature == signature_val)
        self.assertTrue(
            asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature, key_type="rsa"))
        )
        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="rsa")
            )
        )

    def test_import_keypair_ed25519(self) -> None:
        """Import keypair with key_label in the PKCS11 device.

        Generate pub and priv with
        openssl genpkey -algorithm ed25519 -out private.pem
        openssl pkey -in private.pem -outform DER -out private.key
        openssl pkey -in private.pem -pubout -outform DER -out public.key
        """

        priv = b"0.\x02\x01\x000\x05\x06\x03+ep\x04\"\x04 ~n\xc3\xf5\x93\xb7\x1dYgO\x88\x90K\x9b\xe1&h\x0f\x0e@\xddh\xcc'\x98\xd2\xe7\xe7\xfb\x03T\xd1"  # pylint: disable=C0301
        pub = b"0*0\x05\x06\x03+ep\x03!\x00\x8b\x07J\x99[\xe4g\x9c\xd9\xfa'\x03\x9a\xb8\x01>&\x10\x1cay~\xadf\x80j\x9eq;\xb3\xf3\x9c"  # pylint: disable=C0301

        imported_key_label = "imported_keypair_label_ed25519"
        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)

        asyncio.run(PKCS11Session.create_keypair(new_key_label, key_type="ed25519"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label, "ed25519"))

        asyncio.run(PKCS11Session.import_keypair(pub, priv, imported_key_label, key_type="ed25519"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, "ed25519"))

        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(identifier == b"\xdc\xceO\\\xbe'\x84\xf5\x9b*\x84~;\x1e\xeciJ\xa8\xe3\xd4")
        self.assertTrue(isinstance(pk_info, str))

        self.assertTrue(imported_key_label in asyncio.run(PKCS11Session.key_labels()))
        self.assertTrue(asyncio.run(PKCS11Session.key_labels())[imported_key_label] == "ed25519")
        with self.assertRaises(MultipleObjectsReturned):
            asyncio.run(
                PKCS11Session.import_keypair(
                    pub,
                    priv,
                    imported_key_label,
                    key_type="ed25519",
                )
            )

        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"
        signature = asyncio.run(
            PKCS11Session.sign(imported_key_label, data_to_be_signed, verify_signature=True, key_type="ed25519")
        )
        self.assertTrue(isinstance(signature, bytes))
        self.assertTrue(
            signature
            == b"%\xf4\xadk\x08\xb5\xb4u\xc0Y&\x12\xad\xafn\xed\xd3WJ\x8d(\xb8\xbf\xcb\xc9\x19\xf3\x13\x0e\x9a\x89\xec\x8dk\xd7g;\xb5\xb1\x06;!\x12\xcbW\xcdsT\xce\x87\xe2\xf2\x97\x9eX\xb0i\xccn\xf7\x88\xcd`\r"  # pylint: disable=C0301
        )
        self.assertTrue(
            asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature, key_type="ed25519"))
        )
        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="ed25519"
                )
            )
        )
        with self.assertRaises(ValueError):
            asyncio.run(
                PKCS11Session.sign(
                    imported_key_label, b"data_to_be_signed", mechanism=Mechanism.SHA256_RSA_PKCS, key_type="ed25519"
                )
            )
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type="ed25519"))

    def test_import_keypair_ed448(self) -> None:
        """Import keypair with key_label in the PKCS11 device.

        Generate pub and priv with
        openssl genpkey -algorithm ed448 -out private.pem
        openssl pkey -in private.pem -outform DER -out private.key
        openssl pkey -in private.pem -pubout -outform DER -out public.key
        """

        priv = b"0G\x02\x01\x000\x05\x06\x03+eq\x04;\x049@\x02h\x89\xb4\xfdk\x05\xeblM\xe2\x8fT\x90QH\xacF\x8f\x9c\xd5\xf0b6U\x91Gu\x119Q\xff\x10\xae\x9fG\xe1\x7fiUu\xf3-\xdf\x9di(\xa26.\x93\x0f\xd6{#?"  # pylint: disable=C0301
        pub = b"0C0\x05\x06\x03+eq\x03:\x00N\x9e/u\xd35x]8k\xad\xbf\xf4\x06D\xf83\xcf\xea0\x91WS\xc0o\x17\x9f\xdc\xc7\xd8\xb2\x96\x07a\x14\xea\xf5\xcd\xe2D\xde\x8d\x15\xeb\x9b\xf6\xa7\xbe\r\x81\xa0\xfd\x10\xb2G \x80"  # pylint: disable=C0301

        imported_key_label = "imported_keypair_label_ed448"
        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)

        asyncio.run(PKCS11Session.create_keypair(new_key_label, key_type="ed448"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label, "ed448"))

        asyncio.run(PKCS11Session.import_keypair(pub, priv, imported_key_label, key_type="ed448"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type="ed448"))
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(identifier == b"\xcb\x8d\xa5\x80.\x84\xc87\x18\x99\x1f\x18z^2!\xe6qe=")
        self.assertTrue(isinstance(pk_info, str))

        self.assertTrue(imported_key_label in asyncio.run(PKCS11Session.key_labels()))
        self.assertTrue(asyncio.run(PKCS11Session.key_labels())[imported_key_label] == "ed448")
        with self.assertRaises(MultipleObjectsReturned):
            asyncio.run(
                PKCS11Session.import_keypair(
                    pub,
                    priv,
                    imported_key_label,
                    "ed448",
                )
            )

        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"
        signature = asyncio.run(
            PKCS11Session.sign(imported_key_label, data_to_be_signed, verify_signature=True, key_type="ed448")
        )
        self.assertTrue(isinstance(signature, bytes))
        self.assertTrue(
            signature
            == b'@5\xf1(\x94l\xf6\xec\xd1\x1d\xc43W\xe3\xcb\xaf\x12\xe04\xe6X\xc5<s\xfe\x89\xfa\xb6-\xbe\xaf\x02<\xaa\xd8\xa7\xd8\xea\x01\xcbt\x99\x973sc\x89\xb3\xadG\x0c\xa1\x8e\xc7zY\x80"\xb3\x93\x94\xfaCAwz\x0cs\xf7\xday\x14w\x0f\x94\x05iu\x17J\x8f\x1a\xe2\x8e\xd7\x86ms\t\xc0\x0b\xccq\x10\xd9\xab\xd5\xb6\x98e\xb3\x16#\xef\x93\x1c\xe7\x7f^\r\x9c?\x12\x00'  # pylint: disable=C0301
        )
        self.assertTrue(
            asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature, key_type="ed448"))
        )
        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="ed448"
                )
            )
        )
        with self.assertRaises(ValueError):
            asyncio.run(
                PKCS11Session.sign(
                    imported_key_label, b"data_to_be_signed", mechanism=Mechanism.SHA256_RSA_PKCS, key_type="ed448"
                )
            )
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type="ed448"))

    def test_import_keypair_secp256r1(self) -> None:
        """Import keypair with key_label in the PKCS11 device.

        openssl ecparam -name secp256r1 -genkey -noout -out private.pem
        openssl ec -in private.pem -outform DER -out private.key
        openssl ec -in private.pem -pubout -out public.pem
        openssl ec -in private.pem -pubout -outform DER -out public.key

        """

        priv = b"0w\x02\x01\x01\x04 \xc1\x96a \xd3M\xe2\x04\xaaY\xe8{%F\x0eTt?\xa7\x0c\x85\xf3Hh\xbd,&\xe5\x8c\xb5\xa3[\xa0\n\x06\x08*\x86H\xce=\x03\x01\x07\xa1D\x03B\x00\x04\xae-\x90\t\xee-\x8d\xe4\x1b\xcfC\xb4TJ\x89[\x89\x82\x85+9\xb7\x96\xef\x12\xae\xfeG\x1f\xf7aX\x88\xca\xcf\xab9\x0b\xcd>\xb8\xfc\x95g\xa4\xca \r\x9d_\xa2\x1b1*\x17\x11\xc2\x8b\xd0\x98\x94Za\x82"  # pylint: disable=C0301
        pub = b"0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04\xae-\x90\t\xee-\x8d\xe4\x1b\xcfC\xb4TJ\x89[\x89\x82\x85+9\xb7\x96\xef\x12\xae\xfeG\x1f\xf7aX\x88\xca\xcf\xab9\x0b\xcd>\xb8\xfc\x95g\xa4\xca \r\x9d_\xa2\x1b1*\x17\x11\xc2\x8b\xd0\x98\x94Za\x82"  # pylint: disable=C0301

        imported_key_label = "imported_keypair_label_secp256r1"
        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)

        asyncio.run(PKCS11Session.create_keypair(new_key_label, key_type="secp256r1"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label, "secp256r1"))

        asyncio.run(PKCS11Session.import_keypair(pub, priv, imported_key_label, key_type="secp256r1"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type="secp256r1"))
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(identifier == b"E\xb4i\xf6\x9b\xb06\xc2\x1b8!\x1cel\xdc\xcfu$+E")
        self.assertTrue(isinstance(pk_info, str))

        self.assertTrue(imported_key_label in asyncio.run(PKCS11Session.key_labels()))
        self.assertTrue(asyncio.run(PKCS11Session.key_labels())[imported_key_label] == "secp256r1")
        with self.assertRaises(MultipleObjectsReturned):
            asyncio.run(
                PKCS11Session.import_keypair(
                    pub,
                    priv,
                    imported_key_label,
                    "secp256r1",
                )
            )

        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"
        signature = asyncio.run(
            PKCS11Session.sign(imported_key_label, data_to_be_signed, verify_signature=True, key_type="secp256r1")
        )
        self.assertTrue(isinstance(signature, bytes))
        # self.assertTrue(
        #    signature
        #    == b'vk\xf9:\x0fA\x04\x1c3\xf6\xd2>*v\xfc\xa9/\xf03\xfb9\xf4\xcc\xc7\x9a\xc2\xb0\xb0GB\xd5\xe4\xef\xdfK/E\xe7\x96-\xf5\x9e\xc2t\xfd\xfa\xe8\xf6\x9d\x83\xf8\x9e\x0f\x90)\x1f\x08\x85.\x7f\xabD\x10\xf0'  # pylint: disable=C0301
        # )
        # self.assertTrue(
        #    asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature, key_type="secp256r1"))
        # )
        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="secp256r1"
                )
            )
        )
        with self.assertRaises(ValueError):
            asyncio.run(
                PKCS11Session.sign(
                    imported_key_label, b"data_to_be_signed", mechanism=Mechanism.SHA256_RSA_PKCS, key_type="secp256r1"
                )
            )
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type="secp256r1"))

    def test_import_keypair_secp384r1(self) -> None:
        """Import keypair with key_label in the PKCS11 device.

        openssl ecparam -name secp384r1 -genkey -noout -out private.pem
        openssl ec -in private.pem -outform DER -out private.key
        openssl ec -in private.pem -pubout -out public.pem
        openssl ec -in private.pem -pubout -outform DER -out public.key

        """

        priv = b'0\x81\xa4\x02\x01\x01\x040:-e\x12#\xab\xcb\xa3v\xfd\xc5\xe2W\x87\x82\x17\x1d\x7f\xbcg\x92\x7f\xc9\xe0G\xdde\x9e0\xf6\x00\x97\xcc\xda\x04\xa0\xda\xf9\x13\x86\x8e7x^\xa8\xbe\xd8\xd7\xa0\x07\x06\x05+\x81\x04\x00"\xa1d\x03b\x00\x04>\x11_\x9f\xb6z\xe6\xdc\xfc\xa7\x1a]\x02\x82\xbe\xdfh\xee\xca\xa6\xd6\xd9\x84\x87[m\x15\x11\xa7\xbea\x94<\x07!\xcb%7\xedFv\xaa\xe0\xf6\x9b\x9c\x00Bo\x1c\xc8\n\x8a\x86\xf6\x82\x15\xf5\x0e\xb98\xdf\x9f+\xb4\xfdG\x17\xc0O$a\xedz-\xc1[\xf1\xa5\xab\t\x1a\xdb>\x9d\xf5^\xb0 ,\xe4A\x9e\xfb\x17e'  # pylint: disable=C0301
        pub = b'0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00"\x03b\x00\x04>\x11_\x9f\xb6z\xe6\xdc\xfc\xa7\x1a]\x02\x82\xbe\xdfh\xee\xca\xa6\xd6\xd9\x84\x87[m\x15\x11\xa7\xbea\x94<\x07!\xcb%7\xedFv\xaa\xe0\xf6\x9b\x9c\x00Bo\x1c\xc8\n\x8a\x86\xf6\x82\x15\xf5\x0e\xb98\xdf\x9f+\xb4\xfdG\x17\xc0O$a\xedz-\xc1[\xf1\xa5\xab\t\x1a\xdb>\x9d\xf5^\xb0 ,\xe4A\x9e\xfb\x17e'  # pylint: disable=C0301

        imported_key_label = "imported_keypair_label_secp384r1"
        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)

        asyncio.run(PKCS11Session.create_keypair(new_key_label, key_type="secp384r1"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label, "secp384r1"))

        asyncio.run(PKCS11Session.import_keypair(pub, priv, imported_key_label, key_type="secp384r1"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type="secp384r1"))
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(identifier == b"\xa9\x7f\xe5\x14\xcb\x08\x13\xc6\x18\xf7\xae\t\x8e0\xfc$v\x13\xc8A")
        self.assertTrue(isinstance(pk_info, str))

        self.assertTrue(imported_key_label in asyncio.run(PKCS11Session.key_labels()))
        self.assertTrue(asyncio.run(PKCS11Session.key_labels())[imported_key_label] == "secp384r1")
        with self.assertRaises(MultipleObjectsReturned):
            asyncio.run(
                PKCS11Session.import_keypair(
                    pub,
                    priv,
                    imported_key_label,
                    "secp384r1",
                )
            )

        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"
        signature = asyncio.run(
            PKCS11Session.sign(imported_key_label, data_to_be_signed, verify_signature=True, key_type="secp384r1")
        )
        self.assertTrue(isinstance(signature, bytes))
        # self.assertTrue(
        #    signature
        #    == b'vk\xf9:\x0fA\x04\x1c3\xf6\xd2>*v\xfc\xa9/\xf03\xfb9\xf4\xcc\xc7\x9a\xc2\xb0\xb0GB\xd5\xe4\xef\xdfK/E\xe7\x96-\xf5\x9e\xc2t\xfd\xfa\xe8\xf6\x9d\x83\xf8\x9e\x0f\x90)\x1f\x08\x85.\x7f\xabD\x10\xf0'  # pylint: disable=C0301
        # )
        # self.assertTrue(
        #    asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature, key_type="secp384r1"))
        # )
        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="secp384r1"
                )
            )
        )
        with self.assertRaises(ValueError):
            asyncio.run(
                PKCS11Session.sign(
                    imported_key_label, b"data_to_be_signed", mechanism=Mechanism.SHA256_RSA_PKCS, key_type="secp384r1"
                )
            )
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type="secp384r1"))

    def test_import_keypair_secp521r1(self) -> None:
        """Import keypair with key_label in the PKCS11 device.

        openssl ecparam -name secp521r1 -genkey -noout -out private.pem
        openssl ec -in private.pem -outform DER -out private.key
        openssl ec -in private.pem -pubout -out public.pem
        openssl ec -in private.pem -pubout -outform DER -out public.key

        """

        priv = b'0\x81\xdc\x02\x01\x01\x04B\x00T\xc7"\xc9&\xdb\xe8e\xb8\xf6\xb0\x8c\xd4\xd0\xc0\xbc\xf8\xd8?g\x17Bb:\xeeI\x86\xe6\x86\xb25W\x12\xa9F\x00\xbf\xee\xd7\xb7\xb5}\x9b]\x1a\xce\x97U\x05\x0cX\x19c\x1b\'?i\x94s0,\x175\xfe\x88\xa0\x07\x06\x05+\x81\x04\x00#\xa1\x81\x89\x03\x81\x86\x00\x04\x01\x04\x95"\xe0"\xc6g\xee\xa2:\\\xd9\xa0\x8f\xfa\xad\x07\xeco\t\xa7\x00~3}1\x949\x83\xef\x16-T\x1c\x90\x96) \x8e\x16\xa3\xc1\xd7\xcb\xa0I?\xdf\x07\x8e\xa0\xb8\x82F\xf0\x15\xaf4\x9d\xbb\xd7\xb85\xce\xd4\x01\xc6`\xbd?\xfc]\xa1\x18\x8c\xb9\xb8Z\x10\xb6\x9a&\xa9[\xc9{\xf9\x99\xcc\xe5\xb6\x80!R\xd6(\xa0\x08\xda%\xd45\x0ec[\x87^\xfa\xf7;\x10\t\x95\xbcf\xf1\x97\xd9B7\t\xb6w\x0ce\xec\x81\xe4\xd6~T'  # pylint: disable=C0301
        pub = b'0\x81\x9b0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00#\x03\x81\x86\x00\x04\x01\x04\x95"\xe0"\xc6g\xee\xa2:\\\xd9\xa0\x8f\xfa\xad\x07\xeco\t\xa7\x00~3}1\x949\x83\xef\x16-T\x1c\x90\x96) \x8e\x16\xa3\xc1\xd7\xcb\xa0I?\xdf\x07\x8e\xa0\xb8\x82F\xf0\x15\xaf4\x9d\xbb\xd7\xb85\xce\xd4\x01\xc6`\xbd?\xfc]\xa1\x18\x8c\xb9\xb8Z\x10\xb6\x9a&\xa9[\xc9{\xf9\x99\xcc\xe5\xb6\x80!R\xd6(\xa0\x08\xda%\xd45\x0ec[\x87^\xfa\xf7;\x10\t\x95\xbcf\xf1\x97\xd9B7\t\xb6w\x0ce\xec\x81\xe4\xd6~T'  # pylint: disable=C0301

        imported_key_label = "imported_keypair_label_secp521r1"
        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)

        asyncio.run(PKCS11Session.create_keypair(new_key_label, key_type="secp521r1"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label, "secp521r1"))

        asyncio.run(PKCS11Session.import_keypair(pub, priv, imported_key_label, key_type="secp521r1"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type="secp521r1"))
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(identifier == b"\x02\xf0\xdek\x85\x85\x80\x15\xc3H\xf4\xc5'/\xa4\x1a\x12\x0e\x9a\xd3")
        self.assertTrue(isinstance(pk_info, str))

        self.assertTrue(imported_key_label in asyncio.run(PKCS11Session.key_labels()))
        self.assertTrue(asyncio.run(PKCS11Session.key_labels())[imported_key_label] == "secp521r1")
        with self.assertRaises(MultipleObjectsReturned):
            asyncio.run(
                PKCS11Session.import_keypair(
                    pub,
                    priv,
                    imported_key_label,
                    "secp521r1",
                )
            )

        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"
        signature = asyncio.run(
            PKCS11Session.sign(imported_key_label, data_to_be_signed, verify_signature=True, key_type="secp521r1")
        )
        self.assertTrue(isinstance(signature, bytes))
        # self.assertTrue(
        #    signature
        #    == b'vk\xf9:\x0fA\x04\x1c3\xf6\xd2>*v\xfc\xa9/\xf03\xfb9\xf4\xcc\xc7\x9a\xc2\xb0\xb0GB\xd5\xe4\xef\xdfK/E\xe7\x96-\xf5\x9e\xc2t\xfd\xfa\xe8\xf6\x9d\x83\xf8\x9e\x0f\x90)\x1f\x08\x85.\x7f\xabD\x10\xf0'  # pylint: disable=C0301
        # )
        # self.assertTrue(
        #    asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature, key_type="secp521r1"))
        # )
        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="secp521r1"
                )
            )
        )
        with self.assertRaises(ValueError):
            asyncio.run(
                PKCS11Session.sign(
                    imported_key_label, b"data_to_be_signed", mechanism=Mechanism.SHA256_RSA_PKCS, key_type="secp521r1"
                )
            )
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type="secp521r1"))

    def test_create_keypair(self) -> None:
        """Create keypair with key_label in the PKCS11 device."""

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label, 2048, key_type="rsa"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label, key_type="rsa"))
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(isinstance(pk_info, str))

        with self.assertRaises(MultipleObjectsReturned):
            asyncio.run(PKCS11Session.create_keypair(new_key_label, 2048, key_type="rsa"))
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label, key_type="rsa"))

        asyncio.run(PKCS11Session.create_keypair(new_key_label[:-1], 2048, key_type="rsa"))
        pk_info2, identifier2 = asyncio.run(PKCS11Session.public_key_data(new_key_label[:-1], key_type="rsa"))
        self.assertTrue(isinstance(identifier2, bytes))
        self.assertTrue(isinstance(pk_info2, str))

        self.assertTrue(identifier != identifier2)
        self.assertTrue(pk_info != pk_info2)

        asyncio.run(PKCS11Session.create_keypair(new_key_label[:-2], 4096, key_type="rsa"))
        pk_info2, identifier2 = asyncio.run(PKCS11Session.public_key_data(new_key_label[:-2], key_type="rsa"))
        self.assertTrue(isinstance(identifier2, bytes))
        self.assertTrue(isinstance(pk_info2, str))

        # Test key_labels
        pk_info3, identifier3 = asyncio.run(PKCS11Session.create_keypair(new_key_label[:-3], 4096, key_type="rsa"))
        key_labels = asyncio.run(PKCS11Session.key_labels())
        self.assertTrue(isinstance(key_labels, dict))
        self.assertTrue(len(key_labels) > 0)
        for label in key_labels:
            self.assertTrue(isinstance(label, str))
        self.assertTrue(new_key_label[:-3] in key_labels)
        self.assertFalse("should_not_exists_1232353523" in key_labels)

        pk_info3_1, identifier3_1 = asyncio.run(PKCS11Session.public_key_data(new_key_label[:-3], key_type="rsa"))
        self.assertTrue(pk_info3 == pk_info3_1)
        self.assertTrue(identifier3 == identifier3_1)

    def test_get_public_key_data(self) -> None:
        """
        Get key identifier from public key with key_label in the PKCS11 device.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label))
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(isinstance(pk_info, str))

        with self.assertRaises(NoSuchKey):
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label[:-2]))

    def test_sign_and_verify_data_rsa(self) -> None:
        """
        Sign bytes with key_label in the PKCS11 device.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label, key_type="rsa"))
        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"

        signature = asyncio.run(PKCS11Session.sign(new_key_label, data_to_be_signed, key_type="rsa"))
        self.assertTrue(isinstance(signature, bytes))

        signature = asyncio.run(
            PKCS11Session.sign(new_key_label, data_to_be_signed, Mechanism.SHA512_RSA_PKCS, key_type="rsa")
        )
        self.assertTrue(isinstance(signature, bytes))

        self.assertTrue(asyncio.run(PKCS11Session.verify(new_key_label, data_to_be_signed, signature, key_type="rsa")))

        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(new_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="rsa")
            )
        )

        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    new_key_label,
                    data_to_be_signed,
                    b"NOT VALID SIGNATURE HERE",
                    Mechanism.SHA512_RSA_PKCS,
                    key_type="rsa",
                )
            )
        )

        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    new_key_label, data_to_be_signed, signature, mechanism=Mechanism.SHA512_RSA_PKCS, key_type="rsa"
                )
            )
        )
