"""
Test our PKCS11 session handler
"""
import asyncio
import os
import unittest

from pkcs11.exceptions import MultipleObjectsReturned, NoSuchKey

from src.python_x509_pkcs11.error import PKCS11UnknownErrorException
from src.python_x509_pkcs11.lib import key_types
from src.python_x509_pkcs11.pkcs11_handle import PKCS11Session

# Replace the above with this should you use this code
# from python_x509_pkcs11.pkcs11_handle import PKCS11Session


class TestPKCS11Handle(unittest.TestCase):
    """
    Test our PKCS11 session handler.
    """

    def test_session(self) -> None:
        """Test PKCS11 session"""

        with self.assertRaises(PKCS11UnknownErrorException):
            asyncio.run(PKCS11Session.healthy_session(simulate_pkcs11_timeout=True))

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

        asyncio.run(PKCS11Session.import_keypair(pub, priv, imported_key_label, key_type="rsa_2048"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type="rsa_2048"))

        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(identifier == b'\xf0c\xd5\xe2X\xdc\x19@\xa2\xbc#\x13\x0c_\xaae\x16\xde"f')
        self.assertTrue(isinstance(pk_info, str))

        self.assertTrue(imported_key_label in asyncio.run(PKCS11Session.key_labels()))
        with self.assertRaises(MultipleObjectsReturned):
            asyncio.run(PKCS11Session.import_keypair(pub, priv, imported_key_label, key_type="rsa_2048"))

        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"
        signature = asyncio.run(PKCS11Session.sign(imported_key_label, data_to_be_signed, key_type="rsa_2048"))
        self.assertTrue(isinstance(signature, bytes))
        self.assertTrue(signature == signature_val)
        self.assertTrue(
            asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature, key_type="rsa_2048"))
        )
        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="rsa_2048"
                )
            )
        )

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(imported_key_label, key_type="rsa_2048"))

    def test_import_keypair_rsa_4096(self) -> None:
        """Import keypair with key_label in the PKCS11 device.

        Generate pub and priv with
        openssl genrsa -out rsaprivkey.pem 4096
        openssl rsa -inform pem -in rsaprivkey.pem -outform der -out PrivateKey.der
        openssl rsa -in rsaprivkey.pem -RSAPublicKey_out -outform DER -out PublicKey.der
        """

        pub = b'0\x82\x02\n\x02\x82\x02\x01\x00\xdd\xa8\x14\xa7@h\xb1\xb3\x9e\x82\x87\x0e\xfc\x0c\xb4\xa9\x1f\xe2iO\xc7a\xec,\xb2\x0c\x15N\xe9\xa4nx,c^\xc1\xe2Oe\xfe\x8cG\x1c\xcf#\x195\xd0\xf6\xb3N\xb9\xf7\xe4\xcf\xb0\xfb\xd9<:\xc2\x12\x10\xa1\xd66\xb5\xbd\xedG\x8e(\xb0\x05\xa4.\x12O6\xd0D\xc3\x1a\xed\x00\x86\xe8\x19T\xa6T|\xd8\x8dy&+\xf5\xfb1cq\xac\x92\xed\xed\xe6\xe2\xe9v\xcf\x99\x8a\x9e\xce,"\x8e\xd3\xec\x1e\xa0pl\xe6\xff\x8ai\x9bk\x95\x18\xa6\xcb\x16o\x86\x85T\xe0\x9a)_-#\x87?\x905\xa5\xddw\xb55\xd1\xa1\xd2\x93\xa5\x90\x81\x861\xd3\x82\xd3\x8auy\xc7j\xc2\xed\x92\xdb\x0e>Uam\x13\xde\x03\xfe\xb6\xa0\xfe\xa0\xc8\xb2\x8e\x85\xc2\xc9^w\xe2<$\xe0\xacY\x0b}(H\xb4\xdbj\xe9`\xc4\\\x99\xfesY\xacB;\xae\x82\xfa\xf7\xb2\xef\xea\x9e\xcdS\xe8\x86\xab\x7f\xdb\xc2s\x14!\xf0\xbb\xdd\x03\xe9wa\xe6\xdc/s\xb8\xfb\xef\xefj\xc1SP0c\xa6\xb4R\xca\xa5\x05\x131\xd4\xbfx:\x7f\xc1>\x15\x7f+\xbdlBw\xd9\x80\xc2\x02\xc5I\x8c1\x93w\x8d\x86\x04W~\xa56\xb5oD\x9b\x1f\xc61\xeb\x7f(\xa2\xc0\xd7k\x1d{,\xe4\xac\x81\x10\xbb\ti\x7f\xee\xa4G\xff\xc8\xa3\xfc\xcad41\x82\x1d\x9cb\xa9r\x88\xa1\x92\xdc\x90\xfa\xc4TL\x02v\xc0Ls"\xf4\x08c\x0c|\x8a\xaa\x94\xf6\xae\x8d\xff\x0cE\x94jl\x95\x8b\x10&\x83]\x8f5\xc1\x1e\x8d\x1d*\x19\x06\xff\x1cC\x1ec\xa8\xb4\x05v>\xb9\xb1>\x0b\xd2\xc7q\x99\xc4H\x7f2\xfd\x91\xdc_\x9e\xcd\xdd\x18\x16\xad\xff\xfbY\x13N\xd0L\xb4\x80\x8d\xcc\xb3,p\x84\xd2\x93\xe3\xb0\x1d\xea\xcb\x03\x02o\xc3\x0f\x8b@\xe4NO\x1e;g\xff\x0bm\xe5\xc6\xf86\x9b\xa75\xa9\xb1\x93/Xs\x82\xa8\xd8\xd99B}\x9b\x95\x1e\xba\xb4\xe0\x1fP\x90\xca\xdb\x02\xe2\x14\xca\xf6\x90\x7f\x9a\xd4\xc1\xc2\x84*+\x19\x94\xba%+\x12\xa3\xdf\x97\x02\x03\x01\x00\x01'  # pylint: disable=C0301
        priv = b'0\x82\t)\x02\x01\x00\x02\x82\x02\x01\x00\xdd\xa8\x14\xa7@h\xb1\xb3\x9e\x82\x87\x0e\xfc\x0c\xb4\xa9\x1f\xe2iO\xc7a\xec,\xb2\x0c\x15N\xe9\xa4nx,c^\xc1\xe2Oe\xfe\x8cG\x1c\xcf#\x195\xd0\xf6\xb3N\xb9\xf7\xe4\xcf\xb0\xfb\xd9<:\xc2\x12\x10\xa1\xd66\xb5\xbd\xedG\x8e(\xb0\x05\xa4.\x12O6\xd0D\xc3\x1a\xed\x00\x86\xe8\x19T\xa6T|\xd8\x8dy&+\xf5\xfb1cq\xac\x92\xed\xed\xe6\xe2\xe9v\xcf\x99\x8a\x9e\xce,"\x8e\xd3\xec\x1e\xa0pl\xe6\xff\x8ai\x9bk\x95\x18\xa6\xcb\x16o\x86\x85T\xe0\x9a)_-#\x87?\x905\xa5\xddw\xb55\xd1\xa1\xd2\x93\xa5\x90\x81\x861\xd3\x82\xd3\x8auy\xc7j\xc2\xed\x92\xdb\x0e>Uam\x13\xde\x03\xfe\xb6\xa0\xfe\xa0\xc8\xb2\x8e\x85\xc2\xc9^w\xe2<$\xe0\xacY\x0b}(H\xb4\xdbj\xe9`\xc4\\\x99\xfesY\xacB;\xae\x82\xfa\xf7\xb2\xef\xea\x9e\xcdS\xe8\x86\xab\x7f\xdb\xc2s\x14!\xf0\xbb\xdd\x03\xe9wa\xe6\xdc/s\xb8\xfb\xef\xefj\xc1SP0c\xa6\xb4R\xca\xa5\x05\x131\xd4\xbfx:\x7f\xc1>\x15\x7f+\xbdlBw\xd9\x80\xc2\x02\xc5I\x8c1\x93w\x8d\x86\x04W~\xa56\xb5oD\x9b\x1f\xc61\xeb\x7f(\xa2\xc0\xd7k\x1d{,\xe4\xac\x81\x10\xbb\ti\x7f\xee\xa4G\xff\xc8\xa3\xfc\xcad41\x82\x1d\x9cb\xa9r\x88\xa1\x92\xdc\x90\xfa\xc4TL\x02v\xc0Ls"\xf4\x08c\x0c|\x8a\xaa\x94\xf6\xae\x8d\xff\x0cE\x94jl\x95\x8b\x10&\x83]\x8f5\xc1\x1e\x8d\x1d*\x19\x06\xff\x1cC\x1ec\xa8\xb4\x05v>\xb9\xb1>\x0b\xd2\xc7q\x99\xc4H\x7f2\xfd\x91\xdc_\x9e\xcd\xdd\x18\x16\xad\xff\xfbY\x13N\xd0L\xb4\x80\x8d\xcc\xb3,p\x84\xd2\x93\xe3\xb0\x1d\xea\xcb\x03\x02o\xc3\x0f\x8b@\xe4NO\x1e;g\xff\x0bm\xe5\xc6\xf86\x9b\xa75\xa9\xb1\x93/Xs\x82\xa8\xd8\xd99B}\x9b\x95\x1e\xba\xb4\xe0\x1fP\x90\xca\xdb\x02\xe2\x14\xca\xf6\x90\x7f\x9a\xd4\xc1\xc2\x84*+\x19\x94\xba%+\x12\xa3\xdf\x97\x02\x03\x01\x00\x01\x02\x82\x02\x01\x00\x82\xa01;\xb7\x8b{]\xddF\x13\r\xd3\xa01?\x92\x18\xbd\xf3T\x0e\xf3>\x0b\xd7o\x1fH5\xad\x1c\x89\x1c.\x95\x98\'.vjx\xe6\x13t\x1d\xc1GZ{\xa5#\x97ar\xbc\\OS]UM\x8c\x1b\xb3\xc0\x1e.\xc5\x8c\xeb\xcc2\x9f\xc0w\x9e6\xac\x98\xe4M\x0e\xab)*W\xd1\xc5\xbf\x17\xffS\'\\\x84\x10X0&\x94\xf2B\xbf|\x14=\x82\xf0\x0f"\x9c\xdb\xc2f\xc2?\xc3hD\xb8o\xd8\x91u8\x97{Q*\x7f}=\x9ee\xa4g\xe4_v\xd5\xa3\x18\x01\xe3\xf4*\x93s\xeaA\xaf\xf0L\xbd3\xde\x83@\x88\xfe\xab\xf4\xe5/.7d\xaf\xd5\xc3\xa7\x08\x97\t\x1dE\xc2\xcf]\x96\xdd\xba\x00\xfb\xe3\xb8\xebL\x1b^>\x99\xe2N\x17\xdcm\x91V\x0e{\x93w\xb8\xab\xd0Y\x96\x91\xde\x83\x1a\x07n\x9a\xcf\xf7\xe28\x85\xc9\x8e\xd96\xcc\x88\xb9\xf9K?\xb7M\x8eV\x16+\xf7ka\x11uX~\xd7\xea\x0cA*}\xca@>\xd0\x1bZ\xa6\x19\x83\xb0l\xee\xbf<\xa5\x15\xe3\xfd\xde\xc3\x85N\xf0\xda\xaa\x05.\xd3\x7fg\x85\x95\r\xdai\x00k\x80\x9c\x81\xb2\x0c\xe5\xd8s!@\xe8\xea%d\x87\n\x9eB8\xdd\xe3\xdfh5\xfb$\x14\xa9\xd3\xc5\xbf\xbfx\xfc\xf9\xf2\xfc\xc1\xb9\x1d\x14"\x1e\x98<?\xb7\x90*{X\xa0\xeb\xa9\xa9\x10Y\x19V\xf2\x83:LB\xdd\xae(B\xd2\xb5B\xc8\x8a\x08\xffM\xcc)h\x8fS|\xa5\xa3>&\x14.\x9c\'\xfe\xe0/\xc9\xdb\x9e\xc9\xfc&\xc8\x10>i\xd3ZT\x99n\x02c\x86\xe6:\xb7\x96\xd11\xe7\x00M\x9f\xf1\x83\xe8{\xa6F\x1f \xbas\n\x19pP\xe8\x0b\x02j\xe1z\xe8A\x82u\xc2\xce|d,$\xaf\xf6<7\xd6\x08\x92\xa9\x82\x9c\xb4\x8a\xbeA\xa8\x82\x8d\x83\x1f\x08g\x99\xdc\x7f\xe9\xb5C\xca\xcc\xd7\xb3J\x82\xb9\xfc\xe8\xf2\x1bU\xa0VK\xe1\xbd\x8f\x90\x08\xec\x97\x93\x8d\xbd\x975]8Ax\xde\x80\xd3\xbdr\r\xc639\xd9\x9dTZ\xce!!\x02\x82\x01\x01\x00\xf8btWk~\n\xd9^L\x1b\x16iN\x0b\xb4/\xd6\x9f\xe5\xf3;\xca\xe3\xf46g*ih\xfa\xd9|\x83eR^\x1d\x913\xf9q"\xcf\x84M\x85]\xcapy2|@G3jvp}\x15\xf4\x80\xd0\xbb\xe6\xd75\xb3|\x8d\xbc,\xcc\x83\xf0E\x87\x9c\xab\n\xac\xe1#`\x85-\xaf\x8d/\x08\x9a\xdc\x89\x11\xdbp\x1fcv\xf7\xe0\xc6s\xa2\xdeJM\xd9ku\x93\xa4\xc9\xf0\x9a\x17I\xbd9t\x8f\x1c\xd2\xa9\xefP\x80?\xec\xdd\x97x\x1a\xf4\xd3\t\xac\xd7\xb0\t+\x94\xaf\x90\xdf9N\x0eva!\xd0\x90>\xcf\xfcS\xa9\\\\\xb2a\xaad\xea\x06\xa9\xab\xa50\xfftg-\xcd7\xf8\xae)-\x19\xc9\x8b\xd6\xa8\xe5+W\x8e\xbb\xe6\xe4\xe2%a\x0c\x88\xe9HF\x06\xc2\x7f\xbd\xba\x92\xae\r\xf7"\xa9\xbdK5\xb19\n\x03\xc1p\x05\x04\x87\xf9\xaa\xf3xQ\xd3z\xfb\xab\x8f\xdb\xec\xb30G[B\xf6\x03\xa7\xb4o/\xbb\xf3\xf1Xv&\x90\xab\xdf\x02\x82\x01\x01\x00\xe4s\xd76\rR\xa63\x9cQD\xa7 \x81\xcb\xa3l<B\x95?\x12\n\xc5\xady\x83O5U\x1a\xc0\xd2*\xd4I\x96\xb8\xc3\xfeH1\xecS)j!\xda<\xd3F\xa7Pe[\x1dacL\xf7\xa2\x93\xbf\xc3\xb9\xb4\x1a\x89\x9e\xaf\xf2\xb3\xec\xbe\x11\xe5\x1c$\xb3y\xde\x90t%Q\xb5\x03Ep-\xea\x16f9\xec\x9a\x82\xd1%d\xa3\x0b\xee\xdc\xd8\xd0\xe8\x00\xdb\xed\xa6\xb0\xa8I\x98\xbb\x8d\x1a\xc6\xb7\xb2l\xac\xeb\x83\xab\xac\xa1\xfb\x86\x91\x17\xf6\xb8\x02\xd9v\xacCr\t~\xc6\xfa\xb7\xc8\\F\xc9\x00U\x1cR6\x06\xea\x9b\xa4\xc9/\xd8\rU\x96\xd8Vz\xcel\xcaH2\xb5\x9b\xc0\x89\x0b,\xd9\xc93fh\x92\xa9&\xbal\xf1\x8f\x82\xd5\x9d\x16\xd5\xc4\x9f\xa6\x051\'=\x8c\x1f\xa8\x14?=\x04\xf6\xeb7\x05\xd6\x00/7\x8d\xb97W\xe6\xdf|\x06\x04\x9f\xded\xd2\xa7aN\x1e"\x99a\xb9\x10o\x85\xa9$\xe8\x98\xb1\x9b\x94Y\xf2\xc33\xae\x88\xc3I\x02\x82\x01\x00`@&\xbdI\x96J5\xf9h\x9c\x86\x8e\xc0\x03\xa1\x0bx\xab\xf5\xbb\xcf\xcb\xcb\x91\xf3\x12\xffHa\xb9\xf3U`\xc5~\xa9\xa1\xe3\x86\xb4~\xb6\xf2\x9b^>\xf4\x1db\x80T\xa3\xf9t\x9d\xe3\xff\x89\x8f\xafVT$\x8e\xeb\xe11\x9a \x05\xfc\x89\x8f\xa7\x01\x10\xb0\x80qwm\x8e\xc0\xda\xc2@\xf5\xeaK\xf3\x95\xaf(\x1e\x97^W\x8b\x7f\xaa\x86\x9b\xe0k\x98\xa0J\x92\x9a%\xb1\xd5\x05\xbc\n\xbaC\x84\xe4"\xda\xe2\\p%\xa0\x98R-C\xa1R\x95\x7f\x91\xd8\t\xf6z\xec\xd2\xca\x87N(rXa\x1aV\x81x\x04\xad\x92\x83A\x18<\x06_\xc9\xa0\xf2\x02\x0e\x1a\xe9\xbc\xd5\xc3\xe8#\xa3\x88\x06\xcc\x83\x10\xc9\xbdXp\xab\xfa>\xf4\x10\xb5\xea\xf2\x8awg\xec\xb7\xa2\xc6c\x8f_G7\xa1\x1a\x0f\x85\x0b<]^QP7\xba9T<(Ut\\Q$\xda\xae\x06N\x0f\x19u5\x02FB\xef\x1d"I\xa7%\x16=\x82\x9a#q>\x12\xa4)\x04\xc0\xc3\x19\x02\x82\x01\x00m\xc2V0\xca\xff\xdd\x88H_\'K\xe0\xab[\xaa]\xb3*\x0eH\xaa#p\xcc"\xe8z\xa2\xd6\x0b\xaf~\x8aCJC\xd6\xeb\x9b}\x167C\xd1O\x03\x8a\xb5\xd4\x90J\x8c\xae\xd5\xb2\xec\xfag\x9dF\x88\x14\x076n\x98\x9dl\x17~\xd5\x016d\xa4\x9d\xfb\xe8\x1a\xf2Z\x96\xe2\xe39\xc3\xa3\x95\xfd\tM\xcf\xb9\x9e\xba\xb1\x85H\xa0\xecQ,g\x00\xe8\x85\xbe\xfb\xebW=\xe2\xec\xd1+\xb2\xe4\x9dz\xde\x87\xa6 \xd57#\x0f\x04(\xa8\x07Jk(;P\xef\xfc\xcb\x8aRU\xc9Y\x893\x04sG\xec\x9cY\xc7IUh\x88(}\x0b!\x84\xf0\x9fj\x15@\x9e6%\xaf\xef_0\x86\xe7N\x9a(7\xc0\xc9\x17E\x9b\xac\xcf\xf0\xd3\x11z\x0e*MtU{\xcf\\\xc9L\xa1\xc9\x07\xd9\nu\x07\xb0\x96[\xee:\xde\x05\xd1|\x0e\xf3\xcf\x10\xc6h\xf0\xffA\xcb\xf8\xc6\xd8\xd2@T\xec,\xa3-\xe5\xfe\x9e\xca H|,@\xe2j\xc0\xdf\x162\x91\xd4\xb9\x02\x82\x01\x01\x00\xcdZ\x83\xcf\x9b\x0b\xe17\xd9w\xf0y\xc6\xaa]\xbf\xd7\xc9\tt\x8d\xb5e^\xe4\xda\xad\xa1-\x06\xca\x87\xb9\xe9V\xbe\xcc\xbf"-\xe9\x04\xc8\x97I\xc6\x8c\xf7\'\'\xa8\xb9\xc9V\xb6a\xff$\xb1i\xd8e\x9f@\xba-_NP-F\x1f\x1f\x89h\xa4Q\x1e\xb8*=\x15\xc1\xf4;\xf2\xbbl\x19f\xe0\rLo#\x9ai\xc9\xd8\xfa\x96["\xd9\xa7\x12}\x91\x1a\xb0\xa0<\xa2\xa4\x88.;\xfb\xa7\xab\xc5\x03\x8cI\xaf\n.\xd1\xfayb\x00|`\x04\xf3`\xa1\x9b\xe2\xee\xd7\x8d[a\xdf\x93`\xde\x00\tQ\x94.\x94&s@XqNf\xe5T\xb9\xbc\xc5\xc0Ack!\xca\x90\xe0\xb1o\xcfv\x19\x7f\x8a\x8e\xd7]\x8d\x1a\'\xf6\x11\xc4\x92@\xc8#\xbd\xba\x12\x8bf\x0e\xad\xb3(m\r\xa7U\x90sD\xb0U\xaf\xc5Aw\xb08\xd6\xf8\x9f\xf9\x9c5\x13iQ\xa4<h\xb4\x06\xd8E\xe8\xd1\xd9\xee\x02CX\x8e\xa4\xa3\x97\xd4^\xf4\x89N\x9d}M\xfb\x83'  # pylint: disable=C0301

        imported_key_label = "imported_keypair_label_RSA_4096"
        signature_val = b"\xad>\xb6\xf4\x8f\xb1s>\xa8\x99\x10zt\xa2\xf2\xc0&C.\"\x96\x0fOaD\xfa\x10\xe1\xc4qqx\xfd\xc0\x82,\xc1\x0e\xcf\x82\xda\x8d\x9d\xec\xe3\xd6\xe2\xa10;s,\xbb\xa5_\xa4\xb3?\x8bm\x8d!\x85\xacb\xfd\xdc,fkl\r\xb5j\x0e<\xfcI\xea_\x03\x03\x1bi\xa3\x8f\xc2y\xeb^\xe1u\xee\x91dg\xf9y\xd0\xb0\xa4\x00\xba\x0cm\x05\xf9\x19\xec\tq\x8e\xe2]<\x83\xf0\x9f;\xfa\x11}# \xa2\x05\x93\x82\xb9T\xd7\x05n\xa5S\xa7[\xed\xc5\x979\xce\xf8m\xfeA\x8c$09,\xd5\x0f/g\xa1D\x05\xc1`\xd5\x1d\x03#\xd6\x9c\xc9K\xf04\x8fsM\xb6\xd2\x97W\xa9T\x8c\r\xcb\xff[!\xbb\xc2\xfa@\x1a\xbc\xd2r\xbb\x95\x06\x9c\xd7\x88\x9f\x06\t\xb3\xa4\x8f\xed\xa8-\xde\xdd5\xad\xf8F\xbbH\xa6\xdaX\x81\x00\xf7Tge\x04E\xda\xfcN\xf4\xfc\x88X\xebu\x00\x02R\xdePB\x90\xa5\xf2\xb8=vC}(\xee`\xa3:\xe9f3\xf111\xfb\n\x88%A\x87\x9a;\x1e\xfe\x7f5\xeefe=\xbf~\xcf\xbd\x89\xa9\x8d\xd6\x92\x07F\xa0\xc3\xab\x0f\x82\x91\xf8\x1f\xad\xc6)\xd7\xe2r\\\x87\xebS\xaa\xf6\xfb\\\xa76\x16\xb0\xbe\xe5\x1c\x11c\xf7\x03\x83\x0f%\xd1\x17\x8d\x0b9wH\x9d{f\x9f\xc7\xd8\xa8f\xf0\x8d\r;\xdbqZ\xb0p\\G2B8n\x19\x8bOca\xe8S{\xa2s\xc6tcZrl[\xd6\x1c*\x96\xbf\xbd\x87p\xe7\x18K\x1ep\x1aYs\x1e?\xa2\xcd\x8b\xbd\xb2z\xf0d\xb8|I\xb9\x86{\r\xa2A\xe8\x9b[.\x8eu\xa1\xb1\x9f\x00\xe33cF\xc48*\xabHf\x93$o\xa2\x9foVP\xae\xe2[D\xe3A\xb9\xca\xeb\xa9\x13\x00\xce\x03\x81\xe1\xad\xf5\xc0\x8d\x83g1\xfa`'f\xcd\xa1D#\x16\xb4\xf0\x02C?G`{I\x96\xd2_\xdbeYd\xab\xb7\xe9nFx\x07k\xcd\xe9cQ),\x18\xa2\xdb\xac\xd9\xb5?\x85\xac\x11X&l\xb9`\x17"  # pylint: disable=C0301

        asyncio.run(PKCS11Session.import_keypair(pub, priv, imported_key_label, key_type="rsa_4096"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type="rsa_4096"))

        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(identifier == b"\xb9\xdc.\x1a\x15\x8eQ\xd5;\x1d\xab*#\xbcFH\x05\xb4QH")
        self.assertTrue(isinstance(pk_info, str))

        self.assertTrue(imported_key_label in asyncio.run(PKCS11Session.key_labels()))
        with self.assertRaises(MultipleObjectsReturned):
            asyncio.run(PKCS11Session.import_keypair(pub, priv, imported_key_label, key_type="rsa_4096"))

        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"
        signature = asyncio.run(PKCS11Session.sign(imported_key_label, data_to_be_signed, key_type="rsa_4096"))
        self.assertTrue(isinstance(signature, bytes))
        self.assertTrue(signature == signature_val)
        self.assertTrue(
            asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature, key_type="rsa_4096"))
        )
        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="rsa_4096"
                )
            )
        )

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(imported_key_label, key_type="rsa_4096"))

    def test_import_keypair_ed25519(self) -> None:
        """Import keypair with key_label in the PKCS11 device.

        Generate pub and priv with
        openssl genpkey -algorithm ed25519 -out private.pem
        openssl pkey -in private.pem -outform DER -out private.key
        openssl pkey -in private.pem -pubout -outform DER -out public.key
        """

        priv = b"0.\x02\x01\x000\x05\x06\x03+ep\x04\"\x04 ~n\xc3\xf5\x93\xb7\x1dYgO\x88\x90K\x9b\xe1&h\x0f\x0e@\xddh\xcc'\x98\xd2\xe7\xe7\xfb\x03T\xd1"  # pylint: disable=C0301
        pub = b"0*0\x05\x06\x03+ep\x03!\x00\x8b\x07J\x99[\xe4g\x9c\xd9\xfa'\x03\x9a\xb8\x01>&\x10\x1cay~\xadf\x80j\x9eq;\xb3\xf3\x9c"  # pylint: disable=C0301

        for key_type in ["ed25519", None]:
            imported_key_label = "imported_keypair_label_ed25519"
            new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)

            asyncio.run(PKCS11Session.create_keypair(new_key_label, key_type=key_type))
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label, key_type))

            asyncio.run(PKCS11Session.import_keypair(pub, priv, imported_key_label, key_type="ed25519"))
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(imported_key_label, key_type))

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
                PKCS11Session.sign(imported_key_label, data_to_be_signed, verify_signature=True, key_type=key_type)
            )
            self.assertTrue(isinstance(signature, bytes))
            self.assertTrue(
                signature
                == b"%\xf4\xadk\x08\xb5\xb4u\xc0Y&\x12\xad\xafn\xed\xd3WJ\x8d(\xb8\xbf\xcb\xc9\x19\xf3\x13\x0e\x9a\x89\xec\x8dk\xd7g;\xb5\xb1\x06;!\x12\xcbW\xcdsT\xce\x87\xe2\xf2\x97\x9eX\xb0i\xccn\xf7\x88\xcd`\r"  # pylint: disable=C0301
            )
            self.assertTrue(
                asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature, key_type=key_type))
            )
            self.assertFalse(
                asyncio.run(
                    PKCS11Session.verify(
                        imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type=key_type
                    )
                )
            )

            # Delete the test key
            asyncio.run(PKCS11Session.delete_keypair(imported_key_label, key_type=key_type))
            asyncio.run(PKCS11Session.delete_keypair(new_key_label, key_type=key_type))

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

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(imported_key_label, key_type="ed448"))
        asyncio.run(PKCS11Session.delete_keypair(new_key_label, key_type="ed448"))

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

        self.assertTrue(
            asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature, key_type="secp256r1"))
        )
        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="secp256r1"
                )
            )
        )

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(imported_key_label, key_type="secp256r1"))
        asyncio.run(PKCS11Session.delete_keypair(new_key_label, key_type="secp256r1"))

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

        self.assertTrue(
            asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature, key_type="secp384r1"))
        )
        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="secp384r1"
                )
            )
        )

        # Delete the test keys
        asyncio.run(PKCS11Session.delete_keypair(imported_key_label, key_type="secp384r1"))
        asyncio.run(PKCS11Session.delete_keypair(new_key_label, key_type="secp384r1"))

    def test_import_keypair_secp521r1(self) -> None:
        """Import keypair with key_label in the PKCS11 device.

        openssl ecparam -name secp521r1 -genkey -noout -out private.pem
        openssl ec -in private.pem -outform DER -out private.key
        openssl ec -in private.pem -pubout -out public.pem
        openssl ec -in private.pem -pubout -outform DER -out public.key

        """

        with self.assertRaises(ValueError):
            asyncio.run(PKCS11Session.import_keypair(b"dummy", b"dummy_data", "dummy", key_type="dummy_key_type"))

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

        self.assertTrue(
            asyncio.run(PKCS11Session.verify(imported_key_label, data_to_be_signed, signature, key_type="secp521r1"))
        )
        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    imported_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="secp521r1"
                )
            )
        )

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(imported_key_label, key_type="secp521r1"))
        asyncio.run(PKCS11Session.delete_keypair(new_key_label, key_type="secp521r1"))

    def test_create_keypair(self) -> None:
        """Create keypair with key_label in the PKCS11 device."""

        with self.assertRaises(ValueError):
            asyncio.run(PKCS11Session.create_keypair("dummy", key_type="dummy_key_type"))

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label, key_type="rsa_2048"))
        pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label, key_type="rsa_2048"))
        self.assertTrue(isinstance(identifier, bytes))
        self.assertTrue(isinstance(pk_info, str))

        with self.assertRaises(MultipleObjectsReturned):
            asyncio.run(PKCS11Session.create_keypair(new_key_label, key_type="rsa_2048"))
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label, key_type="rsa_2048"))

        asyncio.run(PKCS11Session.create_keypair(new_key_label[:-1], key_type="rsa_2048"))
        pk_info2, identifier2 = asyncio.run(PKCS11Session.public_key_data(new_key_label[:-1], key_type="rsa_2048"))
        self.assertTrue(isinstance(identifier2, bytes))
        self.assertTrue(isinstance(pk_info2, str))

        self.assertTrue(identifier != identifier2)
        self.assertTrue(pk_info != pk_info2)

        asyncio.run(PKCS11Session.create_keypair(new_key_label[:-2], key_type="rsa_4096"))
        pk_info2, identifier2 = asyncio.run(PKCS11Session.public_key_data(new_key_label[:-2], key_type="rsa_4096"))
        self.assertTrue(isinstance(identifier2, bytes))
        self.assertTrue(isinstance(pk_info2, str))

        # Test key_labels
        pk_info3, identifier3 = asyncio.run(PKCS11Session.create_keypair(new_key_label[:-3], key_type="rsa_4096"))
        key_labels = asyncio.run(PKCS11Session.key_labels())
        self.assertTrue(isinstance(key_labels, dict))
        self.assertTrue(len(key_labels) > 0)
        for label in key_labels:
            self.assertTrue(isinstance(label, str))
        self.assertTrue(new_key_label[:-3] in key_labels)
        self.assertFalse("should_not_exists_1232353523" in key_labels)

        pk_info3_1, identifier3_1 = asyncio.run(PKCS11Session.public_key_data(new_key_label[:-3], key_type="rsa_4096"))
        self.assertTrue(pk_info3 == pk_info3_1)
        self.assertTrue(identifier3 == identifier3_1)

        # Delete the test keys
        asyncio.run(PKCS11Session.delete_keypair(new_key_label, key_type="rsa_4096"))
        asyncio.run(PKCS11Session.delete_keypair(new_key_label[:-1], key_type="rsa_4096"))
        asyncio.run(PKCS11Session.delete_keypair(new_key_label[:-2], key_type="rsa_4096"))
        asyncio.run(PKCS11Session.delete_keypair(new_key_label[:-3], key_type="rsa_4096"))

    def test_delete_keypair(self) -> None:
        """
        Delete keypair with key_label in the PKCS11 device.
        """

        with self.assertRaises(ValueError):
            asyncio.run(PKCS11Session.delete_keypair("dummy", key_type="dummy_key_type"))

        for key_type in key_types:
            new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)

            with self.assertRaises(NoSuchKey):
                asyncio.run(PKCS11Session.delete_keypair(new_key_label, key_type=key_type))

            asyncio.run(PKCS11Session.create_keypair(new_key_label, key_type=key_type))
            asyncio.run(PKCS11Session.delete_keypair(new_key_label, key_type=key_type))

            with self.assertRaises(NoSuchKey):
                _, _ = asyncio.run(PKCS11Session.public_key_data(new_key_label, key_type=key_type))

    def test_get_public_key_data(self) -> None:
        """
        Get key identifier from public key with key_label in the PKCS11 device.
        """

        with self.assertRaises(ValueError):
            asyncio.run(PKCS11Session.public_key_data("dummy", key_type="dummy_key_type"))

        for key_type in key_types:
            new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
            asyncio.run(PKCS11Session.create_keypair(new_key_label, key_type=key_type))
            pk_info, identifier = asyncio.run(PKCS11Session.public_key_data(new_key_label, key_type=key_type))
            self.assertTrue(isinstance(identifier, bytes))
            self.assertTrue(isinstance(pk_info, str))

            with self.assertRaises(NoSuchKey):
                _, _ = asyncio.run(PKCS11Session.public_key_data(new_key_label[:-2], key_type=key_type))

            # Delete the test key
            asyncio.run(PKCS11Session.delete_keypair(new_key_label, key_type=key_type))

    def test_sign_and_verify_data_rsa(self) -> None:
        """
        Sign bytes with key_label in the PKCS11 device.
        """

        with self.assertRaises(ValueError):
            asyncio.run(PKCS11Session.sign("dummy", b"dummy_data", key_type="dummy_key_type"))

        with self.assertRaises(ValueError):
            asyncio.run(PKCS11Session.verify("dummy", b"dummy_data", b"dummy_sig", key_type="dummy_key_type"))

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label, key_type="rsa_2048"))
        data_to_be_signed = b"MY TEST DATA TO BE SIGNED HERE"

        signature = asyncio.run(PKCS11Session.sign(new_key_label, data_to_be_signed, key_type="rsa_2048"))
        self.assertTrue(isinstance(signature, bytes))

        signature = asyncio.run(PKCS11Session.sign(new_key_label, data_to_be_signed, key_type="rsa_2048"))
        self.assertTrue(isinstance(signature, bytes))

        self.assertTrue(
            asyncio.run(PKCS11Session.verify(new_key_label, data_to_be_signed, signature, key_type="rsa_2048"))
        )

        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(new_key_label, data_to_be_signed, b"NOT VALID SIGNATURE HERE", key_type="rsa_2048")
            )
        )

        self.assertFalse(
            asyncio.run(
                PKCS11Session.verify(
                    new_key_label,
                    data_to_be_signed,
                    b"NOT VALID SIGNATURE HERE",
                    key_type="rsa_2048",
                )
            )
        )

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(new_key_label, key_type="rsa_2048"))
