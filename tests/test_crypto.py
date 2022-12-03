"""
Test out crypto module
"""
import unittest

from src.python_x509_pkcs11.crypto import (
    ASN1_INIT,
    ASN1_INTEGER_CODE,
    ASN1_SECP521R1_CODE,
    convert_asn1_ec_signature,
    convert_rs_ec_signature,
)

# Replace the above with this should you use this code
# from python_x509_pkcs11.ca import create

curves = ["secp256r1", "secp384r1", "secp521r1"]

signatures = [
    b"0F\x02!\x00\x86X\x9a\x11\x90\x96\x80\xeb6\xbe\xa8\x8c\x8f\x15\xa3\xc0\xde\xef\xf4\xb1\xe4\x14S)\x03\xaf\x1b\xe3\xa1\xd9=\xc5\x02!\x00\x92K\x15\x0f\xea\x8aE\x02F\xc0\xd9\xa6\x11\xe7/\xc4R\xa1\xac\xf7e_\xf9\x1e\x00\xdd%\xf2\xbc\xf3,\x00",  # pylint: disable=C0301
    b"0e\x021\x00\xbc\x0cIu\xd8S\xdb\x14\x18\xa3#\xc4\xbc\xa4\xbcb*\x1a|\xb5\xb8\xf9\x7fT6\xd8\xe4\xe6\xd5Hq\x1d\xf6\xfe\x96\x1c\xf1\xec\x86\x019\xa8U\xc2.\xbe\xf6\xba\x020\x07\xe9\xbcyb\xc5@~q\x97\xb0\x13\x02\xa5\x81:.\xaede\xf4]Q\x18a\x00\x82\rA+\x15\x07^\x1f\xb2\x07\xc1\x9bi\xe3\xb4(\xd0\xa4\xb7\xbf\x98\xf5",  # pylint: disable=C0301
    b'0\x81\x87\x02B\x01v\x1f\xa5\xb3\x87\x1d\x91i\x13\xe0\xb8\xc0:|Lx\xa3\xa5\xf2\x1d\n\xa6\x88\xccK8L\xdb\xed\x7f\xbd\x125200\xb6e\x93\xd5\xe3\xe2\x9fe\x88ml\xe6\xaa\xc6\\\x15\x1aM\xd2\x97Q\x90\xc7\x08\x1d\x8bu\xd0U\x02AU\xacA\xea\x05\xc3\xf3\x06\x9eGI\x91-\xda\xc2wh\xbb+\t\x9aY\x02\x98\xa3t\x18\x02\x16\xd6\xff\xda\xdc\x0f\xdc/\x13\x9d\x97\xe8\x0b\x0c>\xdc\x1f"\xa2\xdb\xa6\xed\x8c\xd4\xa0S3\xab\xb4\xb3FN\xba\x1b\xc6\x83\x1a',  # pylint: disable=C0301
]


class TestCrypto(unittest.TestCase):
    """
    Test our crypto module
    """

    def test_convert(self) -> None:
        """
        Convert asn1 to r&s and then convert back, ensure equal
        """

        for index, curve in enumerate(curves):
            r_s = convert_asn1_ec_signature(signatures[index], key_type=curve)
            asn1_conv = convert_rs_ec_signature(r_s, curve)
            self.assertTrue(asn1_conv == signatures[index])

    def test_invalid_input(self) -> None:
        """
        Check invalid input
        """

        with self.assertRaises(ValueError):
            convert_asn1_ec_signature(b"dummy", key_type="rsa_4096")
        with self.assertRaises(ValueError):
            convert_rs_ec_signature(b"dummy", key_type="rsa_4096")

        for curve in curves:
            with self.assertRaises(ValueError):
                convert_asn1_ec_signature(b"dummy", key_type=curve)

        for curve in curves:
            with self.assertRaises(ValueError):
                convert_asn1_ec_signature(b"dummy", key_type=curve)

            with self.assertRaises(ValueError):
                convert_asn1_ec_signature(bytes(bytearray([ASN1_INIT]) + b"dummydummy"), key_type=curve)

            if curve == "secp521r1":
                with self.assertRaises(ValueError):
                    convert_asn1_ec_signature(
                        bytes(bytearray([ASN1_INIT]) + bytearray([ASN1_SECP521R1_CODE]) + b"dummydummy"), key_type=curve
                    )

                with self.assertRaises(IndexError):
                    convert_asn1_ec_signature(
                        bytes(
                            bytearray([ASN1_INIT])
                            + bytearray([ASN1_SECP521R1_CODE])
                            + bytearray([80])
                            + bytearray([ASN1_INTEGER_CODE])
                            + b"dummsfsdfsdfydummy"
                        ),
                        key_type=curve,
                    )
            else:
                with self.assertRaises(ValueError):
                    convert_asn1_ec_signature(bytes(bytearray([ASN1_INIT]) + b"dummydummy"), key_type=curve)
                with self.assertRaises(IndexError):
                    convert_asn1_ec_signature(
                        bytes(
                            bytearray([ASN1_INIT])
                            + bytearray([80])
                            + bytearray([ASN1_INTEGER_CODE])
                            + b"dummsfsdfsdfydummy"
                        ),
                        key_type=curve,
                    )
