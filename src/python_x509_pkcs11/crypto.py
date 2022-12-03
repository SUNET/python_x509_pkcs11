"""Our crypto module"""
from typing import Dict, Union

from asn1crypto.algos import SignedDigestAlgorithmId
from asn1crypto.keys import OctetString, PrivateKeyInfo, PublicKeyInfo
from pkcs11 import Attribute, Key, KeyType, ObjectClass
from pkcs11.util.ec import encode_named_curve_parameters

ASN1_INTEGER_CODE = 2
ASN1_INIT = 48
ASN1_SECP521R1_CODE = 129


def convert_asn1_ec_signature(signature: bytes, key_type: str) -> bytes:
    """Convert an ASN1 ECDSA signature into R&S format.

    https://stackoverflow.com/questions/66101825/asn-1-structure-of-ecdsa-signature-in-x-509-certificate

    Parameters:
    signature (bytes): The signature.
    key_type (str): Key type.

    Returns:
    bytes
    """

    if key_type not in ["secp256r1", "secp384r1", "secp521r1"]:
        raise ValueError(f"key_type must be in {['secp256r1', 'secp384r1', 'secp521r1']}")

    if key_type == "secp521r1":
        if signature[0] != ASN1_INIT or signature[1] != ASN1_SECP521R1_CODE or signature[3] != ASN1_INTEGER_CODE:
            raise ValueError("ERROR: Signature was not in ASN1 format")
        init_size = 2
    else:
        if signature[0] != ASN1_INIT or signature[2] != ASN1_INTEGER_CODE:
            raise ValueError("ERROR: Signature was not in ASN1 format")
        init_size = 1

    # Get R
    r_data_start = init_size + 3
    r_length = signature[r_data_start - 1]
    r_data = signature[r_data_start : r_data_start + r_length]

    # Get S
    s_data_start = r_data_start + r_length + 2
    s_length = signature[s_data_start - 1]
    s_data = signature[s_data_start : s_data_start + s_length + 1]

    # Get key size for current curve
    if key_type == "secp256r1":
        key_size = 32
    elif key_type == "secp384r1":
        key_size = 48
    else:
        key_size = 66

    # Add missing leading zeros
    while len(r_data) < key_size:
        r_data = bytearray([0]) + r_data
    while len(s_data) < key_size:
        s_data = bytearray([0]) + s_data

    # Remove extra zeros
    while len(r_data) > key_size:
        r_data = r_data[1:]
    while len(s_data) > key_size:
        s_data = s_data[1:]

    return bytes(r_data + s_data)


def convert_rs_ec_signature(signature: bytes, key_type: str) -> bytes:
    """Convert an R&S ECDSA signature into the default ASN1 format.

    https://stackoverflow.com/questions/66101825/asn-1-structure-of-ecdsa-signature-in-x-509-certificate

    Parameters:
    signature (bytes): The signature.
    key_type (str): Key type.

    Returns:
    bytes
    """

    if key_type not in ["secp256r1", "secp384r1", "secp521r1"]:
        raise ValueError(f"key_type must be in {['secp256r1', 'secp384r1', 'secp521r1']}")

    if key_type in ["secp521r1"]:
        asn1_init = [ASN1_INIT, ASN1_SECP521R1_CODE]
    else:
        asn1_init = [ASN1_INIT]

    r_length = int(len(signature) / 2)
    s_length = int(len(signature) / 2)

    # Get R and S bytes
    r_data = signature[:r_length]
    s_data = signature[r_length:]

    # Remove leading zeros, since integers cant start with a 0
    while r_data[0] == 0:
        r_data = r_data[1:]
        r_length -= 1
    while s_data[0] == 0:
        s_data = s_data[1:]
        s_length -= 1

    # Ensure the integers are positive numbers
    if r_data[0] >= 128:
        r_data = bytearray([0]) + r_data[:]
        r_length += 1
    if s_data[0] >= 128:
        s_data = bytearray([0]) + s_data[:]
        s_length += 1

    return bytes(
        bytearray(asn1_init)
        + bytearray([r_length + s_length + 4])
        + bytearray([ASN1_INTEGER_CODE, r_length])
        + r_data
        + bytearray([ASN1_INTEGER_CODE, s_length])
        + s_data
    )


# Taken from https://github.com/danni/python-pkcs11/blob/master/pkcs11/util/ec.py
# Will submit merge request soon
def decode_eddsa_public_key(der: bytes, encode_eddsa_point: bool = True) -> Dict[int, Union[str, int, bytes]]:
    """
    Decode a DER-encoded EdDSA public key as stored by OpenSSL into a dictionary
    of attributes able to be passed to :meth:`pkcs11.Session.create_object`.
    .. note:: **encode_eddsa_point**
        For use as an attribute `EC_POINT` should be DER-encoded (True).
        For key derivation implementations can vary.  Since v2.30 the
        specification says implementations MUST accept a raw `EC_POINT` for
        ECDH (False), however not all implementations follow this yet.
    :param bytes der: DER-encoded key
    :param encode_eddsa_point: See text.
    :rtype: dict(Attribute,*)
    """

    asn1 = PublicKeyInfo.load(der)

    if asn1.algorithm not in ["ed25519", "ed448"]:
        raise ValueError("Wrong algorithm, not an eddsa key!")

    ecpoint = bytes(asn1["public_key"])

    if encode_eddsa_point:
        ecpoint = OctetString(ecpoint).dump()

    return {
        Attribute.KEY_TYPE: KeyType.EC_EDWARDS,
        Attribute.CLASS: ObjectClass.PUBLIC_KEY,
        Attribute.EC_PARAMS: encode_named_curve_parameters(SignedDigestAlgorithmId(asn1.algorithm).dotted),
        Attribute.EC_POINT: ecpoint,
    }


def decode_eddsa_private_key(der: bytes) -> Dict[int, Union[str, int, bytes]]:
    """
    Decode a DER-encoded EdDSA private key as stored by OpenSSL into a dictionary
    of attributes able to be passed to :meth:`pkcs11.Session.create_object`.
    :param bytes der: DER-encoded key
    :rtype: dict(Attribute,*)
    """

    asn1 = PrivateKeyInfo.load(der)
    return {
        Attribute.KEY_TYPE: KeyType.EC_EDWARDS,
        Attribute.CLASS: ObjectClass.PRIVATE_KEY,
        Attribute.EC_PARAMS: encode_named_curve_parameters(SignedDigestAlgorithmId(asn1.algorithm).dotted),
        # Only the last 32/57 bytes is the private key values
        Attribute.VALUE: asn1["private_key"].contents[-32:]
        if asn1.algorithm == "ed25519"
        else asn1["private_key"].contents[-57:],
    }


def encode_eddsa_public_key(key: Key) -> bytes:
    """
    Encode a DER-encoded EdDSA public key as stored by OpenSSL.
    :param PublicKey key: EdDSA public key
    :rtype: bytes
    """

    ecpoint = bytes(OctetString.load(key[Attribute.EC_POINT]))
    ret: bytes = PublicKeyInfo(
        {"algorithm": {"algorithm": "ed25519" if len(ecpoint) == 32 else "ed448"}, "public_key": ecpoint}
    ).dump()
    return ret
