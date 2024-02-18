"""Module which have common functions and constants"""

from enum import Enum
from typing import Dict, Set

from asn1crypto.algos import SignedDigestAlgorithm, SignedDigestAlgorithmId
from pkcs11 import KeyType

DEBUG = False


# Enum for Key types and sizes we support
class KEYTYPES(Enum):
    ED25519 = "ed25519"
    ED448 = "ed448"
    SECP256r1 = "secp256r1"
    SECP384r1 = "secp384r1"
    SECP521r1 = "secp521r1"
    RSA2048 = "rsa_2048"
    RSA4096 = "rsa_4096"


# This is the default key type
DEFAULT_KEY_TYPE = KEYTYPES.ED25519

KEY_TYPE_VALUES: Dict[KEYTYPES, KeyType] = {
    KEYTYPES.ED25519: KeyType.EC_EDWARDS,
    KEYTYPES.ED448: KeyType.EC_EDWARDS,
    KEYTYPES.SECP256r1: KeyType.EC,
    KEYTYPES.SECP384r1: KeyType.EC,
    KEYTYPES.SECP521r1: KeyType.EC,
    KEYTYPES.RSA2048: KeyType.RSA,
    KEYTYPES.RSA4096: KeyType.RSA,
}


def get_keytypes_enum(value: str) -> KEYTYPES:
    """Returns the correct enum for the given key type.

    :param value: key type as string.

    :returns: KEYTYPES
    :raises: ValueError if unknown key type.
    """
    if value == "ed25519":
        return KEYTYPES.ED25519
    elif value == "ed448":
        return KEYTYPES.ED448
    elif value == "secp256r1":
        return KEYTYPES.SECP256r1
    elif value == "secp384r1":
        return KEYTYPES.SECP384r1
    elif value == "secp521r1":
        return KEYTYPES.SECP521r1
    elif value == "rsa_2048":
        return KEYTYPES.RSA2048
    elif value == "rsa_4096":
        return KEYTYPES.RSA4096
    raise ValueError(f"{value} key type is not supported.")


def signed_digest_algo(key_type: KEYTYPES) -> SignedDigestAlgorithm:
    """Return a SignedDigestAlgorithm valid for the key type

    Parameters:
    key_type (KEYTYPES): Key type.

    Returns:
    bytes
    """

    algo = SignedDigestAlgorithm()
    if key_type == KEYTYPES.ED25519:
        algo["algorithm"] = SignedDigestAlgorithmId("ed25519")
    elif key_type == KEYTYPES.ED448:
        algo["algorithm"] = SignedDigestAlgorithmId("ed448")
    elif key_type == KEYTYPES.SECP256r1:
        algo["algorithm"] = SignedDigestAlgorithmId("sha256_ecdsa")
    elif key_type == KEYTYPES.SECP384r1:
        algo["algorithm"] = SignedDigestAlgorithmId("sha384_ecdsa")
    elif key_type == KEYTYPES.SECP521r1:
        algo["algorithm"] = SignedDigestAlgorithmId("sha512_ecdsa")
    elif key_type == KEYTYPES.RSA2048:
        algo["algorithm"] = SignedDigestAlgorithmId("sha256_rsa")
    elif key_type == KEYTYPES.RSA4096:
        algo["algorithm"] = SignedDigestAlgorithmId("sha512_rsa")

    return algo
