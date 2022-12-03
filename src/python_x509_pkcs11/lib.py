"""Module which have common functions and constants"""

from typing import Dict, List

from asn1crypto.algos import SignedDigestAlgorithm, SignedDigestAlgorithmId
from pkcs11 import KeyType

DEBUG = False

# Key types and sizes we support
key_types: List[str] = [
    "ed25519",
    "ed448",
    "secp256r1",
    "secp384r1",
    "secp521r1",
    "rsa_2048",
    "rsa_4096",
]

key_type_values: Dict[str, KeyType] = {
    "ed25519": KeyType.EC_EDWARDS,
    "ed448": KeyType.EC_EDWARDS,
    "secp256r1": KeyType.EC,
    "secp384r1": KeyType.EC,
    "secp521r1": KeyType.EC,
    "rsa_2048": KeyType.RSA,
    "rsa_4096": KeyType.RSA,
}


def signed_digest_algo(key_type: str) -> SignedDigestAlgorithm:
    """Return a SignedDigestAlgorithm valid for the key type

    Parameters:
    key_type (str): Key type.

    Returns:
    bytes
    """

    if key_type == "ed25519":
        algo = SignedDigestAlgorithm()
        algo["algorithm"] = SignedDigestAlgorithmId("ed25519")
    elif key_type == "ed448":
        algo = SignedDigestAlgorithm()
        algo["algorithm"] = SignedDigestAlgorithmId("ed448")
    elif key_type == "secp256r1":
        algo = SignedDigestAlgorithm()
        algo["algorithm"] = SignedDigestAlgorithmId("sha256_ecdsa")
    elif key_type == "secp384r1":
        algo = SignedDigestAlgorithm()
        algo["algorithm"] = SignedDigestAlgorithmId("sha384_ecdsa")
    elif key_type == "secp521r1":
        algo = SignedDigestAlgorithm()
        algo["algorithm"] = SignedDigestAlgorithmId("sha512_ecdsa")
    elif key_type == "rsa_2048":
        algo = SignedDigestAlgorithm()
        algo["algorithm"] = SignedDigestAlgorithmId("sha256_rsa")
    elif key_type == "rsa_4096":
        algo = SignedDigestAlgorithm()
        algo["algorithm"] = SignedDigestAlgorithmId("sha512_rsa")
    else:
        raise ValueError(f"key_type must be in {key_types}")

    return algo
