"""Module which have common functions and constants"""

from typing import Dict, List
from asn1crypto.algos import SignedDigestAlgorithm, SignedDigestAlgorithmId

DEBUG = False

# Key types and sizes we support
key_types: Dict[str, List[int]] = {
    "RSA": [2048, 4096],
    "ed25519": [256],
}

key_type_values: Dict[str, int] = {
    "RSA": 0x00000000,
    "ed25519": 0x00000040,
}


def signed_digest_algo(key_type: str) -> SignedDigestAlgorithm:
    """Return a SignedDigestAlgorithm valid for the key type

    Parameters:
    key_type (str): Key type.

    Returns:
    bytes
    """

    if key_type == "RSA":
        algo = SignedDigestAlgorithm()
        algo["algorithm"] = SignedDigestAlgorithmId("sha256_rsa")
    else:  # key_type == "ed25519":
        algo = SignedDigestAlgorithm()
        algo["algorithm"] = SignedDigestAlgorithmId("ed25519")

    return algo
