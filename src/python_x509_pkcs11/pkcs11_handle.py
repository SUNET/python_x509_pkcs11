"""
Module which handles a PKCS11 session and its exposed methods

# Better to keep a pkcs11 session reference all the time
# and then when it fails to open a new session for performance
# See PKCS11Session._healthy_session()

Exposes the functions:
- sign()
- create_keypair_if_not_exists()
- create_keypair()
- key_identifier()
"""

import typing
from types import FrameType
import hashlib
import threading
import os
import signal
from contextlib import contextmanager
from collections.abc import Generator

from asn1crypto.keys import (
    PublicKeyInfo,
    PublicKeyAlgorithm,
    RSAPublicKey,
    PublicKeyAlgorithmId,
)
from pkcs11.exceptions import NoSuchKey
from pkcs11 import KeyType, ObjectClass, Mechanism, lib, Session, Token
from pkcs11.util.rsa import encode_rsa_public_key

from .error import PKCS11TimeoutException

LOCK = threading.Lock()
DEBUG = False


@contextmanager
def _time_limit(seconds: int) -> Generator[None, None, None]:
    """
    Context manager to call PKCS11 functions with a time limit.

    Parameters:
    seconds (int): Time limit in seconds.

    Returns:
    None

    """

    def signal_handler(signum: int, frame: typing.Optional[FrameType]) -> None:
        raise PKCS11TimeoutException()

    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)

    try:
        yield
    finally:
        signal.alarm(0)


class PKCS11Session:
    """
    Persistent PKCS11 session wrapper.
    """

    session: Session = None
    token: Token = None

    @classmethod
    def _healthy_session(cls) -> None:
        """
        Check if our persistent PKCS11 session is healthy.
        If not then open a new session.

        Parameters:

        Returns:
        None

        """

        try:
            with _time_limit(3):
                if cls.session.token.label != os.environ["PKCS11_TOKEN"]:
                    cls.session.close()
                    pkcs11_lib = lib(os.environ["PKCS11_MODULE"])
                    cls.token = pkcs11_lib.get_token(
                        token_label=os.environ["PKCS11_TOKEN"]
                    )
                    cls.session = cls.token.open(
                        rw=True, user_pin=os.environ["PKCS11_PIN"]
                    )
        except Exception as ex:  # pylint: disable=broad-except
            pkcs11_lib = lib(os.environ["PKCS11_MODULE"])
            cls.token = pkcs11_lib.get_token(token_label=os.environ["PKCS11_TOKEN"])
            cls.session = cls.token.open(rw=True, user_pin=os.environ["PKCS11_PIN"])
            if DEBUG:
                print(ex)
                print("Opening a new pkcs11 session")

    @classmethod
    def sign(cls, key_label: str, data: bytes) -> bytes:
        """
        Sign the data: bytes using the private key
        with the label in the PKCS11 device.

        Returns the signed data: bytes for the x509 extension and
        'Authority Key Identifier' valid for this keypair.

        Parameters:
        key_label (str): Keypair label.
        data (bytes): Bytes to be signed.

        Returns:
        typing.Tuple[PublicKeyInfo, bytes]

        """

        with LOCK:
            # Ensure we get a healthy pkcs11 session
            cls._healthy_session()

            try:
                with _time_limit(4):
                    # Get private key to sign the data with
                    key_priv = cls.session.get_key(
                        key_type=KeyType.RSA,
                        object_class=ObjectClass.PRIVATE_KEY,
                        label=key_label,
                    )

                    # Sign the data
                    signature = key_priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
                    assert isinstance(signature, bytes)
                    return signature
            except Exception as ex:
                raise ex

    @classmethod
    def create_keypair_if_not_exists(
        cls, key_label: str, key_size: int
    ) -> typing.Tuple[PublicKeyInfo, bytes]:
        """
        Create a RSA keypair in the PKCS11 device with this label.
        If the label exists then return the data for that keypair
        Returns the data for the x509 'Subject Public Key Info'
        and x509 extension 'Subject Key Identifier' valid for this keypair.

        Parameters:
        key_label (str): Keypair label.
        key_size (int): Size of the key.

        Returns:
        typing.Tuple[PublicKeyInfo, bytes]

        """

        with LOCK:
            # Ensure we get a healthy pkcs11 session
            cls._healthy_session()

            try:
                with _time_limit(4):
                    try:
                        key_pub = cls.session.get_key(
                            key_type=KeyType.RSA,
                            object_class=ObjectClass.PUBLIC_KEY,
                            label=key_label,
                        )

                    except NoSuchKey as ex:
                        if DEBUG:
                            print(ex)
                            print(
                                "Generating a key since "
                                + "no key with that label was found"
                            )

                        # Generate the rsa keypair
                        key_pub, _ = cls.session.generate_keypair(
                            KeyType.RSA, key_size, store=True, label=key_label
                        )

                    # Create the PublicKeyInfo object
                    rsa_pub = RSAPublicKey.load(encode_rsa_public_key(key_pub))

                    pki = PublicKeyInfo()
                    pka = PublicKeyAlgorithm()
                    pka["algorithm"] = PublicKeyAlgorithmId("rsa")
                    pki["algorithm"] = pka
                    pki["public_key"] = rsa_pub

                    return (
                        pki,
                        hashlib.sha1(encode_rsa_public_key(key_pub)).digest(),
                    )
            except Exception as ex:
                raise ex

    @classmethod
    def create_keypair(
        cls, key_label: str, key_size: int
    ) -> typing.Tuple[PublicKeyInfo, bytes]:
        """
        Create a RSA keypair in the PKCS11 device with this label.
        Returns the data for the x509 'Subject Public Key Info'
        and x509 extension 'Subject Key Identifier' valid for this keypair.

        Parameters:
        key_label (str): Keypair label.
        key_size (int): Size of the key.

        Returns:
        typing.Tuple[PublicKeyInfo, bytes]

        """

        with LOCK:
            # Ensure we get a healthy pkcs11 session
            cls._healthy_session()

            try:
                with _time_limit(4):
                    # Generate the rsa keypair
                    key_pub, _ = cls.session.generate_keypair(
                        KeyType.RSA, key_size, store=True, label=key_label
                    )

                    # Create the PublicKeyInfo object
                    rsa_pub = RSAPublicKey.load(encode_rsa_public_key(key_pub))

                    pki = PublicKeyInfo()
                    pka = PublicKeyAlgorithm()
                    pka["algorithm"] = PublicKeyAlgorithmId("rsa")
                    pki["algorithm"] = pka
                    pki["public_key"] = rsa_pub

                    return (
                        pki,
                        hashlib.sha1(encode_rsa_public_key(key_pub)).digest(),
                    )
            except Exception as ex:
                raise ex

    @classmethod
    def key_identifier(cls, key_label: str) -> bytes:
        """
        Returns the bytes for x509 extension 'Authority Key Identifier'
        valid for this keypair.

        Parameters:
        key_label (str): Keypair label.

        Returns:
        bytes

        """

        with LOCK:
            # Ensure we get a healthy pkcs11 session
            cls._healthy_session()

            try:
                with _time_limit(3):
                    key_pub = cls.session.get_key(
                        key_type=KeyType.RSA,
                        object_class=ObjectClass.PUBLIC_KEY,
                        label=key_label,
                    )

                    return hashlib.sha1(encode_rsa_public_key(key_pub)).digest()
            except Exception as ex:
                raise ex
