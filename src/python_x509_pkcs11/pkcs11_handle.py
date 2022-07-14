"""Module which handles a PKCS11 session and its exposed methods

# Better to keep a pkcs11 session reference all the time
# and then when it fails to open a new session for performance
# See PKCS11Session._healthy_session()

Exposes the functions:
- import_keypair()
- create_keypair()
- key_labels()
- sign()
- verify()
- public_key_data()
"""

import typing
from typing import Tuple, List
from types import FrameType
import hashlib
from threading import Lock, Thread
import os

from asn1crypto.keys import (
    PublicKeyInfo,
    PublicKeyAlgorithm,
    RSAPublicKey,
    PublicKeyAlgorithmId,
)
from pkcs11.exceptions import NoSuchKey, SignatureInvalid, MultipleObjectsReturned
from pkcs11 import KeyType, ObjectClass, Mechanism, lib, Session, Token, Attribute
from pkcs11.util.rsa import encode_rsa_public_key, decode_rsa_public_key, decode_rsa_private_key

from .error import PKCS11TimeoutException, PKCS11UnknownErrorException

LOCK = Lock()
DEBUG = False
TIMEOUT = 6  # Seconds


class PKCS11Session:
    """Persistent PKCS11 session wrapper."""

    _session_status: int = 9
    session: Session = None
    token: Token = None

    @classmethod
    def _open_session(cls, force: bool = False) -> None:

        cls._session_status = 9
        try:
            if force or cls.session is None:
                pkcs11_lib = lib(os.environ["PKCS11_MODULE"])
                cls.token = pkcs11_lib.get_token(token_label=os.environ["PKCS11_TOKEN"])
                cls.session = cls.token.open(rw=True, user_pin=os.environ["PKCS11_PIN"])

            _ = cls.session.get_key(
                key_type=KeyType.RSA,
                object_class=ObjectClass.PUBLIC_KEY,
                label="test_pkcs11_device_do_not_use",
            )
            cls._session_status = 0
        except NoSuchKey:
            cls._session_status = 0

    @classmethod
    def _healthy_session(cls) -> None:
        p = Thread(target=cls._open_session, args=())
        p.start()
        p.join(timeout=TIMEOUT)

        if p.is_alive() or cls._session_status != 0:
            if DEBUG:
                print("Current PKCS11 session is unhealthy, opening a new session")

            p2 = Thread(target=cls._open_session, args=({"force": True}))
            p2.start()
            p2.join(timeout=TIMEOUT)

            if p2.is_alive():
                raise PKCS11TimeoutException(
                    "ERROR: Could not get a healthy PKCS11 connection in time"
                )
        if cls._session_status != 0:
            raise PKCS11UnknownErrorException("ERROR: Could not get a healthy PKCS11 connection")

    @classmethod
    def import_keypair(
        cls, key_label: str, public_key: bytes, private_key: bytes
    ) -> typing.Tuple[PublicKeyInfo, bytes]:
        """Import a RSA keypair into the PKCS11 device with this label.
        If the label already exists in the PKCS11 device then raise pkcs11.MultipleObjectsReturned.

        Generating public_key and private_key can be done with:
        openssl genrsa -out rsaprivkey.pem 2048
        openssl rsa -inform pem -in rsaprivkey.pem -outform der -out PrivateKey.der
        openssl rsa -in rsaprivkey.pem -RSAPublicKey_out -outform DER -out PublicKey.der

        Returns the data for the x509 'Subject Public Key Info'
        and x509 extension 'Subject Key Identifier' valid for this keypair.

        Parameters:
        key_label (str): Keypair label.
        public_key (bytes): Public RSA key in DER form
        private_key (bytes): Private RSA key in DER form

        Returns:
        typing.Tuple[asn1crypto.keys.PublicKeyInfo, bytes]
        """

        with LOCK:

            # Ensure we get a healthy pkcs11 session
            cls._healthy_session()

            try:
                key_pub = cls.session.get_key(
                    key_type=KeyType.RSA,
                    object_class=ObjectClass.PUBLIC_KEY,
                    label=key_label,
                )
                raise MultipleObjectsReturned
            except NoSuchKey as ex:
                pass

            key_pub = decode_rsa_public_key(public_key)
            key_priv = decode_rsa_private_key(private_key)

            key_pub[Attribute.TOKEN] = True
            key_pub[Attribute.LABEL] = key_label
            key_priv[Attribute.TOKEN] = True
            key_priv[Attribute.LABEL] = key_label

            cls.session.create_object(key_pub)
            cls.session.create_object(key_priv)

            # Create the PublicKeyInfo object
            rsa_pub = RSAPublicKey.load(encode_rsa_public_key(key_pub))
            pki = PublicKeyInfo()
            pka = PublicKeyAlgorithm()
            pka["algorithm"] = PublicKeyAlgorithmId("rsa")
            pki["algorithm"] = pka
            pki["public_key"] = rsa_pub
            return pki, hashlib.sha1(encode_rsa_public_key(key_pub)).digest()

    @classmethod
    def create_keypair(
        cls, key_label: str, key_size: int = 2048
    ) -> typing.Tuple[PublicKeyInfo, bytes]:
        """Create a RSA keypair in the PKCS11 device with this label.
        If the label already exists in the PKCS11 device then raise pkcs11.MultipleObjectsReturned.
        Returns the data for the x509 'Subject Public Key Info'
        and x509 extension 'Subject Key Identifier' valid for this keypair.

        Parameters:
        key_label (str): Keypair label.
        key_size (int = 2048): Size of the key.

        Returns:
        typing.Tuple[asn1crypto.keys.PublicKeyInfo, bytes]
        """

        with LOCK:

            # Ensure we get a healthy pkcs11 session
            cls._healthy_session()

            try:
                key_pub = cls.session.get_key(
                    key_type=KeyType.RSA,
                    object_class=ObjectClass.PUBLIC_KEY,
                    label=key_label,
                )
                raise MultipleObjectsReturned
            except NoSuchKey as ex:
                if DEBUG:
                    print(ex)
                    print("Generating a key since " + "no key with that label was found")
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
            return pki, hashlib.sha1(encode_rsa_public_key(key_pub)).digest()

    @classmethod
    def key_labels(cls) -> List[str]:
        """Return a list of key labels in the PKCS11 device.

        Returns:
        typing.List[str]
        """

        with LOCK:

            # Ensure we get a healthy pkcs11 session
            cls._healthy_session()

            key_labels: List[str] = []
            for obj in cls.session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                    Attribute.KEY_TYPE: KeyType.RSA,
                }
            ):
                key_labels.append(obj.label)
            return key_labels

    @classmethod
    def sign(
        cls,
        key_label: str,
        data: bytes,
        verify_signature: bool = True,
        mechanism: Mechanism = Mechanism.SHA256_RSA_PKCS,
    ) -> bytes:
        """Sign the data: bytes using the private key
        with the label in the PKCS11 device.

        Returns the signed data: bytes for the x509 extension and
        'Authority Key Identifier' valid for this keypair.

        Parameters:
        key_label (str): Keypair label.
        data (bytes): Bytes to be signed.
        verify_signature (bool = True): If is should verify the signature. PKCS11 operations can be expensive
        mechanism (pkcs11.Mechanism = Mechanism.SHA256_RSA_PKCS]): Which signature mechanism to use

        Returns:
        bytes
        """

        with LOCK:
            # Ensure we get a healthy pkcs11 session
            cls._healthy_session()

            # Get private key to sign the data with
            key_priv = cls.session.get_key(
                key_type=KeyType.RSA,
                object_class=ObjectClass.PRIVATE_KEY,
                label=key_label,
            )

            if verify_signature:
                key_pub = cls.session.get_key(
                    key_type=KeyType.RSA,
                    object_class=ObjectClass.PUBLIC_KEY,
                    label=key_label,
                )

            # Sign the data
            signature = key_priv.sign(data, mechanism=Mechanism(mechanism))

            if not isinstance(signature, bytes):
                raise SignatureInvalid

            if verify_signature:
                if not key_pub.verify(data, signature, mechanism=mechanism):
                    raise SignatureInvalid
            return signature

    @classmethod
    def verify(
        cls,
        key_label: str,
        data: bytes,
        signature: bytes,
        mechanism: Mechanism = Mechanism.SHA256_RSA_PKCS,
    ) -> bool:
        """Verify a signature with its data using the private key
        with the label in the PKCS11 device.

        Returns True if the signature is valid.

        Parameters:
        key_label (str): Keypair label.
        data (bytes): Bytes to be signed.
        signature (bytes): The signature.
        mechanism (pkcs11.Mechanism = Mechanism.SHA256_RSA_PKCS): Which signature mechanism to use

        Returns:
        bool
        """

        with LOCK:
            # Ensure we get a healthy pkcs11 session
            cls._healthy_session()

            # Get public key to sign the data with
            key_pub = cls.session.get_key(
                key_type=KeyType.RSA,
                object_class=ObjectClass.PUBLIC_KEY,
                label=key_label,
            )

            if key_pub.verify(data, signature, mechanism=mechanism):
                return True
            return False

    @classmethod
    def public_key_data(cls, key_label: str) -> Tuple[PublicKeyInfo, bytes]:
        """Returns the data for the x509 'Public Key Info'
        and 'Key Identifier' valid for this keypair.

        Parameters:
        key_label (str): Keypair label.

        Returns:
        typing.Tuple[asn1crypto.keys.PublicKeyInfo, bytes]
        """

        with LOCK:
            # Ensure we get a healthy pkcs11 session
            cls._healthy_session()

            key_pub = cls.session.get_key(
                key_type=KeyType.RSA,
                object_class=ObjectClass.PUBLIC_KEY,
                label=key_label,
            )
            # Create the PublicKeyInfo object
            rsa_pub = RSAPublicKey.load(encode_rsa_public_key(key_pub))

            pki = PublicKeyInfo()
            pka = PublicKeyAlgorithm()
            pka["algorithm"] = PublicKeyAlgorithmId("rsa")
            pki["algorithm"] = pka
            pki["public_key"] = rsa_pub

            return pki, hashlib.sha1(encode_rsa_public_key(key_pub)).digest()
