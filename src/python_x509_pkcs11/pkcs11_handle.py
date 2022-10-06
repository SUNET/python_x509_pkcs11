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

from typing import Tuple, AsyncIterator, Dict, Union, Any
from threading import Lock, Thread
import os
from concurrent.futures import ThreadPoolExecutor
from asyncio import get_event_loop, sleep
from contextlib import asynccontextmanager

from asn1crypto import pem as asn1_pem
from asn1crypto.keys import (
    OctetString,
    PrivateKeyInfo,
    PublicKeyAlgorithm,
    PublicKeyAlgorithmId,
    PublicKeyInfo,
    RSAPublicKey,
)
from pkcs11 import (
    Attribute,
    KeyType,
    lib,
    Mechanism,
    ObjectClass,
    PublicKey,
    Session,
    Token,
)
from pkcs11.exceptions import NoSuchKey, SignatureInvalid, MultipleObjectsReturned
from pkcs11.util.rsa import encode_rsa_public_key, decode_rsa_public_key, decode_rsa_private_key
from pkcs11.util.ec import encode_named_curve_parameters

from .error import PKCS11TimeoutException, PKCS11UnknownErrorException
from .lib import DEBUG, key_types, key_type_values

TIMEOUT = 3  # Seconds
pool = ThreadPoolExecutor()

# Taken from https://github.com/danni/python-pkcs11/blob/master/pkcs11/util/ec.py
# Will submit merge request soon
def decode_ed25519_public_key(der: bytes, encode_ec_point: bool = True) -> Dict[int, Any]:
    """
    Decode a DER-encoded EC public key as stored by OpenSSL into a dictionary
    of attributes able to be passed to :meth:`pkcs11.Session.create_object`.
    .. note:: **encode_ec_point**
        For use as an attribute `EC_POINT` should be DER-encoded (True).
        For key derivation implementations can vary.  Since v2.30 the
        specification says implementations MUST accept a raw `EC_POINT` for
        ECDH (False), however not all implementations follow this yet.
    :param bytes der: DER-encoded key
    :param encode_ec_point: See text.
    :rtype: dict(Attribute,*)
    """

    asn1 = PublicKeyInfo.load(der)

    assert asn1.algorithm == "ed25519", "Wrong algorithm, not an ed25519 key!"

    ecpoint = bytes(asn1["public_key"])

    if encode_ec_point:
        ecpoint = OctetString(ecpoint).dump()

    return {
        Attribute.KEY_TYPE: KeyType.EC_EDWARDS,
        Attribute.CLASS: ObjectClass.PUBLIC_KEY,
        Attribute.EC_PARAMS: b"\x13\x0cedwards25519",
        Attribute.EC_POINT: ecpoint,
    }


def decode_ed25519_private_key(der: bytes) -> Dict[int, Any]:
    """
    Decode a DER-encoded EC private key as stored by OpenSSL into a dictionary
    of attributes able to be passed to :meth:`pkcs11.Session.create_object`.
    :param bytes der: DER-encoded key
    :rtype: dict(Attribute,*)
    """

    asn1 = PrivateKeyInfo.load(der)
    return {
        Attribute.KEY_TYPE: KeyType.EC_EDWARDS,
        Attribute.CLASS: ObjectClass.PRIVATE_KEY,
        Attribute.EC_PARAMS: b"\x13\x0cedwards25519",
        # Apparently only the last 32 bytes is the private key values
        Attribute.VALUE: asn1["private_key"].contents[-32:],
    }


def encode_ed25519_public_key(key: PublicKey) -> PublicKeyInfo:
    """
    Encode a DER-encoded EC public key as stored by OpenSSL.
    :param PublicKey key: EC public key
    :rtype: bytes
    """

    ecpoint = bytes(OctetString.load(key[Attribute.EC_POINT]))

    return PublicKeyInfo(
        {
            "algorithm": {
                "algorithm": "ed25519",
            },
            "public_key": ecpoint,
        }
    )


@asynccontextmanager
async def async_lock(lock: Lock) -> AsyncIterator[None]:
    """Used as a simple async lock"""
    loop = get_event_loop()
    await loop.run_in_executor(pool, lock.acquire)
    try:
        yield  # the lock is held
    finally:
        lock.release()


class PKCS11Session:
    """Persistent PKCS11 session wrapper."""

    _session_status: int = 9
    _lock = Lock()

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
    async def _healthy_session(cls) -> None:
        thread = Thread(target=cls._open_session, args=())
        thread.start()
        thread.join(timeout=TIMEOUT)

        if thread.is_alive() or cls._session_status != 0:
            if DEBUG:
                print("Current PKCS11 session is unhealthy, opening a new session")

            thread2 = Thread(target=cls._open_session, args=({"force": True}))
            thread2.start()

            # yield to other coroutines while we wait for thread2 to join
            await sleep(0)

            thread2.join(timeout=TIMEOUT)

            if thread2.is_alive():
                raise PKCS11TimeoutException("ERROR: Could not get a healthy PKCS11 connection in time")
        if cls._session_status != 0:
            raise PKCS11UnknownErrorException("ERROR: Could not get a healthy PKCS11 connection")

    @classmethod
    async def import_keypair(cls, public_key: bytes, private_key: bytes, key_label: str, key_type: str) -> None:
        """Import a DER encoded keypair into the PKCS11 device with this label.
        If the label already exists in the PKCS11 device then raise pkcs11.MultipleObjectsReturned.

        Generating public_key and private_key can be done with:
        openssl genpkey -algorithm ed25519 -out private.pem
        openssl pkey -in private.pem -outform DER -out private.key
        openssl pkey -in private.pem -pubout -out public.pem
        openssl pkey -in private.pem -pubout -outform DER -out public.key

        Parameters:
        public_key (bytes): Public RSA key in DER form.
        private_key (bytes): Private RSA key in DER form.
        key_label (str): Keypair label.
        key_type (str = "ed25519"): Key type.

        Returns:
        None
        """

        if key_type not in key_types:
            raise ValueError(f"key_type must be in {key_types}")

        async with async_lock(cls._lock):
            # Ensure we get a healthy pkcs11 session
            await cls._healthy_session()

            try:
                key_pub = cls.session.get_key(
                    key_type=key_type_values[key_type],
                    object_class=ObjectClass.PUBLIC_KEY,
                    label=key_label,
                )
                raise MultipleObjectsReturned
            except NoSuchKey:
                pass

            if key_type == "RSA":
                key_pub = decode_rsa_public_key(public_key)
                key_priv = decode_rsa_private_key(private_key)

            else:  # key_type == "ed25519":
                key_pub = decode_ed25519_public_key(public_key)
                key_priv = decode_ed25519_private_key(private_key)

            key_pub[Attribute.TOKEN] = True
            key_pub[Attribute.LABEL] = key_label
            key_priv[Attribute.TOKEN] = True
            key_priv[Attribute.LABEL] = key_label
            cls.session.create_object(key_pub)
            cls.session.create_object(key_priv)

    @classmethod
    async def create_keypair(cls, key_label: str, key_size: int = 2048, key_type: str = "ed25519") -> Tuple[str, bytes]:
        """Create a RSA keypair in the PKCS11 device with this label.
        If the label already exists in the PKCS11 device then raise pkcs11.MultipleObjectsReturned.
        Returns the data for the x509 'Subject Public Key Info'
        and x509 extension 'Subject Key Identifier' valid for this keypair.

        Parameters:
        key_label (str): Keypair label.
        key_size (int = 2048): Size of the key.
        key_type (str = "ed25519"): Key type.


        Returns:
        typing.Tuple[str, bytes]
        """

        if key_type not in key_types:
            raise ValueError(f"key_type must be in {key_types}")

        async with async_lock(cls._lock):
            # Ensure we get a healthy pkcs11 session
            await cls._healthy_session()

            try:
                key_pub = cls.session.get_key(
                    key_type=key_type_values[key_type],
                    object_class=ObjectClass.PUBLIC_KEY,
                    label=key_label,
                )
                raise MultipleObjectsReturned
            except NoSuchKey as ex:
                if DEBUG:
                    print(ex)
                    print("Generating a key since " + "no key with that label was found")
                # Generate the rsa keypair
                if key_type == "RSA":
                    key_pub, _ = cls.session.generate_keypair(KeyType.RSA, key_size, store=True, label=key_label)
                else:  # key_type == "ed25519":
                    parameters = cls.session.create_domain_parameters(
                        KeyType.EC_EDWARDS,
                        {Attribute.EC_PARAMS: encode_named_curve_parameters("1.3.101.112")},
                        local=True,
                    )
                    key_pub, _ = parameters.generate_keypair(
                        mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN, store=True, label=key_label
                    )

            if key_type == "RSA":
                # Create the PublicKeyInfo object
                rsa_pub = RSAPublicKey.load(encode_rsa_public_key(key_pub))
                pki = PublicKeyInfo()
                pka = PublicKeyAlgorithm()
                pka["algorithm"] = PublicKeyAlgorithmId("rsa")
                pki["algorithm"] = pka
                pki["public_key"] = rsa_pub
            else:  # key_type == "ed25519":
                pki = encode_ed25519_public_key(key_pub)

            key_pub_pem: bytes = asn1_pem.armor("PUBLIC KEY", pki.dump())
            return key_pub_pem.decode("utf-8"), pki.sha1

    @classmethod
    async def key_labels(cls) -> Dict[str, str]:
        """Return a dict of key labels as keys and key type as values in the PKCS11 device.

        Returns:
        typing.Dict[str, str]
        """

        async with async_lock(cls._lock):
            # Ensure we get a healthy pkcs11 session
            await cls._healthy_session()

            key_labels: Dict[str, str] = {}
            for key_type in key_types:
                for obj in cls.session.get_objects(
                    {
                        Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                        Attribute.KEY_TYPE: key_type_values[key_type],
                    }
                ):
                    key_labels[obj.label] = key_type
            return key_labels

    @classmethod
    async def sign(  # pylint: disable-msg=too-many-arguments
        cls,
        key_label: str,
        data: bytes,
        verify_signature: bool = False,
        mechanism: Union[Mechanism, None] = None,
        key_type: str = "ed25519",
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
        key_type (str = "ed25519"): Key type.

        Returns:
        bytes
        """

        if key_type not in key_types:
            raise ValueError(f"key_type must be in {key_types}")

        async with async_lock(cls._lock):
            # Ensure we get a healthy pkcs11 session
            await cls._healthy_session()

            # Get private key to sign the data with
            key_priv = cls.session.get_key(
                key_type=key_type_values[key_type],
                object_class=ObjectClass.PRIVATE_KEY,
                label=key_label,
            )
            if verify_signature:
                key_pub = cls.session.get_key(
                    key_type=key_type_values[key_type],
                    object_class=ObjectClass.PUBLIC_KEY,
                    label=key_label,
                )

            if key_type == "ed25519":
                if mechanism is not None and mechanism != Mechanism.EDDSA:
                    raise ValueError("mechanism for key_type 'ed25519' must be None or Mechanism.EDDSA")
                mech = Mechanism.EDDSA
            else:
                if mechanism is None:
                    mech = Mechanism.SHA256_RSA_PKCS
                else:
                    mech = mechanism

            # Sign the data
            signature = key_priv.sign(data, mechanism=mech)

            if not isinstance(signature, bytes):
                raise SignatureInvalid

            if verify_signature:
                if not key_pub.verify(data, signature, mechanism=mech):
                    raise SignatureInvalid
            return signature

    @classmethod
    async def verify(  # pylint: disable-msg=too-many-arguments
        cls,
        key_label: str,
        data: bytes,
        signature: bytes,
        mechanism: Union[Mechanism, None] = None,
        key_type: str = "ed25519",
    ) -> bool:
        """Verify a signature with its data using the private key
        with the label in the PKCS11 device.

        Returns True if the signature is valid.

        Parameters:
        key_label (str): Keypair label.
        data (bytes): Bytes to be signed.
        signature (bytes): The signature.
        mechanism (pkcs11.Mechanism = Mechanism.SHA256_RSA_PKCS): Which signature mechanism to use
        key_type (str = "ed25519"): Key type.

        Returns:
        bool
        """

        if key_type not in key_types:
            raise ValueError(f"key_type must be in {key_types}")

        async with async_lock(cls._lock):
            # Ensure we get a healthy pkcs11 session
            await cls._healthy_session()

            # Get public key to sign the data with
            key_pub = cls.session.get_key(
                key_type=key_type_values[key_type],
                object_class=ObjectClass.PUBLIC_KEY,
                label=key_label,
            )

            if key_type == "ed25519":
                if mechanism is not None and mechanism != Mechanism.EDDSA:
                    raise ValueError("mechanism for key_type 'ed25519' must be None or Mechanism.EDDSA")
                mech = Mechanism.EDDSA
            else:
                if mechanism is None:
                    mech = Mechanism.SHA256_RSA_PKCS
                else:
                    mech = mechanism

            if key_pub.verify(data, signature, mechanism=mech):
                return True
            return False

    @classmethod
    async def public_key_data(cls, key_label: str, key_type: str = "ed25519") -> Tuple[str, bytes]:
        """Returns the public key in PEM form
        and 'Key Identifier' valid for this keypair.

        Parameters:
        key_label (str): Keypair label.
        key_type (str = "ed25519"): Key type.

        Returns:
        typing.Tuple[str, bytes]
        """

        if key_type not in key_types:
            raise ValueError(f"key_type must be in {key_types}")

        async with async_lock(cls._lock):
            # Ensure we get a healthy pkcs11 session
            await cls._healthy_session()

            key_pub = cls.session.get_key(
                key_type=key_type_values[key_type],
                object_class=ObjectClass.PUBLIC_KEY,
                label=key_label,
            )

            if key_type == "RSA":
                # Create the PublicKeyInfo object
                rsa_pub = RSAPublicKey.load(encode_rsa_public_key(key_pub))

                pki = PublicKeyInfo()
                pka = PublicKeyAlgorithm()
                pka["algorithm"] = PublicKeyAlgorithmId("rsa")
                pki["algorithm"] = pka
                pki["public_key"] = rsa_pub

            else:  # key_type == "ed25519":
                pki = encode_ed25519_public_key(key_pub)

            key_pub_pem: bytes = asn1_pem.armor("PUBLIC KEY", pki.dump())
            return key_pub_pem.decode("utf-8"), pki.sha1
