"""Module which handles a PKCS11 session and its exposed methods

# Better to keep a pkcs11 session reference all the time
# and then when it fails to open a new session for performance
# See PKCS11Session._healthy_session()

The classes PKCS11Session and RemotePKCS11 exposes the functions:
- import_keypair()
- create_keypair()
- key_labels()
- sign()
- verify()
- delete_keypair()
- public_key_data()
- import_certificate()
- export_certificate()
- delete_certificate()
- get_session()
"""
import base64
import os
import time
from asyncio import get_event_loop, sleep
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from email import header
from hashlib import sha256, sha384, sha512
from socket import timeout
from threading import Lock, Thread
from typing import AsyncIterator, Dict, Optional, Tuple, Union

import aiohttp
from asn1crypto import pem as asn1_pem
from asn1crypto import x509 as asn1_x509
from asn1crypto.algos import SignedDigestAlgorithmId
from asn1crypto.keys import PublicKeyAlgorithm, PublicKeyAlgorithmId, PublicKeyInfo, RSAPublicKey
from pkcs11 import Attribute, Key, KeyType, Mechanism, ObjectClass, Session, Token, lib
from pkcs11.exceptions import GeneralError, MultipleObjectsReturned, NoSuchKey, SignatureInvalid
from pkcs11.util.ec import (
    decode_ec_private_key,
    decode_ec_public_key,
    encode_ec_public_key,
    encode_named_curve_parameters,
)
from pkcs11.util.rsa import decode_rsa_private_key, decode_rsa_public_key, encode_rsa_public_key
from pkcs11.util.x509 import decode_x509_certificate

from .crypto import (
    convert_asn1_ec_signature,
    convert_rs_ec_signature,
    decode_eddsa_private_key,
    decode_eddsa_public_key,
    encode_eddsa_public_key,
)
from .error import PKCS11UnknownErrorException
from .lib import DEBUG, key_type_values, key_types

TIMEOUT = 3  # Seconds
pool = ThreadPoolExecutor()


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
    _token: Token
    _lib: lib

    base_url: Optional[str]
    http_data: Optional[Dict[str, str]] = None
    http_headers: Optional[Dict[str, str]] = None

    lock = Lock()
    session: Session

    @classmethod
    def __init__(
        cls,
        base_url: Optional[str] = None,
        http_data: Optional[Dict[str, str]] = None,
        http_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        cls.base_url = base_url
        cls.http_data = http_data
        cls.http_headers = http_headers

        if "PKCS11_BASE_URL" in os.environ:
            cls.base_url = os.environ["PKCS11_BASE_URL"]

    @classmethod
    def _get_pub_key(cls, key_label: str, key_type: str) -> Key:
        return cls.session.get_key(
            key_type=key_type_values[key_type],
            object_class=ObjectClass.PUBLIC_KEY,
            label=key_label,
        )

    @classmethod
    def _public_key_data(cls, key_pub: Key, key_type: str) -> Tuple[str, bytes]:
        if key_type in ["rsa_2048", "rsa_4096"]:
            # Create the PublicKeyInfo object
            rsa_pub = RSAPublicKey.load(encode_rsa_public_key(key_pub))

            pki = PublicKeyInfo()
            pka = PublicKeyAlgorithm()
            pka["algorithm"] = PublicKeyAlgorithmId("rsa")
            pki["algorithm"] = pka
            pki["public_key"] = rsa_pub

        elif key_type in ["ed25519", "ed448"]:
            pki = PublicKeyInfo.load(encode_eddsa_public_key(key_pub))

        elif key_type in ["secp256r1", "secp384r1", "secp521r1"]:
            pki = PublicKeyInfo.load(encode_ec_public_key(key_pub))
        else:
            raise ValueError(f"key_type must be in {key_types}")

        key_pub_pem: bytes = asn1_pem.armor("PUBLIC KEY", pki.dump())
        return key_pub_pem.decode("utf-8"), pki.sha1

    @classmethod
    def _open_session(cls, force: Optional[bool] = None, simulate_pkcs11_timeout: Optional[bool] = None) -> None:
        if simulate_pkcs11_timeout:
            time.sleep(TIMEOUT + 1)

        if "PKCS11_MODULE" not in os.environ:
            print("ERROR: PKCS11_MODULE was not an env variable")
        if "PKCS11_TOKEN" not in os.environ:
            print("ERROR: PKCS11_TOKEN was not an env variable")
        if "PKCS11_PIN" not in os.environ:
            print("ERROR: PKCS11_PIN was not an env variable")

        cls._session_status = 9
        try:
            # if force or cls.session is None:
            if force or not hasattr(cls, "session"):
                # Reload the PKCS11 lib
                cls._lib = lib(os.environ["PKCS11_MODULE"])
                cls._lib.reinitialize()

                # Open the PKCS11 session
                cls._token = cls._lib.get_token(token_label=os.environ["PKCS11_TOKEN"])
                # user_pin need to be a string, not bytes
                cls.session = cls._token.open(rw=True, user_pin=os.environ["PKCS11_PIN"])

            # Test get a public key from the PKCS11 device
            _ = cls.session.get_key(
                key_type=KeyType.RSA,
                object_class=ObjectClass.PUBLIC_KEY,
                label="test_pkcs11_device_do_not_use",
            )
            cls._session_status = 0

        except NoSuchKey:
            try:
                _, _ = cls.session.generate_keypair(KeyType.RSA, 512, label="test_pkcs11_device_do_not_use", store=True)
                cls._session_status = 0
            except GeneralError:
                pass

        except GeneralError as exc:
            if DEBUG:
                print("Failed to open PKCS11 session")
                print(exc)

    @classmethod
    async def healthy_session(cls, simulate_pkcs11_timeout: Optional[bool] = None) -> None:
        """Run the PKCS11 test command in a thread to easy handle PKCS11 timeouts."""

        thread = Thread(target=cls._open_session, args=([False, simulate_pkcs11_timeout]))
        thread.start()
        await sleep(0)
        thread.join(timeout=TIMEOUT)

        if thread.is_alive() or cls._session_status != 0:
            thread2 = Thread(target=cls._open_session, args=([True, simulate_pkcs11_timeout]))
            thread2.start()
            # yield to other coroutines while we wait for thread2 to join
            await sleep(0)
            thread2.join(timeout=TIMEOUT)

            if thread2.is_alive() or cls._session_status != 0:
                raise PKCS11UnknownErrorException("ERROR: Could not get a healthy PKCS11 connection in time")

    @classmethod
    async def get_session(cls) -> Session:
        """Return the PKCS11 session."""

        async with async_lock(cls.lock):
            # Ensure we get a healthy pkcs11 session
            await cls.healthy_session()
            return cls.session

    @classmethod
    async def import_certificate(cls, cert_pem: str, cert_label: str) -> None:
        """Import a certificate into the PKCS11 device with this label.

        Parameters:
        cert_pem (str): Certificate in PEM form.
        cert_label (str): Certificate label in the PKCS11 device.

        Returns:
        None
        """

        if cls.base_url is not None:
            http_request_data: Dict[str, str] = {}

            if cls.http_data is not None:
                http_request_data.update(cls.http_data)

            http_request_data["cert_pem"] = cert_pem
            http_request_data["cert_label"] = cert_label

            async with aiohttp.ClientSession(headers=cls.http_headers) as session:
                async with session.post(
                    url=f"{cls.base_url}/import_certificate",
                    json=http_request_data,
                    headers=cls.http_headers,
                    timeout=10,
                ) as response:
                    response.raise_for_status()
                    # json_body = await response.json()
                    return

        async with async_lock(cls.lock):
            # Ensure we get a healthy pkcs11 session
            await cls.healthy_session()

            for cert in cls.session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.CERTIFICATE,
                    Attribute.LABEL: cert_label,
                }
            ):
                raise ValueError("Certificate with that label already exists in the PKCS11 device")

            data = cert_pem.encode("utf-8")
            if asn1_pem.detect(data):
                _, _, data = asn1_pem.unarmor(data)

            cert = decode_x509_certificate(data)
            cert[Attribute.TOKEN] = True
            cert[Attribute.LABEL] = cert_label
            cls.session.create_object(cert)

    @classmethod
    async def export_certificate(cls, cert_label: str) -> str:
        """Export a certificate from the PKCS11 device with this label.
        Returns the PEM encoded cert.

        Parameters:
        cert_label (str): Certificate label in the PKCS11 device.

        Returns:
        str
        """

        if cls.base_url is not None:
            http_request_data: Dict[str, str] = {}

            if cls.http_data is not None:
                http_request_data.update(cls.http_data)

            http_request_data["cert_label"] = cert_label

            async with aiohttp.ClientSession(headers=cls.http_headers) as session:
                async with session.post(
                    url=f"{cls.base_url}/export_certificate",
                    json=http_request_data,
                    headers=cls.http_headers,
                    timeout=10,
                ) as response:
                    response.raise_for_status()
                    json_body = await response.json()
                    ret = json_body["certificate"]  # handle errors
                    if isinstance(ret, str):
                        return ret
                    raise ValueError("Problem with cert")

        async with async_lock(cls.lock):
            # Ensure we get a healthy pkcs11 session
            await cls.healthy_session()

            for cert in cls.session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.CERTIFICATE,
                    Attribute.LABEL: cert_label,
                }
            ):
                der_bytes = cert[Attribute.VALUE]

                # Load a certificate object from the DER-encoded value
                cert_asn1 = asn1_x509.Certificate.load(der_bytes)

                # Write out a PEM encoded value
                ret_data: bytes = asn1_pem.armor("CERTIFICATE", cert_asn1.dump())
                return ret_data.decode("utf-8")

            raise ValueError("No such certificate in the PKCS11 device")

    @classmethod
    async def delete_certificate(cls, cert_label: str) -> None:
        """Delete a certificate from the PKCS11 device with this label.

        Parameters:
        cert_label (str): Certificate label in the PKCS11 device.
        """

        if cls.base_url is not None:
            http_request_data: Dict[str, str] = {}

            if cls.http_data is not None:
                http_request_data.update(cls.http_data)

            http_request_data["cert_label"] = cert_label

            async with aiohttp.ClientSession(headers=cls.http_headers) as session:
                async with session.post(
                    url=f"{cls.base_url}/delete_certificate",
                    json=http_request_data,
                    headers=cls.http_headers,
                    timeout=10,
                ) as response:
                    response.raise_for_status()
                    return
                    # json_body = await response.json()
                    # return json_body["cert_label"] # handle errors

        async with async_lock(cls.lock):
            # Ensure we get a healthy pkcs11 session
            await cls.healthy_session()

            for cert in cls.session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.CERTIFICATE,
                    Attribute.LABEL: cert_label,
                }
            ):
                cert.destroy()

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
        key_type (str): Key type.

        Returns:
        None
        """

        if key_type not in key_types:
            raise ValueError(f"key_type must be in {key_types}")

        if cls.base_url is not None:
            http_request_data: Dict[str, str] = {}

            if cls.http_data is not None:
                http_request_data.update(cls.http_data)

            http_request_data["public_key_b64"] = base64.b64encode(public_key).decode("utf-8")
            http_request_data["private_key_b64"] = base64.b64encode(private_key).decode("utf-8")
            http_request_data["key_label"] = key_label
            http_request_data["key_type"] = key_type

            async with aiohttp.ClientSession(headers=cls.http_headers) as session:
                async with session.post(
                    url=f"{cls.base_url}/import_keypair", json=http_request_data, headers=cls.http_headers, timeout=10
                ) as response:
                    response.raise_for_status()
                    return
                    # json_body = await response.json()

        async with async_lock(cls.lock):
            # Ensure we get a healthy pkcs11 session
            await cls.healthy_session()

            try:
                key_pub = cls._get_pub_key(key_label, key_type)
                raise MultipleObjectsReturned
            except NoSuchKey:
                pass

            if key_type in ["rsa_2048", "rsa_4096"]:
                key_pub = decode_rsa_public_key(public_key)
                key_priv = decode_rsa_private_key(private_key)

            elif key_type in ["ed25519", "ed448"]:
                key_pub = decode_eddsa_public_key(public_key)
                key_priv = decode_eddsa_private_key(private_key)

            elif key_type in ["secp256r1", "secp384r1", "secp521r1"]:
                key_pub = decode_ec_public_key(public_key)
                key_priv = decode_ec_private_key(private_key)

            key_pub[Attribute.TOKEN] = True
            key_pub[Attribute.LABEL] = key_label
            key_priv[Attribute.TOKEN] = True
            key_priv[Attribute.LABEL] = key_label

            cls.session.create_object(key_pub)
            cls.session.create_object(key_priv)

    @classmethod
    async def create_keypair(cls, key_label: str, key_type: Optional[str] = None) -> Tuple[str, bytes]:
        """Create an RSA keypair in the PKCS11 device with this label.
        If the label already exists in the PKCS11 device then raise pkcs11.MultipleObjectsReturned.
        Returns the data for the x509 'Subject Public Key Info'
        and x509 extension 'Subject Key Identifier' valid for this keypair.

        ed25519 is default key_type.

        Parameters:
        key_label (str): Keypair label.
        key_type (str = None): Key type.


        Returns:
        Tuple[str, bytes]
        """

        if key_type is None:
            key_type = "ed25519"

        if key_type not in key_types:
            raise ValueError(f"key_type must be in {key_types}")

        if cls.base_url is not None:
            http_request_data: Dict[str, str] = {}

            if cls.http_data is not None:
                http_request_data.update(cls.http_data)

            http_request_data["key_label"] = key_label
            http_request_data["key_type"] = key_type

            async with aiohttp.ClientSession(headers=cls.http_headers) as session:
                async with session.post(
                    url=f"{cls.base_url}/create_keypair", json=http_request_data, headers=cls.http_headers, timeout=10
                ) as response:
                    response.raise_for_status()
                    json_body = await response.json()
                    spi = json_body["subjectPublicKeyInfo"]  # handle errors
                    ski = json_body["subjectKeyIdentifier_b64"]

                    if isinstance(spi, str) and isinstance(ski, str):  # handle errors
                        return spi, base64.b64decode(ski)
                    raise ValueError("Problem with create keypair")

        async with async_lock(cls.lock):
            # Ensure we get a healthy pkcs11 session
            await cls.healthy_session()

            # Try to get the key, if not exist then create it
            try:
                key_pub = cls._get_pub_key(key_label, key_type)
                raise MultipleObjectsReturned
            except NoSuchKey:
                # Generate the rsa keypair
                if key_type in ["rsa_2048", "rsa_4096"]:
                    key_pub, _ = cls.session.generate_keypair(
                        KeyType.RSA, int(key_type.split("_")[1]), store=True, label=key_label
                    )

                elif key_type in ["ed25519", "ed448"]:
                    parameters = cls.session.create_domain_parameters(
                        KeyType.EC_EDWARDS,
                        {
                            Attribute.EC_PARAMS: encode_named_curve_parameters(
                                SignedDigestAlgorithmId(key_type).dotted
                            ),
                        },
                        local=True,
                    )
                    key_pub, _ = parameters.generate_keypair(
                        mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN, store=True, label=key_label
                    )

                elif key_type in ["secp256r1", "secp384r1", "secp521r1"]:
                    parameters = cls.session.create_domain_parameters(
                        KeyType.EC,
                        {Attribute.EC_PARAMS: encode_named_curve_parameters(key_type)},
                        local=True,
                    )
                    key_pub, _ = parameters.generate_keypair(
                        store=True,
                        label=key_label,
                    )

            return cls._public_key_data(key_pub, key_type)

    @classmethod
    async def key_labels(cls) -> Dict[str, str]:
        """Return a dict of key labels as keys and key type as values in the PKCS11 device.

        Returns:
        Dict[str, str]
        """

        if cls.base_url is not None:
            async with aiohttp.ClientSession(headers=cls.http_headers) as session:
                async with session.post(
                    url=f"{cls.base_url}/key_labels", json=cls.http_data, headers=cls.http_headers, timeout=10
                ) as response:
                    response.raise_for_status()
                    json_body = await response.json()
                    ret = json_body["key_labels"]  # handle errors

                    if isinstance(ret, dict):  # handle only [str, str]
                        return ret
                    raise ValueError("Problem with key labels")

        async with async_lock(cls.lock):
            # Ensure we get a healthy pkcs11 session
            await cls.healthy_session()

            key_labels: Dict[str, str] = {}

            # For rsa
            for obj in cls.session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                    Attribute.KEY_TYPE: key_type_values["rsa_2048"],
                }
            ):
                if obj.key_length == 2048:
                    key_labels[obj.label] = "rsa_2048"
                elif obj.key_length == 4096:
                    key_labels[obj.label] = "rsa_4096"
                else:
                    key_labels[obj.label] = "rsa_512"

            # For ed25519
            for obj in cls.session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                    Attribute.KEY_TYPE: key_type_values["ed25519"],
                    Attribute.EC_PARAMS: encode_named_curve_parameters("1.3.101.112"),
                }
            ):
                key_labels[obj.label] = "ed25519"

            # For ed448
            for obj in cls.session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                    Attribute.KEY_TYPE: key_type_values["ed448"],
                    Attribute.EC_PARAMS: encode_named_curve_parameters("1.3.101.113"),
                }
            ):
                key_labels[obj.label] = "ed448"

            # for secp256r1, secp384r1, secp521r1
            for curve in ["secp256r1", "secp384r1", "secp521r1"]:
                for obj in cls.session.get_objects(
                    {
                        Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                        Attribute.KEY_TYPE: key_type_values[curve],
                        Attribute.EC_PARAMS: encode_named_curve_parameters(curve),
                    }
                ):
                    key_labels[obj.label] = curve

            return key_labels

    @classmethod
    async def _sign(  # pylint: disable-msg=too-many-arguments
        cls,
        key_label: str,
        data: bytes,
        verify_signature: Optional[bool],
        mechanism: Mechanism,
        key_type: str,
    ) -> bytes:
        async with async_lock(cls.lock):
            # Ensure we get a healthy pkcs11 session
            await cls.healthy_session()

            # Get private key to sign the data with
            key_priv = cls.session.get_key(
                key_type=key_type_values[key_type],
                object_class=ObjectClass.PRIVATE_KEY,
                label=key_label,
            )
            if verify_signature:
                key_pub = cls._get_pub_key(key_label, key_type)

            # Sign the data
            signature = key_priv.sign(data, mechanism=mechanism)

            if not isinstance(signature, bytes):
                raise SignatureInvalid

            if verify_signature:
                if not key_pub.verify(data, signature, mechanism=mechanism):
                    raise SignatureInvalid

            return signature

    @classmethod
    async def sign(
        cls,
        key_label: str,
        data: bytes,
        verify_signature: Optional[bool] = None,
        key_type: Optional[str] = None,
    ) -> bytes:
        """Sign the data: bytes using the private key
        with the label in the PKCS11 device.

        Returns the signed data: bytes for the x509 extension and
        'Authority Key Identifier' valid for this keypair.

        Parameters:
        key_label (str): Keypair label.
        data (bytes): Bytes to be signed.
        verify_signature (Union[bool, None] = None):
        If we should verify the signature. PKCS11 operations can be expensive, default None (False)
        key_type (Union[str, None] = None): Key type.

        Returns:
        bytes
        """

        if key_type is None:
            key_type = "ed25519"

        if key_type not in key_types:
            raise ValueError(f"key_type must be in {key_types}")

        if cls.base_url is not None:
            http_request_data: Dict[str, Union[str, bool]] = {}

            if cls.http_data is not None:
                http_request_data.update(cls.http_data)

            http_request_data["data_b64"] = base64.b64encode(data).decode("utf-8")
            http_request_data["key_label"] = key_label
            http_request_data["key_type"] = key_type

            if verify_signature is None or not verify_signature:
                http_request_data["verify_signature"] = False
            else:
                http_request_data["verify_signature"] = True

            async with aiohttp.ClientSession(headers=cls.http_headers) as session:
                async with session.post(
                    url=f"{cls.base_url}/sign", json=http_request_data, headers=cls.http_headers, timeout=10
                ) as response:
                    response.raise_for_status()
                    json_body = await response.json()
                    ret = json_body["signature_b64"]  # handle errors

                    if isinstance(ret, str):
                        return base64.b64decode(ret)
                    raise ValueError("Problem with signature")

        if key_type in ["ed25519", "ed448"]:
            mech = Mechanism.EDDSA

        elif key_type in ["secp256r1", "secp384r1", "secp521r1"]:
            mech = Mechanism.ECDSA

            # Set hash alg
            if key_type == "secp256r1":
                hash_obj = sha256()
            elif key_type == "secp384r1":
                hash_obj = sha384()
            else:
                hash_obj = sha512()

            hash_obj.update(data)
            data = hash_obj.digest()

        else:
            if key_type == "rsa_2048":
                mech = Mechanism.SHA256_RSA_PKCS
            else:
                mech = Mechanism.SHA512_RSA_PKCS

        signature = await cls._sign(key_label, data, verify_signature, mech, key_type)

        # PKCS11 specific stuff for EC curves, sig is in R&S format, convert it to openssl format
        if key_type in ["secp256r1", "secp384r1", "secp521r1"]:
            signature = convert_rs_ec_signature(signature, key_type)

        return signature

    @classmethod
    async def verify(  # pylint: disable-msg=too-many-arguments
        cls,
        key_label: str,
        data: bytes,
        signature: bytes,
        key_type: Optional[str] = None,
    ) -> bool:
        """Verify a signature with its data using the private key
        with the label in the PKCS11 device.

        Returns True if the signature is valid.

        Parameters:
        key_label (str): Keypair label.
        data (bytes): Bytes to be signed.
        signature (bytes): The signature.
        key_type (Union[str, None] = None): Key type.

        Returns:
        bool
        """

        if key_type is None:
            key_type = "ed25519"

        if key_type not in key_types:
            raise ValueError(f"key_type must be in {key_types}")

        if cls.base_url is not None:
            http_request_data: Dict[str, str] = {}

            if cls.http_data is not None:
                http_request_data.update(cls.http_data)

            http_request_data["data_b64"] = base64.b64encode(data).decode("utf-8")
            http_request_data["signature_b64"] = base64.b64encode(signature).decode("utf-8")
            http_request_data["key_label"] = key_label
            http_request_data["key_type"] = key_type

            async with aiohttp.ClientSession(headers=cls.http_headers) as session:
                async with session.post(
                    url=f"{cls.base_url}/verify", json=http_request_data, headers=cls.http_headers, timeout=10
                ) as response:
                    response.raise_for_status()
                    json_body = await response.json()
                    ret = json_body["verified"]  # handle errors

                    if isinstance(ret, bool):
                        return ret
                    raise ValueError("Problem with verify")

        async with async_lock(cls.lock):
            # Ensure we get a healthy pkcs11 session
            await cls.healthy_session()

            # Get public key to sign the data with
            key_pub = cls._get_pub_key(key_label, key_type)

            if key_type in ["ed25519", "ed448"]:
                mech = Mechanism.EDDSA

            elif key_type in ["secp256r1", "secp384r1", "secp521r1"]:
                mech = Mechanism.ECDSA

                # Set hash alg
                if key_type == "secp256r1":
                    hash_obj = sha256()
                elif key_type == "secp384r1":
                    hash_obj = sha384()
                else:
                    hash_obj = sha512()

                hash_obj.update(data)
                data = hash_obj.digest()

                try:
                    signature = convert_asn1_ec_signature(signature, key_type)
                except (IndexError, ValueError):
                    # Signature was not in ASN1 format, signature verification will probably fail.
                    pass

            else:  # rsa
                if key_type == "rsa_2048":
                    mech = Mechanism.SHA256_RSA_PKCS
                else:
                    mech = Mechanism.SHA512_RSA_PKCS

            if key_pub.verify(data, signature, mechanism=mech):
                return True
            return False

    @classmethod
    async def delete_keypair(cls, key_label: str, key_type: Optional[str] = None) -> None:
        """Delete the keypair from the PKCS11 device.

        Parameters:
        key_label (str): Keypair label.
        key_type (Union[str, None] = None): Key type.

        Returns:
        None
        """

        if key_type is None:
            key_type = "ed25519"

        if key_type not in key_types:
            raise ValueError(f"key_type must be in {key_types}")

        if cls.base_url is not None:
            http_request_data: Dict[str, str] = {}

            if cls.http_data is not None:
                http_request_data.update(cls.http_data)

            http_request_data["key_type"] = key_type
            http_request_data["key_label"] = key_label

            async with aiohttp.ClientSession(headers=cls.http_headers) as session:
                async with session.post(
                    url=f"{cls.base_url}/delete_keypair", json=http_request_data, headers=cls.http_headers, timeout=10
                ) as response:
                    response.raise_for_status()
                    json_body = await response.json()
                    return
                    # ret = json_body["verified"]  # handle errors

        async with async_lock(cls.lock):
            # Ensure we get a healthy pkcs11 session
            await cls.healthy_session()

            try:
                cls.session.get_key(
                    key_type=key_type_values[key_type],
                    object_class=ObjectClass.PUBLIC_KEY,
                    label=key_label,
                ).destroy()
            finally:
                cls.session.get_key(
                    key_type=key_type_values[key_type],
                    object_class=ObjectClass.PRIVATE_KEY,
                    label=key_label,
                ).destroy()

    @classmethod
    async def public_key_data(cls, key_label: str, key_type: Optional[str] = None) -> Tuple[str, bytes]:
        """Returns the public key in PEM form
        and 'Key Identifier' valid for this keypair.

        Parameters:
        key_label (str): Keypair label.
        key_type (Union[str, None] = None): Key type.

        Returns:
        Tuple[str, bytes]
        """

        if key_type is None:
            key_type = "ed25519"

        if key_type not in key_types:
            raise ValueError(f"key_type must be in {key_types}")

        if cls.base_url is not None:
            http_request_data: Dict[str, str] = {}

            if cls.http_data is not None:
                http_request_data.update(cls.http_data)

            http_request_data["key_label"] = key_label
            http_request_data["key_type"] = key_type

            async with aiohttp.ClientSession(headers=cls.http_headers) as session:
                async with session.post(
                    url=f"{cls.base_url}/public_key_data", json=http_request_data, headers=cls.http_headers, timeout=10
                ) as response:
                    response.raise_for_status()
                    json_body = await response.json()

                    if json_body["status"] == "error" and json_body["detail"] == "NoSuchKey":
                        raise NoSuchKey()

                    spi = json_body["subjectPublicKeyInfo"]  # handle errors
                    ski = json_body["subjectKeyIdentifier_b64"]

                    if isinstance(spi, str) and isinstance(ski, str):
                        return spi, base64.b64decode(ski)
                    raise ValueError("Problem with create keypair")

        async with async_lock(cls.lock):
            # Ensure we get a healthy pkcs11 session
            await cls.healthy_session()

            key_pub = cls._get_pub_key(key_label, key_type)
            return cls._public_key_data(key_pub, key_type)
