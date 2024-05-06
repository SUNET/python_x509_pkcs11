"Private key implementations for cryptography.x509 usage"

import asyncio
from typing import Union

from cryptography.hazmat.primitives import _serialization, hashes
from cryptography.hazmat.primitives._asymmetric import AsymmetricPadding as AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurve,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicKey,
    EllipticCurveSignatureAlgorithm,
)
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .lib import KEYTYPES
from .pkcs11_handle import PKCS11Session


class PKCS11RSAPrivateKey(rsa.RSAPrivateKey):
    "RSA private key implementation for HSM."

    def __init__(self, session: PKCS11Session, key_label: str, key_type: KEYTYPES):
        self.session = session
        self.key_label = key_label
        self.key_type = key_type

    def sign(
        self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: Union[asym_utils.Prehashed, hashes.HashAlgorithm],
    ) -> bytes:
        """Signs the given data using RSA key in PKCS11 device.

        :param data: bytes, data to be signed.
        :param padding: (NOT IN USE) padding to be used.
        :param algorithm: (NOT IN USE) hash algorithm to be used.

        :returns: signature in bytes
        """
        return asyncio.run(self.session.sign(key_label=self.key_label, data=data, key_type=self.key_type))

    # Following methods are not implemented.
    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError()

    @property
    def key_size(self) -> int:
        return self.public_key().key_size

    def public_key(self) -> "rsa.RSAPublicKey":
        "Returns the public key."
        public_key, _ = asyncio.run(PKCS11Session().public_key_data(self.key_label, self.key_type))
        # This is the issuer public key
        key = load_pem_public_key(public_key.encode("utf-8"))
        if isinstance(key, rsa.RSAPublicKey):
            return key
        raise ValueError("Wrong Public key value.")

    def private_numbers(self) -> "rsa.RSAPrivateNumbers":
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()


class PKCS11ECPrivateKey(ec.EllipticCurvePrivateKey):
    "EC private key implementation for HSM."

    def __init__(self, session: PKCS11Session, key_label: str, key_type: KEYTYPES):
        self.session = session
        self.key_label = key_label
        self.key_type = key_type

    def sign(
        self,
        data: bytes,
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        """Signs the given data using EC key in PKCS11 device.

        :param data: bytes, data to be signed.
        :param signature_algorithm: (NOT IN USE) hash algorithm to be used.

        :returns: signature in bytes
        """
        return asyncio.run(self.session.sign(key_label=self.key_label, data=data, key_type=self.key_type))

    def exchange(self, algorithm: ECDH, peer_public_key: EllipticCurvePublicKey) -> bytes:
        raise NotImplementedError()

    def public_key(self) -> EllipticCurvePublicKey:
        "The EllipticCurvePublicKey for this private key."
        public_key, _ = asyncio.run(PKCS11Session().public_key_data(self.key_label, self.key_type))
        # This is the issuer public key
        key = load_pem_public_key(public_key.encode("utf-8"))
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise ValueError("Wrong Public key value.")
        return key

    @property
    def curve(self) -> EllipticCurve:
        """
        The EllipticCurve that this key is on.
        """
        return self.public_key().curve

    @property
    def key_size(self) -> int:
        """
        Bit size of a secret scalar for the curve.
        """
        return self.public_key().key_size

    def private_numbers(self) -> EllipticCurvePrivateNumbers:
        """
        Returns an EllipticCurvePrivateNumbers.
        """
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        Returns the key serialized as bytes.
        """
        raise NotImplementedError()


class PKCS11ED25519PrivateKey(Ed25519PrivateKey):
    "ED25519 private key implementation for HSM."

    def __init__(self, session: PKCS11Session, key_label: str, key_type: KEYTYPES = KEYTYPES.ED25519):
        self.session = session
        self.key_label = key_label
        self.key_type = key_type

    def public_key(self) -> Ed25519PublicKey:
        """
        The Ed25519PublicKey derived from the private key.
        """
        public_key, _ = asyncio.run(PKCS11Session().public_key_data(self.key_label, self.key_type))
        # This is the issuer public key
        key = load_pem_public_key(public_key.encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Wrong Public key value.")
        return key

    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        The serialized bytes of the private key.
        """
        raise NotImplementedError()

    def private_bytes_raw(self) -> bytes:
        """
        The raw bytes of the private key.
        Equivalent to private_bytes(Raw, Raw, NoEncryption()).
        """
        raise NotImplementedError()

    def sign(self, data: bytes) -> bytes:
        """Signs the given data using ED25519 key in PKCS11 device.

        :param data: bytes, data to be signed.

        :returns: signature in bytes
        """
        return asyncio.run(self.session.sign(key_label=self.key_label, data=data, key_type=self.key_type))


class PKCS11ED448PrivateKey(Ed448PrivateKey):
    "ED448 private key implementation for HSM."

    def __init__(self, session: PKCS11Session, key_label: str, key_type: KEYTYPES = KEYTYPES.ED448):
        self.session = session
        self.key_label = key_label
        self.key_type = key_type

    def sign(self, data: bytes) -> bytes:
        """Signs the given data using ED25519 key in PKCS11 device.

        :param data: bytes, data to be signed.

        :returns: signature in bytes
        """
        return asyncio.run(self.session.sign(key_label=self.key_label, data=data, key_type=self.key_type))

    def public_key(self) -> Ed448PublicKey:
        """
        The Ed448PublicKey derived from the private key.
        """
        public_key, _ = asyncio.run(PKCS11Session().public_key_data(self.key_label, self.key_type))
        # This is the issuer public key
        key = load_pem_public_key(public_key.encode("utf-8"))
        if isinstance(key, Ed448PublicKey):
            return key
        raise ValueError("Wrong Public key value.")

    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        The serialized bytes of the private key.
        """
        raise NotImplementedError()

    def private_bytes_raw(self) -> bytes:
        """
        The raw bytes of the private key.
        Equivalent to private_bytes(Raw, Raw, NoEncryption()).
        """
        raise NotImplementedError()
