"""Module which sign CSR

Exposes the functions:
- sign_csr()
"""

import datetime
import os
from typing import Dict, Optional, Union

from asn1crypto import pem as asn1_pem
from asn1crypto.core import OctetString
from asn1crypto.csr import CertificationRequest
from asn1crypto.x509 import (
    AuthorityKeyIdentifier,
    Certificate,
    Extension,
    ExtensionId,
    Extensions,
    Name,
    TbsCertificate,
    Time,
    Validity,
)

from .error import DuplicateExtensionException
from .lib import DEFAULT_KEY_TYPE, KEYTYPES, get_keytypes_enum, signed_digest_algo
from .pkcs11_handle import PKCS11Session


def _append_extensions(exts: Extensions, extensions: Extensions, ignore_auth_exts: Optional[bool]) -> None:
    for _, extension in enumerate(extensions):
        # Ignore auth exts, should be set by CA not by the requester anyway
        if ignore_auth_exts is not None and ignore_auth_exts is True:
            if extension["extn_id"].dotted in ["2.5.29.35", "2.5.29.14", "1.3.6.1.5.5.7.1.1", "2.5.29.31"]:
                continue
        exts.append(extension)


def _request_to_tbs_certificate(
    csr_pem: str, keep_csr_extensions: Optional[bool], ignore_auth_exts: Optional[bool]
) -> TbsCertificate:
    "This function converts a CSR into a TBSCertificate."
    data = csr_pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    req = CertificationRequest.load(data)

    # https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2
    # The sequence TBSCertificate contains information associated with the
    # subject of the certificate and the CA that issued it.  Every
    # BSCertificate contains the names of the subject and issuer, a public
    # key associated with the subject, a validity period, a version number,
    # and a serial number; some MAY contain optional unique identifier
    # fields.
    tbs = TbsCertificate()
    tbs["subject"] = req["certification_request_info"]["subject"]
    tbs["subject_public_key_info"] = req["certification_request_info"]["subject_pk_info"]

    if keep_csr_extensions is not None and keep_csr_extensions is False:
        return tbs

    # Set CSR extensions into the tbc certificate
    exts = Extensions()
    attrs = req["certification_request_info"]["attributes"]
    for _, attr in enumerate(attrs):
        for _, extensions in enumerate(attr["values"]):
            _append_extensions(exts, extensions, ignore_auth_exts)

    if len(exts) > 0:
        tbs["extensions"] = exts
    return tbs


def _check_tbs_duplicate_extensions(tbs: TbsCertificate) -> None:
    """A certificate MUST NOT include more
    than one instance of a particular extension. For example, a
    certificate may contain only one authority key identifier extension
    https://www.rfc-editor.org/rfc/rfc5280#section-4.2

    Parameters:
    tbs (TbsCertificate): The 'To be signed' certificate.

    Returns:
    None
    """

    exts = []
    for _, ext in enumerate(tbs["extensions"]):
        if ext["extn_id"].dotted in exts:
            raise DuplicateExtensionException("Found duplicate extension " + ext["extn_id"].dotted)
        exts.append(ext["extn_id"].dotted)


def _set_tbs_issuer(tbs: TbsCertificate, issuer_name: Dict[str, str]) -> TbsCertificate:
    """Sets the issuer of the TBSCertificate.

    https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
    """
    tbs["issuer"] = Name().build(issuer_name)
    return tbs


def _set_tbs_version(tbs: TbsCertificate) -> TbsCertificate:
    """Sets the version of the TBSCertificate, version MUST be 3 (Integer value 2) for certificates with extensions.

    https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.1
    """
    tbs["version"] = 2
    return tbs


def _set_tbs_serial(tbs: TbsCertificate) -> TbsCertificate:
    """Sets the serial number of the TBSCertificate.

    The serial number MUST be a positive integer assigned by the CA to
    each certificate.  It MUST be unique for each certificate issued by a
    given CA (i.e., the issuer name and serial number identify a unique
    certificate).  CAs MUST force the serialNumber to be a non-negative
    integer.

    https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.2
    """
    # Same code as python cryptography lib
    tbs["serial_number"] = int.from_bytes(os.urandom(20), "big") >> 1
    return tbs


def _set_tbs_validity(
    tbs: TbsCertificate,
    not_before: Optional[datetime.datetime],
    not_after: Optional[datetime.datetime],
) -> TbsCertificate:
    """Sets the validity period of the TBSCertificate.

    Currently it is UTC time, after 2050 it will GeneralizedTime.

    https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.1
    """

    val = Validity()

    if not_before is None:
        # -2 minutes to protect from the certificate readers time skew
        val["not_before"] = Time(
            name="utc_time",
            value=(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)).replace(microsecond=0),
        )
    else:
        val["not_before"] = Time(
            name="utc_time",
            value=not_before.replace(microsecond=0),
        )

    if not_after is None:
        val["not_after"] = Time(
            name="utc_time",
            value=(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(365 * 3, 0, 0)).replace(
                microsecond=0
            ),
        )
    else:
        val["not_after"] = Time(
            name="utc_time",
            value=not_after.replace(microsecond=0),
        )

    tbs["validity"] = val
    return tbs


def _set_tbs_ski(tbs: TbsCertificate) -> TbsCertificate:
    """Sets the Subject Key Identifier (SKI) extension of the TBSCertificate.

    The subject key identifier extension provides a means of identifying
    certificates that contain a particular public key.

    https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
    """

    # The keyIdentifier is composed of the 160-bit SHA-1 hash of the
    # value of the BIT STRING subjectPublicKey (excluding the tag,
    # length, and number of unused bits).
    ski = OctetString()
    ski.set(tbs["subject_public_key_info"].sha1)

    for _, extension in enumerate(tbs["extensions"]):
        if extension["extn_id"].dotted == "2.5.29.14":
            extension["extn_value"] = ski
            return tbs

    ext = Extension()
    ext["extn_id"] = ExtensionId("2.5.29.14")
    ext["extn_value"] = ski

    if len(tbs["extensions"]) == 0:
        exts = Extensions()
        exts.append(ext)
        tbs["extensions"] = exts
    else:
        tbs["extensions"].append(ext)
    return tbs


def _set_tbs_aki(tbs: TbsCertificate, identifier: bytes) -> TbsCertificate:
    """Sets the Authority Key Identifier (AKI) extension of the TBSCertificate.

    The authority key identifier extension provides a means of
    identifying the public key corresponding to the private key used to
    sign a certificate.

    https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1
    """

    # The value of the keyIdentifier field SHOULD be derived from the
    # public key used to verify the certificate's signature or a method
    # that generates unique values.
    aki = AuthorityKeyIdentifier()
    aki["key_identifier"] = identifier

    for _, extension in enumerate(tbs["extensions"]):
        if extension["extn_id"].dotted == "2.5.29.35":
            extension["extn_value"] = aki
            return tbs

    ext = Extension()
    ext["extn_id"] = ExtensionId("2.5.29.35")
    ext["extn_value"] = aki

    if len(tbs["extensions"]) == 0:
        exts = Extensions()
        exts.append(ext)
        tbs["extensions"] = exts
    else:
        tbs["extensions"].append(ext)
    return tbs


def _set_tbs_extra_extensions(tbs: TbsCertificate, extra_extensions: Extensions) -> TbsCertificate:
    """Sets the extra extensions of the TBSCertificate.

    https://datatracker.ietf.org/doc/html/rfc5280#section-4.2
    """
    if len(tbs["extensions"]) == 0:
        exts = Extensions()
    else:
        exts = tbs["extensions"]

    for _, ext in enumerate(extra_extensions):
        exts.append(ext)

    tbs["extensions"] = exts
    return tbs


def _set_tbs_extensions(tbs: TbsCertificate, aki: bytes, extra_extensions: Optional[Extensions]) -> TbsCertificate:
    "Takes the TBSCertificate and sets the extensions and AKI and SKI extensions."

    # First set the extensions
    if extra_extensions is not None and len(extra_extensions) > 0:
        tbs = _set_tbs_extra_extensions(tbs, extra_extensions)

    # Sets Subject Key Identifier (SKI) extension
    tbs = _set_tbs_ski(tbs)
    # Sets Authority Key Identifier (AKI) extension
    tbs = _set_tbs_aki(tbs, aki)
    # Check for any duplicate extensions and raise exception if found.
    _check_tbs_duplicate_extensions(tbs)
    return tbs


async def _set_signature(
    key_label: str, signed_cert: Certificate, key_type: KEYTYPES = DEFAULT_KEY_TYPE
) -> Certificate:
    """Signs the TBSCertificate with the private key corresponding to the key_label.

    https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.3
    """

    signed_cert["tbs_certificate"]["signature"] = signed_digest_algo(key_type)

    # https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2
    signed_cert["signature_algorithm"] = signed_cert["tbs_certificate"]["signature"]

    # https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.3
    signed_cert["signature_value"] = await PKCS11Session().sign(
        key_label, signed_cert["tbs_certificate"].dump(), key_type=key_type.value
    )
    return signed_cert


def _create_tbs_certificate(  # pylint: disable-msg=too-many-arguments
    tbs: TbsCertificate,
    issuer_name: Dict[str, str],
    aki: bytes,
    not_before: Optional[datetime.datetime],
    not_after: Optional[datetime.datetime],
    extra_extensions: Optional[Extensions],
) -> TbsCertificate:
    """Creates the TBSCertificate from the input.s"""

    # Set all extensions
    tbs = _set_tbs_extensions(tbs, aki, extra_extensions)

    # Sets version
    tbs = _set_tbs_version(tbs)
    # Sets issuer
    tbs = _set_tbs_issuer(tbs, issuer_name)
    # Sets unique serial number
    tbs = _set_tbs_serial(tbs)
    # Sets validity period
    tbs = _set_tbs_validity(tbs, not_before, not_after)
    return tbs


async def sign_csr(  # pylint: disable-msg=too-many-arguments
    key_label: str,
    issuer_name: Dict[str, str],
    csr_pem: str,
    not_before: Optional[datetime.datetime] = None,
    not_after: Optional[datetime.datetime] = None,
    keep_csr_extensions: Optional[bool] = None,
    extra_extensions: Optional[Extensions] = None,
    ignore_auth_exts: Optional[bool] = None,
    key_type: Union[str, KEYTYPES] = DEFAULT_KEY_TYPE,
) -> str:
    """Sign a CSR by the key with the key_label in the PKCS11 device.

    Parameters:
    key_label (str): Keypair label.
    issuer_name (Dict[str, str]): Dict with the signers x509 Names.
    csr_pem (Optional[str] = None]): A CSR to sign.
    not_before (Optional[datetime.datetime] = None): The certificate is not valid before this time.
    not_after (Optional[datetime.datetime] = None): The certificate is not valid after this time.
    keep_csr_extensions (Optional[bool] = None]): Should we keep or remove the x509 extensions in the CSR. Default true.
    extra_extensions (Optional[asn1crypto.x509.Extensions] = None]): x509 extensions to write into the certificate.
    key_type (Union[str, KEYTYPES]): Key type to use, KEYTYPES.ED25519 is default.

    Returns:
    str
    """

    if isinstance(key_type, str):
        key_type = get_keytypes_enum(key_type)

    # Gets Authority Key Identifier (AKI) value
    _, aki = await PKCS11Session().public_key_data(key_label, key_type)

    # Creates the TBSCertificate from the CSR
    tbs = _request_to_tbs_certificate(csr_pem, keep_csr_extensions, ignore_auth_exts)
    tbs = _create_tbs_certificate(tbs, issuer_name, aki, not_before, not_after, extra_extensions)

    # Creates an empty certificate
    # https://github.com/wbond/asn1crypto/blob/b763a757bb2bef2ab63620611ddd8006d5e9e4a2/asn1crypto/x509.py#L2162
    signed_cert = Certificate()
    signed_cert["tbs_certificate"] = tbs
    signed_cert = await _set_signature(key_label, signed_cert, key_type)
    pem_enc: bytes = asn1_pem.armor("CERTIFICATE", signed_cert.dump())
    return pem_enc.decode("utf-8")
