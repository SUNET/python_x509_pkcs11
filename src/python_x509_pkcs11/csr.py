"""Module which sign CSR

Exposes the functions:
- sign_csr()
"""

from typing import Union, Dict
import datetime
import os

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

from asn1crypto.csr import CertificationRequest
from asn1crypto import pem as asn1_pem
from asn1crypto.core import OctetString

from .pkcs11_handle import PKCS11Session
from .error import DuplicateExtensionException
from .lib import signed_digest_algo


def _request_to_tbs_certificate(csr_pem: str, keep_csr_extensions: Union[bool, None]) -> TbsCertificate:
    data = csr_pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    req = CertificationRequest.load(data)

    tbs = TbsCertificate()
    tbs["subject"] = req["certification_request_info"]["subject"]
    tbs["subject_public_key_info"] = req["certification_request_info"]["subject_pk_info"]

    if keep_csr_extensions is not None and keep_csr_extensions is False:
        return tbs

    exts = Extensions()
    attrs = req["certification_request_info"]["attributes"]
    for _, attr in enumerate(attrs):
        for _, extensions in enumerate(attr["values"]):
            for _, extension in enumerate(extensions):
                exts.append(extension)

    if len(exts) > 0:
        tbs["extensions"] = exts
    return tbs


def _check_tbs_duplicate_extensions(tbs: TbsCertificate) -> None:
    """A certificate MUST NOT include more
    than one instance of a particular extension. For example, a
    certificate may contain only one authority key identifier extension
    https://www.rfc-editor.org/rfc/rfc5280#section-4.2

    Parameters:
    tbs (TbsCertificate): The 'To be signed' certificate

    Returns:
    None
    """

    exts = []
    for _, ext in enumerate(tbs["extensions"]):
        if ext["extn_id"].dotted in exts:
            raise DuplicateExtensionException("Found duplicate extension " + ext["extn_id"].dotted)
        exts.append(ext["extn_id"].dotted)


def _set_tbs_issuer(tbs: TbsCertificate, issuer_name: Dict[str, str]) -> TbsCertificate:
    tbs["issuer"] = Name().build(issuer_name)
    return tbs


def _set_tbs_version(tbs: TbsCertificate) -> TbsCertificate:
    tbs["version"] = 2
    return tbs


def _set_tbs_serial(tbs: TbsCertificate) -> TbsCertificate:
    # Same code as python cryptography lib
    tbs["serial_number"] = int.from_bytes(os.urandom(20), "big") >> 1
    return tbs


def _set_tbs_validity(
    tbs: TbsCertificate,
    not_before: Union[datetime.datetime, None],
    not_after: Union[datetime.datetime, None],
) -> TbsCertificate:
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
    if len(tbs["extensions"]) == 0:
        exts = Extensions()
    else:
        exts = tbs["extensions"]

    for _, ext in enumerate(extra_extensions):
        exts.append(ext)

    tbs["extensions"] = exts
    return tbs


def _set_tbs_extensions(tbs: TbsCertificate, aki: bytes, extra_extensions: Extensions) -> TbsCertificate:
    if extra_extensions is not None:
        tbs = _set_tbs_extra_extensions(tbs, extra_extensions)

    tbs = _set_tbs_ski(tbs)
    tbs = _set_tbs_aki(tbs, aki)
    _check_tbs_duplicate_extensions(tbs)
    return tbs


def _create_tbs_certificate(  # pylint: disable-msg=too-many-arguments
    tbs: TbsCertificate,
    issuer_name: Dict[str, str],
    aki: bytes,
    not_before: Union[datetime.datetime, None],
    not_after: Union[datetime.datetime, None],
    extra_extensions: Extensions,
) -> TbsCertificate:

    # Set all extensions
    tbs = _set_tbs_extensions(tbs, aki, extra_extensions)

    # Set non extensions
    tbs = _set_tbs_version(tbs)
    tbs = _set_tbs_issuer(tbs, issuer_name)
    tbs = _set_tbs_serial(tbs)
    tbs = _set_tbs_validity(tbs, not_before, not_after)
    return tbs


async def _set_signature(key_label: str, key_type: Union[str, None], signed_cert: Certificate) -> Certificate:
    if key_type is None:
        key_type = "ed25519"

    signed_cert["tbs_certificate"]["signature"] = signed_digest_algo(key_type)
    signed_cert["signature_algorithm"] = signed_cert["tbs_certificate"]["signature"]
    signed_cert["signature_value"] = await PKCS11Session().sign(
        key_label, signed_cert["tbs_certificate"].dump(), key_type=key_type
    )
    return signed_cert


async def sign_csr(  # pylint: disable-msg=too-many-arguments
    key_label: str,
    issuer_name: Dict[str, str],
    csr_pem: str,
    not_before: Union[datetime.datetime, None] = None,
    not_after: Union[datetime.datetime, None] = None,
    keep_csr_extensions: Union[bool, None] = None,
    extra_extensions: Union[Extensions, None] = None,
    key_type: Union[str, None] = None,
) -> str:
    """Sign a CSR by the key with the key_label in the PKCS11 device.

    Parameters:
    key_label (str): Keypair label.
    issuer_name (Dict[str, str]): Dict with the signers x509 Names.
    csr_pem (Union[str, None] = None]): A CSR to sign.
    not_before (Union[datetime.datetime, None] = None): The certificate is not valid before this time.
    not_after (Union[datetime.datetime, None] = None): The certificate is not valid after this time.
    keep_csr_extensions (bool = True]): If we should keep or remove the x509 extensions in the CSR.
    extra_extensions (Union[asn1crypto.x509.Extensions, None] = None]): x509 extensions to write into the certificate.
    key_type (Union[str, None] = None): Key type to use, ed25519 is default.

    Returns:
    str
    """

    _, aki = await PKCS11Session().public_key_data(key_label, key_type)

    tbs = _request_to_tbs_certificate(csr_pem, keep_csr_extensions)
    tbs = _create_tbs_certificate(tbs, issuer_name, aki, not_before, not_after, extra_extensions)

    signed_cert = Certificate()
    signed_cert["tbs_certificate"] = tbs
    signed_cert = await _set_signature(key_label, key_type, signed_cert)
    pem_enc: bytes = asn1_pem.armor("CERTIFICATE", signed_cert.dump())
    return pem_enc.decode("utf-8")
