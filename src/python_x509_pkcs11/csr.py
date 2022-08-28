"""Module which sign CRS

Exposes the functions:
- sign_csr()
"""

from typing import Union, Dict
import datetime
import os

from asn1crypto import x509 as asn1_x509
from asn1crypto import csr as asn1_csr
from asn1crypto import pem as asn1_pem
from asn1crypto.core import OctetString
from asn1crypto.algos import SignedDigestAlgorithm, SignedDigestAlgorithmId

from .pkcs11_handle import PKCS11Session
from .error import DuplicateExtensionException


def _request_to_tbs_certificate(csr_pem: str, keep_csr_extensions: bool) -> asn1_x509.TbsCertificate:

    data = csr_pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    req = asn1_csr.CertificationRequest.load(data)

    tbs = asn1_x509.TbsCertificate()
    tbs["subject"] = req["certification_request_info"]["subject"]
    tbs["subject_public_key_info"] = req["certification_request_info"]["subject_pk_info"]

    if not keep_csr_extensions:
        return tbs

    exts = asn1_x509.Extensions()
    attrs = req["certification_request_info"]["attributes"]
    for _, attr in enumerate(attrs):
        for _, extensions in enumerate(attr["values"]):
            for _, extension in enumerate(extensions):
                exts.append(extension)

    if len(exts) > 0:
        tbs["extensions"] = exts
    return tbs


def _check_tbs_duplicate_extensions(tbs: asn1_x509.TbsCertificate) -> None:
    """A certificate MUST NOT include more
    than one instance of a particular extension. For example, a
    certificate may contain only one authority key identifier extension
    https://www.rfc-editor.org/rfc/rfc5280#section-4.2

    Parameters:
    tbs (asn1_x509.TbsCertificate): The 'To be signed' certificate

    Returns:
    None
    """

    exts = []
    for _, ext in enumerate(tbs["extensions"]):
        if ext["extn_id"].dotted in exts:
            raise DuplicateExtensionException("Found duplicate extension " + ext["extn_id"].dotted)
        exts.append(ext["extn_id"].dotted)


def _set_tbs_issuer(tbs: asn1_x509.TbsCertificate, issuer_name: Dict[str, str]) -> asn1_x509.TbsCertificate:

    tbs["issuer"] = asn1_csr.Name().build(issuer_name)
    return tbs


def _set_tbs_version(tbs: asn1_x509.TbsCertificate) -> asn1_x509.TbsCertificate:

    tbs["version"] = 2
    return tbs


def _set_tbs_serial(tbs: asn1_x509.TbsCertificate) -> asn1_x509.TbsCertificate:

    # Same code as python cryptography lib
    tbs["serial_number"] = int.from_bytes(os.urandom(20), "big") >> 1
    return tbs


def _set_tbs_validity(
    tbs: asn1_x509.TbsCertificate,
    not_before: Union[datetime.datetime, None],
    not_after: Union[datetime.datetime, None],
) -> asn1_x509.TbsCertificate:

    val = asn1_x509.Validity()

    if not_before is None:
        val["not_before"] = asn1_x509.Time(
            name="utc_time",
            value=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(2),
        )
    else:
        val["not_before"] = asn1_x509.Time(
            name="utc_time",
            value=not_before,
        )

    if not_after is None:
        val["not_after"] = asn1_x509.Time(
            name="utc_time",
            value=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(365 * 3, 0, 0),
        )
    else:
        val["not_after"] = asn1_x509.Time(
            name="utc_time",
            value=not_after,
        )

    tbs["validity"] = val
    return tbs


def _set_tbs_ski(tbs: asn1_x509.TbsCertificate) -> asn1_x509.TbsCertificate:

    ski = OctetString()
    ski.set(tbs["subject_public_key_info"].sha1)

    for _, extension in enumerate(tbs["extensions"]):
        if extension["extn_id"].dotted == "2.5.29.14":
            extension["extn_value"] = ski
            return tbs

    ext = asn1_x509.Extension()
    ext["extn_id"] = asn1_x509.ExtensionId("2.5.29.14")
    ext["extn_value"] = ski

    if len(tbs["extensions"]) == 0:
        exts = asn1_x509.Extensions()
        exts.append(ext)
        tbs["extensions"] = exts
    else:
        tbs["extensions"].append(ext)
    return tbs


def _set_tbs_aki(tbs: asn1_x509.TbsCertificate, identifier: bytes) -> asn1_x509.TbsCertificate:

    aki = asn1_x509.AuthorityKeyIdentifier()
    aki["key_identifier"] = identifier

    for _, extension in enumerate(tbs["extensions"]):
        if extension["extn_id"].dotted == "2.5.29.35":
            extension["extn_value"] = aki
            return tbs

    ext = asn1_x509.Extension()
    ext["extn_id"] = asn1_x509.ExtensionId("2.5.29.35")
    ext["extn_value"] = aki

    if len(tbs["extensions"]) == 0:
        exts = asn1_x509.Extensions()
        exts.append(ext)
        tbs["extensions"] = exts
    else:
        tbs["extensions"].append(ext)
    return tbs


def _set_tbs_signature(
    tbs: asn1_x509.TbsCertificate,
) -> asn1_x509.TbsCertificate:

    sda = SignedDigestAlgorithm()
    sda["algorithm"] = SignedDigestAlgorithmId("sha256_rsa")
    tbs["signature"] = sda
    return tbs


def _set_tbs_extra_extensions(
    tbs: asn1_x509.TbsCertificate, extra_extensions: asn1_x509.Extensions
) -> asn1_x509.TbsCertificate:

    if len(tbs["extensions"]) == 0:
        exts = asn1_x509.Extensions()
    else:
        exts = tbs["extensions"]

    for _, ext in enumerate(extra_extensions):
        exts.append(ext)

    tbs["extensions"] = exts
    return tbs


def _set_tbs_extensions(
    tbs: asn1_x509.TbsCertificate, aki: bytes, extra_extensions: asn1_x509.Extensions
) -> asn1_x509.TbsCertificate:
    """Set all x509 extensions"""

    if extra_extensions is not None:
        tbs = _set_tbs_extra_extensions(tbs, extra_extensions)

    tbs = _set_tbs_ski(tbs)
    tbs = _set_tbs_aki(tbs, aki)
    _check_tbs_duplicate_extensions(tbs)
    return tbs


def _create_tbs_certificate(  # pylint: disable-msg=too-many-arguments
    tbs: asn1_x509.TbsCertificate,
    issuer_name: Dict[str, str],
    aki: bytes,
    not_before: Union[datetime.datetime, None],
    not_after: Union[datetime.datetime, None],
    extra_extensions: asn1_x509.Extensions,
) -> asn1_x509.TbsCertificate:

    # Set all extensions
    tbs = _set_tbs_extensions(tbs, aki, extra_extensions)

    # Set non extensions
    tbs = _set_tbs_version(tbs)
    tbs = _set_tbs_issuer(tbs, issuer_name)
    tbs = _set_tbs_serial(tbs)
    tbs = _set_tbs_validity(tbs, not_before, not_after)
    tbs = _set_tbs_signature(tbs)
    return tbs


async def sign_csr(  # pylint: disable-msg=too-many-arguments
    key_label: str,
    issuer_name: Dict[str, str],
    csr_pem: str,
    not_before: Union[datetime.datetime, None] = None,
    not_after: Union[datetime.datetime, None] = None,
    keep_csr_extensions: bool = True,
    extra_extensions: Union[asn1_x509.Extensions, None] = None,
) -> str:
    """Sign a CSR by the key with the key_label in the PKCS11 device.

    Parameters:
    key_label (str): Keypair label.
    issuer_name (typing.Dict[str, str]): Dict with the signers x509 Names.
    csr_pem (Union[str, None] = None]): A CSR to sign.
    not_before (Union[datetime.datetime, None] = None): The certificate is not valid before this time.
    not_after (Union[datetime.datetime, None] = None): The certificate is not valid after this time.
    keep_csr_extensions (bool = True]): If we should keep or remove the x509 extensions in the CSR.
    extra_extensions (Union[asn1crypto.x509.Extensions, None] = None]): x509 extensions to write into the certificate.

    Returns:
    str
    """

    _, aki = await PKCS11Session().public_key_data(key_label)

    tbs = _request_to_tbs_certificate(csr_pem, keep_csr_extensions)

    tbs = _create_tbs_certificate(tbs, issuer_name, aki, not_before, not_after, extra_extensions)

    signed_cert = asn1_x509.Certificate()
    signed_cert["tbs_certificate"] = tbs
    signed_cert["signature_algorithm"] = tbs["signature"]
    signed_cert["signature_value"] = await PKCS11Session().sign(key_label, tbs.dump())

    pem_enc: bytes = asn1_pem.armor("CERTIFICATE", signed_cert.dump())
    return pem_enc.decode("utf-8")
