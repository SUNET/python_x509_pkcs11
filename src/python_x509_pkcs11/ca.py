"""Module which create a CA

Exposes the functions:
- create()
"""

from typing import Union, Dict, Tuple
import datetime

from asn1crypto.x509 import (
    BasicConstraints,
    Extension,
    Extensions,
    ExtensionId,
    KeyUsage,
    Name,
)
from asn1crypto.csr import (
    CertificationRequest,
    CertificationRequestInfo,
    CRIAttribute,
    CRIAttributes,
    CSRAttributeType,
    SetOfExtensions,
)
from asn1crypto import pem as asn1_pem
from asn1crypto.keys import PublicKeyInfo

from .pkcs11_handle import PKCS11Session
from .csr import sign_csr
from .lib import signed_digest_algo


def _set_tbs_version(
    tbs: CertificationRequestInfo,
) -> CertificationRequestInfo:
    tbs["version"] = 0
    return tbs


def _set_tbs_subject(tbs: CertificationRequestInfo, subject_name: Dict[str, str]) -> CertificationRequestInfo:
    tbs["subject"] = Name().build(subject_name)
    return tbs


def _set_tbs_subject_pk_info(
    tbs: CertificationRequestInfo,
    pk_info: PublicKeyInfo,
) -> CertificationRequestInfo:
    tbs["subject_pk_info"] = pk_info
    return tbs


def _set_tbs_basic_constraints(
    tbs: CertificationRequestInfo,
) -> CertificationRequestInfo:
    b_c = BasicConstraints()
    b_c["ca"] = True

    ext = Extension()
    ext["extn_id"] = ExtensionId("2.5.29.19")
    ext["critical"] = True
    ext["extn_value"] = b_c

    exts = Extensions()
    exts.append(ext)

    ses = SetOfExtensions()
    ses.append(exts)

    cria = CRIAttribute()
    cria["type"] = CSRAttributeType("1.2.840.113549.1.9.14")
    cria["values"] = ses

    if len(tbs["attributes"]) == 0:
        crias = CRIAttributes()
        crias.append(cria)
        tbs["attributes"] = crias
    else:
        tbs["attributes"].append(cria)
    return tbs


def _set_tbs_key_usage(
    tbs: CertificationRequestInfo,
) -> CertificationRequestInfo:
    # https://github.com/wbond/asn1crypto/blob/master/asn1crypto/x509.py#L438
    # Bit 0, 5 ,6, from left to right
    k_u = KeyUsage(("100001100",))
    ext = Extension()
    ext["extn_id"] = ExtensionId("2.5.29.15")
    ext["critical"] = True
    ext["extn_value"] = k_u

    exts = Extensions()
    exts.append(ext)

    ses = SetOfExtensions()
    ses.append(exts)

    cria = CRIAttribute()
    cria["type"] = CSRAttributeType("1.2.840.113549.1.9.14")
    cria["values"] = ses

    if len(tbs["attributes"]) == 0:
        crias = CRIAttributes()
        crias.append(cria)
        tbs["attributes"] = crias
    else:
        tbs["attributes"].append(cria)
    return tbs


def _set_tbs_extra_extensions(tbs: CertificationRequestInfo, extra_extensions: Extensions) -> CertificationRequestInfo:

    ses = SetOfExtensions()
    ses.append(extra_extensions)

    cria = CRIAttribute()
    cria["type"] = CSRAttributeType("1.2.840.113549.1.9.14")
    cria["values"] = ses

    if len(tbs["attributes"]) == 0:
        crias = CRIAttributes()
        crias.append(cria)
        tbs["attributes"] = crias
    else:
        tbs["attributes"].append(cria)

    return tbs


def _set_tbs_extensions(tbs: CertificationRequestInfo, extra_extensions: Extensions) -> CertificationRequestInfo:
    """Set all x509 extensions"""

    if extra_extensions is not None:
        tbs = _set_tbs_extra_extensions(tbs, extra_extensions)

    tbs = _set_tbs_basic_constraints(tbs)
    tbs = _set_tbs_key_usage(tbs)
    return tbs


def _create_tbs(
    subject_name: Dict[str, str],
    pk_info: PublicKeyInfo,
    extra_extensions: Extensions,
) -> CertificationRequestInfo:
    tbs = CertificationRequestInfo()

    # Set all extensions
    tbs = _set_tbs_extensions(tbs, extra_extensions)

    # Set non extensions
    tbs = _set_tbs_version(tbs)
    tbs = _set_tbs_subject(tbs, subject_name)
    tbs = _set_tbs_subject_pk_info(tbs, pk_info)
    return tbs


async def _set_csr_signature(key_label: str, key_type: str, signed_csr: CertificationRequest) -> CertificationRequest:
    signed_csr["signature_algorithm"] = signed_digest_algo(key_type)
    signed_csr["signature"] = await PKCS11Session().sign(
        key_label, signed_csr["certification_request_info"].dump(), key_type=key_type
    )
    return signed_csr


async def create(  # pylint: disable-msg=too-many-arguments
    key_label: str,
    subject_name: Dict[str, str],
    key_size: int = 2048,
    signer_subject_name: Union[Dict[str, str], None] = None,
    signer_key_label: Union[str, None] = None,
    not_before: Union[datetime.datetime, None] = None,
    not_after: Union[datetime.datetime, None] = None,
    extra_extensions: Union[Extensions, None] = None,
    key_type: str = "ed25519",
) -> Tuple[str, str]:
    """Create and sign a CSR with in the PKCS11 device.

    Returns the csr and the signed ca.

    Parameters:
    key_label (str): Keypair label to create for the new ca
    subject_name (typing.Dict[str, str]): Dict with x509 subject names
    key_size (int = 2048): Key size, 2048 and 4096 works best.
    signer_subject_name (Union[typing.Dict[str, str], None] = None):
    Dict with x509 subject names, if None then this will be root a (selfsigned) ca.
    signer_key_label (Union[str, None] = None):
    Keylabel to sign this ca with, if None then this will be root a (selfsigned) ca.
    not_before (Union[datetime.datetime, None] = None): The ca is not valid before this time.
    not_after (Union[datetime.datetime, None] = None): The ca is not valid after this time.
    extra_extensions (Union[asn1crypto.x509.Extensions, None] = None]): x509 extensions to write into the ca.
    key_type (str = "ed25519"): Key type.

    Returns:
    typing.Tuple[str, str]
    """

    pk_info, _ = await PKCS11Session().create_keypair(key_label, key_size, key_type=key_type)
    data = pk_info.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    tbs = _create_tbs(subject_name, PublicKeyInfo.load(data), extra_extensions)
    signed_csr = CertificationRequest()
    signed_csr["certification_request_info"] = tbs
    signed_csr = await _set_csr_signature(key_label, key_type, signed_csr)
    pem_enc: bytes = asn1_pem.armor("CERTIFICATE REQUEST", signed_csr.dump())

    # If this will be a root CA or not
    if signer_key_label is not None and signer_subject_name is not None:
        key_label = signer_key_label
        subject_name = signer_subject_name

    return pem_enc.decode("utf-8"), await sign_csr(
        key_label,
        subject_name,
        pem_enc.decode("utf-8"),
        not_before=not_before,
        not_after=not_after,
        keep_csr_extensions=True,
        key_type=key_type,
    )
