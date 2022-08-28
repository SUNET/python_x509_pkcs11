"""Module which create a CA

Exposes the functions:
- create()
"""

from typing import Union, Dict, Tuple
import datetime

import asn1crypto
from asn1crypto.keys import PublicKeyInfo
from asn1crypto import x509 as asn1_x509
from asn1crypto import csr as asn1_csr
from asn1crypto import pem as asn1_pem
from asn1crypto.algos import SignedDigestAlgorithm, SignedDigestAlgorithmId

from .pkcs11_handle import PKCS11Session
from .csr import sign_csr


def _set_tbs_version(
    tbs: asn1_csr.CertificationRequestInfo,
) -> asn1_csr.CertificationRequestInfo:
    tbs["version"] = 0
    return tbs


def _set_tbs_subject(
    tbs: asn1_csr.CertificationRequestInfo, subject_name: Dict[str, str]
) -> asn1_csr.CertificationRequestInfo:
    tbs["subject"] = asn1_csr.Name().build(subject_name)
    return tbs


def _set_tbs_subject_pk_info(
    tbs: asn1_csr.CertificationRequestInfo,
    pk_info: asn1crypto.keys.PublicKeyInfo,
) -> asn1_csr.CertificationRequestInfo:
    tbs["subject_pk_info"] = pk_info
    return tbs


def _set_tbs_basic_constraints(
    tbs: asn1_csr.CertificationRequestInfo,
) -> asn1_csr.CertificationRequestInfo:
    b_c = asn1_x509.BasicConstraints()
    b_c["ca"] = True

    ext = asn1_x509.Extension()
    ext["extn_id"] = asn1_x509.ExtensionId("2.5.29.19")
    ext["critical"] = True
    ext["extn_value"] = b_c

    exts = asn1_csr.Extensions()
    exts.append(ext)

    ses = asn1_csr.SetOfExtensions()
    ses.append(exts)

    cria = asn1_csr.CRIAttribute()
    cria["type"] = asn1_csr.CSRAttributeType("1.2.840.113549.1.9.14")
    cria["values"] = ses

    if len(tbs["attributes"]) == 0:
        crias = asn1_csr.CRIAttributes()
        crias.append(cria)
        tbs["attributes"] = crias
    else:
        tbs["attributes"].append(cria)
    return tbs


def _set_tbs_key_usage(
    tbs: asn1_csr.CertificationRequestInfo,
) -> asn1_csr.CertificationRequestInfo:
    # https://github.com/wbond/asn1crypto/blob/master/asn1crypto/x509.py#L438
    # Bit 0, 5 ,6, from left to right
    k_u = asn1_x509.KeyUsage(("100001100",))
    ext = asn1_x509.Extension()
    ext["extn_id"] = asn1_x509.ExtensionId("2.5.29.15")
    ext["critical"] = True
    ext["extn_value"] = k_u

    exts = asn1_csr.Extensions()
    exts.append(ext)

    ses = asn1_csr.SetOfExtensions()
    ses.append(exts)

    cria = asn1_csr.CRIAttribute()
    cria["type"] = asn1_csr.CSRAttributeType("1.2.840.113549.1.9.14")
    cria["values"] = ses

    if len(tbs["attributes"]) == 0:
        crias = asn1_csr.CRIAttributes()
        crias.append(cria)
        tbs["attributes"] = crias
    else:
        tbs["attributes"].append(cria)
    return tbs


def _set_tbs_extra_extensions(
    tbs: asn1_csr.CertificationRequestInfo, extra_extensions: asn1_x509.Extensions
) -> asn1_csr.CertificationRequestInfo:

    ses = asn1_csr.SetOfExtensions()
    ses.append(extra_extensions)

    cria = asn1_csr.CRIAttribute()
    cria["type"] = asn1_csr.CSRAttributeType("1.2.840.113549.1.9.14")
    cria["values"] = ses

    if len(tbs["attributes"]) == 0:
        crias = asn1_csr.CRIAttributes()
        crias.append(cria)
        tbs["attributes"] = crias
    else:
        tbs["attributes"].append(cria)

    return tbs


def _set_tbs_extensions(
    tbs: asn1_csr.CertificationRequestInfo, extra_extensions: asn1_x509.Extensions
) -> asn1_csr.CertificationRequestInfo:
    """Set all x509 extensions"""

    if extra_extensions is not None:
        tbs = _set_tbs_extra_extensions(tbs, extra_extensions)

    tbs = _set_tbs_basic_constraints(tbs)
    tbs = _set_tbs_key_usage(tbs)
    return tbs


def _create_tbs(
    subject_name: Dict[str, str],
    pk_info: asn1crypto.keys.PublicKeyInfo,
    extra_extensions: asn1_x509.Extensions,
) -> asn1_csr.CertificationRequestInfo:
    tbs = asn1_csr.CertificationRequestInfo()

    # Set all extensions
    tbs = _set_tbs_extensions(tbs, extra_extensions)

    # Set non extensions
    tbs = _set_tbs_version(tbs)
    tbs = _set_tbs_subject(tbs, subject_name)
    tbs = _set_tbs_subject_pk_info(tbs, pk_info)
    return tbs


async def create(  # pylint: disable-msg=too-many-arguments
    key_label: str,
    subject_name: Dict[str, str],
    key_size: int = 2048,
    signer_key_label: Union[str, None] = None,
    not_before: Union[datetime.datetime, None] = None,
    not_after: Union[datetime.datetime, None] = None,
    extra_extensions: Union[asn1_x509.Extensions, None] = None,
) -> Tuple[str, str]:
    """Create and sign a CSR with in the PKCS11 device.

    Returns the csr and the signed ca

    Parameters:
    key_label (str): Keypair label to create for the new ca
    subject_name (typing.Dict[str, str]): Dict with x509 subject names
    key_size (int = 2048): Key size, 2048 and 4096 works best.
    signer_key_label (str): Keylabel to sign this ca with, if None then this will be root (selfsigned) ca.
    not_before (Union[datetime.datetime, None] = None): The ca is not valid before this time.
    not_after (Union[datetime.datetime, None] = None): The ca is not valid after this time.
    extra_extensions (Union[asn1crypto.x509.Extensions, None] = None]): x509 extensions to write into the ca.

    Returns:
    typing.Tuple[str, str]
    """
    pk_info, _ = await PKCS11Session().create_keypair(key_label, key_size)
    data = pk_info.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    decoded_pk_info = PublicKeyInfo.load(data)

    tbs = _create_tbs(subject_name, decoded_pk_info, extra_extensions)

    signed_csr = asn1_csr.CertificationRequest()
    signed_csr["certification_request_info"] = tbs

    sda = SignedDigestAlgorithm()
    sda["algorithm"] = SignedDigestAlgorithmId("sha256_rsa")

    signed_csr["signature_algorithm"] = sda
    signed_csr["signature"] = await PKCS11Session().sign(key_label, tbs.dump())

    pem_enc: bytes = asn1_pem.armor("CERTIFICATE REQUEST", signed_csr.dump())

    # If this will be a root CA or not
    if signer_key_label is None:
        signer_key_label = key_label

    return pem_enc.decode("utf-8"), await sign_csr(
        signer_key_label,
        subject_name,
        pem_enc.decode("utf-8"),
        not_before=not_before,
        not_after=not_after,
        keep_csr_extensions=True,
    )
