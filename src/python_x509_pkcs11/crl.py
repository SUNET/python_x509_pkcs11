"""Module which creates CRLs
Can also append to an existing CRL

Exposes the functions:
- create()
"""

from typing import Union, Dict
import datetime

from asn1crypto import crl as asn1_crl
from asn1crypto import pem as asn1_pem
from asn1crypto.algos import SignedDigestAlgorithm, SignedDigestAlgorithmId

from .pkcs11_handle import PKCS11Session
from .error import DuplicateExtensionException


def _check_tbs_duplicate_extensions(tbs: asn1_crl.TbsCertList) -> None:
    """A certificate MUST NOT include more
    than one instance of a particular extension. For example, a
    certificate may contain only one authority key identifier extension
    https://www.rfc-editor.org/rfc/rfc5280#section-4.2

    Parameters:
    tbs (asn1_crl.TbsCertList): The 'To be signed' crl

    Returns:
    None
    """

    extensions = []
    for _, ext in enumerate(tbs["crl_extensions"]):
        if ext["extn_id"].dotted in extensions:
            raise DuplicateExtensionException("Found duplicate extension " + ext["extn_id"].dotted)
        extensions.append(ext["extn_id"].dotted)


def _set_tbs_version(tbs: asn1_crl.TbsCertList) -> asn1_crl.TbsCertList:

    tbs["version"] = 2
    return tbs


def _set_tbs_issuer(tbs: asn1_crl.TbsCertList, subject_name: Dict[str, str]) -> asn1_crl.TbsCertList:

    tbs["issuer"] = asn1_crl.Name().build(subject_name)
    return tbs


def _set_tbs_next_update(
    tbs: asn1_crl.TbsCertList, next_update: Union[datetime.datetime, None]
) -> asn1_crl.TbsCertList:

    if next_update is None:
        tbs["next_update"] = asn1_crl.Time(
            name="utc_time",
            value=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),
        )
    else:
        tbs["next_update"] = asn1_crl.Time(name="utc_time", value=next_update)
    return tbs


def _set_tbs_this_update(
    tbs: asn1_crl.TbsCertList, this_update: Union[datetime.datetime, None]
) -> asn1_crl.TbsCertList:

    if this_update is None:
        tbs["this_update"] = asn1_crl.Time(
            name="utc_time",
            value=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2),
        )
    else:
        tbs["this_update"] = asn1_crl.Time(name="utc_time", value=this_update)
    return tbs


def _set_tbs_aki(tbs: asn1_crl.TbsCertList, identifier: bytes) -> asn1_crl.TbsCertList:

    aki = asn1_crl.AuthorityKeyIdentifier()
    aki["key_identifier"] = identifier

    for _, extension in enumerate(tbs["crl_extensions"]):
        if extension["extn_id"].dotted == "2.5.29.35":
            extension["extn_value"] = aki
            return tbs

    ext = asn1_crl.TBSCertListExtension()
    ext["extn_id"] = asn1_crl.TBSCertListExtensionId("2.5.29.35")
    ext["extn_value"] = aki

    if len(tbs["crl_extensions"]) == 0:
        exts = asn1_crl.TBSCertListExtensions()
        exts.append(ext)
        tbs["crl_extensions"] = exts
    else:
        tbs["crl_extensions"].append(ext)
    return tbs


def _set_tbs_update_crl_number(
    tbs: asn1_crl.TbsCertList,
) -> asn1_crl.TbsCertList:

    for _, extension in enumerate(tbs["crl_extensions"]):
        if extension["extn_id"].dotted == "2.5.29.20":
            extension["extn_value"] = extension["extn_value"].native + 1
            return tbs

    ext = asn1_crl.TBSCertListExtension()
    ext["extn_id"] = asn1_crl.TBSCertListExtensionId("2.5.29.20")
    ext["extn_value"] = 1

    if len(tbs["crl_extensions"]) == 0:
        exts = asn1_crl.TBSCertListExtensions()
        exts.append(ext)
        tbs["crl_extensions"] = exts
    else:
        tbs["crl_extensions"].append(ext)
    return tbs


def _set_tbs_signature(tbs: asn1_crl.TbsCertList) -> asn1_crl.TbsCertList:

    algo = SignedDigestAlgorithm()
    algo["algorithm"] = SignedDigestAlgorithmId("sha256_rsa")
    tbs["signature"] = algo
    return tbs


def _set_tbs_revoke_serial_numer(tbs: asn1_crl.TbsCertList, serial_number: int, reason: int) -> asn1_crl.TbsCertList:

    r_cert = asn1_crl.RevokedCertificate()
    r_cert["user_certificate"] = serial_number
    r_cert["revocation_date"] = asn1_crl.Time(
        name="utc_time",
        value=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(2),
    )

    ext = asn1_crl.CRLEntryExtension()
    ext["extn_id"] = asn1_crl.CRLEntryExtensionId("2.5.29.21")
    ext["critical"] = False
    ext["extn_value"] = reason

    exts = asn1_crl.CRLEntryExtensions()
    exts.append(ext)

    r_cert["crl_entry_extensions"] = exts

    rcs = asn1_crl.RevokedCertificates()

    if len(tbs["revoked_certificates"]) != 0:
        # Overwrite the old entry for this serial number
        for _, revoked in enumerate(tbs["revoked_certificates"]):
            if serial_number != revoked["user_certificate"].native:
                rcs.append(revoked)

    rcs.append(r_cert)
    tbs["revoked_certificates"] = rcs
    return tbs


def _set_tbs_extensions(tbs: asn1_crl.TbsCertList, aki: bytes) -> asn1_crl.TbsCertList:
    """Set all x509 extensions"""

    tbs = _set_tbs_aki(tbs, aki)
    _check_tbs_duplicate_extensions(tbs)
    return tbs


def _create_tbs_cert_list(
    tbs: asn1_crl.TbsCertList,
    subject_name: Dict[str, str],
    aki: bytes,
    this_update: Union[datetime.datetime, None],
    next_update: Union[datetime.datetime, None],
) -> asn1_crl.TbsCertList:

    # Set extensions
    tbs = _set_tbs_extensions(tbs, aki)

    # Set non extensions
    tbs = _set_tbs_version(tbs)
    tbs = _set_tbs_issuer(tbs, subject_name)
    tbs = _set_tbs_next_update(tbs, next_update)
    tbs = _set_tbs_this_update(tbs, this_update)
    tbs = _set_tbs_update_crl_number(tbs)
    tbs = _set_tbs_signature(tbs)
    return tbs


def _load_crl(crl_pem: str) -> asn1_crl.CertificateList:
    data = crl_pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert_list = asn1_crl.CertificateList.load(data)
    return cert_list


async def create(  # pylint: disable-msg=too-many-arguments
    key_label: str,
    subject_name: Dict[str, str],
    old_crl_pem: Union[str, None] = None,
    serial_number: Union[int, None] = None,
    reason: Union[int, None] = None,
    this_update: Union[datetime.datetime, None] = None,
    next_update: Union[datetime.datetime, None] = None,
) -> str:
    """Create a CRL signed by the key with the key_label in the PKCS11 device.

    Parameters:
    key_label (str): Keypair label.
    subject_name (typing.Dict[str, str]): Dict with x509 Names.
    old_crl_pem (Union[str, None] = None]): A pem encoded CRL to append to, skip if None.
    serial_number (Union[int, None] = None]): Serial to the CRL, skip if None.
    reason (Union[int, None] = None]): The reason for revocation, skip if None.
    this_update (Union[datetime.datetime, None] = None): The CRLs timestamp.
    next_update (Union[datetime.datetime, None] = None): The next CRLs timestamp.

    Returns:
    str
    """
    _, aki = await PKCS11Session().public_key_data(key_label)

    # If appending to existing crl or creating a new empty crl
    if old_crl_pem is not None:
        tbs = _load_crl(old_crl_pem)["tbs_cert_list"]
    else:
        tbs = asn1_crl.TbsCertList()

    # If appending serial number to exisiting crl or creating a new empty crl
    if serial_number is not None and reason is not None:
        tbs = _set_tbs_revoke_serial_numer(tbs, serial_number, reason)

    tbs = _create_tbs_cert_list(tbs, subject_name, aki, this_update, next_update)

    cert_list = asn1_crl.CertificateList()
    cert_list["tbs_cert_list"] = tbs
    cert_list["signature_algorithm"] = tbs["signature"]
    cert_list["signature"] = await PKCS11Session.sign(key_label, tbs.dump())
    pem_enc: bytes = asn1_pem.armor("X509 CRL", cert_list.dump())

    return pem_enc.decode("utf-8")
