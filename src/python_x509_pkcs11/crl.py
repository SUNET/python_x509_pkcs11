"""Module which creates CRLs
Can also append to an existing CRL

Exposes the functions:
- create()
"""

import datetime
from typing import Dict, Optional, Union

from asn1crypto import pem as asn1_pem
from asn1crypto.crl import (
    AuthorityKeyIdentifier,
    CertificateList,
    CRLEntryExtension,
    CRLEntryExtensionId,
    CRLEntryExtensions,
    Name,
    RevokedCertificate,
    RevokedCertificates,
    TbsCertList,
    TBSCertListExtension,
    TBSCertListExtensionId,
    TBSCertListExtensions,
    Time,
)

from .error import DuplicateExtensionException
from .lib import DEFAULT_KEY_TYPE, KEYTYPES, get_keytypes_enum, signed_digest_algo
from .pkcs11_handle import PKCS11Session


def _check_tbs_duplicate_extensions(tbs: TbsCertList) -> None:
    """A certificate MUST NOT include more
    than one instance of a particular extension. For example, a
    certificate may contain only one authority key identifier extension
    https://www.rfc-editor.org/rfc/rfc5280#section-4.2

    Raises DuplicateExtensionException if duplicate extensions are found.

    Parameters:
    tbs (TbsCertList): The 'To be signed' crl

    Returns:
    None
    """

    extensions = []
    for _, ext in enumerate(tbs["crl_extensions"]):
        if ext["extn_id"].dotted in extensions:
            raise DuplicateExtensionException(f"Found duplicate extension {ext['extn_id'].dotted}")
        extensions.append(ext["extn_id"].dotted)


def _set_tbs_version(tbs: TbsCertList) -> TbsCertList:
    """Sets CRL version to 2 (integer value 1).

    https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.2.1
    """
    tbs["version"] = 1
    return tbs


def _set_tbs_issuer(tbs: TbsCertList, subject_name: Dict[str, str]) -> TbsCertList:
    """Sets CRL issuer to the given subject name.

    https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.2.3
    """
    tbs["issuer"] = Name().build(subject_name)
    return tbs


def _set_tbs_next_update(tbs: TbsCertList, next_update: Optional[datetime.datetime]) -> TbsCertList:
    """Sets the CRL next update time to the given datetime.

    https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.2.5
    """
    if next_update is None:
        tbs["next_update"] = Time(
            name="utc_time",
            value=(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).replace(microsecond=0),
        )
    else:
        tbs["next_update"] = Time(name="utc_time", value=next_update.replace(microsecond=0))
    return tbs


def _set_tbs_this_update(tbs: TbsCertList, this_update: Optional[datetime.datetime]) -> TbsCertList:
    """Sets the CRL this update time to the given datetime.

    https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.2.4
    """
    if this_update is None:
        # -2 minutes to protect from the certificate readers time skew
        tbs["this_update"] = Time(
            name="utc_time",
            value=(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)).replace(microsecond=0),
        )
    else:
        tbs["this_update"] = Time(name="utc_time", value=this_update.replace(microsecond=0))
    return tbs


def _set_tbs_aki(tbs: TbsCertList, identifier: bytes) -> TbsCertList:
    """Sets the CRL authority key identifier extension to the given identifier.

    https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.1
    """
    aki = AuthorityKeyIdentifier()
    aki["key_identifier"] = identifier

    # https://github.com/wbond/asn1crypto/blob/b763a757bb2bef2ab63620611ddd8006d5e9e4a2/asn1crypto/crl.py#L67
    for _, extension in enumerate(tbs["crl_extensions"]):
        if extension["extn_id"].dotted == "2.5.29.35":
            extension["extn_value"] = aki
            return tbs

    ext = TBSCertListExtension()
    ext["extn_id"] = TBSCertListExtensionId("2.5.29.35")
    ext["extn_value"] = aki

    if len(tbs["crl_extensions"]) == 0:
        exts = TBSCertListExtensions()
        exts.append(ext)
        tbs["crl_extensions"] = exts
    else:
        tbs["crl_extensions"].append(ext)
    return tbs


def _set_tbs_update_crl_number(tbs: TbsCertList) -> TbsCertList:
    """Sets the CRL number extension to the given integer value.

    https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3
    """
    for _, extension in enumerate(tbs["crl_extensions"]):
        if extension["extn_id"].dotted == "2.5.29.20":
            extension["extn_value"] = extension["extn_value"].native + 1
            return tbs
    # https://github.com/wbond/asn1crypto/blob/b763a757bb2bef2ab63620611ddd8006d5e9e4a2/asn1crypto/crl.py#L64
    ext = TBSCertListExtension()
    ext["extn_id"] = TBSCertListExtensionId("2.5.29.20")
    ext["extn_value"] = 1

    if len(tbs["crl_extensions"]) == 0:
        exts = TBSCertListExtensions()
        exts.append(ext)
        tbs["crl_extensions"] = exts
    else:
        tbs["crl_extensions"].append(ext)
    return tbs


def _set_tbs_revoke_serial_numer(tbs: TbsCertList, serial_number: int, reason: int) -> TbsCertList:
    """Sets revocation reason for a certificate.

    https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
    """

    # https://github.com/wbond/asn1crypto/blob/b763a757bb2bef2ab63620611ddd8006d5e9e4a2/asn1crypto/crl.py#L97
    if reason not in [0, 1, 2, 3, 4, 5, 6, 8, 9, 10]:
        raise ValueError(f"ERROR: CRL reason must be in {[0, 1, 2, 3, 4, 5, 6, 8, 9, 10]}")

    r_cert = RevokedCertificate()
    r_cert["user_certificate"] = serial_number
    r_cert["revocation_date"] = Time(
        name="utc_time",
        value=(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)).replace(microsecond=0),
    )

    ext = CRLEntryExtension()
    # https://github.com/wbond/asn1crypto/blob/b763a757bb2bef2ab63620611ddd8006d5e9e4a2/asn1crypto/crl.py#L136
    ext["extn_id"] = CRLEntryExtensionId("2.5.29.21")
    ext["critical"] = False
    ext["extn_value"] = reason

    exts = CRLEntryExtensions()
    exts.append(ext)

    r_cert["crl_entry_extensions"] = exts

    rcs = RevokedCertificates()

    if len(tbs["revoked_certificates"]) != 0:
        # Overwrite the old entry for this serial number
        for _, revoked in enumerate(tbs["revoked_certificates"]):
            if serial_number != revoked["user_certificate"].native:
                rcs.append(revoked)

    rcs.append(r_cert)
    tbs["revoked_certificates"] = rcs
    return tbs


def _set_tbs_extensions(tbs: TbsCertList, aki: bytes) -> TbsCertList:
    tbs = _set_tbs_aki(tbs, aki)
    _check_tbs_duplicate_extensions(tbs)
    return tbs


def _create_tbs_cert_list(
    tbs: TbsCertList,
    subject_name: Dict[str, str],
    aki: bytes,
    this_update: Optional[datetime.datetime],
    next_update: Optional[datetime.datetime],
) -> TbsCertList:
    # Set extensions
    tbs = _set_tbs_extensions(tbs, aki)

    # Set non extensions
    tbs = _set_tbs_version(tbs)
    tbs = _set_tbs_issuer(tbs, subject_name)
    tbs = _set_tbs_next_update(tbs, next_update)
    tbs = _set_tbs_this_update(tbs, this_update)
    tbs = _set_tbs_update_crl_number(tbs)
    return tbs


def _load_crl(crl_pem: str) -> CertificateList:
    """Load a CRL from a PEM string."""
    data = crl_pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert_list = CertificateList.load(data)
    return cert_list


async def _set_signature(
    key_label: str, cert_list: CertificateList, key_type: KEYTYPES = DEFAULT_KEY_TYPE
) -> CertificateList:
    """Sign a CertificateList with the key with the key_label in the PKCS11 device.

    Parameters:
    key_label str: Keypair label.
    key_type KEYTYPES: Key type, default is KEYTYPES.ED25519
    cert_list CertificateList: CertificateList to be signed.
    """

    # https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.1
    cert_list["tbs_cert_list"]["signature"] = signed_digest_algo(key_type)
    # https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.1.2
    cert_list["signature_algorithm"] = cert_list["tbs_cert_list"]["signature"]
    # https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.1.3
    cert_list["signature"] = await PKCS11Session().sign(
        key_label, cert_list["tbs_cert_list"].dump(), key_type=key_type.value
    )
    return cert_list


async def create(  # pylint: disable-msg=too-many-arguments
    key_label: str,
    subject_name: Dict[str, str],
    old_crl_pem: Optional[str] = None,
    serial_number: Optional[int] = None,
    reason: Optional[int] = None,
    this_update: Optional[datetime.datetime] = None,
    next_update: Optional[datetime.datetime] = None,
    key_type: Union[str, KEYTYPES] = DEFAULT_KEY_TYPE,
) -> str:
    """Create a CRL signed by the key with the key_label in the PKCS11 device.

    Parameters:
    key_label (str): Keypair label.
    subject_name (Dict[str, str]): Dict with x509 Names.
    old_crl_pem (Optional[str] = None]): A pem encoded CRL to append to, skip if None.
    serial_number (Optional[int] = None]): Serial to the CRL, skip if None.
    reason (Optional[int] = None]): The reason for revocation, skip if None.
    this_update (Optional[datetime.datetime] = None): The CRLs timestamp.
    next_update (Optional[datetime.datetime] = None): The next CRLs timestamp.
    key_type str: Key type to use, ed25519 is default.

    Returns:
    str
    """
    if isinstance(key_type, str):
        key_type = get_keytypes_enum(key_type)

    _, aki = await PKCS11Session().public_key_data(key_label, key_type=key_type)

    # If appending to existing crl or creating a new empty crl
    if old_crl_pem is not None:
        tbs = _load_crl(old_crl_pem)["tbs_cert_list"]
    else:
        tbs = TbsCertList()

    # If appending serial number to existing crl or creating a new empty crl
    if serial_number is not None and reason is not None:
        tbs = _set_tbs_revoke_serial_numer(tbs, serial_number, reason)

    tbs = _create_tbs_cert_list(tbs, subject_name, aki, this_update, next_update)

    cert_list = CertificateList()
    cert_list["tbs_cert_list"] = tbs
    cert_list = await _set_signature(key_label, cert_list, key_type)
    pem_enc: bytes = asn1_pem.armor("X509 CRL", cert_list.dump())
    return pem_enc.decode("utf-8")
