"""
Module which sign CRS

Exposes the functions:
- sign_csr()
"""

import datetime
import os

from asn1crypto import x509 as asn1_x509
from asn1crypto import csr as asn1_csr
from asn1crypto import pem as asn1_pem
from asn1crypto.core import OctetString
from asn1crypto.algos import SignedDigestAlgorithm, SignedDigestAlgorithmId

from .PKCS11Handle import PKCS11Session

# FIXME allow optional company name when generating csr with openssl
# THAT IS NOT TESTED
def _request_to_tbs_certificate(csr_pem: str
                                ) -> asn1_x509.TbsCertificate:

    data = csr_pem.encode('utf-8')
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    req = asn1_csr.CertificationRequest.load(data)

    exts = asn1_x509.Extensions()

    attrs = req["certification_request_info"]["attributes"]
    for attr, _ in enumerate(attrs):
        for extensions, _ in enumerate(attrs[attr]["values"]):
            for extension, _ in enumerate(attrs[attr]["values"][extensions]):
                exts.append(attrs[attr]["values"][extensions][extension])

    tbs = asn1_x509.TbsCertificate()
    tbs["subject"] = req["certification_request_info"]["subject"]
    tbs["subject_public_key_info"] = req["certification_request_info"]["subject_pk_info"]

    tbs["extensions"] = exts
    return tbs

# Keep only the first one
# FIXME not tested
def _set_tbs_remove_duplicate_extensions(tbs: asn1_x509.TbsCertificate
                                         ) -> asn1_x509.TbsCertificate:

    if len(tbs["extensions"]) == 0:
        return tbs

    extensions = []
    exts = asn1_x509.Extensions()

    for ext, _ in enumerate(tbs["extensions"]):
        if tbs["extensions"][ext]["extn_id"].dotted not in extensions:
            exts.append(tbs["extensions"][ext])
            extensions.append(tbs["extensions"][ext]["extn_id"].dotted)

    tbs["extensions"] = exts
    return tbs

def _set_tbs_issuer(tbs: asn1_x509.TbsCertificate,
                    issuer_name: dict[str, str]
                    ) -> asn1_x509.TbsCertificate:

    tbs["issuer"] = asn1_csr.Name().build(issuer_name)
    return tbs

def _set_tbs_version(tbs: asn1_x509.TbsCertificate
                     ) -> asn1_x509.TbsCertificate:

    tbs["version"] = 2
    return tbs

def _set_tbs_serial(tbs: asn1_x509.TbsCertificate
                    ) -> asn1_x509.TbsCertificate:

    # Same code as python cryptography lib
    tbs["serial_number"] = int.from_bytes(os.urandom(20), "big") >> 1
    return tbs

def _set_tbs_validity(tbs: asn1_x509.TbsCertificate
                      ) -> asn1_x509.TbsCertificate:

    val = asn1_x509.Validity()
    val["not_before"] = asn1_x509.Time(name="utc_time",
                                       value=datetime.datetime.now(
                                           datetime.timezone.utc)
                                       - datetime.timedelta(2))
    val["not_after"] = asn1_x509.Time(name="utc_time",
                                      value=datetime.datetime.now(
                                          datetime.timezone.utc)
                                      + datetime.timedelta(365,0,0))
    tbs["validity"] = val
    return tbs

def _set_tbs_ski(tbs: asn1_x509.TbsCertificate
                 ) -> asn1_x509.TbsCertificate:

    ski = OctetString()
    ski.set(tbs["subject_public_key_info"].sha1)

    for extension in range(len(tbs["extensions"])):
        if tbs["extensions"][extension]["extn_id"].dotted == "2.5.29.14":
            tbs["extensions"][extension]["extn_value"] = ski
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

def _set_tbs_aki(tbs: asn1_x509.TbsCertificate,
                 identifier: bytes
                 ) -> asn1_x509.TbsCertificate:

    aki = asn1_x509.AuthorityKeyIdentifier()
    aki["key_identifier"] = identifier

    for extension, _ in enumerate(tbs["extensions"]):
        if tbs["extensions"][extension]["extn_id"].dotted == "2.5.29.35":
            tbs["extensions"][extension]["extn_value"] = aki
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

def _set_tbs_signature(tbs: asn1_x509.TbsCertificate
                       ) -> asn1_x509.TbsCertificate:

    sda = SignedDigestAlgorithm()
    sda["algorithm"] = SignedDigestAlgorithmId("sha256_rsa")
    tbs["signature"] = sda
    return tbs

def _create_tbs_certificate(tbs: asn1_x509.TbsCertificate,
                            issuer_name: dict[str, str],
                            aki: bytes
                            ) -> asn1_x509.TbsCertificate:

    tbs = _set_tbs_remove_duplicate_extensions(tbs) # FIXME not tested

    tbs = _set_tbs_version(tbs)
    tbs = _set_tbs_issuer(tbs, issuer_name)
    tbs = _set_tbs_serial(tbs)
    tbs = _set_tbs_validity(tbs)
    tbs = _set_tbs_ski(tbs)
    tbs = _set_tbs_aki(tbs, aki)
    tbs = _set_tbs_signature(tbs)
    return tbs

def sign_csr(key_label: str,
             issuer_name: dict[str, str],
             csr_pem: str
             ) -> str:
    """
    Sign a CSR by the key with the key_label in the PKCS11 device.

    Parameters:
    key_label (str): Keypair label.
    issuer_name (dict[str, str]): Dict with the signers x509 Names
    csr_pem (Union[str, None] = None]): A CRL to append to

    Returns:
    str

    """

    aki = PKCS11Session().key_identifier(key_label)

    tbs = _request_to_tbs_certificate(csr_pem)

    tbs = _create_tbs_certificate(tbs, issuer_name, aki)

    signed_cert = asn1_x509.Certificate()
    signed_cert["tbs_certificate"] = tbs
    signed_cert["signature_algorithm"] = tbs["signature"]
    signed_cert["signature_value"] = PKCS11Session().sign(tbs.dump(), key_label)
    pem_enc = asn1_pem.armor('CERTIFICATE', signed_cert.dump())

    # Needed for mypy strict
    assert isinstance(pem_enc, bytes)

    cert_pem = pem_enc.decode('utf-8')

    # Needed for mypy strict
    assert isinstance(cert_pem, str)

    return cert_pem
