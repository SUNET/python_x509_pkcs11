from typing import Union
import datetime
import os
import hashlib
import pkcs11

from asn1crypto import crl as asn1_crl
from asn1crypto import pem as asn1_pem
from asn1crypto.core import Integer as Integer, OctetString
from asn1crypto.algos import SignedDigestAlgorithm, SignedDigestAlgorithmId

import pkcs11_handle

# Keep only the first one
def _set_tbs_remove_duplicate_extensions(tbs: asn1_crl.TbsCertList) -> asn1_crl.TbsCertList:
    if len(tbs["crl_extensions"]) == 0:
        return tbs
    
    extensions = []
    e = asn1_crl.TBSCertListExtensions()

    for x in range(len(tbs["crl_extensions"])):
        if tbs["crl_extensions"][x]["extn_id"].dotted not in extensions:
            e.append(tbs["crl_extensions"][x])
            extensions.append(tbs["crl_extensions"][x]["extn_id"].dotted)

    tbs["crl_extensions"] = e
    return tbs
    
def _set_tbs_version(tbs: asn1_crl.TbsCertList) -> asn1_crl.TbsCertList:
    tbs["version"] = 2
    return tbs

def _set_tbs_issuer(tbs: asn1_crl.TbsCertList) -> asn1_crl.TbsCertList:
    n = asn1_crl.Name().build({"country_name": "SE",
                                "state_or_province_name": "Stockholm",
                                "locality_name": "Stockholm",
                                "organization_name": "SUNET",
                                "organizational_unit_name": "SUNET Infrastructure",
                                "common_name": "ca-test.sunet.se",
                                "email_address": "soc@sunet.se"})

    tbs["issuer"] = n
    return tbs

def _set_tbs_next_update(tbs: asn1_crl.TbsCertList) -> asn1_crl.TbsCertList:
    tbs["next_update"] = asn1_crl.Time(name="utc_time", value=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(1, 0, 0))
    return tbs

def _set_tbs_this_update(tbs: asn1_crl.TbsCertList) -> asn1_crl.TbsCertList:
    tbs["this_update"] = asn1_crl.Time(name="utc_time", value=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(2))
    return tbs

def _set_tbs_aki(tbs: asn1_crl.TbsCertList, identifier: bytes) -> asn1_crl.TbsCertList:
    aki = asn1_crl.AuthorityKeyIdentifier()
    aki["key_identifier"] = identifier
     
    for x in range(len(tbs["crl_extensions"])):
        if tbs["crl_extensions"][x]["extn_id"].dotted == "2.5.29.35":
            tbs["crl_extensions"][x]["extn_value"] = aki
            return tbs

    ee = asn1_crl.TBSCertListExtension()
    ee["extn_id"] = asn1_crl.TBSCertListExtensionId("2.5.29.35")
    ee["extn_value"] = aki

    if len(tbs["crl_extensions"]) == 0:
        e = asn1_crl.TBSCertListExtensions()
        e.append(ee)
        tbs["crl_extensions"] = e
    else:
        tbs["crl_extensions"].append(ee)
    return tbs

def _set_tbs_update_crl_number(tbs: asn1_crl.TbsCertList) -> asn1_crl.TbsCertList:
    for x in range(len(tbs["crl_extensions"])):
        if tbs["crl_extensions"][x]["extn_id"].dotted == "2.5.29.20":
            tbs["crl_extensions"][x]["extn_value"] = tbs["crl_extensions"][x]["extn_value"].native + 1
            return tbs
        
    ee = asn1_crl.TBSCertListExtension()
    ee["extn_id"] = asn1_crl.TBSCertListExtensionId("2.5.29.20")
    ee["extn_value"] = 1

    if len(tbs["crl_extensions"]) == 0:
        e = asn1_crl.TBSCertListExtensions()
        e.append(ee)
        tbs["crl_extensions"] = e
    else:
        tbs["crl_extensions"].append(ee)
    return tbs


def _set_tbs_signature(tbs: asn1_crl.TbsCertList) -> asn1_crl.TbsCertList:
    sda = SignedDigestAlgorithm()
    sda["algorithm"] = SignedDigestAlgorithmId("sha256_rsa")
    tbs["signature"] = sda
    return tbs

# FIXME add CRLEntryExtension as well
def _set_tbs_revoke_serial_numer(tbs: asn1_crl.TbsCertList, serial_number: int, reason: int)  -> asn1_crl.TbsCertList:
    r = asn1_crl.RevokedCertificate()
    r["user_certificate"] = serial_number
    r["revocation_date"] = asn1_crl.Time(name="utc_time", value=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(2))

    cs = asn1_crl.CRLEntryExtensions()
    c = asn1_crl.CRLEntryExtension()
    c["extn_id"] = asn1_crl.CRLEntryExtensionId("2.5.29.21")
    c["critical"] = False
    c["extn_value"] = reason
    cs.append(c)
    r["crl_entry_extensions"] = cs

    rs = asn1_crl.RevokedCertificates()
    
    if len(tbs["revoked_certificates"]) != 0:
        # Overwrite the old entry for this serial number
        for x in range(len(tbs["revoked_certificates"])):
            if serial_number != tbs["revoked_certificates"][x]["user_certificate"].native:
                rs.append(tbs["revoked_certificates"][x])

    rs.append(r)
    tbs["revoked_certificates"] = rs
    return tbs
        
def _create_tbs_cert_list(tbs: asn1_crl.TbsCertList, aki: bytes) -> asn1_crl.TbsCertList:
    tbs = _set_tbs_remove_duplicate_extensions(tbs)
    tbs = _set_tbs_version(tbs)
    tbs = _set_tbs_issuer(tbs)
    tbs = _set_tbs_next_update(tbs)
    tbs = _set_tbs_this_update(tbs)
    tbs = _set_tbs_signature(tbs)
    tbs = _set_tbs_update_crl_number(tbs)
    tbs = _set_tbs_aki(tbs, aki)
    return tbs

def _load_crl(c: str) -> asn1_crl.CertificateList:
    data = c.encode('utf-8')
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cl = asn1_crl.CertificateList.load(data)
    return cl

    # FIXME add CRLEntryExtension as well to reboed serial number
def create(key_label: str,    
           old_crl: Union[str, None] = None,
           serial_number: Union[int, None] = None,
           reason: Union[int, None] = None
           ) -> bytes:
    
    aki = pkcs11_handle.Session().key_identifier(key_label)

    # If appending to exisiting crl or creating a new empty crl
    if old_crl is not None:
        tbs = _load_crl(old_crl)["tbs_cert_list"]
    else:
        tbs = asn1_crl.TbsCertList()

    # If appending serial number to exisiting crl or creating a new empty crl
    if serial_number is not None and reason is not None:
        tbs = _set_tbs_revoke_serial_numer(tbs, serial_number, reason)

    tbs = _create_tbs_cert_list(tbs, aki)
        
    cl = asn1_crl.CertificateList()
    cl["tbs_cert_list"] = tbs
    cl["signature_algorithm"] = tbs["signature"]
    cl["signature"] = pkcs11_handle.Session.sign(tbs.dump(), key_label)
    r = asn1_pem.armor('X509 CRL', cl.dump())

    # Needed for mypy strict
    assert(isinstance(r, bytes))
    
    return r

# with open ("google_crl_example.crl", "rb") as f:
#    cr = f.read()
    
# a = create("test3", cr)
# a = create("test3", cr, 23434634563456, 4)
# a = create("test3", serial_number=23434634563456, reason=4)
a = create("test3")

with open("tbscrl.crl", "wb") as w:
    w.write(a)



