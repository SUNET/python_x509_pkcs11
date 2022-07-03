import datetime
import hashlib
import os
import pkcs11

from asn1crypto import x509 as asn1_x509
from asn1crypto import csr as asn1_csr
from asn1crypto import pem as asn1_pem
from asn1crypto.core import Integer as Integer, OctetString
from asn1crypto.algos import SignedDigestAlgorithm, SignedDigestAlgorithmId

import pkcs11_handle

# FIXME rewrite this code
def _request_to_tbs_certificate(r: str) -> asn1_x509.TbsCertificate:
    tbs = asn1_x509.TbsCertificate()

    data = r.encode('utf-8')
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
            
    req = asn1_csr.CertificationRequest.load(data)
        
    tbs["subject"] = req["certification_request_info"]["subject"]
    tbs["subject_public_key_info"] = req["certification_request_info"]["subject_pk_info"]
        

    es = asn1_x509.Extensions()

    attrs = req["certification_request_info"]["attributes"]
    for attr in range(len(attrs)):
        for extensions in range(len(attrs[attr]["values"])):
            for extension in range(len(attrs[attr]["values"][extensions])):
                es.append(attrs[attr]["values"][extensions][extension])

                #print (attr)
                # FIXME allow optional company name when generating csr with openssl
                # THAT IS NOT TESTED
        
    tbs["extensions"] = es
    return tbs

# Keep only the first one
# FIXME not tested
def _set_tbs_remove_duplicate_extensions(tbs: asn1_x509.TbsCertificate) -> asn1_x509.TbsCertificate:
    if len(tbs["extensions"]) == 0:
        return tbs

    extensions = []
    e = asn1_x509.Extensions()
        
    for x in range(len(tbs["extensions"])):
        if tbs["extensions"][x]["extn_id"].dotted not in extensions:
            e.append(tbs["extensions"][x])
            extensions.append(tbs["extensions"][x]["extn_id"].dotted)

    tbs["extensions"] = e
    return tbs
    
def _set_tbs_issuer(tbs: asn1_x509.TbsCertificate) -> asn1_x509.TbsCertificate:
    n = asn1_x509.Name().build({"country_name": "SE",
                                "state_or_province_name": "Stockholm",
                                "locality_name": "Stockholm",
                                "organization_name": "SUNET",
                                "organizational_unit_name": "SUNET Infrastructure",
                                "common_name": "ca-test.sunet.se",
                                "email_address": "soc@sunet.se"})

    tbs["issuer"] = n
    return tbs

def _set_tbs_version(tbs: asn1_x509.TbsCertificate) -> asn1_x509.TbsCertificate:
    tbs["version"] = 2
    return tbs

def _set_tbs_serial(tbs: asn1_x509.TbsCertificate) -> asn1_x509.TbsCertificate:
    # Same code as python cryptography lib
    tbs["serial_number"] = int.from_bytes(os.urandom(20), "big") >> 1
    return tbs

def _set_tbs_validity(tbs: asn1_x509.TbsCertificate) -> asn1_x509.TbsCertificate:
    v = asn1_x509.Validity()
    v["not_before"] = asn1_x509.Time(name="utc_time", value=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(2))
    v["not_after"] = asn1_x509.Time(name="utc_time", value=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(365,0,0))
    tbs["validity"] = v
    return tbs

def _set_tbs_ski(tbs: asn1_x509.TbsCertificate) -> asn1_x509.TbsCertificate:
    ski = OctetString()
    ski.set(tbs["subject_public_key_info"].sha1)
     
    for x in range(len(tbs["extensions"])):
        if tbs["extensions"][x]["extn_id"].dotted == "2.5.29.14":
            tbs["extensions"][x]["extn_value"] = ski
            return tbs

    ee = asn1_x509.Extension()
    ee["extn_id"] = asn1_x509.ExtensionId("2.5.29.14")
    ee["extn_value"] = ski

    if len(tbs["extensions"]) == 0:
        e = asn1_x509.Extensions()
        e.append(ee)
        tbs["extensions"] = e
    else:
        tbs["extensions"].append(ee)
    return tbs

def _set_tbs_aki(tbs: asn1_x509.TbsCertificate, identifier: bytes) -> asn1_x509.TbsCertificate:
    aki = asn1_x509.AuthorityKeyIdentifier()
    aki["key_identifier"] = identifier

    for x in range(len(tbs["extensions"])):
        if tbs["extensions"][x]["extn_id"].dotted == "2.5.29.35":
            tbs["extensions"][x]["extn_value"] = aki
            return tbs

    ee = asn1_x509.Extension()
    ee["extn_id"] = asn1_x509.ExtensionId("2.5.29.35")
    ee["extn_value"] = aki

    if len(tbs["extensions"]) == 0:
        e = asn1_x509.Extensions()
        e.append(ee)
        tbs["extensions"] = e
    else:
        tbs["extensions"].append(ee)
    return tbs
    
def _set_tbs_signature(tbs: asn1_x509.TbsCertificate) -> asn1_x509.TbsCertificate:
    sda = SignedDigestAlgorithm()
    sda["algorithm"] = SignedDigestAlgorithmId("sha256_rsa")
    tbs["signature"] = sda
    return tbs

def _create_tbs_certificate(tbs: asn1_x509.TbsCertificate, aki: bytes) -> asn1_x509.TbsCertificate:
    tbs = _set_tbs_remove_duplicate_extensions(tbs) # FIXME not tested
        
    tbs = _set_tbs_version(tbs)
    tbs = _set_tbs_issuer(tbs)
    tbs = _set_tbs_serial(tbs)
    tbs = _set_tbs_validity(tbs)
    tbs = _set_tbs_ski(tbs)
    tbs = _set_tbs_aki(tbs, aki)
    tbs = _set_tbs_signature(tbs)
    return tbs
    
def sign_csr(key_label: str, csr: str) -> bytes:
    
    aki = pkcs11_handle.Session().key_identifier(key_label)

    tbs = _request_to_tbs_certificate(csr)
    
    tbs = _create_tbs_certificate(tbs, aki)

    signed_cert = asn1_x509.Certificate()
    signed_cert["tbs_certificate"] = tbs
    signed_cert["signature_algorithm"] = tbs["signature"]
    signed_cert["signature_value"] = pkcs11_handle.Session().sign(tbs.dump(), key_label)
    r = asn1_pem.armor('CERTIFICATE', signed_cert.dump())

    # Needed for mypy strict
    assert(isinstance(r, bytes))
    
    return r
    

with open ("MYCSR.csr", "rb") as f:
    cr = f.read()

ce = sign_csr("test3", cr.decode('utf-8'))

with open("tbscert.pem", "wb") as w:
     w.write(ce)

