"""
Test to create a new root CA
"""
import unittest
import datetime
import os
import asyncio

from asn1crypto.core import GeneralizedTime
from asn1crypto import x509 as asn1_x509
from asn1crypto import csr as asn1_csr
from asn1crypto import pem as asn1_pem

from src.python_x509_pkcs11.ca import create

# Replace the above with this should you use this code
# from python_x509_pkcs11.ca import create

name_dict = {
    "country_name": "SE",
    "state_or_province_name": "Stockholm",
    "locality_name": "Stockholm",
    "organization_name": "SUNET",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test.sunet.se",
    "email_address": "soc@sunet.se",
}


class TestCa(unittest.TestCase):
    """
    Test our root ca module.
    """

    def test_create_ca(self) -> None:
        """
        Create and selfsign a CSR with the key_label in the pkcs11 device.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)

        # Test non default key size
        _, root_cert_pem = asyncio.run(create(new_key_label[:-1], name_dict, 4096))
        data = root_cert_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))

        # Test default values
        csr_pem, root_cert_pem = asyncio.run(create(new_key_label[:-2], name_dict))
        data = root_cert_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_cert = asn1_x509.Certificate.load(data)

        data = csr_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_csr = asn1_csr.CertificationRequest.load(data)

        self.assertTrue(isinstance(test_csr, asn1_csr.CertificationRequest))
        tbs = asn1_x509.TbsCertificate()
        tbs["subject_public_key_info"] = test_csr["certification_request_info"]["subject_pk_info"]
        self.assertTrue(
            tbs["subject_public_key_info"].dump() == test_cert["tbs_certificate"]["subject_public_key_info"].dump()
        )

        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))
        cert_exts = test_cert["tbs_certificate"]["extensions"]
        self.assertTrue(isinstance(cert_exts, asn1_x509.Extensions))
        # CSR exts (key usage and basic constraints
        # + authority and subject key identifier = 4
        self.assertTrue(len(cert_exts) == 4)

        # Test not_before parameter
        not_before = datetime.datetime(2022, 1, 1, tzinfo=datetime.timezone.utc)
        _, root_cert_pem = asyncio.run(
            create(
                new_key_label[:-3],
                name_dict,
                not_before=not_before,
            )
        )
        data = root_cert_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_c = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_c, asn1_x509.Certificate))
        self.assertTrue(test_c["tbs_certificate"]["validity"]["not_before"].native == not_before)

        # Test not_after parameter
        not_after = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        _, root_cert_pem = asyncio.run(
            create(
                new_key_label[:-4],
                name_dict,
                not_after=not_after,
            )
        )
        data = root_cert_pem.encode("utf-8")  # pylint: disable=duplicate-code
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        test_c = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_c, asn1_x509.Certificate))
        self.assertTrue(test_c["tbs_certificate"]["validity"]["not_after"].native == not_after)

    def test_create_ca_with_extensions(self) -> None:
        """
        Create and selfsign a CSR with the key_label in the pkcs11 device.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        exts = asn1_csr.Extensions()

        pkup = asn1_x509.PrivateKeyUsagePeriod()
        pkup["not_before"] = GeneralizedTime(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(2))
        pkup["not_after"] = GeneralizedTime(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(365 * 10, 0, 0)
        )

        ext = asn1_x509.Extension()
        ext["extn_id"] = asn1_x509.ExtensionId("2.5.29.16")
        ext["critical"] = False
        ext["extn_value"] = pkup
        exts.append(ext)

        _, root_cert_pem = asyncio.run(create(new_key_label, name_dict, extra_extensions=exts))

        data = root_cert_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)

        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))

        test_cert = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))

        cert_exts = test_cert["tbs_certificate"]["extensions"]
        # test pkup ext + CSR exts (key usage and basic constraints
        # + authority and subject key identifier = 5
        self.assertTrue(len(cert_exts) == 5)
