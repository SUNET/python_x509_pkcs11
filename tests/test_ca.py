"""
Test to create a new root CA
"""
import asyncio
import datetime
import os
import subprocess
import unittest
from typing import Dict

from asn1crypto import csr as asn1_csr
from asn1crypto import pem as asn1_pem
from asn1crypto import x509 as asn1_x509
from asn1crypto.core import GeneralizedTime

from src.python_x509_pkcs11.ca import create
from src.python_x509_pkcs11.lib import key_types
from src.python_x509_pkcs11.pkcs11_handle import PKCS11Session

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

signer_name_dict = {
    "country_name": "SE",
    "state_or_province_name": "StockholmTEST",
    "locality_name": "StockholmTEST",
    "organization_name": "SUNET",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test-15.sunet.se",
    "email_address": "soc@sunet.se",
}

signed_name_dict = {
    "country_name": "SE",
    "state_or_province_name": "StockholmTEST",
    "locality_name": "StockholmTEST",
    "organization_name": "SUNET",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test-16.sunet.se",
    "email_address": "soc@sunet.se",
}


class TestCa(unittest.TestCase):
    """
    Test our root ca module.
    """

    def test_create_ca(self) -> None:
        """
        Create and self sign a CSR with the key_label in the pkcs11 device.
        """

        for key_type in key_types:
            new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
            # Test non default key size
            _, root_cert_pem = asyncio.run(create(new_key_label[:-1], name_dict, key_type=key_type))
            data = root_cert_pem.encode("utf-8")
            if asn1_pem.detect(data):
                _, _, data = asn1_pem.unarmor(data)

            test_cert = asn1_x509.Certificate.load(data)
            self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))

            # Ensure subject name and issuer name is the same since this is root ca
            cert_name_dict: Dict[str, str] = test_cert["tbs_certificate"]["subject"].native
            cert_issuer_name_dict: Dict[str, str] = test_cert["tbs_certificate"]["issuer"].native
            self.assertTrue(cert_name_dict["common_name"] == cert_issuer_name_dict["common_name"])

            # Ensure AKI and SKI is the same as this is a root CA
            tbs = test_cert["tbs_certificate"]
            for _, extension in enumerate(tbs["extensions"]):
                if extension["extn_id"].dotted == "2.5.29.14":
                    ski = extension["extn_value"].native
                    break
            else:
                raise ValueError("Could not find SKI")

            for _, extension in enumerate(tbs["extensions"]):
                if extension["extn_id"].dotted == "2.5.29.35":
                    aki = extension["extn_value"].native["key_identifier"]
                    break
            else:
                raise ValueError("Could not find AKI")

            self.assertTrue(aki == ski)

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
            self.assertTrue(isinstance(test_cert["tbs_certificate"]["extensions"], asn1_x509.Extensions))
            # CSR exts (key usage and basic constraints
            # + authority and subject key identifier = 4
            self.assertTrue(len(test_cert["tbs_certificate"]["extensions"]) == 4)

            # Delete the test keys
            asyncio.run(PKCS11Session.delete_keypair(new_key_label[:-1], key_type=key_type))
            asyncio.run(PKCS11Session.delete_keypair(new_key_label[:-2]))

    def test_create_ca_not_before_not_after(self) -> None:
        """
        Create and selfsign a CSR with the key_label in the pkcs11 device
        with non default not_before and not_after.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)

        # Test not_before parameter
        not_before = datetime.datetime(2022, 1, 1, tzinfo=datetime.timezone.utc)
        _, root_cert_pem = asyncio.run(
            create(
                new_key_label[:-1],
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
                new_key_label[:-2],
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

        # Delete the test keys
        asyncio.run(PKCS11Session.delete_keypair(new_key_label[:-1]))
        asyncio.run(PKCS11Session.delete_keypair(new_key_label[:-2]))

    def test_create_ca_with_extensions(self) -> None:
        """
        Create and selfsign a CSR with the key_label in the pkcs11 device.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        exts = asn1_csr.Extensions()

        pkup = asn1_x509.PrivateKeyUsagePeriod()
        pkup["not_before"] = GeneralizedTime(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
        )
        pkup["not_after"] = GeneralizedTime(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(365 * 10, 0, 0)
        )

        ext = asn1_x509.Extension()
        _, root_cert_pem = asyncio.run(create(new_key_label[:-1], name_dict, extra_extensions=exts))
        data = root_cert_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))

        cert_exts = test_cert["tbs_certificate"]["extensions"]
        # test pkup ext + CSR exts (key usage and basic constraints
        # + authority and subject key identifier = 5
        self.assertTrue(len(cert_exts) == 4)

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

        cert_exts = test_cert["tbs_certificate"]["extensions"]
        # test pkup ext + CSR exts (key usage and basic constraints
        # + authority and subject key identifier = 5
        self.assertTrue(len(cert_exts) == 5)

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(new_key_label))
        asyncio.run(PKCS11Session.delete_keypair(new_key_label[:-1]))

    def test_create_intermediate_ca(self) -> None:
        """
        Create an intermediate CA in the pkcs11 device.
        """

        for key_type in key_types:
            new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
            _, root_ca_pem = asyncio.run(create(new_key_label, signer_name_dict, key_type=key_type))

            new_key_label2 = hex(int.from_bytes(os.urandom(20), "big") >> 1)
            _, im_cert_pem = asyncio.run(
                create(
                    new_key_label2,
                    signed_name_dict,
                    signer_subject_name=signer_name_dict,
                    signer_key_label=new_key_label,
                    key_type=key_type,
                    signer_key_type=key_type,
                )
            )

            with open(new_key_label + ".crt", "wb") as f_data:
                f_data.write(root_ca_pem.encode("utf-8"))
            with open(new_key_label2 + ".crt", "wb") as f_data:
                f_data.write(im_cert_pem.encode("utf-8"))

            # Verify with openssl
            subprocess.check_call(
                "openssl verify -verbose -CAfile "
                + new_key_label
                + ".crt"
                + " "
                + new_key_label2
                + ".crt"
                + " > /dev/null && "
                + "rm -f "
                + new_key_label
                + ".crt"
                + " "
                + new_key_label2
                + ".crt",
                shell=True,
            )

            # subprocess.check_call(
            #     "softhsm2-util --delete-token --token my_test_token_1; softhsm2-util "
            #     "--init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN",
            #     shell=True,
            # )

            data = im_cert_pem.encode("utf-8")
            if asn1_pem.detect(data):
                _, _, data = asn1_pem.unarmor(data)

            im_cert_pem_asn1 = asn1_x509.Certificate.load(data)
            self.assertTrue(isinstance(im_cert_pem_asn1, asn1_x509.Certificate))

            # Check subject name and issuer name, should not be equal since this is an intermediate CA
            self.assertTrue(
                im_cert_pem_asn1["tbs_certificate"]["subject"].native["common_name"]
                != im_cert_pem_asn1["tbs_certificate"]["issuer"].native["common_name"]
            )
            # Check AKI and SKI, should not be equal since this is an intermediate CA
            tbs = im_cert_pem_asn1["tbs_certificate"]
            for _, extension in enumerate(tbs["extensions"]):
                if extension["extn_id"].dotted == "2.5.29.14":
                    ski = extension["extn_value"].native
            for _, extension in enumerate(tbs["extensions"]):
                if extension["extn_id"].dotted == "2.5.29.35":
                    aki = extension["extn_value"].native["key_identifier"]
            self.assertTrue(ski != aki)

            # Delete the test keys
            asyncio.run(PKCS11Session.delete_keypair(new_key_label, key_type=key_type))
            asyncio.run(PKCS11Session.delete_keypair(new_key_label2, key_type=key_type))

    def test_create_intermediate_diff_key_type_ca(self) -> None:
        """
        Create an intermediate CA with different key label in the pkcs11 device.
        """
        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        _, root_ca_pem = asyncio.run(create(new_key_label, signer_name_dict, key_type="ed25519"))

        new_key_label2 = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        _, im_cert_pem = asyncio.run(
            create(
                new_key_label2,
                signed_name_dict,
                signer_subject_name=signer_name_dict,
                signer_key_label=new_key_label,
                key_type="secp256r1",
                signer_key_type="ed25519",
            )
        )

        with open(new_key_label + ".crt", "wb") as f_data:
            f_data.write(root_ca_pem.encode("utf-8"))
        with open(new_key_label2 + ".crt", "wb") as f_data:
            f_data.write(im_cert_pem.encode("utf-8"))

        # Verify with openssl
        subprocess.check_call(
            "openssl verify -verbose -CAfile "
            + new_key_label
            + ".crt"
            + " "
            + new_key_label2
            + ".crt"
            + " > /dev/null "
            + "&& rm -f "
            + new_key_label
            + ".crt"
            + " "
            + new_key_label2
            + ".crt",
            shell=True,
        )

        data = im_cert_pem.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        im_cert_pem_asn1 = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(im_cert_pem_asn1, asn1_x509.Certificate))

        # Check subject name and issuer name, should not be equal since this is an intermediate CA
        self.assertTrue(
            im_cert_pem_asn1["tbs_certificate"]["subject"].native["common_name"]
            != im_cert_pem_asn1["tbs_certificate"]["issuer"].native["common_name"]
        )

        # Delete the test keys
        asyncio.run(PKCS11Session.delete_keypair(new_key_label, key_type="ed25519"))
        asyncio.run(PKCS11Session.delete_keypair(new_key_label2, key_type="secp256r1"))
