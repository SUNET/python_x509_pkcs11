"""
Test our OCSP
"""
import asyncio
import datetime
import os
import unittest
from secrets import token_bytes
from typing import List

from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import pem as asn1_pem
from asn1crypto import x509 as asn1_x509

from src.python_x509_pkcs11.error import (
    DuplicateExtensionException,
    OCSPMissingExtensionException,
)
from src.python_x509_pkcs11.ocsp import (
    certificate_ocsp_data,
    request,
    request_nonce,
    response,
)
from src.python_x509_pkcs11.pkcs11_handle import PKCS11Session

# Replace the above with this should you use this code
# from python_x509_pkcs11.ca import create

name_dict = {
    "country_name": "SE",
    "state_or_province_name": "Stockholm",
    "locality_name": "Stockholm_TEST",
    "organization_name": "SUNET",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test-ocsp-14.sunet.se",
    "email_address": "soc@sunet.se",
}

TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIFTjCCBDagAwIBAgIUTSCngZMLWEY0NsmHifr/Pu2bsicwDQYJKoZIhvcNAQEL
BQAwgZwxCzAJBgNVBAYTAlNFMRIwEAYDVQQIDAlTdG9ja2hvbG0xEjAQBgNVBAcM
CVN0b2NraG9sbTEOMAwGA1UECgwFU1VORVQxHTAbBgNVBAsMFFNVTkVUIEluZnJh
c3RydWN0dXJlMRkwFwYDVQQDDBBjYS10ZXN0LnN1bmV0LnNlMRswGQYJKoZIhvcN
AQkBFgxzb2NAc3VuZXQuc2UwHhcNMjIwOTI3MDYzODQwWhcNMjUwOTI2MDY0MDQw
WjCBqzELMAkGA1UEBhMCU0UxEjAQBgNVBAgMCVN0b2NraG9sbTEXMBUGA1UEBwwO
U3RvY2tob2xtX3Rlc3QxDjAMBgNVBAoMBVNVTkVUMR0wGwYDVQQLDBRTVU5FVCBJ
bmZyYXN0cnVjdHVyZTEjMCEGA1UEAwwaY2EtdGVzdC1jcmVhdGUtMjAuc3VuZXQu
c2UxGzAZBgkqhkiG9w0BCQEWDHNvY0BzdW5ldC5zZTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALZdE70YSvQgHIhWw+LQ47M9lEEeFjC0xKoptV6G586m
yHKS4ti2NclE82sPrFiUye3/FitLT7Pf+eTKZ4rAU+P/LuirL5XYsTgf6Pf6UsKw
9T9DDycO2llMmOHCGa+qPlMzDAJ/9Vffzr/bFz+Cv/n1/TWZhTMzAk4aGWfXvWbq
CHpGhPLuB1TXfmRBOB8cUCfbrfUJ+i0lD8oivrJtAdEEJDLuAQ5sZ7YI5Xw1AFPZ
fYHMY5Nw5PWydUI3OnpLL4rrAGDvHEvwtLro6znd8elHiK3SjgpMyTAgD4F2oZqQ
zBrO/cUksMCkQiwPa0kgfRNu91vq2SpKo47eYdPFo1cCAwEAAaOCAXUwggFxMA4G
A1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MIGgBggrBgEFBQcBAQSBkzCB
kDBlBggrBgEFBQcwAoZZaHR0cDovL2xvY2FsaG9zdDo4MDAwL2NhLzNhOWU1ZTYy
ZjFlN2IzZTIxN2RiMWUzNTNmMjA4MzNmZDI4NzI4ZThhZWMzZTEzOWU3OTRkMDFj
NTE5ZGU5MTcwJwYIKwYBBQUHMAGGG2h0dHA6Ly9sb2NhbGhvc3Q6ODAwMC9vY3Nw
LzBrBgNVHR8EZDBiMGCgXqBchlpodHRwOi8vbG9jYWxob3N0OjgwMDAvY3JsLzNh
OWU1ZTYyZjFlN2IzZTIxN2RiMWUzNTNmMjA4MzNmZDI4NzI4ZThhZWMzZTEzOWU3
OTRkMDFjNTE5ZGU5MTcwHQYDVR0OBBYEFFmrno6DYIVpbwUvhaMPr242LhmYMB8G
A1UdIwQYMBaAFK3QiERXlifO9CLGxzdXye9ppFuLMA0GCSqGSIb3DQEBCwUAA4IB
AQAkh+ijRkxjABqfkw4+fr8ZYAbdaZdXdZ2NgXGeB3DAFPYp6xZIREB+bE4YRd5n
xIsYWZTya1oTTCcMA2oLMO7Jv5KqJgkS5jDKM+SK3QIK68HfCW2ZrhkcGAmYmxOY
4eUkhFY3axEJ501/PqVxBRCj/FJbXsoI72v7lFj6MdESxEtJCj8lz5DdH3OHDgDd
4SQomVowm8nIfuxIuuoSoZR4DluPeWMDUoiKky8ocVxEymtE1tJYdrrL3f0ZcFey
mF+JNgr8wdkW7fMy3HpRk7QOvJ2calp9V2THBZ8T+UPKmCkBxdW511hDzLpIb7rA
lgIDB0Y1AZDNLKuq6QWifdf3
-----END CERTIFICATE-----
"""

requestor_name_dict = {
    "state_or_province_name": "Stockholm",
    "country_name": "FI",
    "organization_name": "SUNET",
    "locality_name": "Stockholm_test",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test-ocsp-14.sunet.se",
    "email_address": "soc@sunet.se",
}


def _mixed_response(ocsp_request: asn1_ocsp.OCSPRequest) -> asn1_ocsp.Responses:
    cert_ids: List[asn1_ocsp.CertId] = []
    responses = asn1_ocsp.Responses()

    for _, curr_req in enumerate(ocsp_request["tbs_request"]["request_list"]):
        cert_ids.append(curr_req["req_cert"])

    for index, cert_id in enumerate(cert_ids):
        curr_response = asn1_ocsp.SingleResponse()
        curr_response["cert_id"] = cert_id

        if index == 0:
            curr_response["cert_status"] = asn1_ocsp.CertStatus("good")
        elif index == 1:
            revoked_info = asn1_ocsp.RevokedInfo()
            revoked_info["revocation_time"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
                minutes=20
            )
            revoked_info["revocation_reason"] = asn1_ocsp.CRLReason(5)
            curr_response["cert_status"] = asn1_ocsp.CertStatus({"revoked": revoked_info})
        elif index == 2:
            curr_response["cert_status"] = asn1_ocsp.CertStatus("unknown")

        curr_response["this_update"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
        responses.append(curr_response)
    return responses


def _good_response(ocsp_request: asn1_ocsp.OCSPRequest) -> asn1_ocsp.Responses:
    cert_ids: List[asn1_ocsp.CertId] = []
    responses = asn1_ocsp.Responses()

    for _, curr_req in enumerate(ocsp_request["tbs_request"]["request_list"]):
        cert_ids.append(curr_req["req_cert"])

    for _, cert_id in enumerate(cert_ids):
        curr_response = asn1_ocsp.SingleResponse()
        curr_response["cert_id"] = cert_id
        curr_response["cert_status"] = asn1_ocsp.CertStatus("good")
        curr_response["this_update"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
        responses.append(curr_response)
    return responses


def _revoked_response(ocsp_request: asn1_ocsp.OCSPRequest) -> asn1_ocsp.Responses:
    cert_ids: List[asn1_ocsp.CertId] = []
    responses = asn1_ocsp.Responses()

    for _, curr_req in enumerate(ocsp_request["tbs_request"]["request_list"]):
        cert_ids.append(curr_req["req_cert"])

    for _, cert_id in enumerate(cert_ids):
        curr_response = asn1_ocsp.SingleResponse()
        curr_response["cert_id"] = cert_id

        revoked_info = asn1_ocsp.RevokedInfo()
        revoked_info["revocation_time"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=20)
        revoked_info["revocation_reason"] = asn1_ocsp.CRLReason(5)

        curr_response["cert_status"] = asn1_ocsp.CertStatus({"revoked": revoked_info})
        curr_response["this_update"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
        responses.append(curr_response)
    return responses


def _unknown_response(ocsp_request: asn1_ocsp.OCSPRequest) -> asn1_ocsp.Responses:
    cert_ids: List[asn1_ocsp.CertId] = []
    responses = asn1_ocsp.Responses()

    for _, curr_req in enumerate(ocsp_request["tbs_request"]["request_list"]):
        cert_ids.append(curr_req["req_cert"])

    for _, cert_id in enumerate(cert_ids):
        curr_response = asn1_ocsp.SingleResponse()
        curr_response["cert_id"] = cert_id
        curr_response["cert_status"] = asn1_ocsp.CertStatus("unknown")
        curr_response["this_update"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
        responses.append(curr_response)
    return responses


class TestOCSP(unittest.TestCase):
    """
    Test our OCSP module.
    """

    def test_ocsp_request(self) -> None:
        """
        Create an ocsp request.
        """

        # Test default
        i_name_h, i_key_h, serial, _ = certificate_ocsp_data(TEST_CERT)
        data = asyncio.run(request([(i_name_h, i_key_h, serial)]))
        test_ocsp = asn1_ocsp.OCSPRequest.load(data)
        self.assertTrue(isinstance(test_ocsp, asn1_ocsp.OCSPRequest))
        self.assertTrue(test_ocsp["tbs_request"]["version"].native == "v1")
        self.assertTrue(len(test_ocsp["tbs_request"]["request_list"]) == 1)
        self.assertTrue(test_ocsp["optional_signature"].native is None)

        # Test requestor name
        self.assertTrue(test_ocsp["tbs_request"]["requestor_name"].native is None)
        g_n = asn1_x509.GeneralName(name="directory_name", value=(asn1_ocsp.Name().build(requestor_name_dict)))
        data = asyncio.run(request([(i_name_h, i_key_h, serial)], requestor_name=g_n))
        test_ocsp = asn1_ocsp.OCSPRequest.load(data)
        self.assertTrue(isinstance(test_ocsp, asn1_ocsp.OCSPRequest))
        self.assertTrue(test_ocsp["tbs_request"]["requestor_name"] == g_n)

        # Test no certs in request
        with self.assertRaises(ValueError):
            data = asyncio.run(request([]))

        # Test multiple certs in request
        data = asyncio.run(request([(i_name_h, i_key_h, serial), (i_name_h, i_key_h, serial)]))
        test_ocsp = asn1_ocsp.OCSPRequest.load(data)
        self.assertTrue(isinstance(test_ocsp, asn1_ocsp.OCSPRequest))
        self.assertTrue(len(test_ocsp["tbs_request"]["request_list"]) == 2)

        # Test nonce extension
        nonce_val = token_bytes(32)
        nonce_ext = asn1_ocsp.TBSRequestExtension()
        nonce_ext["extn_id"] = asn1_ocsp.TBSRequestExtensionId("1.3.6.1.5.5.7.48.1.2")
        nonce_ext["extn_value"] = nonce_val
        extra_extensions = asn1_ocsp.TBSRequestExtensions()
        extra_extensions.append(nonce_ext)

        data = asyncio.run(
            request([(i_name_h, i_key_h, serial), (i_name_h, i_key_h, serial)], extra_extensions=extra_extensions)
        )
        test_ocsp = asn1_ocsp.OCSPRequest.load(data)
        self.assertTrue(isinstance(test_ocsp, asn1_ocsp.OCSPRequest))
        self.assertTrue(test_ocsp["tbs_request"]["request_extensions"][0]["extn_value"].native == nonce_val)

    def test_signed_ocsp_request(self) -> None:
        """
        Create a signed_ocsp request.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))
        i_name_h, i_key_h, serial, _ = certificate_ocsp_data(TEST_CERT)
        g_n = asn1_x509.GeneralName(name="directory_name", value=(asn1_ocsp.Name().build(requestor_name_dict)))

        # Test signed but no requestor name
        with self.assertRaises(ValueError):
            data = asyncio.run(request([(i_name_h, i_key_h, serial)], key_label=new_key_label))

        data = asyncio.run(request([(i_name_h, i_key_h, serial)], key_label=new_key_label, requestor_name=g_n))
        test_ocsp = asn1_ocsp.OCSPRequest.load(data)
        self.assertTrue(isinstance(test_ocsp, asn1_ocsp.OCSPRequest))

        # Ensure we have a sig
        self.assertTrue(isinstance(test_ocsp["optional_signature"]["signature"].native, bytes))
        self.assertTrue(len(test_ocsp["optional_signature"]["signature"].native) > 32)

        # 0 extra certs
        data = asyncio.run(request([(i_name_h, i_key_h, serial)], key_label=new_key_label, requestor_name=g_n))
        test_ocsp = asn1_ocsp.OCSPRequest.load(data)
        self.assertTrue(isinstance(test_ocsp, asn1_ocsp.OCSPRequest))
        self.assertTrue(len(test_ocsp["optional_signature"]["certs"]) == 0)

        # 2 extra certs
        data = asyncio.run(
            request(
                [(i_name_h, i_key_h, serial)], key_label=new_key_label, requestor_name=g_n, certs=[TEST_CERT, TEST_CERT]
            )
        )
        test_ocsp = asn1_ocsp.OCSPRequest.load(data)
        self.assertTrue(isinstance(test_ocsp, asn1_ocsp.OCSPRequest))
        self.assertTrue(len(test_ocsp["optional_signature"]["certs"]) == 2)

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(new_key_label))

    def test_ocsp_response(self) -> None:
        """
        Create an ocsp response.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))

        i_name_h, i_key_h, serial, _ = certificate_ocsp_data(TEST_CERT)
        data = asyncio.run(request([(i_name_h, i_key_h, serial)]))
        test_request = asn1_ocsp.OCSPRequest.load(data)
        self.assertTrue(isinstance(test_request, asn1_ocsp.OCSPRequest))
        data = asyncio.run(response(new_key_label, name_dict, _good_response(test_request), 0))
        test_response = asn1_ocsp.OCSPResponse.load(data)
        self.assertTrue(isinstance(test_response, asn1_ocsp.OCSPResponse))
        self.assertTrue(test_response["response_bytes"].native is not None)
        self.assertTrue(
            test_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"]
            == "good"
        )
        self.assertTrue(
            test_response["response_bytes"]["response"].native["tbs_response_data"]["response_extensions"] is None
            or len(test_response["response_bytes"]["response"].native["tbs_response_data"]["response_extensions"]) == 0
        )

        # Test produced_at
        i_name_h, i_key_h, serial, _ = certificate_ocsp_data(TEST_CERT)
        data = asyncio.run(request([(i_name_h, i_key_h, serial)]))
        test_request = asn1_ocsp.OCSPRequest.load(data)
        self.assertTrue(isinstance(test_request, asn1_ocsp.OCSPRequest))
        produced_at = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)).replace(
            microsecond=0
        )
        data = asyncio.run(response(new_key_label, name_dict, _good_response(test_request), 0, produced_at=produced_at))
        test_response = asn1_ocsp.OCSPResponse.load(data)
        self.assertTrue(
            test_response["response_bytes"]["response"].native["tbs_response_data"]["produced_at"] == produced_at
        )

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(new_key_label))

    def test_ocsp_response_cert_status(self) -> None:
        """
        Create an ocsp responses with different cert status
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))

        i_name_h, i_key_h, serial, _ = certificate_ocsp_data(TEST_CERT)

        # Revoked
        data = asyncio.run(request([(i_name_h, i_key_h, serial)]))
        test_request = asn1_ocsp.OCSPRequest.load(data)
        self.assertTrue(isinstance(test_request, asn1_ocsp.OCSPRequest))
        data = asyncio.run(response(new_key_label, name_dict, _revoked_response(test_request), 0))
        test_response = asn1_ocsp.OCSPResponse.load(data)
        self.assertTrue(isinstance(test_response, asn1_ocsp.OCSPResponse))
        self.assertTrue(
            test_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"][
                "revocation_reason"
            ]
            == "cessation_of_operation"
        )

        # Unknown
        data = asyncio.run(response(new_key_label, name_dict, _unknown_response(test_request), 0))
        test_response = asn1_ocsp.OCSPResponse.load(data)
        self.assertTrue(isinstance(test_response, asn1_ocsp.OCSPResponse))
        self.assertTrue(
            test_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"]
            == "unknown"
        )

        # Mixed
        data = asyncio.run(
            request([(i_name_h, i_key_h, serial), (i_name_h, i_key_h, serial), (i_name_h, i_key_h, serial)])
        )
        test_request = asn1_ocsp.OCSPRequest.load(data)
        self.assertTrue(isinstance(test_request, asn1_ocsp.OCSPRequest))
        data = asyncio.run(response(new_key_label, name_dict, _mixed_response(test_request), 0))
        test_response = asn1_ocsp.OCSPResponse.load(data)
        self.assertTrue(isinstance(test_response, asn1_ocsp.OCSPResponse))
        self.assertTrue(test_response["response_bytes"].native is not None)
        self.assertTrue(
            test_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"]
            == "good"
        )
        self.assertTrue(
            test_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][1]["cert_status"][
                "revocation_reason"
            ]
            == "cessation_of_operation"
        )
        self.assertTrue(
            test_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][2]["cert_status"]
            == "unknown"
        )

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(new_key_label))

    def test_ocsp_response_fail(self) -> None:
        """
        Create an unsuccessful ocsp response.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))

        i_name_h, i_key_h, serial, _ = certificate_ocsp_data(TEST_CERT)
        data = asyncio.run(request([(i_name_h, i_key_h, serial)]))
        test_request = asn1_ocsp.OCSPRequest.load(data)

        # Test status codes
        data = asyncio.run(response(new_key_label, name_dict, _good_response(test_request), 1))
        test_response = asn1_ocsp.OCSPResponse.load(data)
        self.assertTrue(isinstance(test_response, asn1_ocsp.OCSPResponse))
        self.assertTrue(test_response["response_bytes"].native is None)
        data = asyncio.run(response(new_key_label, name_dict, _good_response(test_request), 2))
        test_response = asn1_ocsp.OCSPResponse.load(data)
        self.assertTrue(test_response["response_bytes"].native is None)
        data = asyncio.run(response(new_key_label, name_dict, _good_response(test_request), 3))
        test_response = asn1_ocsp.OCSPResponse.load(data)
        self.assertTrue(test_response["response_bytes"].native is None)
        data = asyncio.run(response(new_key_label, name_dict, _good_response(test_request), 5))
        test_response = asn1_ocsp.OCSPResponse.load(data)
        self.assertTrue(test_response["response_bytes"].native is None)
        data = asyncio.run(response(new_key_label, name_dict, _good_response(test_request), 6))
        test_response = asn1_ocsp.OCSPResponse.load(data)
        self.assertTrue(test_response["response_bytes"].native is None)

        with self.assertRaises(ValueError):
            data = asyncio.run(response(new_key_label, name_dict, _good_response(test_request), 4))
            test_response = asn1_ocsp.OCSPResponse.load(data)
        with self.assertRaises(ValueError):
            data = asyncio.run(response(new_key_label, name_dict, _good_response(test_request), 99))
            test_response = asn1_ocsp.OCSPResponse.load(data)

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(new_key_label))

    def test_ocsp_response_extensions(self) -> None:
        """
        Create an ocsp response with extra extensions.
        """

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))

        i_name_h, i_key_h, serial, _ = certificate_ocsp_data(TEST_CERT)
        data = asyncio.run(request([(i_name_h, i_key_h, serial)]))
        test_request = asn1_ocsp.OCSPRequest.load(data)

        # Test too big nonce
        nonce_ext = asn1_ocsp.ResponseDataExtension()
        nonce_ext["extn_id"] = asn1_ocsp.ResponseDataExtensionId("1.3.6.1.5.5.7.48.1.2")
        nonce_ext["extn_value"] = token_bytes(33)
        extra_extensions = asn1_ocsp.ResponseDataExtensions()
        extra_extensions.append(nonce_ext)
        with self.assertRaises(ValueError):
            data = asyncio.run(
                response(
                    new_key_label, name_dict, _revoked_response(test_request), 0, extra_extensions=extra_extensions
                )
            )
        nonce_val = token_bytes(32)
        nonce_ext["extn_value"] = nonce_val
        extra_extensions = asn1_ocsp.ResponseDataExtensions()
        extra_extensions.append(nonce_ext)
        extra_extensions.append(nonce_ext)
        with self.assertRaises(DuplicateExtensionException):
            data = asyncio.run(
                response(
                    new_key_label, name_dict, _revoked_response(test_request), 0, extra_extensions=extra_extensions
                )
            )

        # Test both ok
        extra_extensions = asn1_ocsp.ResponseDataExtensions()
        extended_revoke_ext = asn1_ocsp.ResponseDataExtension()
        extended_revoke_ext["extn_id"] = asn1_ocsp.ResponseDataExtensionId("1.3.6.1.5.5.7.48.1.9")
        extended_revoke_ext["extn_value"] = None
        extra_extensions.append(nonce_ext)
        extra_extensions.append(extended_revoke_ext)
        data = asyncio.run(
            response(new_key_label, name_dict, _revoked_response(test_request), 0, extra_extensions=extra_extensions)
        )
        test_response = asn1_ocsp.OCSPResponse.load(data)
        self.assertTrue(isinstance(test_response, asn1_ocsp.OCSPResponse))
        self.assertTrue(
            test_response["response_bytes"]["response"].native["tbs_response_data"]["response_extensions"][0][
                "extn_value"
            ]
            == nonce_val
        )
        self.assertTrue(
            test_response["response_bytes"]["response"].native["tbs_response_data"]["response_extensions"][1]["extn_id"]
            == "extended_revoke"
        )

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(new_key_label))

    def test_request_nonce(self) -> None:
        """
        Test request nonce function.
        """

        nonce_ext = asn1_ocsp.TBSRequestExtension()
        nonce_ext["extn_id"] = asn1_ocsp.TBSRequestExtensionId("1.3.6.1.5.5.7.48.1.2")
        nonce_val = token_bytes(32)
        nonce_ext["extn_value"] = nonce_val
        extra_extensions = asn1_ocsp.TBSRequestExtensions()
        extra_extensions.append(nonce_ext)

        request_certs_data = [
            (
                b"R\x94\xca?\xac`\xf7i\x819\x14\x94\xa7\x085H\x84\xb4&\xcc",
                b"\xad\xd0\x88DW\x96'\xce\xf4\"\xc6\xc77W\xc9\xefi\xa4[\x8b",
                440320505043419981128735462508870123525487964711,
            )
        ]
        ocsp_request_bytes = asyncio.run(request(request_certs_data, extra_extensions=extra_extensions))
        nonce = request_nonce(ocsp_request_bytes)
        self.assertTrue(isinstance(nonce, bytes))
        self.assertTrue(nonce_val == nonce)

        ocsp_request_bytes = asyncio.run(request(request_certs_data))
        nonce = request_nonce(ocsp_request_bytes)
        self.assertTrue(nonce is None)

    def test_certificate_ocsp_data(self) -> None:
        """
        Test request certificate_ocsp_data function.
        """

        non_ocsp_cert = """-----BEGIN CERTIFICATE-----
MIIFIjCCBAqgAwIBAgIUQihqqBASG58siv7si/dOKCr4yH8wDQYJKoZIhvcNAQEL
BQAwgZwxCzAJBgNVBAYTAlNFMRIwEAYDVQQIDAlTdG9ja2hvbG0xEjAQBgNVBAcM
CVN0b2NraG9sbTEOMAwGA1UECgwFU1VORVQxHTAbBgNVBAsMFFNVTkVUIEluZnJh
c3RydWN0dXJlMRkwFwYDVQQDDBBjYS10ZXN0LnN1bmV0LnNlMRswGQYJKoZIhvcN
AQkBFgxzb2NAc3VuZXQuc2UwHhcNMjIwOTI4MTExOTU1WhcNMjUwOTI3MTEyMTU1
WjCBqzELMAkGA1UEBhMCU0UxEjAQBgNVBAgMCVN0b2NraG9sbTEXMBUGA1UEBwwO
U3RvY2tob2xtX3Rlc3QxDjAMBgNVBAoMBVNVTkVUMR0wGwYDVQQLDBRTVU5FVCBJ
bmZyYXN0cnVjdHVyZTEjMCEGA1UEAwwaY2EtdGVzdC1jcmVhdGUtMjAuc3VuZXQu
c2UxGzAZBgkqhkiG9w0BCQEWDHNvY0BzdW5ldC5zZTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAK7oiAE2i2/ggmRfkccHxeeA3OzN+GRZuKV0Gh/f+WE7
+1uq1Wm0wuovnpdDmQpsfXnu6D4zbzy9jysnS+7EcLQcEhSfq6ixBayj0yPjHz/i
sSk1lbFh94o/5TZE+o/gcqgsVTbjTGqIOQ/EfD+E3xMF8ZnNyvJjslu8SMuPbj6B
WRBBTKB7baGLoaOlxJTZ0c97oVGdSH46x782sKooyQInO81gNwWcBUTHBjG216wP
vMVtW9gxplm2dVw/l2nrz6g7Hp6xyY12ESWOdaRT73RdxmnQETe2wLHA0u7qcfmS
c8MUA6qeXcwwHzcoF8onUbV0UVJXhRPoLQ6R45q5C4ECAwEAAaOCAUkwggFFMA4G
A1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MHUGCCsGAQUFBwEBBGkwZzBl
BggrBgEFBQcwAoZZaHR0cDovL2xvY2FsaG9zdDo4MDAwL2NhLzMwMmVkNWE2NTQz
NDliYWYxNWU0MDAzMDhlODlmMmE3MzExODJhODJmMzgxODJjYzgxZWQyMzE3ZTkx
ODYwM2QwawYDVR0fBGQwYjBgoF6gXIZaaHR0cDovL2xvY2FsaG9zdDo4MDAwL2Ny
bC8zMDJlZDVhNjU0MzQ5YmFmMTVlNDAwMzA4ZTg5ZjJhNzMxMTgyYTgyZjM4MTgy
Y2M4MWVkMjMxN2U5MTg2MDNkMB0GA1UdDgQWBBQjhvSAPiHHO9ypvQW/5euSCcsx
dDAfBgNVHSMEGDAWgBRx52znW9b1xo5nW/lL+SukqsuVnzANBgkqhkiG9w0BAQsF
AAOCAQEAK1xFV5bpCulzA+a2g8pWSidaWW4stTZOvUrrpqMDXkicvsRjz7z7VrLG
3/B2ktD6vbq2PbOV92HmRSQeLfeOX9Mt4fYDYgvMNTopPA03WxIUngNOTSq4En97
ImB+yAP/aDnWPEIHFB+OtzKG4keGFEz4MLIwtaRALYfLstq6QWHShueSnX2HpKvU
S5G5p16d5rgraJAzUYzG7tn6jZxFSp2uAiOJDmegf6ss9fN+AOVN2GVEuQCRbICi
qYr0IdrSItJfk89KDm/ZB74C2xn1XUdvsxsM8HoKOotusIdFvpvrj/DCiKoqv7id
cvFnVe0ady+2DhPNGwbUXz1ExrpNcA==
-----END CERTIFICATE-----
"""

        non_aki_cert = """-----BEGIN CERTIFICATE-----
MIIFLTCCBBWgAwIBAgIUbaNUJW4TG3H+AqUS7pUgxUmO8AQwDQYJKoZIhvcNAQEL
BQAwgZwxCzAJBgNVBAYTAlNFMRIwEAYDVQQIDAlTdG9ja2hvbG0xEjAQBgNVBAcM
CVN0b2NraG9sbTEOMAwGA1UECgwFU1VORVQxHTAbBgNVBAsMFFNVTkVUIEluZnJh
c3RydWN0dXJlMRkwFwYDVQQDDBBjYS10ZXN0LnN1bmV0LnNlMRswGQYJKoZIhvcN
AQkBFgxzb2NAc3VuZXQuc2UwHhcNMjIwOTI4MTEyODIwWhcNMjUwOTI3MTEzMDIw
WjCBqzELMAkGA1UEBhMCU0UxEjAQBgNVBAgMCVN0b2NraG9sbTEXMBUGA1UEBwwO
U3RvY2tob2xtX3Rlc3QxDjAMBgNVBAoMBVNVTkVUMR0wGwYDVQQLDBRTVU5FVCBJ
bmZyYXN0cnVjdHVyZTEjMCEGA1UEAwwaY2EtdGVzdC1jcmVhdGUtMjAuc3VuZXQu
c2UxGzAZBgkqhkiG9w0BCQEWDHNvY0BzdW5ldC5zZTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAL9TpOoJz8ycTteEiTQUmalQvWxuMnWCHn7szRjakUl6
ujvRKz+20OzV6H/DDNpL4lEZovF2alJGVrLfMs7ZkF+UUG9ycSzSvMS8s3ywPIt0
HxRTR6gFU6Wdl6F9Bme7w+LHxu1MFL47Q0auTz0/X097zh1uDsUFPgJfgsjwzyWb
RG5sNQucm6jGv3Z/VyRKGCJXD9n15WMH2KFHylPRzMpUZSSs57aH0Qxg9+D83lkA
igr1+POAHpi1cl2n3JNxLtwGLl9EZE2Dhqrtl7aY8nBm/7YT5dtfUWG+DHy4HPwc
bXmjq7wwFjrBe2LPEucNpZ7F/KJ21/eAASbe4DmWfxUCAwEAAaOCAVQwggFQMA4G
A1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MIGgBggrBgEFBQcBAQSBkzCB
kDBlBggrBgEFBQcwAoZZaHR0cDovL2xvY2FsaG9zdDo4MDAwL2NhL2UxZjBiZmE5
M2Q1NThhNzEyYWI1ODhlZmQ4NjNkNjY2YjU3ZWVlNGY0ZTkwYjA1Zjk2MzhlNzg4
MDU5ZjNmNzEwJwYIKwYBBQUHMAGGG2h0dHA6Ly9sb2NhbGhvc3Q6ODAwMC9vY3Nw
LzBrBgNVHR8EZDBiMGCgXqBchlpodHRwOi8vbG9jYWxob3N0OjgwMDAvY3JsL2Ux
ZjBiZmE5M2Q1NThhNzEyYWI1ODhlZmQ4NjNkNjY2YjU3ZWVlNGY0ZTkwYjA1Zjk2
MzhlNzg4MDU5ZjNmNzEwHQYDVR0OBBYEFCKpVTSPtd1YC6y9AvjeGOGBiYKMMA0G
CSqGSIb3DQEBCwUAA4IBAQBoYAT/9pR9ZlCKy6kIc8QQYMX+2towZ1np5hPVgPDk
iiReMrSH3D+5FNVjcnSRhqD60fbYo2F145udyahrGRbfvrtAY65awpf9F0OTV6Wa
VGd3J2pSVOPt17ORgvA+ll91F9zJWKu/wFK2ZgtdAovIp12KBekAbkYcbbGxiHaV
xyfmfj1WbL6QDY8MYTQcKmuqWSu7G5aSPHk0XzS5yykhy5f6yBg558X1SFDfhv9s
5uF/z6UzswbYGC/xEQ5k3Lso7llb2NoEfEsPyeXJjdI4AEdT/0NAMOqssl81kHGU
EaD/MrXPmz2BUG2NHMOLXE09ryqQzfVPfBliBaf7Zwfg
-----END CERTIFICATE-----
"""
        valid_certificate_ocsp_data_cert = """-----BEGIN CERTIFICATE-----
MIIFTjCCBDagAwIBAgIUbdJG1iVUuT7Uo27pfZRCp3iD1yEwDQYJKoZIhvcNAQEL
BQAwgZwxCzAJBgNVBAYTAlNFMRIwEAYDVQQIDAlTdG9ja2hvbG0xEjAQBgNVBAcM
CVN0b2NraG9sbTEOMAwGA1UECgwFU1VORVQxHTAbBgNVBAsMFFNVTkVUIEluZnJh
c3RydWN0dXJlMRkwFwYDVQQDDBBjYS10ZXN0LnN1bmV0LnNlMRswGQYJKoZIhvcN
AQkBFgxzb2NAc3VuZXQuc2UwHhcNMjIwOTI4MTEzNTM4WhcNMjUwOTI3MTEzNzM4
WjCBqzELMAkGA1UEBhMCU0UxEjAQBgNVBAgMCVN0b2NraG9sbTEXMBUGA1UEBwwO
U3RvY2tob2xtX3Rlc3QxDjAMBgNVBAoMBVNVTkVUMR0wGwYDVQQLDBRTVU5FVCBJ
bmZyYXN0cnVjdHVyZTEjMCEGA1UEAwwaY2EtdGVzdC1jcmVhdGUtMjAuc3VuZXQu
c2UxGzAZBgkqhkiG9w0BCQEWDHNvY0BzdW5ldC5zZTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBANkCM+bjU9rXA6yaFMPZGVGUpwovhmWI0bxEZyuCOd18
W6wTbAU0/4liSgXh21F/GGRljlpYZPyASETBlqtOrOWoXWTKyNmOKjoY+vdmZqVS
eFuc4PnA7I0TxcazHsTyyc30OONDABoRPI/f19t8hlszbb36vq7nA5OlG2X0lFs8
qxwPbc5hnbJoCOQIHoc12T70gq2cwCLjEsz8U37diQG3GFfRzb4PFMJVxpetIcqI
G778quRIPQZwusMUGjFen433gEXDSSP1e92pFRdudYTK8SBr6g4o5spT57M4pwpz
OFPH/+ixZ8hHPmFUw52Vy+YEwcUP8bUW/8MQOiA2mskCAwEAAaOCAXUwggFxMA4G
A1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MIGgBggrBgEFBQcBAQSBkzCB
kDBlBggrBgEFBQcwAoZZaHR0cDovL2xvY2FsaG9zdDo4MDAwL2NhLzRhZGMzMTEz
MTI4NmUxOGQzNDg0OTcxNzk4OTNmYjA3MmFiYmZiNjgwMDdiMGMxZGI1Nzc2ODMx
YjcyYzJiNTQwJwYIKwYBBQUHMAGGG2h0dHA6Ly9sb2NhbGhvc3Q6ODAwMC9vY3Nw
LzBrBgNVHR8EZDBiMGCgXqBchlpodHRwOi8vbG9jYWxob3N0OjgwMDAvY3JsLzRh
ZGMzMTEzMTI4NmUxOGQzNDg0OTcxNzk4OTNmYjA3MmFiYmZiNjgwMDdiMGMxZGI1
Nzc2ODMxYjcyYzJiNTQwHQYDVR0OBBYEFLaiqsKj6bS2zfkwInlUhglbLzS0MB8G
A1UdIwQYMBaAFJ5ZDq9Xsd/VQ7YGwKolpxn0PM3jMA0GCSqGSIb3DQEBCwUAA4IB
AQAf9meVVFl13r4mAbhAYTLFCYjbD19WE2qccRNWzBYYDHRyfsNWap2XqtBCclx9
a+f69800sVqG0QLO4z614wTreM4fDafv5F+AS9Rjv3LsWh/3L6AjLId+VOr2MQ1l
fZblPuENO0Ifcbtu1KUBvUBCGhENof/c+64uCFd3YsSxcNSk0cRpjrWWtKXimp/j
dqc1yIVY8FUMpQZDb0jLXMI3ZhcKwkBo1K7sxve6Ehwy26NJQHvkjNH1DGegbNir
ZHIK3/RRSe1UPB8Jin34rr7BpW90/n43nqMB9SROpr4LeI+oUo5NhKnnKWi57MrT
iou2IdA6xuQG7IlqFPaCjJsn
-----END CERTIFICATE-----
"""

        with self.assertRaises(OCSPMissingExtensionException):
            i_n_h, i_k_h, serial, ocsp_url = certificate_ocsp_data(non_ocsp_cert)
        with self.assertRaises(OCSPMissingExtensionException):
            i_n_h, i_k_h, serial, ocsp_url = certificate_ocsp_data(non_aki_cert)

        i_n_h, i_k_h, serial, ocsp_url = certificate_ocsp_data(valid_certificate_ocsp_data_cert)
        self.assertTrue(isinstance(i_n_h, bytes))
        self.assertTrue(len(i_n_h) > 5)
        self.assertTrue(isinstance(i_k_h, bytes))
        self.assertTrue(len(i_k_h) > 5)
        self.assertTrue(isinstance(serial, int))
        self.assertTrue(isinstance(ocsp_url, str))
        self.assertTrue(len(ocsp_url) > 3)

    def test_ocsp_response_extra_certs(self) -> None:
        """
        Test OCSP response extra certs
        """

        extra_cert1 = """-----BEGIN CERTIFICATE-----
MIIE/jCCA+agAwIBAgIUQaPasXjfn0GaQozLCX54rl1mjXYwDQYJKoZIhvcNAQEL
BQAwga4xCzAJBgNVBAYTAlNFMRIwEAYDVQQIDAlTdG9ja2hvbG0xFzAVBgNVBAcM
DlN0b2NraG9sbV90ZXN0MRMwEQYDVQQKDApTVU5FVF9vY3NwMR0wGwYDVQQLDBRT
VU5FVCBJbmZyYXN0cnVjdHVyZTEhMB8GA1UEAwwYY2EtdGVzdC1vY3NwLTQ1LnN1
bmV0LnNlMRswGQYJKoZIhvcNAQkBFgxzb2NAc3VuZXQuc2UwHhcNMjIxMDAyMTEy
MjA4WhcNMjUxMDAxMTEyNDA4WjBrMQswCQYDVQQGEwJTRTETMBEGA1UECAwKU29t
ZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMSQwIgYD
VQQDDBtjaGVjay1vY3NwLnRlc3QtNTcuc3VuZXQuc2UwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCpnsovJqsHTTWNTYTy09j6NuzYU0F9CDmB5u9YzG1q
nZQbYdCVr7aveYpYB+Z3mufT0pvk9O9W+YUC5/uYAuWw7DU+mOjSdB5AbfgVNDZ+
bI7liviriwi/udkTUy0AW7BAELTHEn9q6d/tPQjhVMrOKTlSqaXO3M+F2uEIBI4C
Byo5Jip2XyMNC0pOTsXVUXbXM7CK9nbfvloFzrO0S+AupJ2yHi3EUphHBSb+yUGA
YSm2xE79mdjiWt9e5IPEDLuNHFYfKst+6vcjm2RWpjEGcUwJ2PANXcs9qUpw0OKb
qf7nYuEhYT7f3LjKd88FgOlP/g1dZzvU9uuavgbC4anvAgMBAAGjggFUMIIBUDCB
oAYIKwYBBQUHAQEEgZMwgZAwZQYIKwYBBQUHMAKGWWh0dHA6Ly9sb2NhbGhvc3Q6
ODAwMC9jYS80MTJjODBlMGMxYjMxNmYxM2FlMjA0Y2ViMmI5MDY4MTljZTM5ZWI1
NmVkZTA5YmVlOTI4N2Y4MzhmZjQ5MTJiMCcGCCsGAQUFBzABhhtodHRwOi8vbG9j
YWxob3N0OjgwMDAvb2NzcC8wawYDVR0fBGQwYjBgoF6gXIZaaHR0cDovL2xvY2Fs
aG9zdDo4MDAwL2NybC80MTJjODBlMGMxYjMxNmYxM2FlMjA0Y2ViMmI5MDY4MTlj
ZTM5ZWI1NmVkZTA5YmVlOTI4N2Y4MzhmZjQ5MTJiMB0GA1UdDgQWBBRgaGcW/4/T
Dsx4Ccfc286GTZjwWjAfBgNVHSMEGDAWgBRZvuLKRazQkrNdouoG2y22z04/ezAN
BgkqhkiG9w0BAQsFAAOCAQEAkQBHhVJcNq47Xo8gC2sVofRkDtTXxP66LDGULm9Y
WaBAszSaDMisAMoaP9/VLgI7SkJN9aqLZYBo7EDIUVV5Na2iIOacFzDFAG25NmHU
8ewSlZ4NB5bdzGr0BF/Vz5ucJokTYzUjTyadQPSdwzTGYhVKfNH54yYQWdhiZIt+
cbUX2K+u7abHpQXgrWdqyUKLk5KRoKXAgnjyvsKsc1sWmZAYZQ9VoXQ9rFhUrbFB
lZAbNZd5zXBFkrW5U1cHn22S61XFOjbDRt1Y80WAZR1dZ1YQBUqTTVAtpreSB3GY
irPMqk3fnoma+7NawnMv/SJzFPoI1jrww/LnyN+XLIotLw==
-----END CERTIFICATE-----
"""
        extra_cert2 = """-----BEGIN CERTIFICATE-----
MIIE/jCCA+agAwIBAgIUMGcej1HFWNHrbcRZ0SHX64Th/fYwDQYJKoZIhvcNAQEL
BQAwga4xCzAJBgNVBAYTAlNFMRIwEAYDVQQIDAlTdG9ja2hvbG0xFzAVBgNVBAcM
DlN0b2NraG9sbV90ZXN0MRMwEQYDVQQKDApTVU5FVF9vY3NwMR0wGwYDVQQLDBRT
VU5FVCBJbmZyYXN0cnVjdHVyZTEhMB8GA1UEAwwYY2EtdGVzdC1vY3NwLTQ1LnN1
bmV0LnNlMRswGQYJKoZIhvcNAQkBFgxzb2NAc3VuZXQuc2UwHhcNMjIxMDAyMTEy
MzAwWhcNMjUxMDAxMTEyNTAwWjBrMQswCQYDVQQGEwJTRTETMBEGA1UECAwKU29t
ZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMSQwIgYD
VQQDDBtjaGVjay1vY3NwLnRlc3QtNTcuc3VuZXQuc2UwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCpnsovJqsHTTWNTYTy09j6NuzYU0F9CDmB5u9YzG1q
nZQbYdCVr7aveYpYB+Z3mufT0pvk9O9W+YUC5/uYAuWw7DU+mOjSdB5AbfgVNDZ+
bI7liviriwi/udkTUy0AW7BAELTHEn9q6d/tPQjhVMrOKTlSqaXO3M+F2uEIBI4C
Byo5Jip2XyMNC0pOTsXVUXbXM7CK9nbfvloFzrO0S+AupJ2yHi3EUphHBSb+yUGA
YSm2xE79mdjiWt9e5IPEDLuNHFYfKst+6vcjm2RWpjEGcUwJ2PANXcs9qUpw0OKb
qf7nYuEhYT7f3LjKd88FgOlP/g1dZzvU9uuavgbC4anvAgMBAAGjggFUMIIBUDCB
oAYIKwYBBQUHAQEEgZMwgZAwZQYIKwYBBQUHMAKGWWh0dHA6Ly9sb2NhbGhvc3Q6
ODAwMC9jYS8xNzNkZTU1NTRmZmNmM2I0NmI3ZWY3MWUxNGMzZTZjOTE4MzYxZDA1
NWRjNWMxNDI5Mzk1NmJmYmJjZjUxMWViMCcGCCsGAQUFBzABhhtodHRwOi8vbG9j
YWxob3N0OjgwMDAvb2NzcC8wawYDVR0fBGQwYjBgoF6gXIZaaHR0cDovL2xvY2Fs
aG9zdDo4MDAwL2NybC8xNzNkZTU1NTRmZmNmM2I0NmI3ZWY3MWUxNGMzZTZjOTE4
MzYxZDA1NWRjNWMxNDI5Mzk1NmJmYmJjZjUxMWViMB0GA1UdDgQWBBRgaGcW/4/T
Dsx4Ccfc286GTZjwWjAfBgNVHSMEGDAWgBQaGUp9TABn4AuWI6ahidTMYWHpazAN
BgkqhkiG9w0BAQsFAAOCAQEA2kF5wSSJwy05CSk44/HOcWju6tYPko4uT4v4zRim
+UBvR9yMXz/+RdwHurWmSBZPCm7cRbkLdXJk+XCz/3g24CvHgKoe4YumogoEQHlP
C8Nzo/mRk8C0Gcbl4GkDSN/ujrECoapLbxsuKDLhPa6lkmn/N1BWVoohkvwZGcca
HJfKd3Am/5yYf8w+QQH0LeyZZk9tM+d9XBGrqOFpL0T19zsyKiddbbRXceyftxyc
5VGw62FbGoNqyVYDR1kX5FSuvOT/29L/5fSLCgn6ow3mH7TX16ZL8vTzDLUqlBtE
FvdQ0EEx2Pssrry0iD5AieGyK2nKW94UA0gQenvtMS9mxQ==
-----END CERTIFICATE-----
"""

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        asyncio.run(PKCS11Session.create_keypair(new_key_label))

        i_name_h, i_key_h, serial, _ = certificate_ocsp_data(TEST_CERT)
        data = asyncio.run(request([(i_name_h, i_key_h, serial)]))
        test_request = asn1_ocsp.OCSPRequest.load(data)
        self.assertTrue(isinstance(test_request, asn1_ocsp.OCSPRequest))
        data = asyncio.run(
            response(new_key_label, name_dict, _good_response(test_request), 0, extra_certs=[extra_cert1, extra_cert2])
        )
        test_response = asn1_ocsp.OCSPResponse.load(data)
        self.assertTrue(isinstance(test_response, asn1_ocsp.OCSPResponse))
        self.assertTrue(test_response["response_bytes"].native is not None)
        self.assertTrue(
            test_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"]
            == "good"
        )
        self.assertTrue(len(test_response["response_bytes"]["response"].native["certs"]) == 2)

        # Ensure certs are the same
        cert_data = extra_cert1.encode("utf-8")
        if asn1_pem.detect(cert_data):
            _, _, cert_data = asn1_pem.unarmor(cert_data)
        self.assertTrue(
            test_response["response_bytes"]["response"].native["certs"][0]
            == asn1_ocsp.Certificate.load(cert_data).native
        )
        cert_data = extra_cert2.encode("utf-8")
        if asn1_pem.detect(cert_data):
            _, _, cert_data = asn1_pem.unarmor(cert_data)
        self.assertTrue(
            test_response["response_bytes"]["response"].native["certs"][1]
            == asn1_ocsp.Certificate.load(cert_data).native
        )

        # Delete the test key
        asyncio.run(PKCS11Session.delete_keypair(new_key_label))
