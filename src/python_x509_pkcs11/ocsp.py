"""Module which creates OCSP requests and responses

Exposes the functions:
- request() - Create a OCSP request
- response() - Create a OCSP response
- request_nonce() - Quickly extract the nonce or None from a OCSP request
- certificate_ocsp_data() - Quickly extract the OCSP data from a certificate
"""

from typing import Union, List, Tuple, Dict
import datetime

from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem
from asn1crypto.algos import DigestAlgorithm, DigestAlgorithmId, SignedDigestAlgorithm, SignedDigestAlgorithmId

from .pkcs11_handle import PKCS11Session
from .error import OCSPMissingExtensionException, DuplicateExtensionException


def _create_ocsp_request(issuer_name_hash: bytes, issuer_key_hash: bytes, serial_number: int) -> asn1_ocsp.TBSRequest:
    cert_id = asn1_ocsp.CertId()
    cert_id["issuer_name_hash"] = issuer_name_hash
    cert_id["issuer_key_hash"] = issuer_key_hash
    cert_id["serial_number"] = serial_number

    dal = DigestAlgorithm()
    dal["algorithm"] = DigestAlgorithmId("sha1")
    cert_id["hash_algorithm"] = dal

    req = asn1_ocsp.Request()
    req["req_cert"] = cert_id
    return req


def _set_response_data(
    single_responses: asn1_ocsp.Responses,
    responder_id: Dict[str, str],
    produced_at: Union[datetime.datetime, None],
    extra_extensions: Union[asn1_ocsp.ResponseDataExtensions, None],
) -> asn1_ocsp.ResponseData:
    response_data = asn1_ocsp.ResponseData()

    # Set the version
    response_data["version"] = 0

    # Set the responder id
    response_data["responder_id"] = asn1_ocsp.ResponderId({"by_name": asn1_ocsp.Name().build(responder_id)})

    # Set the produced at
    if produced_at is None:
        # -2 minutes to protect from the OCSP response readers time skew
        response_data["produced_at"] = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
        ).replace(microsecond=0)
    else:
        response_data["produced_at"] = produced_at.replace(microsecond=0)

    # Remove fractional seconds from this update and next update
    for _, resps in enumerate(single_responses):
        if resps["this_update"].native.microsecond != 0:
            resps["this_update"] = resps["this_update"].native.replace(microsecond=0)
        if resps["next_update"].native is not None and resps["next_update"].native.microsecond != 0:
            resps["next_update"] = resps["next_update"].native.replace(microsecond=0)

    # Set the single responses
    response_data["responses"] = single_responses

    # Set extra extensions if exists
    if extra_extensions is not None:
        exts = asn1_ocsp.ResponseDataExtensions()

        for _, ext in enumerate(extra_extensions):
            if ext["extn_id"].dotted == "1.3.6.1.5.5.7.48.1.2":
                if len(ext["extn_value"].native) < 1 or len(ext["extn_value"].native) > 32:
                    raise ValueError("Nonce length error, https://datatracker.ietf.org/doc/html/rfc8954")
                if len(ext["extn_value"].native) < 16:
                    print("Warning: Ignoring nonce since its smaller than 16 bytes")
                    print("https://datatracker.ietf.org/doc/html/rfc8954")
                    continue

            exts.append(ext)
        response_data["response_extensions"] = exts

    # Check for duplicate extensions
    exts = []
    for _, ext in enumerate(response_data["response_extensions"]):
        if ext["extn_id"].dotted in exts:
            raise DuplicateExtensionException("Found duplicate extension " + ext["extn_id"].dotted)
        exts.append(ext["extn_id"].dotted)

    return response_data


async def _set_response_signature(
    key_label: str, extra_certs: Union[List[str], None], basic_ocsp_response: asn1_ocsp.BasicOCSPResponse
) -> asn1_ocsp.BasicOCSPResponse:
    sda = SignedDigestAlgorithm()
    sda["algorithm"] = SignedDigestAlgorithmId("sha256_rsa")
    basic_ocsp_response["signature_algorithm"] = sda
    basic_ocsp_response["signature"] = await PKCS11Session().sign(
        key_label, basic_ocsp_response["tbs_response_data"].dump()
    )

    if extra_certs:
        resp_certs = asn1_ocsp.Certificates()
        for cert in extra_certs:
            cert_data = cert.encode("utf-8")
            if asn1_pem.detect(cert_data):
                _, _, cert_data = asn1_pem.unarmor(cert_data)
            resp_certs.append(asn1_ocsp.Certificate.load(cert_data))
        basic_ocsp_response["certs"] = resp_certs

    return basic_ocsp_response


async def _set_request_signature(
    key_label: str, signature: asn1_ocsp.Signature, data: asn1_ocsp.TBSRequest, certs: Union[List[str], None]
) -> asn1_ocsp.Signature:
    sda = SignedDigestAlgorithm()
    sda["algorithm"] = SignedDigestAlgorithmId("sha256_rsa")

    signature["signature_algorithm"] = sda
    signature["signature"] = await PKCS11Session().sign(key_label, data.dump())

    if certs:
        req_certs = asn1_ocsp.Certificates()
        for cert in certs:
            cert_data = cert.encode("utf-8")
            if asn1_pem.detect(cert_data):
                _, _, cert_data = asn1_pem.unarmor(cert_data)
            req_certs.append(asn1_ocsp.Certificate.load(cert_data))
        signature["certs"] = req_certs

    return signature


def request_nonce(data: bytes) -> Union[bytes, None]:
    """Get nonce from OCSP request.
    None if the request has no nonce.

    Parameters:
    data (bytes): OCSP request bytes.

    Returns:
    Union[bytes, None]
    """

    ocsp_request = asn1_ocsp.OCSPRequest.load(data)
    if len(ocsp_request["tbs_request"]["request_extensions"]) == 0:
        return None

    for _, ext in enumerate(ocsp_request["tbs_request"]["request_extensions"]):
        if ext["extn_id"].native == "nonce":
            ret: bytes = ext["extn_value"].native
            return ret
    return None


def certificate_ocsp_data(pem: str) -> Tuple[bytes, bytes, int, str]:
    """Get OCSP request data from a certificate.
    Returns a tuple of:
    sha1 hash of issuer name
    sha1 hash of issuer public key
    serial number
    ocsp url

    The certificate MUST have the AKI extension (2.5.29.35)
    and the AIA extension with ocsp method (1.3.6.1.5.5.7.1.1)
    raises OCSPMissingExtensionException if not.

    Parameters:
    pem (str): PEM encoded certificate.

    Returns:
    Tuple[bytes, bytes, int, str]
    """

    issuer_name_hash: bytes
    issuer_key_hash: bytes
    serial_number: int
    ocsp_url: str

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert = asn1_x509.Certificate.load(data)

    # Issuer name hash
    issuer_name_hash = cert["tbs_certificate"]["issuer"].sha1

    # Issuer key hash
    found = False
    for _, extension in enumerate(cert["tbs_certificate"]["extensions"]):
        if extension["extn_id"].dotted == "2.5.29.35":
            issuer_key_hash = extension["extn_value"].native["key_identifier"]
            found = True
    if not found:
        raise OCSPMissingExtensionException(
            "AKI extension with key_identifier method was not found in certificate " + pem
        )

    # serial number
    serial_number = cert["tbs_certificate"]["serial_number"].native

    # OCSP URL
    for _, extension in enumerate(cert["tbs_certificate"]["extensions"]):
        if extension["extn_id"].dotted == "1.3.6.1.5.5.7.1.1":
            for _, descr in enumerate(extension["extn_value"].native):
                if descr["access_method"] == "ocsp" and "/ocsp/" in descr["access_location"]:
                    ocsp_url = descr["access_location"]
                    return issuer_name_hash, issuer_key_hash, serial_number, ocsp_url
    raise OCSPMissingExtensionException("AIA extension with ocsp method was not found in certificate/ " + pem)


async def request(
    request_certs_data: List[Tuple[bytes, bytes, int]],
    key_label: Union[str, None] = None,
    requestor_name: Union[asn1_ocsp.GeneralName, None] = None,
    certs: Union[List[str], None] = None,
    extra_extensions: Union[asn1_ocsp.TBSRequestExtensions, None] = None,
) -> bytes:
    """Create an OCSP request.
    See https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1

    If key_label is not None and requestor_name is not None
    Then sign the request with the key_label key in the PKCS11 device.

    Parameters:
    request_certs_data (List[Tuple[bytes, bytes, int]]):
    List of tuples (SHA1 hash of issuer Name, SHA1 hash of issuer public key, certificate serial number)
    key_label (Union[str, None] = None): Keypair label in the PKCS11 device to sign with.
    certs (Union[List[str], None] = None):
    Certificates in PEM form to help the OCSP server to validate the OCSP request signature.
    extra_extensions (Union[asn1crypto.ocsp.TBSRequestExtensions, None] = None): Extra extensions.

    Returns:
    bytes
    """

    # Ensure input data has atleast one cert data tuple
    if not request_certs_data:
        raise ValueError("request_certs_data must NOT be empty")

    reqs = asn1_ocsp.Requests()
    for cert_data in request_certs_data:
        req = _create_ocsp_request(cert_data[0], cert_data[1], cert_data[2])
        reqs.append(req)

    tbs_request = asn1_ocsp.TBSRequest()
    tbs_request["version"] = 0
    tbs_request["request_list"] = reqs

    if requestor_name is not None:
        tbs_request["requestor_name"] = requestor_name

    if extra_extensions is not None:
        tbs_request["request_extensions"] = extra_extensions

    ocsp_request = asn1_ocsp.OCSPRequest()
    ocsp_request["tbs_request"] = tbs_request

    if key_label is not None:
        if requestor_name is None:
            raise ValueError("signing a request requires the requestor_name parameter")

        ocsp_request["optional_signature"] = await _set_request_signature(
            key_label, asn1_ocsp.Signature(), ocsp_request["tbs_request"], certs
        )

    ret: bytes = ocsp_request.dump()
    return ret


async def response(  # pylint: disable-msg=too-many-arguments
    key_label: str,
    responder_id: Dict[str, str],
    single_responses: asn1_ocsp.Responses,
    response_status: int,
    extra_extensions: Union[asn1_ocsp.ResponseDataExtensions, None] = None,
    produced_at: Union[datetime.datetime, None] = None,
    extra_certs: Union[List[str], None] = None,
) -> bytes:
    """Create an OCSP response with the key_label key in the PKCS11 device.
    See https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1

    Parameters:
    key_label (str): Keypair label in the PKCS11 device to sign with.
    responder_id (Dict[str, str]): Dict with the responders x509 Names.
    single_responses (asn1_ocsp.Responses): Responses for all certs in request.
    response_status (int): Status code for the OCSP response.
    extra_extensions (Union[asn1crypto.ocsp.ResponseDataExtensions, None] = None):
    Extra extensions to be written into the response, for example the nonce extension.
    produced_at (Union[datetime.datetime, None] = None): What time to write into produced_at.
    It must be in UTC timezone. If None then it will be 2 minutes before UTC now.
    extra_certs (Union[List[str], None] = None): List of PEM encoded certs
    for the client the verify the signature chain.

    Returns:
    bytes
    """

    ret: bytes

    # Ensure valid response status
    if response_status not in [0, 1, 2, 3, 5, 6]:  # 4 is not used
        raise ValueError("status code must be one of [0, 1, 2, 3, 5, 6]")

    # OCSP response
    ocsp_response = asn1_ocsp.OCSPResponse()

    # Set response status
    ocsp_response["response_status"] = asn1_ocsp.OCSPResponseStatus(response_status)

    # Is error status
    if response_status != 0:
        ret = ocsp_response.dump()
        return ret

    # Basic OCSP response
    basic_ocsp_response = asn1_ocsp.BasicOCSPResponse()

    # Set response data
    basic_ocsp_response["tbs_response_data"] = _set_response_data(
        single_responses, responder_id, produced_at, extra_extensions
    )

    # Sign the response
    basic_ocsp_response = await _set_response_signature(key_label, extra_certs, basic_ocsp_response)

    # Response bytes
    response_bytes = asn1_ocsp.ResponseBytes()
    response_bytes["response_type"] = asn1_ocsp.ResponseType("1.3.6.1.5.5.7.48.1.1")
    response_bytes["response"] = basic_ocsp_response
    ocsp_response["response_bytes"] = response_bytes

    ret = ocsp_response.dump()
    return ret
