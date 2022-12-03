"""Module which creates OCSP requests and responses

Exposes the functions:
- request() - Create a OCSP request
- response() - Create a OCSP response
- request_nonce() - Quickly extract the nonce or None from a OCSP request
- certificate_ocsp_data() - Quickly extract the OCSP data from a certificate
"""

import datetime
from typing import Dict, List, Optional, Tuple

from asn1crypto import pem as asn1_pem
from asn1crypto.algos import DigestAlgorithm, DigestAlgorithmId
from asn1crypto.ocsp import (
    BasicOCSPResponse,
    CertId,
    Certificate,
    Certificates,
    GeneralName,
    Name,
    OCSPRequest,
    OCSPResponse,
    OCSPResponseStatus,
    Request,
    Requests,
    ResponderId,
    ResponseBytes,
    ResponseData,
    ResponseDataExtensions,
    Responses,
    ResponseType,
    Signature,
    TBSRequest,
    TBSRequestExtensions,
)

from .error import DuplicateExtensionException, OCSPMissingExtensionException
from .lib import signed_digest_algo
from .pkcs11_handle import PKCS11Session


def _create_ocsp_request(issuer_name_hash: bytes, issuer_key_hash: bytes, serial_number: int) -> Request:
    cert_id = CertId()
    cert_id["issuer_name_hash"] = issuer_name_hash
    cert_id["issuer_key_hash"] = issuer_key_hash
    cert_id["serial_number"] = serial_number

    dal = DigestAlgorithm()
    dal["algorithm"] = DigestAlgorithmId("sha1")
    cert_id["hash_algorithm"] = dal

    req = Request()
    req["req_cert"] = cert_id
    return req


def _set_response_data(
    single_responses: Responses,
    responder_id: Dict[str, str],
    produced_at: Optional[datetime.datetime],
    extra_extensions: Optional[ResponseDataExtensions],
) -> ResponseData:
    response_data = ResponseData()

    # Set the version
    response_data["version"] = 0

    # Set the responder id
    response_data["responder_id"] = ResponderId({"by_name": Name().build(responder_id)})

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
    if extra_extensions is not None and len(extra_extensions) > 0:
        exts = ResponseDataExtensions()

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
    key_label: str,
    key_type: Optional[str],
    extra_certs: Optional[List[str]],
    basic_ocsp_response: BasicOCSPResponse,
) -> BasicOCSPResponse:
    if key_type is None:
        key_type = "ed25519"

    basic_ocsp_response["signature_algorithm"] = signed_digest_algo(key_type)
    basic_ocsp_response["signature"] = await PKCS11Session().sign(
        key_label,
        basic_ocsp_response["tbs_response_data"].dump(),
        key_type=key_type,
    )

    if extra_certs is not None and extra_certs:
        resp_certs = Certificates()
        for cert in extra_certs:
            cert_data = cert.encode("utf-8")
            if asn1_pem.detect(cert_data):
                _, _, cert_data = asn1_pem.unarmor(cert_data)
            resp_certs.append(Certificate.load(cert_data))
        basic_ocsp_response["certs"] = resp_certs

    return basic_ocsp_response


async def _set_request_signature(
    key_label: str,
    key_type: Optional[str],
    signature: Signature,
    data: TBSRequest,
    certs: Optional[List[str]],
) -> Signature:
    if key_type is None:
        key_type = "ed25519"

    signature["signature_algorithm"] = signed_digest_algo(key_type)
    signature["signature"] = await PKCS11Session().sign(key_label, data.dump(), key_type=key_type)

    if certs is not None and certs:
        req_certs = Certificates()
        for cert in certs:
            cert_data = cert.encode("utf-8")
            if asn1_pem.detect(cert_data):
                _, _, cert_data = asn1_pem.unarmor(cert_data)
            req_certs.append(Certificate.load(cert_data))
        signature["certs"] = req_certs

    return signature


def request_nonce(data: bytes) -> Optional[bytes]:
    """Get nonce from OCSP request.
    None if the request has no nonce.

    Parameters:
    data (bytes): OCSP request bytes.

    Returns:
    Optional[bytes]
    """

    ocsp_request = OCSPRequest.load(data)
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
    cert = Certificate.load(data)

    # Issuer name hash
    issuer_name_hash = cert["tbs_certificate"]["issuer"].sha1

    # Issuer key hash
    for _, extension in enumerate(cert["tbs_certificate"]["extensions"]):
        if extension["extn_id"].dotted == "2.5.29.35":
            issuer_key_hash = extension["extn_value"].native["key_identifier"]
            break
    else:
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


async def request(  # pylint: disable-msg=too-many-arguments
    request_certs_data: List[Tuple[bytes, bytes, int]],
    key_label: Optional[str] = None,
    requestor_name: Optional[GeneralName] = None,
    certs: Optional[List[str]] = None,
    extra_extensions: Optional[TBSRequestExtensions] = None,
    key_type: Optional[str] = None,
) -> bytes:
    """Create an OCSP request.
    See https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1

    If key_label is not None and requestor_name is not None
    Then sign the request with the key_label key in the PKCS11 device.

    Parameters:
    request_certs_data (List[Tuple[bytes, bytes, int]]):
    List of tuples (SHA1 hash of issuer Name, SHA1 hash of issuer public key, certificate serial number)
    key_label (Optional[str] = None): Keypair label in the PKCS11 device to sign with.
    certs (Optional[List[str]] = None):
    Certificates in PEM form to help the OCSP server to validate the OCSP request signature.
    extra_extensions (Optional[asn1crypto.ocsp.TBSRequestExtensions] = None): Extra extensions.
    key_type (Optional[str] = None): Key type to use, ed25519 is default.

    Returns:
    bytes
    """

    # Ensure input data has least one cert data tuple
    if not request_certs_data:
        raise ValueError("request_certs_data must NOT be empty")

    reqs = Requests()
    for cert_data in request_certs_data:
        req = _create_ocsp_request(cert_data[0], cert_data[1], cert_data[2])
        reqs.append(req)

    tbs_request = TBSRequest()
    tbs_request["version"] = 0
    tbs_request["request_list"] = reqs

    if requestor_name is not None:
        tbs_request["requestor_name"] = requestor_name

    if extra_extensions is not None and len(extra_extensions) > 0:
        tbs_request["request_extensions"] = extra_extensions

    ocsp_request = OCSPRequest()
    ocsp_request["tbs_request"] = tbs_request

    if key_label is not None:
        if requestor_name is None:
            raise ValueError("signing a request requires the requestor_name parameter")

        ocsp_request["optional_signature"] = await _set_request_signature(
            key_label, key_type, Signature(), ocsp_request["tbs_request"], certs
        )

    ret: bytes = ocsp_request.dump()
    return ret


async def response(  # pylint: disable-msg=too-many-arguments
    key_label: str,
    responder_id: Dict[str, str],
    single_responses: Responses,
    response_status: int,
    extra_extensions: Optional[ResponseDataExtensions] = None,
    produced_at: Optional[datetime.datetime] = None,
    extra_certs: Optional[List[str]] = None,
    key_type: Optional[str] = None,
) -> bytes:
    """Create an OCSP response with the key_label key in the PKCS11 device.
    See https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1

    Parameters:
    key_label (str): Keypair label in the PKCS11 device to sign with.
    responder_id (Dict[str, str]): Dict with the responders x509 Names.
    single_responses (Responses): Responses for all certs in request.
    response_status (int): Status code for the OCSP response.
    extra_extensions (Optional[asn1crypto.ocsp.ResponseDataExtensions] = None):
    Extra extensions to be written into the response, for example the nonce extension.
    produced_at (Optional[datetime.datetime] = None): What time to write into produced_at.
    It must be in UTC timezone. If None then it will be 2 minutes before UTC now.
    extra_certs (Optional[List[str]] = None): List of PEM encoded certs
    for the client to verify the signature chain.
    key_type (Optional[str] = None): Key type to use, ed25519 is default.

    Returns:
    bytes
    """

    ret: bytes

    # Ensure valid response status
    if response_status not in [0, 1, 2, 3, 5, 6]:  # 4 is not used
        raise ValueError("status code must be one of [0, 1, 2, 3, 5, 6]")

    # OCSP response
    ocsp_response = OCSPResponse()

    # Set response status
    ocsp_response["response_status"] = OCSPResponseStatus(response_status)

    # Is error status
    if response_status != 0:
        ret = ocsp_response.dump()
        return ret

    # Basic OCSP response
    basic_ocsp_response = BasicOCSPResponse()

    # Set response data
    basic_ocsp_response["tbs_response_data"] = _set_response_data(
        single_responses, responder_id, produced_at, extra_extensions
    )

    # Sign the response
    basic_ocsp_response = await _set_response_signature(key_label, key_type, extra_certs, basic_ocsp_response)

    # Response bytes
    response_bytes = ResponseBytes()
    response_bytes["response_type"] = ResponseType("1.3.6.1.5.5.7.48.1.1")
    response_bytes["response"] = basic_ocsp_response
    ocsp_response["response_bytes"] = response_bytes

    ret = ocsp_response.dump()
    return ret
