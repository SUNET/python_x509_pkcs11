"""
Module which have all our exceptions
"""


class PKCS11UnknownErrorException(Exception):
    """Exception related to PKCS11 operations."""

    def __init__(self, message: str = "PKCS11 Exception happened.") -> None:
        self.message = message
        super().__init__(self.message)


class DuplicateExtensionException(Exception):
    """Exception due to duplicate extensions."""

    def __init__(self, message: str = "Duplicate extension not allowed.") -> None:
        self.message = message
        super().__init__(self.message)


class OCSPMissingExtensionException(Exception):
    """Exception for missing OCSP extension."""

    def __init__(self, message: str = "Required OCSP extension not found.") -> None:
        self.message = message
        super().__init__(self.message)
