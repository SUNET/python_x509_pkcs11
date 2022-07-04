"""
Module which have all our exceptions
"""

class PKCS11TimeoutException(Exception):
    """Class to handle PKCS11 timeout exceptions
    """
    def __init__(self, message: str = "PKCS11 timeout exceeded") -> None:
        self.message = message
        super().__init__(self.message)

        def __str__(self: PKCS11TimeoutException) -> str:
            return self.message
