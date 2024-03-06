API Usage
=========

Below are the various class and functions available in the module.

.. class:: KEYTYPES
    :canonical: python_x509_pkcs11.KEYTYPES

    .. versionadded:: 0.9.0

    An enumeration for Key Types available on the HSM device, we use this
    to create or sign any given data.

    .. attribute:: ED25519

        For ED25519 key type.

    .. attribute:: ED448

        For ED448 key type.

    .. attribute:: SECP256r1

        EC curve for SECP256r1.

    .. attribute:: SECP384r1

        EC curve for SECP384r1.

    .. attribute:: SECP512r1

        EC curve for SECP512r1.


.. attribute:: DEFAULT_KEY_TYPE
    :canonical: python_x509_pkcs11.DEFAULT_KEY_TYPE

    Defaults to :class:`python_x509_pkcs11.KEYTYPES.ED22519`.

.. function:: get_keytypes_enum(value: str):

   Takes the keytype as a string and returns the corresponding KEYTYPES enumeration value.

   :param value: The type of the key.
   :type value: str

   :returns: :class:`python_x509_pkcs11.KEYTYPES`


.. class:: PKCS11Session
    :canonical: python_x509_pkcs11.PKCS11Session

    This is signleton class, means at a given point of time only one object of
    this type will be available in the memory. From the shell environment it
    takes 3 inputs. `PKCS11_MODULE`, which should point to the shared object
    file for your HSM device, example `/usr/lib64/softhsm/libsofthsm.so`,
    `PKCS11_TOKEN`, that points to the exact TOKEN in the HSM, and
    `PKCS11_PIN`, which is the PIN to the HSM.

    All methods for this class are asyncronous.

    .. method:: create_keypair(key_label: str, key_type: Union[str, KEYTYPES] = DEFAULT_KEY_TYPE):

        Creates a new key pair in the HSM with the given key label and given key type.

        :param key_label: The key label to be used in the HSM.
        :type key_label: str

        :param key_type: The kind of key should be generated.
        :type key_type: Union[str, KEYTYPES]

        :raises pkcs11.MultipleObjectsReturned: If a keypair with the same label already exists, then :class:`pkcs11.MultipleObjectsReturned` will be raised.

        :returns: A tuple of the public key and sha1 value, Tuple[str, bytes]

        Example: 

        .. code-block:: python

            import asyncio
            from python_x509_pkcs11 import PKCS11Session, KEYTYPES
            async def my_func() -> None:
                public_key, identifier = await PKCS11Session().create_keypair("my_ed25519_key", key_type=KEYTYPES.ED22519)
                print(public_key)
                print(identifier)

            asyncio.run(my_func())


    .. method:: delete_keypair(key_label: str, key_type: Union[str, KEYTYPES] = DEFAULT_KEY_TYPE):

        Deletes a given key pair from the HSM.

        :param key_label: The key label to be used in the HSM.
        :type key_label: str

        :param key_type: The kind of key should be generated.
        :type key_type: Union[str, KEYTYPES]

        Example:

        .. code-block:: python

            import asyncio
            from python_x509_pkcs11 import PKCS11Session

            async def my_func() -> None:
                public_key, identifier = await PKCS11Session().create_keypair("my_ed25519_key")
                await PKCS11Session().delete_keypair("my_ed25519_key")

            asyncio.run(my_func())


    .. method:: export_certificate(cert_label: str):

        Exports an existing certificate from the as PEM encoded string.

        :param cert_label: The certificate label.
        :type cert_label: str

        :returns: str value of the PEM encoded certificate.

        Example:

        .. code-block:: python

            import asyncio
            from python_x509_pkcs11 import PKCS11Session

            cert_pem = """-----BEGIN CERTIFICATE-----
            MIIDjDCCAzOgAwIBAgIUB7D/x3LzbzaWjb61EKc5sQOFWZIwCgYIKoZIzj0EAwIw
            gZExCzAJBgNVBAYTAlNFMRIwEAYDVQQIDAlTdG9ja2hvbG0xEjAQBgNVBAcMCVN0
            b2NraG9sbTEOMAwGA1UECgwFU1VORVQxHTAbBgNVBAsMFFNVTkVUIEluZnJhc3Ry
            dWN0dXJlMSswKQYDVQQDDCJjYS10ZXN0LXRpbWVzdGFtcDMtc2lnbmVyLnN1bmV0
            LnNlMB4XDTIzMDUyMjEyMTUwN1oXDTQwMDEwMTAwMDAwMFowgY8xCzAJBgNVBAYT
            AlNFMRIwEAYDVQQIDAlTdG9ja2hvbG0xEjAQBgNVBAcMCVN0b2NraG9sbTEOMAwG
            A1UECgwFU1VORVQxHTAbBgNVBAsMFFNVTkVUIEluZnJhc3RydWN0dXJlMSkwJwYD
            VQQDDCBjYS10ZXN0LXRpbWVzdGFtcDMtY2VydC5zdW5ldC5zZTBZMBMGByqGSM49
            AgEGCCqGSM49AwEHA0IABK4tkAnuLY3kG89DtFRKiVuJgoUrObeW7xKu/kcf92FY
            iMrPqzkLzT64/JVnpMogDZ1fohsxKhcRwovQmJRaYYKjggFnMIIBYzAOBgNVHQ8B
            Af8EBAMCBsAwgZIGCCsGAQUFBwEBBIGFMIGCMF4GCCsGAQUFBzAChlJodHRwOi8v
            Y2E6ODAwNS9jYS9iOThiZmFmZGIwNzVmOWY2MzA4NjhkZTMwMTAyMmUyZGExOWQ0
            MjM0OGVmYWFkNjVhN2U1ODRmYmNlYzAxMDIwMCAGCCsGAQUFBzABhhRodHRwOi8v
            Y2E6ODAwNS9vY3NwLzBkBgNVHR8EXTBbMFmgV6BVhlNodHRwOi8vY2E6ODAwNS9j
            cmwvYjk4YmZhZmRiMDc1ZjlmNjMwODY4ZGUzMDEwMjJlMmRhMTlkNDIzNDhlZmFh
            ZDY1YTdlNTg0ZmJjZWMwMTAyMDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNV
            HQ4EFgQURbRp9puwNsIbOCEcZWzcz3UkK0UwHwYDVR0jBBgwFoAUhtCxna0AdOe6
            J23GIJ4PENiOV6EwCgYIKoZIzj0EAwIDRwAwRAIgCm8D1+Cfwej2pfrPHNV3myIy
            OsgGSmMGs3uYjac7+j4CIHisanLIGlny5Kgnrmk5yNiN3ZFimdhSd+ovaqjy3O4x
            -----END CERTIFICATE-----"""

            async def my_func() -> None:
                await PKCS11Session().import_certificate(cert_pem, "my_cert")
                cert = await PKCS11Session().export_certificate("my_cert")
                print(cert)

            asyncio.run(my_func())


    .. method:: import_certificate(cert_pem: str, cert_label: str):

        Imports a PEM encoded certificate to the HSM.

        :param cert_pem: The actual certificate as PEM encoded value.
        :type cert_pem: str

        :param cert_label: The label of the certificate on the HSM.
        :type cert_label: str

        :raises ValueError: If a certificate with the same label exists on the HSM.

        Example:

        .. code-block:: python

            import asyncio
            from python_x509_pkcs11 import PKCS11Session

            cert_pem = """-----BEGIN CERTIFICATE-----
            MIIDjDCCAzOgAwIBAgIUB7D/x3LzbzaWjb61EKc5sQOFWZIwCgYIKoZIzj0EAwIw
            gZExCzAJBgNVBAYTAlNFMRIwEAYDVQQIDAlTdG9ja2hvbG0xEjAQBgNVBAcMCVN0
            b2NraG9sbTEOMAwGA1UECgwFU1VORVQxHTAbBgNVBAsMFFNVTkVUIEluZnJhc3Ry
            dWN0dXJlMSswKQYDVQQDDCJjYS10ZXN0LXRpbWVzdGFtcDMtc2lnbmVyLnN1bmV0
            LnNlMB4XDTIzMDUyMjEyMTUwN1oXDTQwMDEwMTAwMDAwMFowgY8xCzAJBgNVBAYT
            AlNFMRIwEAYDVQQIDAlTdG9ja2hvbG0xEjAQBgNVBAcMCVN0b2NraG9sbTEOMAwG
            A1UECgwFU1VORVQxHTAbBgNVBAsMFFNVTkVUIEluZnJhc3RydWN0dXJlMSkwJwYD
            VQQDDCBjYS10ZXN0LXRpbWVzdGFtcDMtY2VydC5zdW5ldC5zZTBZMBMGByqGSM49
            AgEGCCqGSM49AwEHA0IABK4tkAnuLY3kG89DtFRKiVuJgoUrObeW7xKu/kcf92FY
            iMrPqzkLzT64/JVnpMogDZ1fohsxKhcRwovQmJRaYYKjggFnMIIBYzAOBgNVHQ8B
            Af8EBAMCBsAwgZIGCCsGAQUFBwEBBIGFMIGCMF4GCCsGAQUFBzAChlJodHRwOi8v
            Y2E6ODAwNS9jYS9iOThiZmFmZGIwNzVmOWY2MzA4NjhkZTMwMTAyMmUyZGExOWQ0
            MjM0OGVmYWFkNjVhN2U1ODRmYmNlYzAxMDIwMCAGCCsGAQUFBzABhhRodHRwOi8v
            Y2E6ODAwNS9vY3NwLzBkBgNVHR8EXTBbMFmgV6BVhlNodHRwOi8vY2E6ODAwNS9j
            cmwvYjk4YmZhZmRiMDc1ZjlmNjMwODY4ZGUzMDEwMjJlMmRhMTlkNDIzNDhlZmFh
            ZDY1YTdlNTg0ZmJjZWMwMTAyMDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNV
            HQ4EFgQURbRp9puwNsIbOCEcZWzcz3UkK0UwHwYDVR0jBBgwFoAUhtCxna0AdOe6
            J23GIJ4PENiOV6EwCgYIKoZIzj0EAwIDRwAwRAIgCm8D1+Cfwej2pfrPHNV3myIy
            OsgGSmMGs3uYjac7+j4CIHisanLIGlny5Kgnrmk5yNiN3ZFimdhSd+ovaqjy3O4x
            -----END CERTIFICATE-----"""

            async def my_func() -> None:
                await PKCS11Session().import_certificate(cert_pem, "my_cert")

            asyncio.run(my_func())


    .. method:: import_keypair(public_key: bytes, private_key: bytes, key_label: str, key_type: Union[str, KEYTYPES]):

        Imports a given keypair to the HSM.

        :param public_key: The public key in DER format.
        :type public_key: bytes.

        :param private_key: The private key in DER format.
        :type private_key: bytes.

        :param key_label: The key pair label on the HSM.
        :type key_label: str.

        :param key_type: The kind of key we are importing.
        :type key_type: Union[str, KEYTYPES]

        :raises MultipleObjectsReturned: If such a key pair already exists with the same key label and key type.

        :returns: None

        Example:

        .. code-block:: bash

                # Generating public_key and private_key can be done with:
                # ed25519 key type
                openssl genpkey -algorithm ed25519 -out private.pem
                openssl pkey -in private.pem -outform DER -out private.key
                openssl pkey -in private.pem -pubout -out public.pem
                openssl pkey -in private.pem -pubout -outform DER -out public.key

                # RSA key type
                openssl genrsa -out rsaprivkey.pem 2048
                openssl rsa -inform pem -in rsaprivkey.pem -outform der -out PrivateKey.der
                openssl rsa -in rsaprivkey.pem -RSAPublicKey_out -outform DER -out PublicKey.der

        And then we can import the key pair.

        .. code-block:: python

                import asyncio
                from python_x509_pkcs11 import PKCS11Session

                pub = b"0\x82\x01\n\x02\x82\x01\x01\x00\xd9\xb6C,O\xc0\x83\xca\xa5\xcc\xa7<_\xbf$\xdd-YJ0m\xbf\xa8\xf9[\xe7\xcb\x14W6G\n\x13__\xea\xb4Z\xab2\x01\x0f\xa4\xd3\x1c\xbb\xa6\x98\x9d\xcdf\xaa\x07\xcb\xff\xd8\x80\xa9\\\xa1\xf44\x01\xdbY\xa6\xcf\x83\xd2\x83Z\x8a<\xc1\x18\xe5\x8d\xff\xbfzU\x03\x01\x11\xa1\xa1\x98\xcf\xcaVu\xf9\xf3\xa7+ \xe7N9\x07\xfd\xc6\xd0\x7f\xa0\xba&\xef\xb2a\xc6\xa5d\x1c\x93\xe6\xc3\x80\xd1*;\xc8@7\x0fm)\xf93\xe4\x1f\x91\xf4=\xa6\xf8\xed\x9cN\x84\x9b\xf2\xc5\x9f\x9f\x82E\xa5Tm\xb9\xb3:T\xc7_\xb1^[\xf4\x0b\xd8\x0b\xd2\xfb\xe1\x13\x1e,L\xd9\xdc\xed]_#\xca\xa0r\xc2\xc5F \xec\xae\x8d\x08v\x059\x062\xe1\xf7%\x9e\xfd\xfb9\x11(\xa4\x86v\x90\x01\x1c\xbeP\x04\xa3%\x91\x08\xc5\xd5\xc1U\xf6\xd3\x7f\x1f\x9f7`\xce\xc9\xa1\xd9\x8f\\Z\xa8\x1cmz\x19x\xa4'F\xdf\xb2\xb2\x87\xba\xf7\n>]\x9f\xc0K@\xd9\xdb\x02\x03\x01\x00\x01"

                priv = b"0\x82\x04\xa4\x02\x01\x00\x02\x82\x01\x01\x00\xd9\xb6C,O\xc0\x83\xca\xa5\xcc\xa7<_\xbf$\xdd-YJ0m\xbf\xa8\xf9[\xe7\xcb\x14W6G\n\x13__\xea\xb4Z\xab2\x01\x0f\xa4\xd3\x1c\xbb\xa6\x98\x9d\xcdf\xaa\x07\xcb\xff\xd8\x80\xa9\\\xa1\xf44\x01\xdbY\xa6\xcf\x83\xd2\x83Z\x8a<\xc1\x18\xe5\x8d\xff\xbfzU\x03\x01\x11\xa1\xa1\x98\xcf\xcaVu\xf9\xf3\xa7+ \xe7N9\x07\xfd\xc6\xd0\x7f\xa0\xba&\xef\xb2a\xc6\xa5d\x1c\x93\xe6\xc3\x80\xd1*;\xc8@7\x0fm)\xf93\xe4\x1f\x91\xf4=\xa6\xf8\xed\x9cN\x84\x9b\xf2\xc5\x9f\x9f\x82E\xa5Tm\xb9\xb3:T\xc7_\xb1^[\xf4\x0b\xd8\x0b\xd2\xfb\xe1\x13\x1e,L\xd9\xdc\xed]_#\xca\xa0r\xc2\xc5F \xec\xae\x8d\x08v\x059\x062\xe1\xf7%\x9e\xfd\xfb9\x11(\xa4\x86v\x90\x01\x1c\xbeP\x04\xa3%\x91\x08\xc5\xd5\xc1U\xf6\xd3\x7f\x1f\x9f7`\xce\xc9\xa1\xd9\x8f\\Z\xa8\x1cmz\x19x\xa4'F\xdf\xb2\xb2\x87\xba\xf7\n>]\x9f\xc0K@\xd9\xdb\x02\x03\x01\x00\x01\x02\x82\x01\x00a5\x1e=\x14\xc6\xf2\x91s\x023\xd1\xa36\xa7q\x12$\x82\x19\xa9\x87 \x1df\xc9\xd2E\x1c\xc3\xa1h\x80I\xdf{\xdeWu\x84\xf80Q\xf9\xe9$h8P\x8d;\xbf\xc3\x87t\x8e\xe8\xb3\xb6&\xa1\xf0\xee\xbbP\x06I5\xa4\xb2\xfd\xa4'\x88Xcv\xc9\xb0g \xba\x1c\xaa\x10\xaf$\x99\xf2\xd04\x11\x0c\x97\xa1\x8c){%\xbf\xc9\xb2\x11\xbaJ\xbb\x93S\x07$\xdd\x1bO\xdd\xea\xb3\xe8\xab\x05\xb9\x83\xc3\xdf\xd85\xcd\x1a%\xd5\xd9\xc4\x933\x83\t\xd3\xea\xcdb\xcb\xec\x9eGqk\x1c\x8c\x06\x8a\\\xae\xbe\xd3+\x0b\xd0R\xbd:\x8a\xf5\xf4\x0f\x0b\xd4\xfa@P=\xe5\xb2\xa1\xb2\x01\x00\x08\xc7\x11?M\x84-\x1e\xbc\xa9\xbf|\x87\x98\xd7\x0e\xf6\xa9\xa6\xcd\x8c8\xa5F8\xacM\x82\xade[\xa9_\xa7Biv\x9c\x06\xa6\x001\xc3I\x1f\xc4\x9by\xd7\xe0\x9e\xb9\n\xbb\x19\\o\xc5i\xd90r\xd4\x1e(\x05\xdd\xedF\xe9\xaa\xbd\x91\xe5\x08\x8f4-\xb6\xd1Q\x02\x81\x81\x00\xf7\x076\xd8i\x87\x12\xf1\xd0$\x07\x1f\xab\xb7^\x0e\xa5\xfb\x83\x98\x00\x0b\\\x1d\xe8s\x15r\x96/\x0e\x0ezB\xc8\xf6\xf3Zmj?\xa0\xc1\x11r\xaf3\x11a\xcd\xa3\xfc\xa0\x03\x04E\x05\x99\x9a\xd9\xff\x8e+\xdcfM\xa8\xe8&\x84\x85\xc5\x11O\x9d4\x1f\xc3\x1f\xef\xed\x13BW\xaa\x93\xc3\x08(v]\xbc\x93V\xb6s\xce\xb1\xa8\xe2\x94\xa5'\xf3\x7f\x90,G[\xfeI\x16\xbe\xb0\xf8J\xca9n\xb5\xfc\x8a\xe2[\xc5\x0c\x95\xd5\x02\x81\x81\x00\xe1\x9ey\xc8\xe2\xd3\x93\xa2nj\xe1.\xaa\xe3\xa7\xf5P\xd1\xd8yM\x01\xdc\x01\x0c\xdbQG\x1b=\xbe\xe4.\x9cM\xc2\xda\xd2\xa4\xb3\x80\xb2\xbd\xbaO\x1bD&]0\x0b\xe6\xf5\x08\xdb*I\xfe+@Aa\x16;\x9a%\x8cof:\x156 \xb0\xe6\xfe\x95\x9bO\x85]\x96\x94S\x05\xc8\x8a\xb6\x92\xb3\x95\xc5\xfbX\xa9S<@\x12\x94K\x8b\xa3\x0f\xebO\xb5\x9f\x0c\x08\xf2\xccS\xfd8\x06\xeb\xaa\x96_\xadm&L~!\x18\xef\x02\x81\x80@.\x04\xa6\xd7K\xfb\xb5\r\xb1\xbe\x94\x10\xe6\x14.\xd4\x1a\xf3\x86\x93D`Kx\xf0%{^\xdf\x9c\xd4P\x19w\xe3\t8\xceB\x93\x83m\x85\xdd\xf8\xfc\xd8\xa0Cp>\x9bH\r\\\xedf\x8a\x1f\xe7P\x85\xbe\xbei\xa0\xdf\xa7\xda8s\t\xdbXi\x89s\x05\xa2-C\x1a\xb2r#\xef\xc0\xf7\xda@\xe2T\x99k\xcf\xcc\xbc\xc5\xb7\x10\x8d\x94B\xa4:\xcd\xf6@Ea\xb1\xe2\x1bRw\x03\xf1E\xfdL>\xbd.\xc0\x94S}\x02\x81\x81\x00\xa2\xce\x13}EH}a\x19\xa2`I\xa7\xa0\xcdc4\xe5\xa7\xfa\xa7\xf9\xee\x82\x87\x7f\x7f\x1f\xfbeK\xe9&E=\xcb\x9c\xd1\xa1m\xb21\xc8\xbc\xb76\xaa\xaf\xb0P\xeaU\xc7}\x93\x80\xe9\x91\xd2-\xf4\xbf\x95&\x7f.\x17/\x8f\xa9\xdc\x02\x8a\x06}9:E\xafUBZU?\xaf\x8d\xad\xa2\xdf+]\xa9V\x9c\xfc\xda\x86@\x89\xe7\x9e\xb7\xed{\xa0F\x8d}nV\xca\xb5l\xe9\xedR\xf9\x1d\xc8\x92\xd3\xf7NJ\xa6=E\xdb\x02\x81\x81\x00\xf5\xa8\xec\x00k\x18\x10KK\xd0D\xa9\xeb\x87==X\xa2\xaa)\xeb\x92\xfa\xf8f\xa6W\xaa\x94\x92\xa1F\t\xc1\x01\xd8%-\x1f\xb71\xefg\x95q\xb3\xa5J[k\xe3\x17\xac\xfd\xbfU\x02\x95\xa4\xf9\xcd\x80!E\x9d\x7f\x9c\xcd\x89uV\x1df\xee\xab\xd3\x1f7$&\x014\xd2\xdd\xc2\xe4?\x1bh*\xb6\x00\x1a\x1fz^\xbc\x97\xde\x9cK\xc8\xf5\xcf0\"\x8c\x8bm\xecUv\xefu\xd9YD\x05\xe8?9J\x8c\x18\x90\x0e\xc4\x88"


                async def my_func() -> None:
                    await PKCS11Session().import_keypair(pub, priv, "my_rsa_key", "rsa_2048")
                    public_key, identifier = await PKCS11Session().public_key_data(
                        "my_rsa_key",
                    key_type="rsa_2048",
                    )
                    print(public_key)
                    print(identifier)

                asyncio.run(my_func()


    .. method:: key_labels():

        Returns a dictionary of the key labels available on the HSM.

        :returns: Dict[str, str]

        Example:

        .. code-block:: python

                import asyncio
                from python_x509_pkcs11 PKCS11Session

                async def my_func() -> None:
                    public_key, identifier = await PKCS11Session().create_keypair("my_ed25519_key")
                    labels = await PKCS11Session().key_labels()
                    print(labels)

                asyncio.run(my_func())


    .. method:: public_key_data(key_label: str, key_type: KEYTYPES = DEFAULT_KEY_TYPE)

        Returns the public key in PEM format and sha1sum in bytes.

        :param key_label: The key label to be used in the HSM.
        :type key_label: str

        :param key_type: The kind of key should be generated.
        :type key_type: Union[str, KEYTYPES]

        :returns: Tuple[str, bytes]


    .. method:: sign(key_label: str, data: bytes, verify_signature: Optional[bool] = None,   key_type: Union[str, KEYTYPES] = DEFAULT_KEY_TYPE)

        Signs the given bytes and returns the signature as bytes.

        :param key_label: The key label to be used for the signing.
        :type key_label: str.

        :param data: The data needs to be signed.
        :type data: bytes.

        :param verify_signature: If we want to verify the signature, default `False`.
        :type verify_signature: bool.

        :param key_type: The type of the key to be used, default DEFAULT_KEY_TYPE.
        :type key_type: Union[str, KEYTYPES]

        :returns: bytes

        Example:

        .. code-block:: python

                import asyncio
                from python_x509_pkcs11 import PKCS11Session

                async def my_func() -> None:
                    data = b"DATA TO BE SIGNED"
                    public_key, identifier = await PKCS11Session().create_keypair("my_ed25519_key")
                    signature = await PKCS11Session().sign("my_ed25519_key", data)
                    print(signature)

                asyncio.run(my_func())



    .. method:: verify(key_label: str, data: bytes, signature: bytes, key_type: Union[str, KEYTYPES] = DEFAULT_KEY_TYPE):

        Verifies a given data and signature on the HSM, returns `True` or `False`.

        :param key_label: The key label to be used for the signing.
        :type key_label: str.

        :param data: The data needs to be verified.
        :type data: bytes

        :param signature: The signature we want to be verified.
        :type signature: bytes

        :param key_type: The type of the key to be used, default DEFAULT_KEY_TYPE.
        :type key_type: Union[str, KEYTYPES]

        :returns: bool

        Example:

        .. code-block:: python

                import asyncio
                from python_x509_pkcs11 import PKCS11Session

                async def my_func() -> None:
                    data = b"DATA TO BE SIGNED"
                    public_key, identifier = await PKCS11Session().create_keypair("my_ed25519_key")
                    signature = await PKCS11Session().sign("my_ed25519_key", data)
                    if await PKCS11Session().verify("my_ed25519_key", data, signature):
                        print("OK sig")
                    else:
                        print("BAD sig")

                asyncio.run(my_func())























