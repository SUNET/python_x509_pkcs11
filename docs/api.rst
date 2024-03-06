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

.. function:: get_keytypes_enum(value: str)

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




























