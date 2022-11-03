# Setup your PKCS11 device

First we need to set up a PKCS11 device.
We will use softhsm for easy testing but any PKCS11 device should work.

```bash
if awk -F= '/^NAME/{print $2}' /etc/os-release | grep -i "debian\|ubuntu"
then
    # Ubuntu / Debian
    sudo apt-get install python3-dev python3-pip softhsm2
    sudo usermod -a -G softhsm $USER
else
    # Redhat / Centos / Fedora
    sudo dnf install python3-devel python3-pip softhsm gcc 
    sudo usermod -a -G ods $USER
fi

# Update your softhsm group membership
exec sudo su -l $USER

# Install this package
pip3 install python_x509_pkcs11

# export env values the code will use
if awk -F= '/^NAME/{print $2}' /etc/os-release | grep -i "debian\|ubuntu"
then
    export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
else
    export PKCS11_MODULE="/usr/lib64/softhsm/libsofthsm.so"
fi
export PKCS11_PIN="1234"
export PKCS11_TOKEN="my_test_token_1"

# Delete the previous token if exists
softhsm2-util --delete-token --token $PKCS11_TOKEN

# Initialize a new fresh PKCS11 token
softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN
```

# PKCS11 device usage
This is basically a wrapper around the [python-pkcs11](https://python-pkcs11.readthedocs.io/en/stable/) package.
Our [pkcs11_handle](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/pkcs11_handle.py) module currently exposes 6 functions:

- `import_keypair(public_key: bytes,
         	  private_key: bytes,
		  key_label: str,
  	          key_type: str,
		  ) -> None:`

- `create_keypair(key_label: str,
		  key_type: Union[str, None] = None,
		  ) -> Tuple[str, bytes]:`

 - `key_labels() -> List[str]:`

 - `sign(key_label: str,
         data: bytes,
	 verify_signature: Union[bool, None] = None,
 	 key_type: Union[str, None] = None,
	 ) -> bytes:`

 - `verify(key_label: str,
          data: bytes,
	  signature: bytes,
	  key_type: Union[str, None] = None,
	  ) -> bool:`

- `public_key_data(key_label: str,
  		   key_type: Union[str, None] = None,
		   ) -> Tuple[str, bytes]:`

## import_keypair()

The `import_keypair()` function imports a DER encoded keypair in the PKCS11 device with this label

key_type must be:
* [ed25519](https://en.wikipedia.org/wiki/EdDSA). This is default.
* ed448
* secp256r1
* secp384r1
* secp521r1
* rsa_2048
* rsa_4096

Generating public_key and private_key can be done with:
```bash
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
```

If a keypair with label already exists in the PKCS11 device
then pkcs11.MultipleObjectsReturned will be raised.

### Example usage for import_keypair():
```python
import asyncio
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

pub = b"0\x82\x01\n\x02\x82\x01\x01\x00\xd9\xb6C,O\xc0\x83\xca\xa5\xcc\xa7<_\xbf$\xdd-YJ0m\xbf\xa8\xf9[\xe7\xcb\x14W6G\n\x13__\xea\xb4Z\xab2\x01\x0f\xa4\xd3\x1c\xbb\xa6\x98\x9d\xcdf\xaa\x07\xcb\xff\xd8\x80\xa9\\\xa1\xf44\x01\xdbY\xa6\xcf\x83\xd2\x83Z\x8a<\xc1\x18\xe5\x8d\xff\xbfzU\x03\x01\x11\xa1\xa1\x98\xcf\xcaVu\xf9\xf3\xa7+ \xe7N9\x07\xfd\xc6\xd0\x7f\xa0\xba&\xef\xb2a\xc6\xa5d\x1c\x93\xe6\xc3\x80\xd1*;\xc8@7\x0fm)\xf93\xe4\x1f\x91\xf4=\xa6\xf8\xed\x9cN\x84\x9b\xf2\xc5\x9f\x9f\x82E\xa5Tm\xb9\xb3:T\xc7_\xb1^[\xf4\x0b\xd8\x0b\xd2\xfb\xe1\x13\x1e,L\xd9\xdc\xed]_#\xca\xa0r\xc2\xc5F \xec\xae\x8d\x08v\x059\x062\xe1\xf7%\x9e\xfd\xfb9\x11(\xa4\x86v\x90\x01\x1c\xbeP\x04\xa3%\x91\x08\xc5\xd5\xc1U\xf6\xd3\x7f\x1f\x9f7`\xce\xc9\xa1\xd9\x8f\\Z\xa8\x1cmz\x19x\xa4'F\xdf\xb2\xb2\x87\xba\xf7\n>]\x9f\xc0K@\xd9\xdb\x02\x03\x01\x00\x01"

priv = b"0\x82\x04\xa4\x02\x01\x00\x02\x82\x01\x01\x00\xd9\xb6C,O\xc0\x83\xca\xa5\xcc\xa7<_\xbf$\xdd-YJ0m\xbf\xa8\xf9[\xe7\xcb\x14W6G\n\x13__\xea\xb4Z\xab2\x01\x0f\xa4\xd3\x1c\xbb\xa6\x98\x9d\xcdf\xaa\x07\xcb\xff\xd8\x80\xa9\\\xa1\xf44\x01\xdbY\xa6\xcf\x83\xd2\x83Z\x8a<\xc1\x18\xe5\x8d\xff\xbfzU\x03\x01\x11\xa1\xa1\x98\xcf\xcaVu\xf9\xf3\xa7+ \xe7N9\x07\xfd\xc6\xd0\x7f\xa0\xba&\xef\xb2a\xc6\xa5d\x1c\x93\xe6\xc3\x80\xd1*;\xc8@7\x0fm)\xf93\xe4\x1f\x91\xf4=\xa6\xf8\xed\x9cN\x84\x9b\xf2\xc5\x9f\x9f\x82E\xa5Tm\xb9\xb3:T\xc7_\xb1^[\xf4\x0b\xd8\x0b\xd2\xfb\xe1\x13\x1e,L\xd9\xdc\xed]_#\xca\xa0r\xc2\xc5F \xec\xae\x8d\x08v\x059\x062\xe1\xf7%\x9e\xfd\xfb9\x11(\xa4\x86v\x90\x01\x1c\xbeP\x04\xa3%\x91\x08\xc5\xd5\xc1U\xf6\xd3\x7f\x1f\x9f7`\xce\xc9\xa1\xd9\x8f\\Z\xa8\x1cmz\x19x\xa4'F\xdf\xb2\xb2\x87\xba\xf7\n>]\x9f\xc0K@\xd9\xdb\x02\x03\x01\x00\x01\x02\x82\x01\x00a5\x1e=\x14\xc6\xf2\x91s\x023\xd1\xa36\xa7q\x12$\x82\x19\xa9\x87 \x1df\xc9\xd2E\x1c\xc3\xa1h\x80I\xdf{\xdeWu\x84\xf80Q\xf9\xe9$h8P\x8d;\xbf\xc3\x87t\x8e\xe8\xb3\xb6&\xa1\xf0\xee\xbbP\x06I5\xa4\xb2\xfd\xa4'\x88Xcv\xc9\xb0g \xba\x1c\xaa\x10\xaf$\x99\xf2\xd04\x11\x0c\x97\xa1\x8c){%\xbf\xc9\xb2\x11\xbaJ\xbb\x93S\x07$\xdd\x1bO\xdd\xea\xb3\xe8\xab\x05\xb9\x83\xc3\xdf\xd85\xcd\x1a%\xd5\xd9\xc4\x933\x83\t\xd3\xea\xcdb\xcb\xec\x9eGqk\x1c\x8c\x06\x8a\\\xae\xbe\xd3+\x0b\xd0R\xbd:\x8a\xf5\xf4\x0f\x0b\xd4\xfa@P=\xe5\xb2\xa1\xb2\x01\x00\x08\xc7\x11?M\x84-\x1e\xbc\xa9\xbf|\x87\x98\xd7\x0e\xf6\xa9\xa6\xcd\x8c8\xa5F8\xacM\x82\xade[\xa9_\xa7Biv\x9c\x06\xa6\x001\xc3I\x1f\xc4\x9by\xd7\xe0\x9e\xb9\n\xbb\x19\\o\xc5i\xd90r\xd4\x1e(\x05\xdd\xedF\xe9\xaa\xbd\x91\xe5\x08\x8f4-\xb6\xd1Q\x02\x81\x81\x00\xf7\x076\xd8i\x87\x12\xf1\xd0$\x07\x1f\xab\xb7^\x0e\xa5\xfb\x83\x98\x00\x0b\\\x1d\xe8s\x15r\x96/\x0e\x0ezB\xc8\xf6\xf3Zmj?\xa0\xc1\x11r\xaf3\x11a\xcd\xa3\xfc\xa0\x03\x04E\x05\x99\x9a\xd9\xff\x8e+\xdcfM\xa8\xe8&\x84\x85\xc5\x11O\x9d4\x1f\xc3\x1f\xef\xed\x13BW\xaa\x93\xc3\x08(v]\xbc\x93V\xb6s\xce\xb1\xa8\xe2\x94\xa5'\xf3\x7f\x90,G[\xfeI\x16\xbe\xb0\xf8J\xca9n\xb5\xfc\x8a\xe2[\xc5\x0c\x95\xd5\x02\x81\x81\x00\xe1\x9ey\xc8\xe2\xd3\x93\xa2nj\xe1.\xaa\xe3\xa7\xf5P\xd1\xd8yM\x01\xdc\x01\x0c\xdbQG\x1b=\xbe\xe4.\x9cM\xc2\xda\xd2\xa4\xb3\x80\xb2\xbd\xbaO\x1bD&]0\x0b\xe6\xf5\x08\xdb*I\xfe+@Aa\x16;\x9a%\x8cof:\x156 \xb0\xe6\xfe\x95\x9bO\x85]\x96\x94S\x05\xc8\x8a\xb6\x92\xb3\x95\xc5\xfbX\xa9S<@\x12\x94K\x8b\xa3\x0f\xebO\xb5\x9f\x0c\x08\xf2\xccS\xfd8\x06\xeb\xaa\x96_\xadm&L~!\x18\xef\x02\x81\x80@.\x04\xa6\xd7K\xfb\xb5\r\xb1\xbe\x94\x10\xe6\x14.\xd4\x1a\xf3\x86\x93D`Kx\xf0%{^\xdf\x9c\xd4P\x19w\xe3\t8\xceB\x93\x83m\x85\xdd\xf8\xfc\xd8\xa0Cp>\x9bH\r\\\xedf\x8a\x1f\xe7P\x85\xbe\xbei\xa0\xdf\xa7\xda8s\t\xdbXi\x89s\x05\xa2-C\x1a\xb2r#\xef\xc0\xf7\xda@\xe2T\x99k\xcf\xcc\xbc\xc5\xb7\x10\x8d\x94B\xa4:\xcd\xf6@Ea\xb1\xe2\x1bRw\x03\xf1E\xfdL>\xbd.\xc0\x94S}\x02\x81\x81\x00\xa2\xce\x13}EH}a\x19\xa2`I\xa7\xa0\xcdc4\xe5\xa7\xfa\xa7\xf9\xee\x82\x87\x7f\x7f\x1f\xfbeK\xe9&E=\xcb\x9c\xd1\xa1m\xb21\xc8\xbc\xb76\xaa\xaf\xb0P\xeaU\xc7}\x93\x80\xe9\x91\xd2-\xf4\xbf\x95&\x7f.\x17/\x8f\xa9\xdc\x02\x8a\x06}9:E\xafUBZU?\xaf\x8d\xad\xa2\xdf+]\xa9V\x9c\xfc\xda\x86@\x89\xe7\x9e\xb7\xed{\xa0F\x8d}nV\xca\xb5l\xe9\xedR\xf9\x1d\xc8\x92\xd3\xf7NJ\xa6=E\xdb\x02\x81\x81\x00\xf5\xa8\xec\x00k\x18\x10KK\xd0D\xa9\xeb\x87==X\xa2\xaa)\xeb\x92\xfa\xf8f\xa6W\xaa\x94\x92\xa1F\t\xc1\x01\xd8%-\x1f\xb71\xefg\x95q\xb3\xa5J[k\xe3\x17\xac\xfd\xbfU\x02\x95\xa4\xf9\xcd\x80!E\x9d\x7f\x9c\xcd\x89uV\x1df\xee\xab\xd3\x1f7$&\x014\xd2\xdd\xc2\xe4?\x1bh*\xb6\x00\x1a\x1fz^\xbc\x97\xde\x9cK\xc8\xf5\xcf0\"\x8c\x8bm\xecUv\xefu\xd9YD\x05\xe8?9J\x8c\x18\x90\x0e\xc4\x88"


async def my_func() -> None:
    await PKCS11Session.import_keypair(pub, priv, "my_rsa_key", "rsa_2048")
    public_key, identifier = await PKCS11Session.public_key_data(
        "my_rsa_key",
	key_type="rsa_2048",
    )
    print(public_key)
    print(identifier)

    
asyncio.run(my_func())
```

## create_keypair()

The `create_keypair()` function generate a keypair in the PKCS11 device with this label
Returns Tuple[asn1crypto.keys.PublicKeyInfo, bytes] which is a tuple of
the public key info and the public keys x509 'Subject Key identifier' value.

key_type must be:
* [ed25519](https://en.wikipedia.org/wiki/EdDSA). This is default.
* ed448
* secp256r1
* secp384r1
* secp521r1
* rsa_2048
* rsa_4096

If a keypair with label already exists in the PKCS11 device
then pkcs11.MultipleObjectsReturned will be raised.

### Example usage for create_keypair():
```python
import asyncio
from python_x509_pkcs11.pkcs11_handle import PKCS11Session


async def my_func() -> None:
    public_key, identifier = await PKCS11Session.create_keypair("my_ed25519_key", key_type="ed25519")
    print(public_key)
    print(identifier)


asyncio.run(my_func())
```

## key_labels()

The `key_labels()` function return a list of key labels in the PKCS11 device.

### Example usage for key_labels():
```python
import asyncio
from python_x509_pkcs11.pkcs11_handle import PKCS11Session


async def my_func() -> None:
    public_key, identifier = await PKCS11Session.create_keypair("my_ed25519_key")
    labels = await PKCS11Session.key_labels()
    print(labels)


asyncio.run(my_func())
```

## sign()

The `sign()` function signs the data using the private_key in the PKCS11 device with this label.

### Example usage for sign():
```python
import asyncio
from python_x509_pkcs11.pkcs11_handle import PKCS11Session


async def my_func() -> None:
    data = b"DATA TO BE SIGNED"
    public_key, identifier = await PKCS11Session.create_keypair("my_ed25519_key")
    signature = await PKCS11Session.sign("my_ed25519_key", data)
    print(signature)


asyncio.run(my_func())
```

## verify()

The `verify()` function verifies a signature and its data using the private_key in the PKCS11 device with this label.

### Example usage for verify():
```python
import asyncio
from python_x509_pkcs11.pkcs11_handle import PKCS11Session


async def my_func() -> None:
    data = b"DATA TO BE SIGNED"
    public_key, identifier = await PKCS11Session.create_keypair("my_ed25519_key")
    signature = await PKCS11Session.sign("my_ed25519_key", data)
    if await PKCS11Session.verify("my_ed25519_key", data, signature):
        print("OK sig")
    else:
        print("BAD sig")


asyncio.run(my_func())
```

## public_key_data()

The `public_key_data()` function returns the data for the x509 'Public Key Info'
and 'Key Identifier' valid for this keypair from the public key in the PKCS11 device with this label.

### Example usage for public_key_data():
```python
import asyncio
from python_x509_pkcs11.pkcs11_handle import PKCS11Session


async def my_func() -> None:
    public_key_created, identifier_created = await PKCS11Session.create_keypair(
        "my_ed25519_key"
    )
    public_key_loaded, identifier_loaded = await PKCS11Session.public_key_data(
        "my_ed25519_key"
    )
    print(public_key_created)
    print(public_key_loaded)
    print(identifier_created)
    print(identifier_loaded)


asyncio.run(my_func())
```

# Sign an CSR
Our [csr](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/csr.py) module currently exposes one function:

 - `sign_csr(key_label: str,
   	     issuer_name: Dict[str, str],
      	     csr_pem: str,
	     not_before: Union[datetime.datetime, None] = None,
    	     not_after: Union[datetime.datetime, None] = None,
    	     keep_csr_extensions: Union[bool, None] = None,
    	     extra_extensions: Union[asn1crypto.x509.Extensions, None] = None,
             key_type: str = "ed25519",
             ) -> str:`
 
## sign_csr()

The `sign_csr()` function signs the pem_encoded CSR, writes the 'Subject Key Identifier'
and 'Authority Key Identifier' extensions into the signed certificate based on
the public key from the CSR and the public key from key_label in the PKCS11 device.

key_type must be:
* [ed25519](https://en.wikipedia.org/wiki/EdDSA). This is default.
* ed448
* secp256r1
* secp384r1
* secp521r1
* rsa_2048
* rsa_4096

keep_csr_extensions is True by default.

The not_before and not_after parameters must be in UTC timezone, for example:
```python
import datetime
datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
```

### Example usage for sign_csr():
```python
import asyncio
from python_x509_pkcs11 import csr
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

csr_pem = """-----BEGIN CERTIFICATE REQUEST-----
MIICwzCCAasCAQAwfjELMAkGA1UEBhMCU0UxEjAQBgNVBAgMCVN0b2NraG9sbTEh
MB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRswGQYDVQQDDBJjYS10
ZXN0LTJAc3VuZXQuc2UxGzAZBgkqhkiG9w0BCQEWDHNvY0BzdW5ldC5zZTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDZWJtcRC/xhft4956paxXhHn95
09XqJvMGDM8ToYNIw8BIH8Id774RjLjaa2Z9UU6OSN0IoTiH/h3wq1hTH9IovkvG
/rNwieo1cvZ0Q3YJblEJ3R450t04w11fp+fOsZSA8NOoINav3b15Zd0ugYYFip+7
4/Meni73FYkrKs8ctsw1bVudDwbRwnPoWcHEEbZwOgMSifgk9k8ST+1OlfdKeUr4
LO+ss/pU516wQoVN0W0gQhahrL5plP8M1a0qo6yaNF68hXa/LmFDi7z6078S6Mpm
fUpLQJ2CiIQL5jFaXaQhp6Uwjbmm+Mnyn+Gqb8NDd5STIG1FhMurjAC+Q6MCAwEA
AaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBSeA9xgZSuEUenuNsYqe9pDm0xagBCuSgo
ROBkrutn/L4cP1y2ZTSkcKScezPeMcYhK3A9ktpXxVVSwjFOvCJT1Lz+JN4Vn3kG
23TCqfTOxgB+ecHKPyKA3112WdXu5B0yRDHrecumxEJDtn3H823xn1WpxzCvqvWX
IgukK0VlN7pUPKMtAx1Y+sY8z4bwgOmZRQVvYaRbsMJHyjBl/I4XU+W0nOyq6nAW
eHqaFEFZApnEybHb7JgdpW5TsnvPN1O5YC6bgbRTgLmwGe+pJ5cEtTwrSvWJra8G
grASjklC2MWbAnXculQuvhPg5F54CK9WldMvd7oYAmbdGIWiffiL
-----END CERTIFICATE REQUEST-----
"""


async def my_func() -> None:

    issuer_name = {
        "country_name": "SE",
        "state_or_province_name": "Stockholm",
        "locality_name": "Stockholm",
        "organization_name": "SUNET",
        "organizational_unit_name": "SUNET Infrastructure",
        "common_name": "ca-test.sunet.se",
        "email_address": "soc@sunet.se",
    }

    public_key, identifier = await PKCS11Session.create_keypair("my_ed25519_key")
    cert_pem = await csr.sign_csr("my_ed25519_key", issuer_name, csr_pem)
    print(cert_pem)


asyncio.run(my_func())
```

# Create a CA

Our [ca](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/ca.py) module currently exposes one function:

 - `create(key_label: str,
	   subject_name: Dict[str, str],
	   signer_subject_name: Union[Dict[str, str], None] = None,
	   signer_key_label: Union[str, None] = None,
   	   signer_key_type: Union[str, None] = None,
	   not_before: Union[datetime.datetime, None] = None,
    	   not_after: Union[datetime.datetime, None] = None,
	   extra_extensions: Union[asn1crypto.x509.Extensions, None] = None,
           key_type: Union[str, None] = None,
           ) -> Tuple[str, str]:`

## create()

The `create()` function generate a CSR and then signs it
with the same key from the key_label in the pkcs11 device.

signer_key_label is the key label for the key in the PKCS11 device should sign this ca. If signer_key_label is None then this will be a root (selfsigned) CA.
signer_key_type, default is ed25519.
signer_subject_name will be the issuing name for CA If signer_key_label is None then this will be a root (selfsigned) CA.

key_type must be:
* [ed25519](https://en.wikipedia.org/wiki/EdDSA). This is default.
* ed448
* secp256r1
* secp384r1
* secp521r1
* rsa_2048
* rsa_4096

If extra_extensions is not None then those extensions will be written into the CA certificate.

The not_before and not_after parameters must be in UTC timezone, for example:
```python
import datetime
datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
```

This function uses the `sign_csr()` from the `csr` module to sign
the generated CSR.

### Example usage for create():
```python
import asyncio
from python_x509_pkcs11.ca import create


async def my_func() -> None:
    root_ca_name_dict = {
        "country_name": "SE",
        "state_or_province_name": "Stockholm",
        "locality_name": "Stockholm",
        "organization_name": "SUNET",
        "organizational_unit_name": "SUNET Infrastructure",
        "common_name": "ca-test.sunet.se",
        "email_address": "soc@sunet.se",
    }
    csr_pem, root_cert_pem = await create("my_ed25519_key", root_ca_name_dict)

    print("CSR which was selfsigned into root CA")
    print(csr_pem)

    print("root CA")
    print(root_cert_pem)


asyncio.run(my_func())
```

# Create a CRL

Our [crl](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/crl.py) module currently exposes one function:

 - `create(key_label: str,
           subject_name: Dict[str, str],
	   old_crl_pem: Union[str, None] = None,
	   serial_number: Union[int, None] = None,
	   reason: Union[int, None] = None,
	   this_update: Union[datetime.datetime, None] = None,
	   next_update: Union[datetime.datetime, None] = None,
           key_type: Union[str, None] = None,
           ) -> str:`

## create()

The `create()` function generate a CRL and then signs it with the
key from the key_label in the pkcs11 device.

If old_crl_pem, a pem encoded CRL, is not None then this function
will take that CRLs with its revoked serial numbers and extensions
and simply overwrite its version, timestamps and signature related fields.

key_type must be:
* [ed25519](https://en.wikipedia.org/wiki/EdDSA). This is default.
* ed448
* secp256r1
* secp384r1
* secp521r1
* rsa_2048
* rsa_4096

If serial_number and [reason](https://github.com/wbond/asn1crypto/blob/b5f03e6f9797c691a3b812a5bb1acade3a1f4eeb/asn1crypto/crl.py#L97) is not None then this serial number
with its reason will be added to the revocation list in the CRL.
                              
this_update and next_update parameters must be in UTC timezone, for example:
```python
import datetime
datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
```

### Example usage for create():
```python
import asyncio
from python_x509_pkcs11.crl import create
from python_x509_pkcs11.pkcs11_handle import PKCS11Session


async def my_func() -> None:
    name_dict = {
        "country_name": "SE",
        "state_or_province_name": "Stockholm",
        "locality_name": "Stockholm",
        "organization_name": "SUNET",
        "organizational_unit_name": "SUNET Infrastructure",
        "common_name": "ca-test.sunet.se",
        "email_address": "soc@sunet.se",
    }

    public_key, identifier = await PKCS11Session.create_keypair("my_ed25519_key")
    crl_pem = await create("my_ed25519_key", name_dict)
    print(crl_pem)


asyncio.run(my_func())
```

# Create OCSP requests and responses

Our [ocsp](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/ocsp.py) module currently exposes four functions:

 - `request(request_certs_data: List[Tuple[bytes, bytes, int]],
            issuer_key_hashes: List[bytes],
            serial_numbers: List[int],
            key_label: Union[str, None] = None,
	    requestor_name: Union[asn1crypto.ocsp.GeneralName, None] = None,
            certs: Union[List[str], None] = None,
            extra_extensions: Union[asn1crypto.ocsp.TBSRequestExtensions, None] = None,
            key_type: Union[str, None] = None,
            ) -> bytes:`

- `response(key_label: str,
	    responder_id: Dict[str,str],
	    single_responses: asn1crypto.ocsp.Responses,
	    response_status: int,
	    extra_extensions: Union[asn1crypto.ocsp.ResponseDataExtensions, None] = None,
	    produced_at: Union[datetime.datetime, None] = None,
	    extra_certs: Union[List[str], None] = None,
            key_type: Union[str, None] = None,
            ) -> bytes:`

- `request_nonce(data: bytes) -> Union[bytes, None]`

- `certificate_ocsp_data(pem: str) -> Tuple[bytes, bytes, int, str]`

## request()

The `request()` function generate a OCSP request.
https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1

If key_label is not None and requestor_name is not None then sign the request with the key_label in the pkcs11 device.
request_certs_data is a list of tuples (SHA1 hash of certificate issuer Name, SHA1 hash of certificate issuer public key, certificate serial number). See certificate_ocsp_data() here below.
If requestor_name is not None then it will be written into the request

key_type must be:
* [ed25519](https://en.wikipedia.org/wiki/EdDSA). This is default.
* ed448
* secp256r1
* secp384r1
* secp521r1
* rsa_2048
* rsa_4096
                              
for example:
```python
from asn1crypto.ocsp import GeneralName, Name

requestor_name_dict = {
    "country_name": "SE",
    "state_or_province_name": "Stockholm",
    "locality_name": "Stockholm",
    "organization_name": "SUNET",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test.sunet.se",
    "email_address": "soc@sunet.se",
}

# https://github.com/wbond/asn1crypto/blob/b5f03e6f9797c691a3b812a5bb1acade3a1f4eeb/asn1crypto/x509.py#L1414
requestor_name = GeneralName(name="directory_name", value=(Name().build(requestor_name_dict)))
print(requestor_name)
```
certs is a list of strings of PEM encoded certificates to write into the request

extra_extensions if not None will be written into the request, for example a nonce:
```python
from secrets import token_bytes
from asn1crypto.ocsp import TBSRequestExtensions, TBSRequestExtension, TBSRequestExtensionId

nonce_ext = TBSRequestExtension()
nonce_ext["extn_id"] = TBSRequestExtensionId("1.3.6.1.5.5.7.48.1.2")
nonce_ext["extn_value"] = token_bytes(32) # The nonce
extra_extensions = TBSRequestExtensions()
extra_extensions.append(nonce_ext)

print(extra_extensions)
```

### Example usage for request():
```python
import asyncio
from python_x509_pkcs11.ocsp import request

async def my_func() -> None:
    request_certs_data = [(b'R\x94\xca?\xac`\xf7i\x819\x14\x94\xa7\x085H\x84\xb4&\xcc', b'\xad\xd0\x88DW\x96\'\xce\xf4"\xc6\xc77W\xc9\xefi\xa4[\x8b', 440320505043419981128735462508870123525487964711)]
    ocsp_request = await request(request_certs_data)
    print(ocsp_request)

asyncio.run(my_func())
```

## response()

The `response()` function generate a OCSP response.
https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1

key_label is the key label in the PKCS11 device that will sign the response.

responder_id is the dict with the responders x509 Names.

single_responses is the single responses for all certs in the OCSP request for this OCSP response.

response_status is the status code (only 0,1,2,3,5,6) for the OCSP response.

extra_extensions if not None will be written into the request, for example a nonce:
```python
from asn1crypto.ocsp import ResponseDataExtensions, ResponseDataExtension, ResponseDataExtensionId

nonce_ext = ResponseDataExtension()
nonce_ext["extn_id"] = ResponseDataExtensionId("1.3.6.1.5.5.7.48.1.2")
nonce_ext["extn_value"] = token_bytes(32)
extra_extensions = ResponseDataExtensions()
extra_extensions.append(nonce_ext)
```

key_type must be:
* [ed25519](https://en.wikipedia.org/wiki/EdDSA). This is default.
* ed448
* secp256r1
* secp384r1
* secp521r1
* rsa_2048
* rsa_4096

produced_at is what time to write into "produced_at" field.
It must be in UTC timezone. If None then it will be 2 minutes before UTC now.

extra_certs is a list of PEM encoded certs for the client to verify the signature chain.
Default value is None.

### Example usage for response():
```python
import datetime
import asyncio
from asn1crypto.ocsp import Responses, SingleResponse, CertStatus, OCSPRequest
from python_x509_pkcs11.ocsp import response, request
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

name_dict = {
    "country_name": "SE",
    "state_or_province_name": "Stockholm",
    "locality_name": "Stockholm",
    "organization_name": "SUNET",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test.sunet.se",
    "email_address": "soc@sunet.se",
}


# Set all cert_statuses to good as a demonstration
def single_responses(ocsp_request: OCSPRequest) -> Responses:
    responses = Responses()

    for _, curr_req in enumerate(ocsp_request["tbs_request"]["request_list"]):
        curr_response = SingleResponse()
        curr_response["cert_id"] = curr_req["req_cert"]
        curr_response["cert_status"] = CertStatus("good")
        curr_response["this_update"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
        responses.append(curr_response)
    return responses


async def my_func() -> None:
    await PKCS11Session.create_keypair("my_ed25519_key")
    request_certs_data = [
        (
            b"R\x94\xca?\xac`\xf7i\x819\x14\x94\xa7\x085H\x84\xb4&\xcc",
            b"\xad\xd0\x88DW\x96'\xce\xf4\"\xc6\xc77W\xc9\xefi\xa4[\x8b",
            440320505043419981128735462508870123525487964711,
        )
    ]
    ocsp_request_bytes = await request(request_certs_data)
    ocsp_request = OCSPRequest.load(ocsp_request_bytes)

    ocsp_response = await response("my_ed25519_key", name_dict, single_responses(ocsp_request), 0)
    print(ocsp_response)


asyncio.run(my_func())
```

## request_nonce()

The `request_nonce()` function extract the nonce or None from a OCSP request.
Input is the bytes of a OCSP request. If you have an asn1crypto.ocsp.OCSPRequest then call dump() on it to get the bytes.

### Example usage for request_nonce():
```python
import asyncio
from secrets import token_bytes
from asn1crypto.ocsp import TBSRequestExtensions, TBSRequestExtension, TBSRequestExtensionId
from python_x509_pkcs11.ocsp import request, request_nonce


async def my_func() -> None:
    nonce_ext = TBSRequestExtension()
    nonce_ext["extn_id"] = TBSRequestExtensionId("1.3.6.1.5.5.7.48.1.2")
    nonce_ext["extn_value"] = token_bytes(32)  # The nonce
    extra_extensions = TBSRequestExtensions()
    extra_extensions.append(nonce_ext)

    request_certs_data = [
        (
            b"R\x94\xca?\xac`\xf7i\x819\x14\x94\xa7\x085H\x84\xb4&\xcc",
            b"\xad\xd0\x88DW\x96'\xce\xf4\"\xc6\xc77W\xc9\xefi\xa4[\x8b",
            440320505043419981128735462508870123525487964711,
        )
    ]
    ocsp_request_bytes = await request(request_certs_data, extra_extensions=extra_extensions)

    nonce = request_nonce(ocsp_request_bytes)
    print(nonce)


asyncio.run(my_func())
```

## certificate_ocsp_data()

The `certificate_ocsp_data()` function extract the OCSP data from a certificate.
Input is a PEM encoded certificate.

Returns a tuple of:
sha1 hash of issuer name
sha1 hash of issuer public key
serial number
ocsp url

The certificate MUST have the AKI extension (2.5.29.35)
and the AIA extension with ocsp method (1.3.6.1.5.5.7.1.1).
If not then OCSPMissingExtensionException will be raised.

### Example usage for certificate_ocsp_data():
```python
from python_x509_pkcs11.ocsp import certificate_ocsp_data

cert = """-----BEGIN CERTIFICATE-----
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

i_n_h, i_k_h, serial, ocsp_url = certificate_ocsp_data(cert)
print(i_n_h)
print(i_k_h)
print(serial)
print(ocsp_url)

# View the cert with:
# openssl x509 -text -noout -in cert.pem
```
