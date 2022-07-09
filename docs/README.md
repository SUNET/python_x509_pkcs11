# Setup your PKCS11 device

First we need to setup a PKCS11 device.
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

# Or reboot, just make sure your shell now has the new group	
echo "logout and login again to fix the softhsm group now"

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
Our [pkcs11_handle](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/pkcs11_handle.py) module currently exposes 4 functions:

- `create_keypair(key_label: str,
         	  key_size: int = 2048,
		  use_existing: bool = True) -> typing.Tuple[asn1crypto.keys.PublicKeyInfo, bytes]:`

 - `sign(key_label: str,
         data: bytes,
	 verify_signature: bool = True,
	 mechanism: pkcs11.Mechanism = Mechanism.SHA256_RSA_PKCS) -> bytes:`

 - `verify(key_label: str,
          data: bytes,
	  signature: bytes,
	  mechanism: pkcs11.Mechanism = Mechanism.SHA256_RSA_PKCS) -> bool:`

- `public_key_data(key_label: str) -> typing.Tuple[asn1crypto.keys.PublicKeyInfo, bytes]`

## create_keypair()

The `create_keypair()` function generate a keypair in the PKCS11 device with this label
Returns typing.Tuple[asn1crypto.keys.PublicKeyInfo, bytes] which is a tuple of
the public key info and the public keys x509 'Subject Key identifier' value.

If a keypair with label already exists then use that one instead.

### Example usage:
```python
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

pk_info, identifier = PKCS11Session.create_keypair("my_rsa_key")
print(pk_info)
print(identifier)
```

## sign()

The `sign()` function signs the data using the private_key in the PKCS11 device with this label.

### Example usage:
```python
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

data = b"DATA TO BE SIGNED"
pk_info, identifier = PKCS11Session.create_keypair("my_rsa_key")
signature = PKCS11Session.sign("my_rsa_key", data)
print(signature)
```

## verify()

The `verify()` function verifies a signature and its data using the private_key in the PKCS11 device with this label.

### Example usage:
```python
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

data = b"DATA TO BE SIGNED"
pk_info, identifier = PKCS11Session.create_keypair("my_rsa_key")
signature = PKCS11Session.sign("my_rsa_key", data)
if PKCS11Session.verify("my_rsa_key", data, signature):
    print("OK sig")
else:
    print("BAD sig")
```

## public_key_data()

The `public_key_data()` function returns the data for the x509 'Public Key Info'
and 'Key Identifier' valid for this keypair from the public key in the PKCS11 device with this label.

### Example usage:
```python
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

pk_info_created, identifier_created = PKCS11Session.create_keypair("my_rsa_key")
pk_info_loaded, identifier_loaded = PKCS11Session.public_key_data("my_rsa_key")
assert (pk_info_created.native == pk_info_loaded.native)
assert (identifier_created == identifier_loaded)
print(pk_info_loaded.native)
print(identifier_loaded)
```

# Sign an CSR
Our [csr](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/csr.py) module currently exposes one function:

 - `sign_csr(key_label: str,
   	     issuer_name: dict[str, str],
      	     csr_pem: str,
	     not_before: Union[datetime.datetime, None] = None,
    	     not_after: Union[datetime.datetime, None] = None,
    	     keep_csr_extensions: bool = True,
    	     extra_extensions: Union[asn1crypto.x509.Extensions, None] = None)`
 
## sign_csr()

The `sign_csr()` function signs the pem_encoded CSR, writes the 'Subject Key Identifier'
and 'Authority Key Identifier' extensions into the signed certificate based on
the public key from the CSR and the public key from key_label in the PKCS11 device.

The not_before and not_after parameters must be in UTC timezone, for example:
```python
import datetime
datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
```

### Example usage:
```python
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

issuer_name = {"country_name": "SE",
               "state_or_province_name": "Stockholm",
               "locality_name": "Stockholm",
               "organization_name": "SUNET",
               "organizational_unit_name": "SUNET Infrastructure",
               "common_name": "ca-test.sunet.se",
               "email_address": "soc@sunet.se"}

pk_info, identifier = PKCS11Session.create_keypair("my_rsa_key")
cert_pem = csr.sign_csr("my_rsa_key", issuer_name, csr_pem)
print(cert_pem)
```

# Create a root CA

Our [root_ca](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/root_ca.py) module currently exposes one function:

 - `create(key_label: str,
           key_size: int,
	   subject_name: dict[str, str],
	   not_before: Union[datetime.datetime, None] = None,
    	   not_after: Union[datetime.datetime, None] = None,
	   exta_extensions: Union[asn1crypto.x509.Extensions] = None])`

The `create()` function generate a CSR and then signs it
with the same key from the key_label in the pkcs11 device.

If extra_extensions is not None then those extensions will be written into the root CA certificate.

The not_before and not_after parameters must be in UTC timezone, for example:
```python
import datetime
datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
```

This function uses the `sign_csr()` from the `csr` module to sign
the generated CSR.

### Example usage:
```python
from python_x509_pkcs11.root_ca import create
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

name_dict = {"country_name": "SE",
             "state_or_province_name": "Stockholm",
             "locality_name": "Stockholm",
             "organization_name": "SUNET",
             "organizational_unit_name": "SUNET Infrastructure",
             "common_name": "ca-test.sunet.se",
             "email_address": "soc@sunet.se"}

root_cert_pem = create("my_rsa_key", name_dict)
print(root_cert_pem)
```

# Create a CRL

Our [crl](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/crl.py) module currently exposes one function:

 - `create(key_label: str,
           subject_name: dict[str, str],
	   old_crl_pem: Union[str, None] = None,
	   serial_number: Union[int, None] = None,
	   reason: Union[int, None] = None
	   this_update: Union[datetime.datetime, None] = None
	   next_update: Union[datetime.datetime, None] = None)`


The `create()` function generate a CRL and then signs it with the
key from the key_label in the pkcs11 device.

If old_crl_pem, an pem encoded CRL, is not None then this function
will take that CRLs with its revoked serial numbers and extensions
and simply overwrite its version, timestamps and signature related fields.

If serial_number and [reason](https://github.com/wbond/asn1crypto/blob/b5f03e6f9797c691a3b812a5bb1acade3a1f4eeb/asn1crypto/crl.py#L97) is not None then this serial number
with its reason will be added to the revocation list in the CRL.

The this_update and next_update parameters must be in UTC timezone, for example:
```python
import datetime
datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
```

### Example usage:
```python
from python_x509_pkcs11.crl import create
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

name_dict = {"country_name": "SE",
             "state_or_province_name": "Stockholm",
             "locality_name": "Stockholm",
             "organization_name": "SUNET",
             "organizational_unit_name": "SUNET Infrastructure",
             "common_name": "ca-test.sunet.se",
             "email_address": "soc@sunet.se"}

pk_info, identifier = PKCS11Session.create_keypair("my_rsa_key")
crl_pem = create("my_rsa_key", name_dict)
print(crl_pem)
```
