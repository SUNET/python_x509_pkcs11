# Setup your PKCS11 device

First we need to setup a PKCS11 device.
We will use softhsm for easy testing but any PKCS11 device should work.

```bash
# Install this package
pip install python_x509_pkcs11

# Install deps
sudo apt-get install opensc softhsm2
sudo usermod -a -G softhsm $USER
sudo reboot # Yeah seem to not update your groups without a reboot

# export environment values the package will use
# Replace with your PKCS11 device .so file
export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_PIN="1234"
export PKCS11_TOKEN="my_test_token_1"

# Initialize the token
softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN
```

# PKCS11 device usage
This is basically a wrapper around the [python-pkcs11](https://python-pkcs11.readthedocs.io/en/stable/) package.
The [pkcs11_handle](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/pkcs11_handle.py) module currently includes 4 functions:

- `create_keypair(key_label: str,
          	  key_size: int,
		  use_existing: bool = True)`

 - `sign(key_label: str,
         data: bytes,
	 verify_signature: bool = True,
	 mechanism: pkcs11.Mechanism = Mechanism.SHA256_RSA_PKCS)`

 - `verify(key_label: str,
          data: bytes,
	  signature: bytes,
	  mechanism: pkcs11.Mechanism = Mechanism.SHA256_RSA_PKCS)`

- `public_key_data(key_label: str)`

## create_keypair()

The `create_keypair()` function generate a keypair in the PKCS11 device with this label
Returns typing.Tuple[asn1crypto.keys.PublicKeyInfo, bytes] which is a tuple of
the public key info and the public keys x509 'Subject Key identifier' value.

If a keypair with label already exists then use that one instead.

```python
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

pk_info, idenfifier = PKCS11Session().create_keypair(key_label, key_size)
```

## sign()

The `sign()` function signs the data using the private_key in the PKCS11 device with this label.

```python
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

data = b"DATA TO BE SIGNED"
signature = PKCS11Session.sign("my_rsa_key", data)
```

## verify()

The `verify()` function verifies a signature and its data using the private_key in the PKCS11 device with this label.

```python
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

data = b"DATA TO BE SIGNED"
signature = PKCS11Session.sign("my_rsa_key", data)
if PKCS11Session.verify("my_rsa_key", data, signature):
    print("OK sig")
else:
    print("BAD sig")
```

## public_key_data()

The `public_key_data()` function returns the data for the x509 'Public Key Info'
and 'Key Identifier' valid for this keypair from the public key in the PKCS11 device with this label.

```python
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

pk_info, identifier = PKCS11Session.public_key_data("my_rsa_key")
```

# Sign an CSR
The [csr](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/csr.py) module currently includes one function:

 - `sign_csr(key_label: str,
   	     issuer_name: dict[str, str],
	     csr_pem: str)`
 
## sign_csr()

The `sign_csr()` function signs the pem_encoded CSR, writes the 'Subject Key Identifier'
and 'Authority Key Identifier' extensions into the signed certificate based on
the public key from the CSR and the public key from key_label in the PKCS11 device.

```python
from python_x509_pkcs11 import csr
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

issuer_name = {"country_name": "SE",
               "state_or_province_name": "Stockholm",
               "locality_name": "Stockholm",
               "organization_name": "SUNET",
               "organizational_unit_name": "SUNET Infrastructure",
               "common_name": "ca-test.sunet.se",
               "email_address": "soc@sunet.se"}

PKCS11Session.create_keypair("my_rsa_key", 4096)
cert_pem = csr.sign_csr("my_rsa_key", issuer_name, csr_pem)
```

# Create a root CA

The [root_ca](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/root_ca.py) module currently includes one function:

 - `create(key_label: str,
           key_size: int,
	   subject_name: dict[str, str],
	   exta_extensions: Union[asn1crypto.x509.Extensions] = None])`

The `create()` function generate a CSR and then signs it
with the same key from the key_label in the pkcs11 device.

If extra_extensions is not None then those extensions will be written into the root CA certificate.


This function uses the `sign_csr()` from the `csr` module to sign
the generated CSR.

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

PKCS11Session.create_keypair("my_rsa_key", 4096, False)
root_cert_pem = create("my_rsa_key", 4096, name_dict)
```

# Create a CRL

The [crl](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/crl.py) module currently includes one function:

 - `create(key_label: str,
           subject_name: dict[str, str],
	   old_crl_pem: Union[str, None] = None,
	   serial_number: Union[int, None] = None,
	   reason: Union[int, None] = None)`


The `create()` function generate a CRL and then signs it with the
key from the key_label in the pkcs11 device.

If old_crl_pem, an pem encoded CRL, is not None then this function
will take that CRLs with its revoked serial numbers and extension
and simply overwrite its version, timestamps and signature related fields.

If serial_number and [reason](https://github.com/wbond/asn1crypto/blob/b5f03e6f9797c691a3b812a5bb1acade3a1f4eeb/asn1crypto/crl.py#L97) is not None then this serial number
with its reason will be added to the revocation list in the CRL

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

PKCS11Session.create_keypair("my_rsa_key", 4096)
root_cert_pem = create("my_rsa_key", 4096, name_dict)
```
