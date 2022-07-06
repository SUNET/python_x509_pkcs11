# Sign an CSR

The [csr](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/csr.py") module currently includes one function:

 - `sign_csr(key_label: str, issuer_name: dict[str, str], csr_pem: str)`
 
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

PKCS11Session.create_keypair_if_not_exists(4096, "my_rsa_key")
cert_pem = csr.sign_csr("my_rsa_key", issuer_name, csr_pem)
```

# Create a root CA

The [root_ca](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/root_ca.py") module currently includes one function:

 - `create(key_label: str, key_size: int, subject_name: dict[str, str])`

The `create()` function generate a CSR and then signs it with the same
same key from the key_label in the pkcs11 device.

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

PKCS11Session.create_keypair_if_not_exists("my_rsa_key", 4096)
root_cert_pem = create("my_rsa_key", 4096, name_dict)
```

# Create a CRL

The [crl](https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/crl.py") module currently includes one function:

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

PKCS11Session.create_keypair_if_not_exists("my_rsa_key", 4096)
root_cert_pem = create("my_rsa_key", 4096, name_dict)
```
