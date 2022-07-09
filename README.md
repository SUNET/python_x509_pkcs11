## python_x509_pkcs11

Seamless signing x509 using PKCS11 device for key storage

Currently supports
* Creating a root CA and generating its RSA key in the PKCS11 device
* Using the key in the PKCS11 device to sign certificates (or Intermediate CAs)
* Creating CRLs with the PKCS11 device key
* Store multiple keys in the PKCS11 device enabling a full PKI infrastructure
* 'Advanced' handling of fragile persistent PKCS11 sessions, including recreating the session if PKCS11 operation timeout

This package is pretty much a wrapper around python-pkcs11 and asn1crypto


## Setup

```bash
# Install libs and add your user to the softhsm group

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
echo "logout and login again now"

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

# Initialize the token
softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN

```

## Usage

Look at the [documentation](https://github.com/SUNET/python_x509_pkcs11/blob/main/docs/README.md) for quick examples to begin.

The [tests](https://github.com/SUNET/python_x509_pkcs11/tree/main/tests) are also a good starting point

Here is the basic, create a root CA and then use its key in the PKCS11 device to sign a csr:

```bash
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

```python
from python_x509_pkcs11 import csr
from python_x509_pkcs11.root_ca import create
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

roo_ca_name_dict = {"country_name": "SE",
             "state_or_province_name": "Stockholm",
             "locality_name": "Stockholm",
             "organization_name": "SUNET",
             "organizational_unit_name": "SUNET Infrastructure",
             "common_name": "ca-test.sunet.se",
             "email_address": "soc@sunet.se"}

root_cert_pem = create("my_rsa_key", root_ca_name_dict)
print("root CA")
print(root_cert_pem)

cert_pem = csr.sign_csr("my_rsa_key", root_ca_name_dict, csr_pem)
print("Cert signed by root CA")
print(cert_pem)
```

## Contributing / Tests
```bash

# Make your code changes
# Then in the root folder, where this README is
bash dev-run.sh
```
