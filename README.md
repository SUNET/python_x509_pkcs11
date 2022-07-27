## python_x509_pkcs11

Seamless async signing x509 using PKCS11 device for key storage

Currently supports
* Creating a root CA and generating its RSA key in the PKCS11 device
* Using the key in the PKCS11 device to sign certificates (or Intermediate CAs)
* Creating CRLs with the PKCS11 device key
* Store multiple keys in the PKCS11 device enabling a full PKI infrastructure
* 'Advanced' handling of fragile persistent PKCS11 sessions, including recreating the session if PKCS11 operation timeout
* This package is heavily uses python-pkcs11 and asn1crypto.
* Package is async but python-pkcs11 is unfortunately still sync, probably due to the fragile nature of PKCS11


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
    csr_pem, root_cert_pem = await create("my_rsa_key", root_ca_name_dict)

    print("CSR which was selfsigned into root CA")
    print(csr_pem)

    print("root CA")
    print(root_cert_pem)


asyncio.run(my_func())
```

## Contributing / Tests
```bash

# install
if awk -F= '/^NAME/{print $2}' /etc/os-release | grep -i "debian\|ubuntu"
then
    # Ubuntu / Debian
    sudo apt-get install flit python3-mypy black
else
    # Redhat / Centos / Fedora
    sudo dnf install python3-flit python3-mypy python3-black
fi


# Make your code changes
# Then in the root folder, where this README is
bash dev-run.sh

# Build the package with flit
flit build

```
