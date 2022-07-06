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

```
# Install this package
pip install python_x509_pkcs11

# Install deps and add your user to the softhsm group
sudo apt-get install opensc softhsm2
sudo usermod -a -G softhsm $USER
sudo reboot # Yeah seem to not update your groups without a reboot

# export env values the code will use
export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_PIN="1234"
export PKCS11_TOKEN="my_test_token_1"

# Initialize the token
softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN

```

## Usage

Look at the [documentation]("https://github.com/SUNET/python_x509_pkcs11/blob/main/docs/README.md")

The [tests]("https://github.com/SUNET/python_x509_pkcs11/blob/main/README.md") are also a good starting point
If you are using the code in tests then dont forget to change

```python
from src.python_x509_pkcs11 import csr
# to
from python_x509_pkcs11 import csr
```


## Tests
```
# Install the package
pip install python_x509_pkcs11

# Export env vars
export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_TOKEN='my_test_token_1'
export PKCS11_PIN='1234'

# Delete and init a token
softhsm2-util --delete-token --token my_test_token_1
softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN

# Run unittest with mypy, pylint and pycodestyle
mypy --strict --namespace-packages --ignore-missing-imports tests/*.py \
&& pylint tests/*.py \
&& pycodestyle tests/*.py \
&& python3 -m unittest
```
