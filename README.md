![workflow debian](https://github.com/SUNET/python_x509_pkcs11/actions/workflows/debian.yaml/badge.svg)

## python_x509_pkcs11

Seamless async signing x509 using PKCS11 device for key storage

Currently supports
* Creating root CAs and generating their keys in the PKCS11 device.
* Using the keys in the PKCS11 device to sign certificates or Intermediate CAs.
* Creating certificates, CSRs, CRLs, OCSPs  with the PKCS11 device keys enabling a full PKI infrastructure.
* 'Advanced' handling of fragile persistent PKCS11 sessions, including recreating the session if PKCS11 operation timeout.
* This package is heavily uses python-pkcs11 and asn1crypto.
* Package is async but python-pkcs11 is unfortunately still sync, probably due to the fragile nature of PKCS11.
* Tested with SoftHSM and LUNAHSM.
* Provides privatekey implementations which can be used with `cryptography`.

You can read full [API documentation](https://python-x509-pkcs11.readthedocs.io/).


## Setup

```bash
# Install libs and add your user to the softhsm group
# You should probably replace softhsm when using this in production, any PKCS11 device should work

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

# Initialize the token
softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN

```

