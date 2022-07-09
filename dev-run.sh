#!/bin/bash

if awk -F= '/^NAME/{print $2}' /etc/os-release | grep -i "debian\|ubuntu"
then
    export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
else
    export PKCS11_MODULE="/usr/lib64/softhsm/libsofthsm.so"
fi
export PKCS11_TOKEN='my_test_token_1'
export PKCS11_PIN='1234'

# Recreating the PKCS11 device token
softhsm2-util --delete-token --token my_test_token_1
softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN | exit 1

echo "Checking package"
mypy  --python-version 3.7 --strict --namespace-packages --ignore-missing-imports --cache-dir=/dev/null src/python_x509_pkcs11/*.py || exit 1
black src/python_x509_pkcs11/*.py || exit 1

echo "Checking tests"
mypy --python-version 3.7 --strict --namespace-packages --ignore-missing-imports --cache-dir=/dev/null tests/*.py || exit 1
black tests/*.py || exit 1

echo "Running tests"
python3 -m unittest