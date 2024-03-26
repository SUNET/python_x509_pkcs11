Installation & setup
======================


You can install the module form PyPI (or from git by the standard commands).

.. code-block:: bash

    python -m pip install python_x509_pkcs11


Setup of OS packages and environment variables
-----------------------------------------------

We will need the module for the HSM device and the secret PIN code and the
`Token Name` in the HSM device. For the development we will use `softhsm
<https://www.opendnssec.org/softhsm/>`_ to emulate a physical device.

The following script will help you to install the packages and setup the environment.

.. code-block:: bash

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

At this moment your system is ready for using the module.



