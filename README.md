## First commit

First commit


## Try pkcs11


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

# 
softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN

```

