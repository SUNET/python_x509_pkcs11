.PHONY: test reformat typecheck clean_softhsm new_softhsm vscode_venv vscode_pip vscode_packages vscode

TOPDIR:=		$(abspath .)
SRCDIR=			$(TOPDIR)/src
SOURCE=			$(SRCDIR)/python_x509_pkcs11
TEST_SOURCE= 	$(TOPDIR)/tests
PYTHON=			$(shell which python)
PIPSYNC=pip-sync --index-url https://pypi.sunet.se/simple --python-executable $(PYTHON)
MYPY_ARGS=		--strict --namespace-packages --ignore-missing-imports --cache-dir=/dev/null

sync_deps:
	$(PIPSYNC) requirements.txt

test:
	PYTHONPATH=$(SRCDIR) pytest -vvv -ra --log-cli-level DEBUG

test_in_ci:
	PYTHONPATH=$(SRCDIR) sudo pytest -vvv -ra --log-cli-level DEBUG

reformat:
	isort --line-width 120 --atomic --project python_x509_pkcs11 $(SOURCE)
	black --line-length 120 --target-version py39 $(SOURCE)
	isort --line-width 120 --atomic --project python_x509_pkcs11 $(TEST_SOURCE)
	black --line-length 120 --target-version py39 $(TEST_SOURCE)

static_code_analyser:
	pylint src || exit 1
	pylint tests || exit 1

build:
	flit build  && pip3 install dist/python_x509_pkcs11*.whl

typecheck:
	MYPYPATH=$(SRCDIR) mypy $(MYPY_ARGS) --namespace-packages -p python_x509_pkcs11
	MYPYPATH=$(TEST_SOURCE) mypy $(MYPY_ARGS) --namespace-packages -p python_x509_pkcs11

upload_pypi: build
	python3 -m pip install --upgrade twine keyring
	python3 -m twine upload --repository pypi dist/* --verbose

clean_softhsm:
	$(info Deleting and reinitialize the PKCS11 token)
	softhsm2-util --delete-token --token  $(PKCS11_TOKEN)

new_softhsm:
	$(info New SoftHSM)
	softhsm2-util --init-token --slot 0 --label $(PKCS11_TOKEN) --pin $(PKCS11_PIN) --so-pin $(PKCS11_PIN)

new_softhsm_in_ci:
	$(info New SoftHSM)
	sudo softhsm2-util --init-token --slot 0 --label $(PKCS11_TOKEN) --pin $(PKCS11_PIN) --so-pin $(PKCS11_PIN)

vscode_venv:
	$(info Creating virtualenv in devcontainer)
	python3 -m venv .venv

vscode_pip: vscode_venv
	$(info Installing pip packages in devcontainer)
	pip3 install --upgrade pip
	pip3 install pip-tools
	.venv/bin/pip install -r requirements.txt

vscode_packages:
	$(info Installing apt packages in devcontainer)
	sudo apt-get update
	sudo apt install -y docker.io softhsm2
	#sudo usermod -a -G softhsm vscode


# This target is used by the devcontainer.json to configure the devcontainer
vscode: vscode_packages vscode_pip sync_deps