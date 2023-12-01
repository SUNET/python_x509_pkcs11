.PHONY: docker-build-pdfsign docker-build-ca docker-push ci vscode_venv vscode_pip vscode_packages vscode

PYTHON=$(shell which python)
PIPCOMPILE=pip-compile -v --upgrade --generate-hashes --allow-unsafe --index-url https://pypi.sunet.se/simple
PIPSYNC=pip-sync --index-url https://pypi.sunet.se/simple --python-executable $(PYTHON)

sync_deps:
	$(PIPSYNC) requirements.txt

update_deps:
	$(PIPCOMPILE) requirements.in

ifndef VERSION
VERSION := latest                                                                                                                                                                                                                              
endif

DOCKER_TAG_CA 			:= 	docker.sunet.se/dc4eu/pkcs11_ca:$(VERSION)
DOCKER_TAG_CA-SOFTHSM2 	:= 	docker.sunet.se/dc4eu/ca-softhsm2:$(VERSION)
DOCKER_TAG_TEST 		:= docker.sunet.se/dc4eu/pkcs11_test:$(VERSION)

docker-build-ca:
	$(info building docker image $(DOCKER_TAG_CA) )
	docker build --tag $(DOCKER_TAG_CA) --file containers/ca/Dockerfile .

docker-build-ca-softhsm2:
	$(info building docker image $(DOCKER_TAG_CA-SOFTHSM2) )
	docker build --tag $(DOCKER_TAG_CA-SOFTHSM2) --file containers/ca-softhsm2 .

docker-build-test:
	$(info building docker image $(DOCKER_TAG_TEST) )
	docker build --tag $(DOCKER_TAG_TEST) --file dockerfiles/test .

docker-build: docker-build-ca

docker-push:
	$(info Pushing docker images)
	docker push $(DOCKER_TAG_CA)
	docker push $(DOCKER_TAG_CA-SOFTHSM2)

start:
	$(info Run!)
	docker-compose -f docker-compose.yml up -d --remove-orphans

stop:
	$(info stopping VC)
	docker-compose -f docker-compose.yml rm -s -f

hard_restart: stop start

docker-unit-test: docker-build-test
	$(info Run unit tests)
	docker run --rm docker.sunet.se/dc4eu/pkcs11_test:latest

ci: docker-build docker-push

developer_setup: developer_create_pki import_pki_into_hsm

developer_create_pki:
	$(info Create developer keys)
	bash -c developer_tools/create_pki.sh

import_pki_into_hsm:
	$(info Import pki into HSM)
	python3 developer_tools/import_pki_into_hsm.py

vscode_venv:
	$(info Creating virtualenv in devcontainer)
	python3 -m venv .venv

vscode_pip: vscode_venv
	$(info Installing pip packages in devcontainer)
	pip3 install --upgrade pip
	pip3 install pip-tools
	.venv/bin/pip install -r requirements.txt
# .venv/bin/mypy --install-types

vscode_packages:
	$(info Installing apt packages in devcontainer)
	sudo apt-get update
	sudo apt install -y docker.io softhsm2

# This target is used by the devcontainer.json to configure the devcontainer
vscode: vscode_packages vscode_pip sync_deps
	sudo usermod -a -G softhsm vscode
	#. .venv/bin/activate