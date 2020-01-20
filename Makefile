VIRTUALENV = virtualenv --python python3
VENV := $(shell echo $${VIRTUAL_ENV-.venv})
PYTHON = $(VENV)/bin/python
TOX = $(VENV)/bin/tox
TEMPDIR := $(shell mktemp -d)
DEV_STAMP = $(VENV)/.dev_env_installed.stamp
INSTALL_STAMP = $(VENV)/.install.stamp

all: install

build-requirements:
	$(VIRTUALENV) $(TEMPDIR)
	$(TEMPDIR)/bin/pip install -U pip
	$(TEMPDIR)/bin/pip install -Ue .
	$(TEMPDIR)/bin/pip freeze | grep -v -- '^-e' > requirements.txt

virtualenv: $(PYTHON)
$(PYTHON):
	virtualenv $(VENV)

install: $(INSTALL_STAMP)
$(INSTALL_STAMP): $(PYTHON) setup.py
	$(VENV)/bin/pip install -U pip
	$(VENV)/bin/pip install -Ue .
	touch $(INSTALL_STAMP)

install-dev: $(INSTALL_STAMP) $(DEV_STAMP)
$(DEV_STAMP): $(PYTHON) dev-requirements.txt
	$(VENV)/bin/pip install -Ur dev-requirements.txt
	touch $(DEV_STAMP)

tox: $(TOX)
$(TOX): virtualenv
	$(VENV)/bin/pip install tox

tests: tox
	$(VENV)/bin/tox

tests-once: install-dev
	$(VENV)/bin/pytest -s --cov-report term-missing --cov-branch --cov-fail-under 100 --cov kinto_nexmo_verify kinto_nexmo_verify

black: install-dev
	$(VENV)/bin/black kinto_nexmo_verify

isort: install-dev
	$(VENV)/bin/isort -y -m3 --line-width=99 --use-parentheses --trailing-comma --recursive --virtual-env=.venv
