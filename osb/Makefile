.PHONY: dev worker test lint fmt install lock audit

dev:
	cd osb && uvicorn main:app --reload --port 8080

worker:
	cd osb && python -m worker

test:
	cd osb && pytest tests/ -v --cov=. --cov-report=term-missing

lint:
	cd osb && ruff check . && ruff format --check .

fmt:
	cd osb && ruff format .

install:
	pip install --require-hashes -r osb/requirements-dev.lock
	pip install --no-deps -e osb/

# Re-resolve the locks, hash-pinned for CPython 3.12 on every platform:
# requirements.lock is what the image installs, requirements-dev.lock adds the
# test and lint tools CI installs, requirements-audit.lock is pip-audit itself
# (from requirements-audit.in). Needs uv.
lock:
	cd osb && uv pip compile pyproject.toml --universal --python-version 3.12 --generate-hashes \
	  --custom-compile-command "make -f osb/Makefile lock" -o requirements.lock
	cd osb && uv pip compile pyproject.toml --extra dev --universal --python-version 3.12 --generate-hashes \
	  --custom-compile-command "make -f osb/Makefile lock" -o requirements-dev.lock
	cd osb && uv pip compile requirements-audit.in --universal --python-version 3.12 --generate-hashes \
	  --custom-compile-command "make -f osb/Makefile lock" -o requirements-audit.lock

# Check both locks against the PyPI advisory data; exits non-zero on any known
# vulnerability. The same command the OSB Test pip-audit job runs. Needs
# `pip install --require-hashes -r osb/requirements-audit.lock`.
audit:
	cd osb && pip-audit --disable-pip --require-hashes --strict --progress-spinner off \
	  -r requirements.lock -r requirements-dev.lock
