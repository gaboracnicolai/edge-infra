.PHONY: dev worker test lint fmt install

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
	pip install -e "osb/[dev]"
