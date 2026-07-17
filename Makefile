.PHONY: install format lint typecheck test coverage run demo docker

install:
	python -m pip install -e ".[dev]"

format:
	python -m ruff format .
	python -m ruff check --fix .

lint:
	python -m ruff format --check .
	python -m ruff check .

typecheck:
	python -m mypy src

test:
	python -m pytest

coverage:
	python -m pytest --cov --cov-report=term-missing --cov-report=html

run:
	python -m uvicorn cti_trust_gateway.api.app:app --host 127.0.0.1 --port 8000

demo:
	cti-trust demo
	python scripts/run_synthetic_benchmark.py

docker:
	docker compose up --build
