.PHONY: install init seed run test clean
install:
	python3 -m venv .venv
	.venv/bin/python -m pip install -r requirements.txt
init:
	.venv/bin/python scripts/init_db.py
seed:
	.venv/bin/python scripts/seed_demo.py
run:
	.venv/bin/python run.py
test:
	.venv/bin/python -m pytest
clean:
	rm -rf .pytest_cache __pycache__ app/**/__pycache__ tests/**/__pycache__ cloudsentinel.db
