.PHONY: test lint build up down

test:
	python -m pytest tests/ -x -q

lint:
	python -m py_compile node.py
	python -m py_compile dual_chain.py
	python -m py_compile evm_gateway.py
	python -m py_compile auth.py

build:
	docker build -t nova-network .

up:
	docker compose up -d

down:
	docker compose down
