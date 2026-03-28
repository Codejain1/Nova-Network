#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
python -m pip install -q -r requirements.txt
python -m py_compile auth.py dual_chain.py node.py cli.py evm_gateway.py
python -m unittest -v tests/test_auth.py tests/test_blockchain.py tests/test_evm_gateway.py tests/test_node.py tests/test_agent_trust.py

echo "All tests passed."
