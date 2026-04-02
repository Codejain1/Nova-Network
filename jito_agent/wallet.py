"""Wallet creation and management for NOVA."""
import json
import os
from typing import Dict

from .crypto import create_wallet as _create_wallet


def create_wallet(label: str = "") -> Dict:
    """
    Generate a new NOVA wallet.
    Returns dict with: address, public_key (JWK), private_key (JWK), label.
    Requires: pip install cryptography
    """
    return _create_wallet(label)


def load_wallet(path: str) -> Dict:
    """Load wallet from a JSON file."""
    with open(path) as f:
        return json.load(f)


def save_wallet(wallet: Dict, path: str) -> None:
    """Save wallet to a JSON file (mode 0o600)."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump(wallet, f, indent=2)
    os.chmod(path, 0o600)
    print(f"Wallet saved to {path}")
    print(f"Address: {wallet['address']}")
    print("Keep your private key safe — it cannot be recovered!")
