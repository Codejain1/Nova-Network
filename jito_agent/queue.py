"""Persistent local queue for background Nova log delivery."""

import json
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional


class PersistentEventQueue:
    """Small JSON-backed queue for pending runtime submissions."""

    def __init__(self, path: str = ".nova_runtime_queue.json") -> None:
        self.path = os.path.abspath(path)
        self._lock = threading.RLock()
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        if not os.path.exists(self.path):
            return {"version": 1, "items": []}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if not isinstance(raw, dict):
                return {"version": 1, "items": []}
            items = raw.get("items", [])
            if not isinstance(items, list):
                items = []
            return {"version": 1, "items": items}
        except Exception:
            return {"version": 1, "items": []}

    def _save_state(self) -> None:
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def enqueue(self, payload: Dict[str, Any], kind: str = "activity_log") -> str:
        with self._lock:
            item_id = uuid.uuid4().hex
            self._state["items"].append({
                "id": item_id,
                "kind": kind,
                "state": "pending",
                "attempts": 0,
                "created_at": time.time(),
                "updated_at": time.time(),
                "last_error": "",
                "payload": payload,
            })
            self._save_state()
            return item_id

    def pending(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = [item for item in self._state["items"] if item.get("state") == "pending"]
            items.sort(key=lambda item: (float(item.get("created_at", 0.0)), str(item.get("id", ""))))
            if limit is not None:
                items = items[:limit]
            return [dict(item) for item in items]

    def mark_delivered(self, item_id: str, result: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            for item in self._state["items"]:
                if item.get("id") == item_id:
                    item["state"] = "delivered"
                    item["updated_at"] = time.time()
                    item["result"] = result or {}
                    break
            self._save_state()

    def mark_failed(self, item_id: str, error: str) -> None:
        with self._lock:
            for item in self._state["items"]:
                if item.get("id") == item_id:
                    item["attempts"] = int(item.get("attempts", 0)) + 1
                    item["updated_at"] = time.time()
                    item["last_error"] = str(error)[:512]
                    break
            self._save_state()

    def requeue_failed(self, max_attempts: int = 0) -> int:
        with self._lock:
            count = 0
            for item in self._state["items"]:
                attempts = int(item.get("attempts", 0))
                if item.get("state") == "failed" and (max_attempts <= 0 or attempts < max_attempts):
                    item["state"] = "pending"
                    item["updated_at"] = time.time()
                    count += 1
            if count:
                self._save_state()
            return count

    def fail_pending(self, item_id: str, error: str, terminal: bool = False) -> None:
        with self._lock:
            for item in self._state["items"]:
                if item.get("id") == item_id:
                    item["attempts"] = int(item.get("attempts", 0)) + 1
                    item["updated_at"] = time.time()
                    item["last_error"] = str(error)[:512]
                    item["state"] = "failed" if terminal else "pending"
                    break
            self._save_state()

    def stats(self) -> Dict[str, int]:
        with self._lock:
            out = {"pending": 0, "delivered": 0, "failed": 0, "total": 0}
            for item in self._state["items"]:
                state = str(item.get("state", "pending"))
                out["total"] += 1
                if state in out:
                    out[state] += 1
            return out

    def prune_delivered(self, keep_last: int = 200) -> int:
        with self._lock:
            delivered = [item for item in self._state["items"] if item.get("state") == "delivered"]
            delivered.sort(key=lambda item: float(item.get("updated_at", 0.0)), reverse=True)
            keep_ids = {item["id"] for item in delivered[: max(0, keep_last)]}
            before = len(self._state["items"])
            self._state["items"] = [
                item for item in self._state["items"]
                if item.get("state") != "delivered" or item.get("id") in keep_ids
            ]
            removed = before - len(self._state["items"])
            if removed:
                self._save_state()
            return removed
