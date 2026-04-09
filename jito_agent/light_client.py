"""Local light-client runtime: queue, cache, and background sync for Nova."""

import json
import os
import threading
import time
from typing import Any, Dict, Optional

from .queue import PersistentEventQueue


class NovaLightClientNode:
    """Light client with a persistent local queue and cached remote snapshots."""

    def __init__(
        self,
        tracker: Any,
        queue_path: str = ".nova_runtime_queue.json",
        cache_path: str = ".nova_light_cache.json",
        flush_interval_s: float = 5.0,
    ) -> None:
        self.tracker = tracker
        self.queue = PersistentEventQueue(queue_path)
        self.cache_path = os.path.abspath(cache_path)
        self.flush_interval_s = max(0.25, float(flush_interval_s))
        self._cache_lock = threading.RLock()
        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._cache = self._load_cache()

    def _load_cache(self) -> Dict[str, Any]:
        if not os.path.exists(self.cache_path):
            return {"version": 1, "snapshots": {}}
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                return {"version": 1, "snapshots": dict(raw.get("snapshots", {}))}
        except Exception:
            pass
        return {"version": 1, "snapshots": {}}

    def _save_cache(self) -> None:
        parent = os.path.dirname(self.cache_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = f"{self.cache_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._cache, f, indent=2, sort_keys=True)
        os.replace(tmp, self.cache_path)

    def enqueue_log(self, payload: Dict[str, Any]) -> str:
        return self.queue.enqueue(payload, kind="activity_log")

    def _submit_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.tracker.client.log_activity(
            wallet=self.tracker.wallet,
            agent_id=self.tracker.agent_id,
            action_type=payload.get("action_type", "activity"),
            input_hash=payload.get("input_hash", ""),
            output_hash=payload.get("output_hash", ""),
            evidence_hash=payload.get("evidence_hash", ""),
            evidence_url=payload.get("evidence_url", ""),
            success=bool(payload.get("success", True)),
            duration_ms=int(payload.get("duration_ms", 0)),
            tags=list(payload.get("tags", [])),
            platform=payload.get("platform", "") or self.tracker.platform,
            external_ref=payload.get("external_ref", ""),
            note=payload.get("note", ""),
            stake_locked=float(payload.get("stake_locked", 0.0)),
        )

    def flush(self, limit: int = 50) -> Dict[str, int]:
        delivered = 0
        failed = 0
        for item in self.queue.pending(limit=limit):
            try:
                result = self._submit_payload(dict(item.get("payload", {})))
                self.queue.mark_delivered(str(item.get("id", "")), result=result if isinstance(result, dict) else {})
                delivered += 1
            except Exception as exc:
                self.queue.fail_pending(str(item.get("id", "")), str(exc), terminal=False)
                failed += 1
        self.queue.prune_delivered()
        return {"delivered": delivered, "failed": failed, **self.queue.stats()}

    def start(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._stop_event.clear()
        self._worker = threading.Thread(target=self._run, name="nova-light-client", daemon=True)
        self._worker.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=self.flush_interval_s * 2)
        self._worker = None

    def _run(self) -> None:
        while not self._stop_event.wait(self.flush_interval_s):
            try:
                self.flush()
            except Exception:
                pass

    def cache_snapshot(self, kind: str, key: str, data: Dict[str, Any]) -> None:
        with self._cache_lock:
            self._cache["snapshots"][f"{kind}:{key}"] = {
                "updated_at": time.time(),
                "data": data,
            }
            self._save_cache()

    def cached_snapshot(self, kind: str, key: str) -> Optional[Dict[str, Any]]:
        with self._cache_lock:
            row = self._cache["snapshots"].get(f"{kind}:{key}")
            if not isinstance(row, dict):
                return None
            data = row.get("data")
            return dict(data) if isinstance(data, dict) else None

    def sync_passport(self, address: str = "") -> Dict[str, Any]:
        target = address or self.tracker.wallet["address"]
        data = self.tracker.client.passport(target)
        self.cache_snapshot("passport", target, data)
        return data

    def sync_capability_profile(self, address: str = "") -> Dict[str, Any]:
        target = address or self.tracker.wallet["address"]
        data = self.tracker.client.capability_profile(target)
        if hasattr(data, "by_action_type"):
            serializable = {
                "address": getattr(data, "address", target),
                "by_action_type": {
                    key: {
                        "total_logs": value.total_logs,
                        "evidenced_logs": value.evidenced_logs,
                        "attested_logs": value.attested_logs,
                        "success_rate": value.success_rate,
                        "evidence_rate": value.evidence_rate,
                        "last_active": value.last_active,
                    }
                    for key, value in data.by_action_type.items()
                },
                "by_tag": {
                    key: {
                        "total_logs": value.total_logs,
                        "evidenced_logs": value.evidenced_logs,
                        "attested_logs": value.attested_logs,
                        "success_rate": value.success_rate,
                        "evidence_rate": value.evidence_rate,
                        "last_active": value.last_active,
                    }
                    for key, value in data.by_tag.items()
                },
                "collab_partners": list(data.collab_partners),
            }
        else:
            serializable = dict(data)
        self.cache_snapshot("capability_profile", target, serializable)
        return serializable

    def status(self) -> Dict[str, Any]:
        return {
            "queue": self.queue.stats(),
            "worker_running": bool(self._worker and self._worker.is_alive()),
            "flush_interval_s": self.flush_interval_s,
            "cache_entries": len(self._cache.get("snapshots", {})),
        }
