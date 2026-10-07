import json
import os
from datetime import datetime, timezone
from threading import Lock


class HistoryManager:
    def __init__(self, storage_path=None, max_entries=100):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        self.storage_path = storage_path or os.path.join(
            base_dir, "data", "analysis_history.json"
        )
        self.max_entries = max_entries
        self._lock = Lock()

        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)

        if not os.path.exists(self.storage_path):
            self._write_history([])

    def _read_history(self):
        try:
            with open(self.storage_path, "r", encoding="utf-8") as file:
                data = json.load(file)

            return data if isinstance(data, list) else []
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return []

    def _write_history(self, history):
        with open(self.storage_path, "w", encoding="utf-8") as file:
            json.dump(history, file, indent=2, ensure_ascii=False)

    def save_analysis(self, analysis):
        if not isinstance(analysis, dict):
            raise ValueError("Analysis must be a dictionary.")

        entry = {
            "analysis_id": datetime.now(timezone.utc).strftime(
                "%Y%m%d%H%M%S%f"
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "contract_address": analysis.get("contract_address"),
            "network": analysis.get("network", "Ethereum Mainnet"),
            "score": analysis.get("score"),
            "risk_level": analysis.get("risk_level"),
            "analysis_duration_seconds": (
                analysis.get("performance_metrics", {})
                .get("total_analysis_duration_seconds")
            ),
            "deployment_readiness": (
                analysis.get("deployment_readiness", {})
                .get("status")
            ),
            "summary_status": (
                analysis.get("security_summary", {})
                .get("summary")
            ),
        }

        with self._lock:
            history = self._read_history()
            history.insert(0, entry)
            history = history[:self.max_entries]
            self._write_history(history)

        return entry

    def get_history(self, limit=None):
        with self._lock:
            history = self._read_history()

        if limit is not None:
            try:
                limit = max(int(limit), 0)
                history = history[:limit]
            except (TypeError, ValueError):
                pass

        return history

    def get_contract_history(self, contract_address, limit=None):
        if not contract_address:
            return []

        with self._lock:
            history = [
                entry
                for entry in self._read_history()
                if entry.get("contract_address", "").lower()
                == contract_address.lower()
            ]

        if limit is not None:
            try:
                history = history[:max(int(limit), 0)]
            except (TypeError, ValueError):
                pass

        return history

    def clear_history(self):
        with self._lock:
            self._write_history([])

        return True

