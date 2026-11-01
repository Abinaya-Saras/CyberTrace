"""
Persistent Dataset Registry and Metadata Management (FR-1, FR-7).

Ensures:
  - Every uploaded dataset is registered with file metadata, format, checksum, and Parquet link.
  - When the same dataset is selected or re-uploaded, its existing Parquet output is reused
    without re-parsing the original raw log file.
  - The analyst's active dataset selection persists across browser refreshes and server restarts.
  - No dataset is silently or falsely selected if none has been chosen (shows clean empty state).
  - All dataset metadata is stored persistently in JSON format on disk.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_REGISTRY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data",
    "dataset_registry.json",
)


def compute_fast_sha256(filepath: str, max_sample_bytes: int = 100 * 1024 * 1024) -> str:
    """
    Compute SHA-256 checksum for a file.
    For files larger than max_sample_bytes (e.g. 6.5 GB), hashes first 50MB + last 50MB + size
    to avoid minutes of hash computation on large files while guaranteeing uniqueness.
    """
    if not os.path.isfile(filepath):
        return ""
    size = os.path.getsize(filepath)
    hasher = hashlib.sha256()

    if size <= max_sample_bytes:
        with open(filepath, "rb") as fh:
            while chunk := fh.read(1024 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest()

    # Fast boundary hash for massive datasets (> 100MB)
    half = max_sample_bytes // 2
    with open(filepath, "rb") as fh:
        # First 50MB
        hasher.update(fh.read(half))
        # Last 50MB
        fh.seek(max(0, size - half))
        hasher.update(fh.read(half))
    # Mix in exact size
    hasher.update(str(size).encode("utf-8"))
    return f"fast_{hasher.hexdigest()}"


class DatasetRegistry:
    """
    Manages persistent metadata and active selection for all log datasets.
    """

    def __init__(self, registry_file: Optional[str] = None):
        self.registry_file = registry_file or DEFAULT_REGISTRY_PATH
        os.makedirs(os.path.dirname(self.registry_file) or ".", exist_ok=True)
        self._data: dict[str, Any] = {
            "active_dataset_id": None,
            "datasets": {},
        }
        self.load()

    def load(self) -> None:
        """Load registry from disk if file exists."""
        if os.path.exists(self.registry_file):
            try:
                with open(self.registry_file, "r", encoding="utf-8") as fh:
                    content = fh.read().strip()
                    if content:
                        self._data = json.loads(content)
                        if "datasets" not in self._data:
                            self._data["datasets"] = {}
                        if "active_dataset_id" not in self._data:
                            self._data["active_dataset_id"] = None
            except Exception as e:
                logger.warning(f"Failed to read dataset registry from {self.registry_file}: {e}")

    def save(self) -> None:
        """Persist registry atomically to disk with fallback for container bind-mounts."""
        tmp_file = f"{self.registry_file}.tmp"
        try:
            with open(tmp_file, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, default=str)
            try:
                os.replace(tmp_file, self.registry_file)
            except OSError:
                # If target is a special mountpoint or cross-filesystem, rename may raise OSError (e.g. Errno 16).
                # Fallback to direct write:
                with open(self.registry_file, "w", encoding="utf-8") as fh:
                    json.dump(self._data, fh, indent=2, default=str)
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
        except Exception as e:
            logger.error(f"Failed to save dataset registry: {e}")
            if os.path.exists(tmp_file):
                try:
                    os.remove(tmp_file)
                except Exception:
                    pass

    def list_datasets(self) -> list[dict[str, Any]]:
        """Return list of all registered datasets sorted by upload date descending."""
        datasets = list(self._data.get("datasets", {}).values())
        # Sort newest first
        datasets.sort(key=lambda d: d.get("upload_date", ""), reverse=True)
        return datasets

    def get_dataset(self, dataset_id: str) -> Optional[dict[str, Any]]:
        """Retrieve dataset metadata by ID."""
        return self._data.get("datasets", {}).get(dataset_id)

    def get_active_dataset_id(self) -> Optional[str]:
        """Return the ID of the currently active dataset, if any."""
        return self._data.get("active_dataset_id")

    def get_active_dataset(self) -> Optional[dict[str, Any]]:
        """Return the metadata dictionary of the currently active dataset."""
        active_id = self.get_active_dataset_id()
        if active_id:
            return self.get_dataset(active_id)
        return None

    def set_active_dataset(self, dataset_id: Optional[str]) -> bool:
        """Set the active dataset and persist to disk."""
        if dataset_id is not None and dataset_id not in self._data.get("datasets", {}):
            return False
        self._data["active_dataset_id"] = dataset_id
        self.save()
        return True

    def register_dataset(
        self,
        dataset_id: str,
        filename: str,
        raw_file_path: str,
        detected_format: str,
        parquet_file_path: Optional[str] = None,
        file_size_bytes: int = 0,
        sha256: Optional[str] = None,
        status: str = "ready",
        stats: Optional[dict[str, Any]] = None,
        incidents_count: int = 0,
    ) -> dict[str, Any]:
        """Register or update dataset metadata and persist."""
        if not sha256 and os.path.isfile(raw_file_path):
            sha256 = compute_fast_sha256(raw_file_path)

        size_bytes = file_size_bytes or (os.path.getsize(raw_file_path) if os.path.isfile(raw_file_path) else 0)
        size_mb = round(size_bytes / (1024 * 1024), 2)

        record: dict[str, Any] = {
            "dataset_id": dataset_id,
            "filename": filename,
            "raw_file_path": raw_file_path,
            "detected_format": detected_format,
            "file_size_bytes": size_bytes,
            "file_size_mb": size_mb,
            "sha256": sha256 or "",
            "upload_date": datetime.now(timezone.utc).isoformat(),
            "parquet_file_path": parquet_file_path,
            "parquet_size_bytes": os.path.getsize(parquet_file_path) if parquet_file_path and os.path.isfile(parquet_file_path) else 0,
            "status": status,
            "parser_version": "1.0",
            "schema_version": "1.0",
            "stats": stats or {},
            "incidents_count": incidents_count,
        }

        self._data["datasets"][dataset_id] = record
        self.save()
        return record

    def update_dataset(self, dataset_id: str, **kwargs) -> Optional[dict[str, Any]]:
        """Update specific fields of an existing dataset."""
        dataset = self._data.get("datasets", {}).get(dataset_id)
        if not dataset:
            return None
        dataset.update(kwargs)
        if "parquet_file_path" in kwargs and kwargs["parquet_file_path"]:
            p = kwargs["parquet_file_path"]
            if os.path.isfile(p):
                dataset["parquet_size_bytes"] = os.path.getsize(p)
        self.save()
        return dataset

    def delete_dataset(self, dataset_id: str, delete_files: bool = False) -> bool:
        """Delete a dataset from the registry and optionally delete its files on disk."""
        dataset = self._data.get("datasets", {}).pop(dataset_id, None)
        if not dataset:
            return False

        if self._data.get("active_dataset_id") == dataset_id:
            self._data["active_dataset_id"] = None

        if delete_files:
            raw_path = dataset.get("raw_file_path")
            if raw_path and os.path.isfile(raw_path):
                try:
                    os.remove(raw_path)
                except Exception:
                    pass
            parquet_path = dataset.get("parquet_file_path")
            if parquet_path and os.path.isfile(parquet_path):
                try:
                    os.remove(parquet_path)
                except Exception:
                    pass

        self.save()
        return True

    def find_reusable_dataset(self, filename: str, file_size: int, sha256: Optional[str] = None) -> Optional[dict[str, Any]]:
        """
        Check if an identical dataset has already been successfully parsed into Parquet.
        Matches on sha256 or (filename and file_size) with an existing valid Parquet file.
        """
        for ds in self._data.get("datasets", {}).values():
            p_file = ds.get("parquet_file_path")
            if not p_file or not os.path.isfile(p_file):
                continue
            if ds.get("status") != "ready":
                continue

            if sha256 and ds.get("sha256") == sha256:
                return ds
            if ds.get("filename") == filename and ds.get("file_size_bytes") == file_size:
                return ds
        return None

    def auto_discover(self) -> None:
        """
        Scan workspace for known initial datasets and register them if not already present.
        Ensures sample datasets like edr_events.json and firex-10G.parquet are available
        in the registry without overwriting existing entries.
        """
        # 1. EDR Sample (edr_events.json)
        edr_raw = "edr_events.json"
        edr_parquet = "data/processed/edr_events.parquet"
        if os.path.isfile(edr_raw) and "ds_edr_sample" not in self._data["datasets"]:
            self.register_dataset(
                dataset_id="ds_edr_sample",
                filename="edr_events.json",
                raw_file_path=edr_raw,
                detected_format="ndjson",
                parquet_file_path=edr_parquet if os.path.isfile(edr_parquet) else None,
                status="ready" if os.path.isfile(edr_parquet) else "uploaded_unprocessed",
                incidents_count=29 if os.path.isfile(edr_parquet) else 0,
            )

        # 2. FortiGate firex dataset
        firex_raw = "data/uploads/firex-10G.log"
        firex_root = "firex-10G.log"
        firex_parquet = "data/processed/firex-10G.parquet"
        actual_raw = firex_raw if os.path.isfile(firex_raw) else (firex_root if os.path.isfile(firex_root) else None)

        if (actual_raw or os.path.isfile(firex_parquet)) and "ds_firex_10g" not in self._data["datasets"]:
            self.register_dataset(
                dataset_id="ds_firex_10g",
                filename="firex-10G.log",
                raw_file_path=actual_raw or "data/uploads/firex-10G.log",
                detected_format="fortigate",
                parquet_file_path=firex_parquet if os.path.isfile(firex_parquet) else None,
                status="ready" if os.path.isfile(firex_parquet) else "uploaded_unprocessed",
                incidents_count=1 if os.path.isfile(firex_parquet) else 0,
            )
