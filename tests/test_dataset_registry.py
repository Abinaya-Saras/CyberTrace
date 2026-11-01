"""
Tests for DatasetRegistry and dataset persistence.
"""

import os
import tempfile
import pytest

from backend.core.dataset_registry import DatasetRegistry, compute_fast_sha256


def test_registry_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        reg_path = os.path.join(tmpdir, "test_registry.json")
        reg = DatasetRegistry(reg_path)

        assert reg.list_datasets() == []
        assert reg.get_active_dataset_id() is None
        assert reg.get_active_dataset() is None

        # Register a dataset
        dummy_raw = os.path.join(tmpdir, "test.log")
        with open(dummy_raw, "w") as f:
            f.write("test log data line 1\nline 2\n")

        ds = reg.register_dataset(
            dataset_id="ds_test_1",
            filename="test.log",
            raw_file_path=dummy_raw,
            detected_format="ndjson",
            parquet_file_path=None,
            status="ready",
        )
        assert ds["dataset_id"] == "ds_test_1"
        assert ds["filename"] == "test.log"

        # List
        all_ds = reg.list_datasets()
        assert len(all_ds) == 1
        assert all_ds[0]["dataset_id"] == "ds_test_1"

        # Set active
        assert reg.set_active_dataset("ds_test_1") is True
        assert reg.get_active_dataset_id() == "ds_test_1"
        assert reg.get_active_dataset()["filename"] == "test.log"

        # Verify disk persistence across new instance
        reg2 = DatasetRegistry(reg_path)
        assert reg2.get_active_dataset_id() == "ds_test_1"
        assert len(reg2.list_datasets()) == 1

        # Find reusable dataset
        reusable = reg2.find_reusable_dataset("test.log", ds["file_size_bytes"])
        # Should be None because parquet_file_path doesn't exist yet
        assert reusable is None

        # Add parquet path and verify reusable match
        dummy_parquet = os.path.join(tmpdir, "test.parquet")
        with open(dummy_parquet, "wb") as f:
            f.write(b"PAR1dummycontent")

        reg2.update_dataset("ds_test_1", parquet_file_path=dummy_parquet)
        reusable2 = reg2.find_reusable_dataset("test.log", ds["file_size_bytes"])
        assert reusable2 is not None
        assert reusable2["dataset_id"] == "ds_test_1"

        # Delete
        assert reg2.delete_dataset("ds_test_1", delete_files=False) is True
        assert reg2.get_active_dataset_id() is None
        assert len(reg2.list_datasets()) == 0
