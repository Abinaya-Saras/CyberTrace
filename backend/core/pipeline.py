"""
CyberTrace ingestion pipeline orchestrator.

Coordinates: file detection → parser selection → Parquet writing → stats.
Measures processing time, peak RAM, and throughput.
"""

import json
import os
import time
from dataclasses import dataclass, field

import psutil

from backend.parsers.ndjson_parser import NDJSONParser
from backend.parsers.fortigate_parser import FortiGateParser
from backend.parsers.writer import ParquetWriter
from backend.core.schema import NORMALIZED_SCHEMA


# ---------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------

def detect_format(filepath: str) -> str:
    """
    Detect log format by inspecting the first non-empty line.

    Returns: "ndjson" | "fortigate" | "unknown"
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            # NDJSON starts with {
            if stripped.startswith("{"):
                return "ndjson"
            # FortiGate starts with key=value (commonly date=)
            if "=" in stripped and not stripped.startswith("{"):
                return "fortigate"
            return "unknown"
    return "unknown"


# ---------------------------------------------------------------
# Stats tracking
# ---------------------------------------------------------------

@dataclass
class PipelineStats:
    """Tracks ingestion pipeline metrics."""
    input_file: str = ""
    file_size_bytes: int = 0
    detected_format: str = ""
    input_records: int = 0
    parsed_ok: int = 0
    malformed: int = 0
    empty_lines: int = 0
    parquet_rows_written: int = 0
    output_file: str = ""
    output_size_bytes: int = 0
    processing_time_sec: float = 0.0
    peak_ram_mb: float = 0.0
    throughput_records_per_sec: float = 0.0
    throughput_mb_per_sec: float = 0.0
    malformed_records: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "input_file": self.input_file,
            "file_size_bytes": self.file_size_bytes,
            "file_size_mb": round(self.file_size_bytes / 1_048_576, 2),
            "detected_format": self.detected_format,
            "input_records": self.input_records,
            "parsed_ok": self.parsed_ok,
            "malformed": self.malformed,
            "empty_lines": self.empty_lines,
            "parquet_rows_written": self.parquet_rows_written,
            "output_file": self.output_file,
            "output_size_bytes": self.output_size_bytes,
            "output_size_mb": round(self.output_size_bytes / 1_048_576, 2),
            "processing_time_sec": round(self.processing_time_sec, 3),
            "peak_ram_mb": round(self.peak_ram_mb, 1),
            "throughput_records_per_sec": round(self.throughput_records_per_sec, 1),
            "throughput_mb_per_sec": round(self.throughput_mb_per_sec, 2),
            "malformed_count": len(self.malformed_records),
        }

    def print_report(self) -> None:
        d = self.to_dict()
        print("\n" + "=" * 60)
        print("  CyberTrace Ingestion Report")
        print("=" * 60)
        for k, v in d.items():
            label = k.replace("_", " ").title()
            print(f"  {label:.<40} {v}")
        print("=" * 60)


# ---------------------------------------------------------------
# RAM tracker
# ---------------------------------------------------------------

class RAMTracker:
    """Track peak RSS of the current process."""

    def __init__(self):
        self._proc = psutil.Process()
        self._peak_bytes = self._proc.memory_info().rss

    def update(self) -> None:
        rss = self._proc.memory_info().rss
        if rss > self._peak_bytes:
            self._peak_bytes = rss

    @property
    def peak_mb(self) -> float:
        return self._peak_bytes / 1_048_576


# ---------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------

def ingest_file(
    input_path: str,
    output_dir: str = "data/processed",
    flush_size: int = 10_000,
    format_hint: str | None = None,
) -> PipelineStats:
    """
    Ingest a single log file: detect format, parse, write Parquet.

    Args:
        input_path:  Path to raw log file.
        output_dir:  Directory for Parquet output.
        flush_size:  Rows per Parquet row-group.
        format_hint: "ndjson" | "fortigate" | None (auto-detect).

    Returns:
        PipelineStats with all metrics.
    """
    stats = PipelineStats()
    stats.input_file = os.path.basename(input_path)
    stats.file_size_bytes = os.path.getsize(input_path)

    # Detect format
    fmt = format_hint or detect_format(input_path)
    stats.detected_format = fmt

    if fmt == "ndjson":
        parser = NDJSONParser()
    elif fmt == "fortigate":
        parser = FortiGateParser()
    else:
        raise ValueError(f"Unknown log format for {input_path}: {fmt}")

    # Output path
    os.makedirs(output_dir, exist_ok=True)
    base = os.path.splitext(stats.input_file)[0]
    output_path = os.path.join(output_dir, f"{base}.parquet")
    stats.output_file = output_path

    # Track resources
    ram = RAMTracker()
    t0 = time.monotonic()

    # Parse and write
    with ParquetWriter(output_path, flush_size=flush_size) as writer:
        for row in parser.parse(input_path):
            writer.add_row(row)
            # Sample RAM every 5000 rows
            if writer.total_written % 5000 == 0:
                ram.update()

        stats.parquet_rows_written = writer.total_written

    t1 = time.monotonic()
    ram.update()

    # Collect stats
    stats.parsed_ok = parser.stats["parsed_ok"]
    stats.malformed = parser.stats["malformed"]
    stats.empty_lines = parser.stats["empty_lines"]
    stats.input_records = parser.stats["total_lines"]
    stats.processing_time_sec = t1 - t0
    stats.peak_ram_mb = ram.peak_mb
    stats.malformed_records = parser.malformed_records

    if os.path.exists(output_path):
        stats.output_size_bytes = os.path.getsize(output_path)

    if stats.processing_time_sec > 0:
        stats.throughput_records_per_sec = stats.parsed_ok / stats.processing_time_sec
        stats.throughput_mb_per_sec = (stats.file_size_bytes / 1_048_576) / stats.processing_time_sec

    return stats


def save_malformed(records: list[dict], output_path: str) -> None:
    """Save malformed records to a JSON file for review."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, default=str)
