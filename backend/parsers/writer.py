"""
Incremental Parquet writer using PyArrow.

Accumulates rows in a buffer and flushes to Parquet row-groups
when the buffer reaches a configurable size.  Uses ZSTD compression.
Never holds more than `flush_size` rows in memory at once.
"""

import os
import pyarrow as pa
import pyarrow.parquet as pq

from backend.core.schema import NORMALIZED_SCHEMA


class ParquetWriter:
    """
    Streaming Parquet writer.

    Usage:
        writer = ParquetWriter("output.parquet")
        for row_dict in parser:
            writer.add_row(row_dict)
        writer.close()   # flush remaining rows
    """

    def __init__(
        self,
        output_path: str,
        schema: pa.Schema = NORMALIZED_SCHEMA,
        flush_size: int = 10_000,
        compression: str = "zstd",
    ):
        self.output_path = output_path
        self.schema = schema
        self.flush_size = flush_size
        self.compression = compression

        # Column-oriented buffers: dict of column_name -> list
        self._buffers: dict[str, list] = {f.name: [] for f in schema}
        self._buffered_rows = 0
        self._total_written = 0

        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        # Create the writer lazily on first flush to avoid empty files
        self._writer: pq.ParquetWriter | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_row(self, row: dict) -> None:
        """Append one normalized row (dict with schema keys)."""
        for col_name in self._buffers:
            self._buffers[col_name].append(row.get(col_name))
        self._buffered_rows += 1

        if self._buffered_rows >= self.flush_size:
            self._flush()

    def add_rows(self, rows: list[dict]) -> None:
        """Append a batch of rows."""
        for row in rows:
            self.add_row(row)

    @property
    def total_written(self) -> int:
        """Total rows written to Parquet (including current buffer)."""
        return self._total_written + self._buffered_rows

    def close(self) -> int:
        """Flush remaining rows and close the file.  Returns total rows written."""
        if self._buffered_rows > 0:
            self._flush()
        if self._writer is not None:
            self._writer.close()
            self._writer = None
        return self._total_written

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _flush(self) -> None:
        """Convert buffered columns to a RecordBatch and write a row-group."""
        if self._buffered_rows == 0:
            return

        arrays = []
        for field in self.schema:
            col_data = self._buffers[field.name]
            arrays.append(pa.array(col_data, type=field.type))

        batch = pa.RecordBatch.from_arrays(arrays, schema=self.schema)

        if self._writer is None:
            self._writer = pq.ParquetWriter(
                self.output_path,
                self.schema,
                compression=self.compression,
                version="2.6",
                write_statistics=True,
            )

        self._writer.write_batch(batch)
        self._total_written += self._buffered_rows

        # Reset buffers
        for col_name in self._buffers:
            self._buffers[col_name] = []
        self._buffered_rows = 0

    # Context-manager support
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
