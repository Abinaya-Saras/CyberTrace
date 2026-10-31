"""
DuckDB connection and query manager for CyberTrace.

Configures DuckDB conservatively for low-RAM machines:
  - Explicit memory limit (default 1 GB)
  - Limited threads (default 2)
  - Disk-based temp storage
  - Direct Parquet querying (no full materialisation)
"""

import os
import duckdb


class DuckDBEngine:
    """
    Manages a DuckDB in-memory connection with conservative resource limits.

    Usage:
        engine = DuckDBEngine()
        result = engine.query("SELECT count(*) FROM 'data/processed/*.parquet'")
        engine.close()
    """

    def __init__(
        self,
        memory_limit: str = "1GB",
        threads: int = 2,
        temp_directory: str | None = None,
    ):
        self.memory_limit = memory_limit
        self.threads = threads

        # Default temp directory next to processed data
        if temp_directory is None:
            temp_directory = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "data", "tmp_duckdb",
            )
        os.makedirs(temp_directory, exist_ok=True)
        self.temp_directory = temp_directory

        # Create connection with conservative settings
        self.conn = duckdb.connect(":memory:")
        self.conn.execute(f"SET memory_limit = '{memory_limit}'")
        self.conn.execute(f"SET threads = {threads}")
        self.conn.execute(f"SET temp_directory = '{temp_directory}'")
        # Enable progress bar for long queries
        self.conn.execute("SET enable_progress_bar = true")

    def query(self, sql: str, params: list | None = None) -> list[tuple]:
        """Execute SQL and return all rows.  Use only for small result sets."""
        if params:
            return self.conn.execute(sql, params).fetchall()
        return self.conn.execute(sql).fetchall()

    def query_df(self, sql: str, params: list | None = None):
        """Execute SQL and return a PyArrow Table (not Pandas)."""
        if params:
            return self.conn.execute(sql, params).fetch_arrow_table()
        return self.conn.execute(sql).fetch_arrow_table()

    def query_one(self, sql: str, params: list | None = None):
        """Execute SQL and return the first row, or None."""
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: list | None = None) -> None:
        """Execute SQL without returning results."""
        if params:
            self.conn.execute(sql, params)
        else:
            self.conn.execute(sql)

    def create_parquet_view(self, view_name: str, parquet_glob: str) -> None:
        """Create a view over Parquet files for zero-copy querying."""
        self.conn.execute(
            f"CREATE OR REPLACE VIEW {view_name} AS "
            f"SELECT * FROM read_parquet('{parquet_glob}')"
        )

    def table_info(self, parquet_glob: str) -> dict:
        """Return basic stats about a Parquet dataset."""
        row = self.query_one(
            f"SELECT count(*) as cnt, "
            f"min(timestamp) as ts_min, "
            f"max(timestamp) as ts_max "
            f"FROM read_parquet('{parquet_glob}')"
        )
        if row:
            return {
                "row_count": row[0],
                "timestamp_min": row[1],
                "timestamp_max": row[2],
            }
        return {"row_count": 0, "timestamp_min": None, "timestamp_max": None}

    def close(self) -> None:
        """Close the DuckDB connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
