"""Global trace state — one loaded trace at a time."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd


@dataclass
class TraceData:
    """Cached data from a loaded ETL trace."""

    etl_path: Path
    export_dir: Path
    symbol_path: str | None = None

    # Parsed DataFrames keyed by profile name
    raw_csv: dict[str, pd.DataFrame] = field(default_factory=dict)

    # Cached per-CPU sampling data (from xperf -a dumper, parsed once on first per-CPU query)
    dumper_df: pd.DataFrame | None = None

    # Metadata
    duration_seconds: float | None = None
    cpu_count: int | None = None
    event_counts: dict[str, int] = field(default_factory=dict)
    export_errors: list[str] = field(default_factory=list)

    @property
    def cpu_sampling(self) -> pd.DataFrame | None:
        return self.raw_csv.get("cpu_sampling")

    @property
    def dpc_isr(self) -> pd.DataFrame | None:
        return self.raw_csv.get("dpc_isr")

    @property
    def cswitch(self) -> pd.DataFrame | None:
        return self.raw_csv.get("cswitch")


# Global singleton — replaced on each load_trace call
_current_trace: TraceData | None = None


def get_trace() -> TraceData | None:
    return _current_trace


def set_trace(trace: TraceData) -> None:
    global _current_trace
    _current_trace = trace


def require_trace() -> TraceData:
    """Get loaded trace or raise a helpful error."""
    t = get_trace()
    if t is None:
        raise ValueError(
            "No trace loaded. Call load_trace first with a path to an .etl file."
        )
    return t
