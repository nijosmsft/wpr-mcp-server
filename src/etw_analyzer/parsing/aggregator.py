"""Aggregation utilities for ETW data analysis."""

from __future__ import annotations

import numpy as np
import pandas as pd


def parse_cpu_filter(cpu_filter: str | None) -> list[int] | None:
    """Parse a CPU filter string like '18-39' or '0,2,4' into a list of CPU numbers."""
    if not cpu_filter:
        return None

    cpus: list[int] = []
    for part in cpu_filter.split(","):
        part = part.strip()
        if "-" in part:
            low, high = part.split("-", 1)
            cpus.extend(range(int(low), int(high) + 1))
        else:
            cpus.append(int(part))
    return cpus


def apply_filters(
    df: pd.DataFrame,
    cpu_filter: str | None = None,
    cpu_col: str = "CPU",
    start_time: float | None = None,
    end_time: float | None = None,
    time_col: str = "TimeStamp",
    module_filter: str | None = None,
    module_col: str = "Module",
    process_filter: str | None = None,
    process_col: str = "Process Name",
    function_filter: str | None = None,
    function_col: str = "Function",
) -> pd.DataFrame:
    """Apply common filters to a DataFrame.

    All filters are optional — only applied if the column exists and the filter is set.
    """
    if df.empty:
        return df

    mask = pd.Series(True, index=df.index)

    # CPU filter
    if cpu_filter and cpu_col in df.columns:
        cpus = parse_cpu_filter(cpu_filter)
        if cpus:
            mask &= df[cpu_col].isin(cpus)

    # Time range filter
    if time_col in df.columns:
        if start_time is not None:
            mask &= df[time_col] >= start_time
        if end_time is not None:
            mask &= df[time_col] <= end_time

    # Module filter (case-insensitive substring)
    if module_filter and module_col in df.columns:
        mask &= df[module_col].astype(str).str.contains(
            module_filter, case=False, na=False
        )

    # Process filter (case-insensitive substring)
    if process_filter and process_col in df.columns:
        mask &= df[process_col].astype(str).str.contains(
            process_filter, case=False, na=False
        )

    # Function filter (case-insensitive substring)
    if function_filter and function_col in df.columns:
        mask &= df[function_col].astype(str).str.contains(
            function_filter, case=False, na=False
        )

    return df[mask]


def group_and_sum(
    df: pd.DataFrame,
    group_cols: list[str],
    sum_col: str = "Weight",
    sort_descending: bool = True,
) -> pd.DataFrame:
    """Group by columns, sum a weight column, compute percentages."""
    if df.empty or sum_col not in df.columns:
        return pd.DataFrame()

    existing_cols = [c for c in group_cols if c in df.columns]
    if not existing_cols:
        return pd.DataFrame()

    result = df.groupby(existing_cols, dropna=False)[sum_col].sum().reset_index()
    total = result[sum_col].sum()
    result["% Weight"] = (result[sum_col] / total * 100) if total > 0 else 0

    if sort_descending:
        result = result.sort_values(sum_col, ascending=False)

    return result.reset_index(drop=True)


def compute_percentiles(
    series: pd.Series,
    percentiles: list[float] | None = None,
) -> dict[str, float]:
    """Compute percentile statistics for a numeric series."""
    if series.empty:
        return {}

    percentiles = percentiles or [50, 95, 99, 99.9]
    s = series.dropna()
    if s.empty:
        return {}

    result = {
        "count": len(s),
        "min": float(s.min()),
        "max": float(s.max()),
        "mean": float(s.mean()),
    }
    for p in percentiles:
        label = f"p{p:g}"
        result[label] = float(np.percentile(s, p))

    return result


def time_bucket(
    df: pd.DataFrame,
    time_col: str = "TimeStamp",
    bucket_seconds: float = 1.0,
) -> pd.DataFrame:
    """Add a time bucket column for timeline aggregation."""
    if time_col not in df.columns:
        return df

    df = df.copy()
    df["TimeBucket"] = (df[time_col] / bucket_seconds).astype(int) * bucket_seconds
    return df
