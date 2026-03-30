"""Markdown table formatting for ETW analysis output."""

from __future__ import annotations

from typing import Any

import pandas as pd


def format_table(
    df: pd.DataFrame,
    columns: list[str] | None = None,
    max_rows: int = 50,
    number_format: dict[str, str] | None = None,
) -> str:
    """Format a DataFrame as a markdown table.

    Args:
        df: Data to format.
        columns: Subset of columns to include. None = all.
        max_rows: Truncate after this many rows.
        number_format: Column name → format string, e.g. {"Weight": ",d", "%": ".2f"}.
    """
    if df.empty:
        return "*No data*"

    if columns:
        df = df[[c for c in columns if c in df.columns]]

    truncated = len(df) > max_rows
    if truncated:
        df = df.head(max_rows)

    number_format = number_format or {}

    # Build header
    headers = list(df.columns)
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]

    # Build rows
    for _, row in df.iterrows():
        cells = []
        for col in headers:
            val = row[col]
            if col in number_format and pd.notna(val):
                try:
                    cells.append(format(val, number_format[col]))
                except (ValueError, TypeError):
                    cells.append(str(val))
            elif isinstance(val, float) and pd.notna(val):
                if val == int(val) and abs(val) < 1e15:
                    cells.append(f"{int(val):,}")
                else:
                    cells.append(f"{val:,.2f}")
            elif isinstance(val, int):
                cells.append(f"{val:,}")
            else:
                cells.append(str(val) if pd.notna(val) else "")
            # Escape pipes in cell content
            cells[-1] = cells[-1].replace("|", "\\|")
        lines.append("| " + " | ".join(cells) + " |")

    if truncated:
        lines.append(f"\n*...truncated to {max_rows} rows*")

    return "\n".join(lines)


def format_histogram(
    values: list[float],
    bins: list[tuple[str, float, float]],
    unit: str = "us",
) -> str:
    """Format a simple text histogram.

    Args:
        values: Raw values to bin.
        bins: List of (label, low, high) tuples.
        unit: Unit label for the axis.
    """
    if not values:
        return "*No data*"

    total = len(values)
    counts: list[tuple[str, int]] = []
    for label, low, high in bins:
        count = sum(1 for v in values if low <= v < high)
        counts.append((label, count))

    max_bar = 40
    max_count = max(c for _, c in counts) if counts else 1

    lines = [f"Distribution ({total:,} samples, unit: {unit})", ""]
    for label, count in counts:
        pct = count / total * 100 if total else 0
        bar_len = int(count / max_count * max_bar) if max_count else 0
        bar = "#" * bar_len
        lines.append(f"  {label:>12s}  {bar:<{max_bar}s}  {count:>8,}  ({pct:5.1f}%)")

    return "\n".join(lines)


def format_number(val: Any) -> str:
    """Format a number with commas or appropriate precision."""
    if isinstance(val, int):
        return f"{val:,}"
    if isinstance(val, float):
        if abs(val) >= 1000:
            return f"{val:,.0f}"
        if abs(val) >= 1:
            return f"{val:.2f}"
        return f"{val:.4f}"
    return str(val)


def format_duration_us(us: float) -> str:
    """Format microsecond duration with appropriate unit."""
    if us >= 1000:
        return f"{us / 1000:.2f} ms"
    if us >= 1:
        return f"{us:.1f} us"
    return f"{us * 1000:.0f} ns"


def format_pct(val: float) -> str:
    """Format percentage."""
    if val >= 10:
        return f"{val:.1f}%"
    if val >= 0.01:
        return f"{val:.2f}%"
    return f"{val:.4f}%"
