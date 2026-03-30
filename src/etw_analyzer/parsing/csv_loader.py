"""Load and cache CSV data exported by wpaexporter."""

from __future__ import annotations

from pathlib import Path

import pandas as pd


def load_csv(csv_path: Path) -> pd.DataFrame:
    """Load a wpaexporter CSV into a DataFrame.

    Handles wpaexporter quirks:
    - BOM markers
    - Trailing comma columns
    - Numeric columns with commas in values (e.g. "1,234,567")
    - Duration columns in various formats
    """
    # wpaexporter CSVs may have BOM
    df = pd.read_csv(csv_path, encoding="utf-8-sig")

    # Drop unnamed columns (trailing commas)
    df = df.loc[:, ~df.columns.str.startswith("Unnamed")]

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Try to convert numeric-looking string columns
    for col in df.columns:
        if df[col].dtype == object:
            # Try removing commas and converting to numeric
            cleaned = df[col].astype(str).str.replace(",", "", regex=False)
            try:
                converted = pd.to_numeric(cleaned, errors="coerce")
                # Only convert if >50% of non-null values succeeded
                if converted.notna().sum() > len(df) * 0.5:
                    df[col] = converted
            except Exception:
                pass

    return df


def parse_duration_to_us(duration_str: str) -> float | None:
    """Parse a WPA duration string to microseconds.

    Formats seen from wpaexporter:
    - "1,234 us" or "1234 us"
    - "0.5 ms"
    - "123 ns"
    - "1.234s"
    - Plain numeric (assumed us)
    """
    if pd.isna(duration_str):
        return None

    s = str(duration_str).strip().replace(",", "")

    # Try plain numeric first
    try:
        return float(s)
    except ValueError:
        pass

    s_lower = s.lower()

    if s_lower.endswith("us") or s_lower.endswith("µs"):
        return float(s_lower.rstrip("usµ "))
    if s_lower.endswith("ms"):
        return float(s_lower.rstrip("ms ")) * 1000.0
    if s_lower.endswith("ns"):
        return float(s_lower.rstrip("ns ")) / 1000.0
    if s_lower.endswith("s"):
        return float(s_lower.rstrip("s ")) * 1_000_000.0

    return None


def normalize_duration_column(df: pd.DataFrame, col: str) -> pd.DataFrame:
    """Convert a duration column to numeric microseconds."""
    if col not in df.columns:
        return df
    if df[col].dtype == object:
        df[col] = df[col].apply(parse_duration_to_us)
    return df


def parse_time_to_seconds(time_str: str) -> float | None:
    """Parse a WPA timestamp string to seconds from trace start.

    Formats: "12.345s", "12.345", "0:00:12.345"
    """
    if pd.isna(time_str):
        return None

    s = str(time_str).strip().replace(",", "")

    # "H:MM:SS.fff" format
    if ":" in s:
        parts = s.split(":")
        try:
            if len(parts) == 3:
                return float(parts[0]) * 3600 + float(parts[1]) * 60 + float(parts[2].rstrip("s "))
            if len(parts) == 2:
                return float(parts[0]) * 60 + float(parts[1].rstrip("s "))
        except ValueError:
            return None

    # Plain seconds
    try:
        return float(s.rstrip("s "))
    except ValueError:
        return None
