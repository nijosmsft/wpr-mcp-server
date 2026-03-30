"""Tests for markdown formatting utilities."""

import pandas as pd
import pytest

from etw_analyzer.formatting.markdown import (
    format_table,
    format_number,
    format_duration_us,
    format_pct,
)


class TestFormatTable:
    def test_basic_table(self):
        df = pd.DataFrame({"A": [1, 2], "B": ["x", "y"]})
        result = format_table(df)
        assert "| A | B |" in result
        assert "| 1 | x |" in result

    def test_max_rows(self):
        df = pd.DataFrame({"A": range(100)})
        result = format_table(df, max_rows=5)
        lines = [l for l in result.strip().split("\n") if l.startswith("|")]
        # Header + separator + 5 data rows = 7 lines
        assert len(lines) == 7

    def test_empty_df(self):
        df = pd.DataFrame()
        result = format_table(df)
        assert "no data" in result.lower()


class TestFormatNumber:
    def test_integer(self):
        assert format_number(1234567) == "1,234,567"

    def test_small_number(self):
        assert format_number(42) == "42"

    def test_zero(self):
        assert format_number(0) == "0"


class TestFormatDurationUs:
    def test_microseconds(self):
        result = format_duration_us(5.0)
        assert "us" in result or "µs" in result

    def test_milliseconds(self):
        result = format_duration_us(5000.0)
        assert "ms" in result

    def test_zero(self):
        result = format_duration_us(0)
        assert "0" in result


class TestFormatPct:
    def test_normal(self):
        result = format_pct(42.5)
        assert "42.5%" in result

    def test_small(self):
        result = format_pct(0.005)
        assert "%" in result

    def test_hundred(self):
        result = format_pct(100.0)
        assert "100" in result
