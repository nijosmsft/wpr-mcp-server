"""Tests for per-CPU analysis tools."""

import pandas as pd
import pytest

from etw_analyzer.tools.per_cpu import (
    _parse_cpu_range,
    _per_cpu_from_timeline,
)


class TestParseCpuRange:
    def test_single(self):
        assert _parse_cpu_range("0") == {0}

    def test_range(self):
        assert _parse_cpu_range("0-3") == {0, 1, 2, 3}

    def test_comma_separated(self):
        assert _parse_cpu_range("0,2,4,6") == {0, 2, 4, 6}

    def test_mixed(self):
        assert _parse_cpu_range("0-2,5,8-10") == {0, 1, 2, 5, 8, 9, 10}


class TestPerCpuFromTimeline:
    @pytest.fixture
    def timeline_df(self):
        """Simulates xperf -a profile -util output."""
        return pd.DataFrame({
            "StartTime": [0, 1000000, 2000000],
            "EndTime": [1000000, 2000000, 3000000],
            "Cpu 0": [94.74, 100.0, 52.14],
            "Cpu 1": [0.7, 0.8, 0.58],
            "Cpu 2": [40.33, 42.83, 24.34],
            "Cpu 3": [0.5, 0.48, 0.6],
        })

    def test_basic_output(self, timeline_df):
        result = _per_cpu_from_timeline(timeline_df, None, None, 80)
        assert "Per-CPU Summary" in result
        assert "CPU" in result

    def test_saturated_cpu_detected(self, timeline_df):
        result = _per_cpu_from_timeline(timeline_df, None, None, 80)
        assert "Saturated" in result  # CPU 0 should be saturated

    def test_idle_cpu_detected(self, timeline_df):
        result = _per_cpu_from_timeline(timeline_df, None, None, 80)
        assert "Idle" in result  # CPU 1, 3 should be idle

    def test_time_filter(self, timeline_df):
        # Only include second 1-2 (steady state)
        result = _per_cpu_from_timeline(timeline_df, start_time=1.0, end_time=2.0, max_rows=80)
        assert "100.0%" in result  # CPU 0 at 100% in that window

    def test_active_cpu_count(self, timeline_df):
        result = _per_cpu_from_timeline(timeline_df, None, None, 80)
        assert "Active CPUs:" in result
