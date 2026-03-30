"""Tests for aggregation and filtering utilities."""

import pandas as pd
import pytest

from etw_analyzer.parsing.aggregator import (
    parse_cpu_filter,
    apply_filters,
    group_and_sum,
    compute_percentiles,
    time_bucket,
)


class TestParseCpuFilter:
    def test_single_cpu(self):
        assert parse_cpu_filter("0") == [0]

    def test_range(self):
        assert parse_cpu_filter("0-3") == [0, 1, 2, 3]

    def test_comma_separated(self):
        assert parse_cpu_filter("0,2,4") == [0, 2, 4]

    def test_mixed(self):
        result = parse_cpu_filter("0-2,5,8-10")
        assert result == [0, 1, 2, 5, 8, 9, 10]

    def test_none(self):
        assert parse_cpu_filter(None) is None

    def test_empty(self):
        assert parse_cpu_filter("") is None


class TestApplyFilters:
    @pytest.fixture
    def sample_df(self):
        return pd.DataFrame({
            "CPU": [0, 0, 1, 1, 2, 2],
            "Module": ["tcpip.sys", "ndis.sys", "tcpip.sys", "afd.sys", "xdp.sys", "tcpip.sys"],
            "Process Name": ["echo", "echo", "idle", "echo", "echo", "idle"],
            "Function": ["UdpSend", "NdisSend", "Idle", "AfdRecv", "XdpDrain", "UdpRecv"],
            "Weight": [100, 50, 200, 75, 300, 25],
            "TimeStamp": [1.0, 1.5, 2.0, 2.5, 3.0, 3.5],
        })

    def test_cpu_filter(self, sample_df):
        result = apply_filters(sample_df, cpu_filter="0", cpu_col="CPU")
        assert len(result) == 2
        assert set(result["CPU"]) == {0}

    def test_cpu_filter_range(self, sample_df):
        result = apply_filters(sample_df, cpu_filter="0-1", cpu_col="CPU")
        assert len(result) == 4

    def test_module_filter(self, sample_df):
        result = apply_filters(sample_df, module_filter="tcpip", module_col="Module")
        assert len(result) == 3

    def test_process_filter(self, sample_df):
        result = apply_filters(sample_df, process_filter="echo", process_col="Process Name")
        assert len(result) == 4

    def test_function_filter(self, sample_df):
        result = apply_filters(sample_df, function_filter="Udp", function_col="Function")
        assert len(result) == 2

    def test_time_filter(self, sample_df):
        result = apply_filters(sample_df, start_time=2.0, end_time=3.0, time_col="TimeStamp")
        assert len(result) == 3  # Includes endpoints: 2.0, 2.5, 3.0

    def test_combined_filters(self, sample_df):
        result = apply_filters(
            sample_df,
            cpu_filter="0", cpu_col="CPU",
            module_filter="tcpip", module_col="Module",
        )
        assert len(result) == 1
        assert result.iloc[0]["Function"] == "UdpSend"

    def test_missing_column_ignored(self, sample_df):
        # Filter on non-existent column should not crash
        result = apply_filters(sample_df, cpu_filter="0", cpu_col="NonExistent")
        assert len(result) == 6  # No filtering applied

    def test_empty_df(self):
        df = pd.DataFrame()
        result = apply_filters(df, cpu_filter="0")
        assert result.empty


class TestGroupAndSum:
    def test_basic_grouping(self):
        df = pd.DataFrame({
            "Module": ["a", "a", "b", "b"],
            "Weight": [10, 20, 30, 40],
        })
        result = group_and_sum(df, ["Module"])
        assert len(result) == 2
        assert result.iloc[0]["Module"] == "b"  # Sorted descending
        assert result.iloc[0]["Weight"] == 70

    def test_percentage(self):
        df = pd.DataFrame({
            "Module": ["a", "b"],
            "Weight": [25, 75],
        })
        result = group_and_sum(df, ["Module"])
        assert result.iloc[0]["% Weight"] == pytest.approx(75.0)
        assert result.iloc[1]["% Weight"] == pytest.approx(25.0)

    def test_multi_column_group(self):
        df = pd.DataFrame({
            "Module": ["a", "a", "a"],
            "Function": ["f1", "f1", "f2"],
            "Weight": [10, 20, 30],
        })
        result = group_and_sum(df, ["Module", "Function"])
        assert len(result) == 2

    def test_empty_df(self):
        df = pd.DataFrame()
        result = group_and_sum(df, ["Module"])
        assert result.empty


class TestComputePercentiles:
    def test_basic(self):
        s = pd.Series(range(100))
        result = compute_percentiles(s)
        assert "p50" in result
        assert "p99" in result
        assert result["count"] == 100
        assert result["min"] == 0
        assert result["max"] == 99

    def test_custom_percentiles(self):
        s = pd.Series([1, 2, 3, 4, 5])
        result = compute_percentiles(s, percentiles=[50])
        assert "p50" in result
        assert "p99" not in result

    def test_empty(self):
        result = compute_percentiles(pd.Series(dtype=float))
        assert result == {}


class TestTimeBucket:
    def test_basic(self):
        df = pd.DataFrame({"TimeStamp": [0.5, 1.2, 1.8, 2.5, 3.1]})
        result = time_bucket(df, "TimeStamp", bucket_seconds=1.0)
        assert "TimeBucket" in result.columns
        assert list(result["TimeBucket"]) == [0.0, 1.0, 1.0, 2.0, 3.0]

    def test_missing_column(self):
        df = pd.DataFrame({"Other": [1, 2, 3]})
        result = time_bucket(df, "TimeStamp", 1.0)
        assert "TimeBucket" not in result.columns
