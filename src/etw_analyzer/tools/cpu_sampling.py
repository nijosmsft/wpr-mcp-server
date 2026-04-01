"""CPU sampling analysis tools — mirrors WPA 'CPU Usage (Sampled)' table."""

from __future__ import annotations

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import require_trace
from etw_analyzer.parsing.aggregator import apply_filters, group_and_sum, parse_cpu_filter
from etw_analyzer.formatting.markdown import format_table, format_pct

import pandas as pd

# Well-known module sets for quick filtering
_NETWORKING_MODULES = [
    "tcpip.sys", "ndis.sys", "netio.sys", "afd.sys", "pacer.sys",
    "http.sys", "mux.sys", "vmswitch.sys", "vmsif.sys",
    "wsk.sys", "nsi.sys", "fwpkclnt.sys",
]

_NIC_DRIVER_MODULES = [
    "mlx5.sys", "mlnx5.sys", "e1q63x64.sys", "ixn63x64.sys",
    "i40e65.sys", "mrvlpcie8897.sys",
]

_XDP_MODULES = [
    "xdp.sys", "xdplwf.sys",
]

_KERNEL_MODULES = [
    "ntoskrnl.exe", "hal.dll",
]

# Default set: broad networking stack coverage
_DEFAULT_HOT_MODULES = _XDP_MODULES + _NETWORKING_MODULES + _NIC_DRIVER_MODULES + _KERNEL_MODULES


def _get_sampling_df() -> pd.DataFrame:
    """Get the CPU sampling DataFrame, trying known profile names."""
    trace = require_trace()
    for key in ["cpu_sampling", "CpuSampling", "CPU Usage (Sampled)"]:
        if key in trace.raw_csv:
            return trace.raw_csv[key].copy()

    # Fall back to first available dataset
    if trace.raw_csv:
        first_key = next(iter(trace.raw_csv))
        return trace.raw_csv[first_key].copy()

    raise ValueError(
        "No CPU sampling data available. The trace may not contain CPU sampling events.\n\n"
        "To capture CPU sampling data, use:\n"
        "  wpr -start CPU              (CPU sampling only)\n"
        "  wpr -start GeneralProfile   (CPU + context switches + DPC/ISR)"
    )


def _find_col(df: pd.DataFrame, candidates: list[str]) -> str | None:
    """Find the first matching column name (case-insensitive)."""
    df_cols_lower = {c.lower(): c for c in df.columns}
    for c in candidates:
        if c.lower() in df_cols_lower:
            return df_cols_lower[c.lower()]
    return None


def _get_per_cpu_sampling_df(
    cpu_filter: str,
    start_time: float | None = None,
    end_time: float | None = None,
) -> pd.DataFrame:
    """Get per-CPU sampling data from cached dumper output.

    On first call, runs xperf -a dumper to parse ALL SampledProfile events
    (all CPUs) and caches the result. Subsequent calls filter in-memory.
    Also persists the cache as parquet for fast reload across sessions.
    """
    trace = require_trace()

    # Load or populate the dumper cache
    if trace.dumper_df is None:
        # Try loading from persisted parquet first
        parquet_path = trace.export_dir / "sampled_profile.parquet"
        if parquet_path.exists():
            trace.dumper_df = pd.read_parquet(parquet_path)
        else:
            # Parse all events (no CPU filter) and cache
            from etw_analyzer.parsing.wpa_exporter import parse_sampled_profile_events

            trace.dumper_df = parse_sampled_profile_events(
                etl_path=trace.etl_path,
                symbol_path=trace.symbol_path,
                cpu_filter=None,  # Parse ALL CPUs
                start_time=None,
                end_time=None,
                timeout_seconds=300,
            )

            # Persist for future sessions
            if not trace.dumper_df.empty:
                trace.export_dir.mkdir(parents=True, exist_ok=True)
                trace.dumper_df.to_parquet(parquet_path, index=False)

    if trace.dumper_df.empty:
        return pd.DataFrame()

    # Filter in-memory by CPU and time range
    df = trace.dumper_df
    cpu_list = parse_cpu_filter(cpu_filter)
    if cpu_list:
        df = df[df["CPU"].isin(cpu_list)]

    if start_time is not None:
        df = df[df["TimeStamp"] >= start_time * 1_000_000]
    if end_time is not None:
        df = df[df["TimeStamp"] <= end_time * 1_000_000]

    return df.copy()


@mcp.tool()
def get_cpu_samples(
    group_by: str = "module",
    cpu_filter: str | None = None,
    module_filter: str | None = None,
    process_filter: str | None = None,
    function_filter: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    max_rows: int = 50,
) -> str:
    """Get CPU sampling data grouped by process, module, or function.

    Shows where CPU time is spent. Use to identify hot modules and functions.

    When cpu_filter is specified, extracts per-CPU sampling data from raw
    SampledProfile events (slower but provides true per-CPU breakdown).
    Without cpu_filter, uses the faster aggregated profile data.

    Args:
        group_by: Grouping level — 'process', 'module', 'function', or 'process+module'. Default: 'module'.
        cpu_filter: CPU range filter, e.g. '0' or '18-39'. Enables per-CPU extraction.
        module_filter: Filter to specific module (substring match), e.g. 'xdp.sys'.
        process_filter: Filter to specific process, e.g. 'echo_server'.
        function_filter: Filter to specific function name (substring).
        start_time: Start of analysis window in seconds from trace start.
        end_time: End of analysis window in seconds from trace start.
        max_rows: Maximum rows to return. Default: 50.
    """
    # When cpu_filter is specified, use per-CPU extraction from raw dumper events
    if cpu_filter:
        df = _get_per_cpu_sampling_df(cpu_filter, start_time, end_time)
        if df.empty:
            return f"*No SampledProfile events found for CPUs {cpu_filter}. Ensure trace has CPU sampling data.*"

        # Standard column names from our parser
        weight_col, module_col, process_col, function_col = "Weight", "Module", "Process Name", "Function"

        # Apply remaining filters (CPU already filtered during extraction)
        df = apply_filters(
            df,
            module_filter=module_filter, module_col=module_col,
            process_filter=process_filter, process_col=process_col,
            function_filter=function_filter, function_col=function_col,
        )
    else:
        df = _get_sampling_df()

        # Identify columns by trying common WPA export names
        weight_col = _find_col(df, ["Weight", "Count", "Sample Count", "Samples"]) or "Weight"
        module_col = _find_col(df, ["Module", "Image", "Module Name"]) or "Module"
        process_col = _find_col(df, ["Process Name", "Process", "Process Name (PID)"]) or "Process Name"
        function_col = _find_col(df, ["Function", "Function Name", "Symbol"]) or "Function"
        cpu_col = _find_col(df, ["CPU", "Cpu", "Processor"]) or "CPU"
        time_col = _find_col(df, ["TimeStamp", "Time", "Timestamp (s)"]) or "TimeStamp"

        # Apply filters
        df = apply_filters(
            df,
            cpu_filter=None, cpu_col=cpu_col,
            start_time=start_time, end_time=end_time, time_col=time_col,
            module_filter=module_filter, module_col=module_col,
            process_filter=process_filter, process_col=process_col,
            function_filter=function_filter, function_col=function_col,
        )

    if df.empty:
        return "*No samples match the specified filters.*"

    # Determine grouping columns
    group_map = {
        "process": [process_col],
        "module": [module_col],
        "function": [module_col, function_col],
        "process+module": [process_col, module_col],
    }
    group_cols = group_map.get(group_by, [module_col])
    group_cols = [c for c in group_cols if c in df.columns]

    if not group_cols:
        return f"*Grouping columns not found. Available columns: {', '.join(df.columns)}*"

    # Aggregate
    result = group_and_sum(df, group_cols, sum_col=weight_col)
    if result.empty:
        return "*No data after aggregation.*"

    total_weight = result[weight_col].sum()

    # Format
    result = result.head(max_rows)
    result["% Weight"] = result["% Weight"].apply(lambda x: format_pct(x))

    header = f"**CPU Samples** (grouped by {group_by})"
    filters_desc = _describe_filters(cpu_filter, module_filter, process_filter, start_time, end_time)
    if filters_desc:
        header += f"\n{filters_desc}"
    header += f"\nTotal weight: {total_weight:,.0f}"

    return f"{header}\n\n{format_table(result, max_rows=max_rows)}"


@mcp.tool()
def get_hot_functions(
    modules: str | None = None,
    cpu_filter: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    max_rows: int = 30,
) -> str:
    """Get hot functions filtered to specific modules.

    By default filters to the Windows networking stack: tcpip.sys, ndis.sys,
    netio.sys, afd.sys, xdp.sys, xdplwf.sys, NIC drivers, ntoskrnl.exe.

    When cpu_filter is specified, extracts per-CPU data from raw SampledProfile
    events (slower but provides true per-CPU breakdown).

    When XDP modules are present in the results, includes CPUMAP bottleneck
    analysis (clone cost, spinlock contention, DPC drain overhead).

    Args:
        modules: Comma-separated module names to include, e.g. 'tcpip.sys,ndis.sys,http.sys'.
                 Use 'all' to skip module filtering. Default: networking stack modules.
        cpu_filter: CPU range filter, e.g. '0' or '18-39'. Enables per-CPU extraction.
        start_time: Start of analysis window (seconds from trace start).
        end_time: End of analysis window (seconds from trace start).
        max_rows: Maximum rows to return. Default: 30.
    """
    if cpu_filter:
        df = _get_per_cpu_sampling_df(cpu_filter, start_time, end_time)
        if df.empty:
            return f"*No SampledProfile events found for CPUs {cpu_filter}.*"
        weight_col, module_col, function_col = "Weight", "Module", "Function"
    else:
        df = _get_sampling_df()
        weight_col = _find_col(df, ["Weight", "Count", "Sample Count"]) or "Weight"
        module_col = _find_col(df, ["Module", "Image"]) or "Module"
        function_col = _find_col(df, ["Function", "Function Name", "Symbol"]) or "Function"
        cpu_col = _find_col(df, ["CPU", "Cpu"]) or "CPU"
        time_col = _find_col(df, ["TimeStamp", "Time"]) or "TimeStamp"

        # Apply time/CPU filters
        df = apply_filters(
            df,
            cpu_filter=None, cpu_col=cpu_col,
            start_time=start_time, end_time=end_time, time_col=time_col,
        )

    if df.empty:
        return "*No samples match the specified filters.*"

    # Resolve module filter list
    if modules and modules.strip().lower() == "all":
        target_modules = None  # No filtering
    elif modules:
        target_modules = [m.strip() for m in modules.split(",") if m.strip()]
    else:
        target_modules = _DEFAULT_HOT_MODULES

    # Filter to target modules
    if target_modules and module_col in df.columns:
        module_mask = df[module_col].astype(str).str.lower().apply(
            lambda m: any(target.lower() in m for target in target_modules)
        )
        df_filtered = df[module_mask]
    else:
        df_filtered = df

    if df_filtered.empty:
        mod_desc = ", ".join(target_modules) if target_modules else "all"
        return f"*No samples from [{mod_desc}] in the specified range.*"

    # Aggregate by module + function
    group_cols = [c for c in [module_col, function_col] if c in df_filtered.columns]
    result = group_and_sum(df_filtered, group_cols, sum_col=weight_col)

    # Compute % relative to ALL samples (not just filtered modules)
    total_all = df[weight_col].sum() if weight_col in df.columns else 1
    result["% of Total"] = (result[weight_col] / total_all * 100).apply(format_pct)

    # Run CPUMAP-specific analysis only when XDP modules are present
    analysis_lines: list[str] = []
    if module_col in result.columns:
        has_xdp = result[module_col].astype(str).str.contains("xdp", case=False, na=False).any()
        if has_xdp:
            analysis_lines = _cpumap_analysis(result, weight_col, function_col, module_col, total_all)

    # Format output
    result = result.head(max_rows)
    result["% Weight"] = result["% Weight"].apply(lambda x: format_pct(x))

    if target_modules:
        header = "**Hot Functions** (filtered modules)"
    else:
        header = "**Hot Functions** (all modules)"
    filters_desc = _describe_filters(cpu_filter, None, None, start_time, end_time)
    if filters_desc:
        header += f"\n{filters_desc}"

    output = f"{header}\n\n{format_table(result, max_rows=max_rows)}"

    if analysis_lines:
        output += "\n\n**CPUMAP Bottleneck Analysis:**\n" + "\n".join(analysis_lines)

    return output


def _cpumap_analysis(
    result: pd.DataFrame,
    weight_col: str,
    function_col: str,
    module_col: str,
    total_weight: float,
) -> list[str]:
    """Check function weights against CPUMAP decision matrix thresholds.

    Only called when XDP modules are detected in the data.
    """
    lines: list[str] = []
    if function_col not in result.columns:
        return lines

    def fn_pct(pattern: str) -> float:
        mask = result[function_col].astype(str).str.contains(pattern, case=False, na=False)
        return float(result.loc[mask, weight_col].sum() / total_weight * 100) if total_weight > 0 else 0

    # Clone alloc/free check (>10% of xdp.sys = problem)
    clone_pct = fn_pct("NdisAllocateClone|NdisFreeClone|CloneNetBuffer")
    xdp_mask = result[module_col].astype(str).str.contains("xdp", case=False, na=False) if module_col in result.columns else pd.Series(False, index=result.index)
    xdp_total = result.loc[xdp_mask, weight_col].sum()
    clone_of_xdp = (clone_pct / (xdp_total / total_weight * 100) * 100) if xdp_total > 0 else 0

    if clone_of_xdp > 10:
        lines.append(f"- **Clone alloc/free: {clone_of_xdp:.1f}% of xdp.sys** — ABOVE threshold (>10%). Consider no-clone optimization.")
    else:
        lines.append(f"- Clone alloc/free: {clone_of_xdp:.1f}% of xdp.sys — below threshold.")

    # Spinlock contention check
    lock_pct = fn_pct("KeAcquireInStackQueuedSpinLock|KeAcquireSpinLock|SpinLock")
    if lock_pct > 10:
        lines.append(f"- **Spinlock contention: {lock_pct:.2f}% of total** — ABOVE threshold (>10%). Consider lock-free rings.")
    else:
        lines.append(f"- Spinlock contention: {lock_pct:.2f}% of total — below threshold.")

    # DPC drain cost
    drain_pct = fn_pct("XdpCpuMapDrainDpc")
    lines.append(f"- DPC drain (XdpCpuMapDrainDpc): {drain_pct:.2f}% of total")

    # Enqueue cost
    flush_pct = fn_pct("XdpCpuMapFlushBatch")
    lines.append(f"- Ring enqueue (XdpCpuMapFlushBatch): {flush_pct:.2f}% of total")

    # Inspect cost
    inspect_pct = fn_pct("XdpInspect|XdpParseFrame")
    lines.append(f"- Packet inspection: {inspect_pct:.2f}% of total")

    return lines


def _describe_filters(
    cpu_filter: str | None,
    module_filter: str | None,
    process_filter: str | None,
    start_time: float | None,
    end_time: float | None,
) -> str:
    parts = []
    if cpu_filter:
        parts.append(f"CPUs: {cpu_filter}")
    if module_filter:
        parts.append(f"Module: {module_filter}")
    if process_filter:
        parts.append(f"Process: {process_filter}")
    if start_time is not None or end_time is not None:
        t0 = f"{start_time:.1f}s" if start_time is not None else "start"
        t1 = f"{end_time:.1f}s" if end_time is not None else "end"
        parts.append(f"Time: {t0}–{t1}")
    return "Filters: " + ", ".join(parts) if parts else ""
