"""Stack analysis tools — function-level inclusive/exclusive weight from xperf butterfly."""

from __future__ import annotations

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import require_trace
from etw_analyzer.parsing.aggregator import apply_filters
from etw_analyzer.tools.cpu_sampling import _get_sampling_df, _find_col
from etw_analyzer.formatting.markdown import format_table, format_pct

import pandas as pd


def _get_stacks_df() -> pd.DataFrame | None:
    """Get the butterfly stack DataFrame if available."""
    trace = require_trace()
    for key in ["stacks", "stack_butterfly"]:
        if key in trace.raw_csv:
            df = trace.raw_csv[key]
            if not df.empty and "Module" in df.columns:
                return df.copy()
    return None


@mcp.tool()
def get_hot_stacks(
    module_filter: str | None = None,
    function_filter: str | None = None,
    cpu_filter: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    max_depth: int = 10,
    min_weight_pct: float = 1.0,
    dpc_only: bool = False,
    max_rows: int = 50,
) -> str:
    """Show hottest functions with inclusive and exclusive CPU weight.

    Uses xperf butterfly stack data when available (includes caller/callee
    relationships and inclusive hit counts). Falls back to flat
    module!function view from CPU sampling data.

    Inclusive = time in function + all functions it calls.
    Exclusive = time in just this function (not callees).

    Args:
        module_filter: Focus on specific module (e.g. 'xdp.sys', 'tcpip.sys').
        function_filter: Focus on specific function (e.g. 'XdpCpuMapDrainDpc').
        cpu_filter: CPU range filter, e.g. '18-39'.
        start_time: Start of analysis window (seconds from trace start).
        end_time: End of analysis window (seconds from trace start).
        max_depth: Not used (kept for API compat). Default: 10.
        min_weight_pct: Prune functions below this % of total. Default: 1.0.
        dpc_only: Not used with xperf backend. Default: false.
        max_rows: Max rows to return. Default: 50.
    """
    # Try butterfly stack data first (has inclusive/exclusive)
    # But butterfly data has no CPU column, so fall back to flat when cpu_filter is set
    if not cpu_filter:
        stacks_df = _get_stacks_df()
        if stacks_df is not None and not stacks_df.empty:
            return _render_butterfly_stacks(
                stacks_df, module_filter, function_filter,
                min_weight_pct, max_rows,
            )

    # Fall back to CPU sampling data (flat module!function only, but supports CPU filter)
    return _render_flat_stacks(
        module_filter, function_filter,
        cpu_filter, start_time, end_time,
        min_weight_pct, max_rows,
    )


def _render_butterfly_stacks(
    df: pd.DataFrame,
    module_filter: str | None,
    function_filter: str | None,
    min_weight_pct: float,
    max_rows: int,
) -> str:
    """Render butterfly stack data as a table with inclusive/exclusive weights."""
    # Apply filters
    if module_filter:
        df = df[df["Module"].astype(str).str.contains(module_filter, case=False, na=False)]
    if function_filter:
        df = df[df["Function"].astype(str).str.contains(function_filter, case=False, na=False)]

    if df.empty:
        return "*No matching functions found with the specified filters.*"

    # Compute total for percentages
    total_inclusive = df["Inclusive"].sum()
    total_exclusive = df["Exclusive"].sum() if "Exclusive" in df.columns else total_inclusive

    # Filter by min weight
    if min_weight_pct > 0 and total_inclusive > 0:
        threshold = total_inclusive * min_weight_pct / 100
        df = df[df["Inclusive"] >= threshold]

    if df.empty:
        return f"*No functions above {min_weight_pct}% threshold.*"

    # Sort by inclusive weight
    df = df.sort_values("Inclusive", ascending=False).head(max_rows).reset_index(drop=True)

    # Format columns
    result = df[["Module", "Function"]].copy()
    result["Inclusive"] = df["Inclusive"]
    result["Incl %"] = (df["Inclusive"] / total_inclusive * 100).apply(format_pct)
    if "Exclusive" in df.columns:
        result["Exclusive"] = df["Exclusive"]
        result["Excl %"] = (df["Exclusive"] / total_exclusive * 100).apply(format_pct)

    header_parts = ["**Hot Functions (with inclusive/exclusive weight)**"]
    if module_filter:
        header_parts.append(f"Module: {module_filter}")
    if function_filter:
        header_parts.append(f"Function: {function_filter}")
    header = "\n".join(header_parts)

    return f"{header}\n\n{format_table(result, max_rows=max_rows)}"


@mcp.tool()
def get_function_callers(
    function_filter: str,
    module_filter: str | None = None,
    direction: str = "callers",
    max_rows: int = 30,
) -> str:
    """Show callers or callees of a function with hit counts.

    Use this to identify which specific code paths call into a function.
    Example: get_function_callers("KeAcquireInStackQueuedSpinLock") shows
    which functions acquire spinlocks and how often.

    Args:
        function_filter: Function name to search for (substring match).
        module_filter: Optional module filter for the target function.
        direction: "callers" (who calls this), "callees" (what this calls), or "both".
        max_rows: Maximum rows to return.
    """
    trace = require_trace()

    df = trace.raw_csv.get("stacks_callers")
    if df is None or df.empty:
        return ("*No caller/callee data available. Re-load the trace with "
                "`load_trace` to generate butterfly stack analysis.*")

    # Find entries where this function is the center (Target_Function)
    mask = df["Target_Function"].str.contains(function_filter, case=False, na=False)
    if module_filter:
        mask &= df["Target_Module"].str.contains(module_filter, case=False, na=False)

    matched = df[mask]

    # If not found as center, try as a related function
    if matched.empty:
        mask2 = df["Caller_Function"].str.contains(function_filter, case=False, na=False)
        if module_filter:
            mask2 &= df["Caller_Module"].str.contains(module_filter, case=False, na=False)
        related = df[mask2]
        if related.empty:
            return f"*No entries found matching '{function_filter}'.*"

        # Show which center functions reference this as caller/callee
        if direction == "callers":
            result = related[related["Direction"] == "caller"]
        elif direction == "callees":
            result = related[related["Direction"] == "callee"]
        else:
            result = related

        if result.empty:
            return f"*No {direction} found for '{function_filter}'.*"

        result = result.sort_values("Weight", ascending=False).head(max_rows)
        total = result["Weight"].sum()

        out = result[["Target_Module", "Target_Function", "Direction",
                       "Caller_Module", "Caller_Function"]].copy()
        out["Hits"] = result["Weight"].values
        out["% of Total"] = (result["Weight"].values / total * 100).round(1).astype(str) + "%"

        header = f"**References to `{function_filter}` (found as caller/callee)**\n"
        header += f"Total hits: {total:,}\n"
        return header + "\n" + format_table(out, max_rows=max_rows)

    # Filter by direction
    if direction == "callers":
        result = matched[matched["Direction"] == "caller"]
        dir_label = "Callers"
    elif direction == "callees":
        result = matched[matched["Direction"] == "callee"]
        dir_label = "Callees"
    else:
        result = matched
        dir_label = "Callers & Callees"

    if result.empty:
        return f"*No {direction} found for '{function_filter}'.*"

    # Get center function name for header
    center = matched.iloc[0]
    center_name = f"{center['Target_Module']}!{center['Target_Function']}"

    result = result.sort_values("Weight", ascending=False).head(max_rows)
    total = result["Weight"].sum()

    out = pd.DataFrame()
    out["Function"] = result["Caller_Function"].values
    out["Module"] = result["Caller_Module"].values
    if direction == "both":
        out["Direction"] = result["Direction"].values
    out["Hits"] = result["Weight"].values
    out["% of Total"] = (result["Weight"].values / total * 100).round(1).astype(str) + "%"

    header = f"**{dir_label} of `{center_name}`**\n"
    header += f"Total hits: {total:,}\n"
    return header + "\n" + format_table(out, max_rows=max_rows)


def _render_flat_stacks(
    module_filter: str | None,
    function_filter: str | None,
    cpu_filter: str | None,
    start_time: float | None,
    end_time: float | None,
    min_weight_pct: float,
    max_rows: int,
) -> str:
    """Fall back to flat module!function view from CPU sampling."""
    df = _get_sampling_df()

    weight_col = _find_col(df, ["Weight", "Count", "Sample Count"]) or "Weight"
    module_col = _find_col(df, ["Module", "Image"]) or "Module"
    function_col = _find_col(df, ["Function", "Function Name", "Symbol"]) or "Function"
    cpu_col = _find_col(df, ["CPU", "Cpu"]) or "CPU"
    time_col = _find_col(df, ["TimeStamp", "Time"]) or "TimeStamp"

    # Apply filters
    df = apply_filters(
        df,
        cpu_filter=cpu_filter, cpu_col=cpu_col,
        start_time=start_time, end_time=end_time, time_col=time_col,
        module_filter=module_filter, module_col=module_col,
        function_filter=function_filter, function_col=function_col,
    )

    if df.empty:
        return "*No matching samples found with the specified filters.*"

    total_weight = df[weight_col].sum()

    # Filter by min weight
    if min_weight_pct > 0 and total_weight > 0:
        threshold = total_weight * min_weight_pct / 100
        # Group first, then filter
        group_cols = [c for c in [module_col, function_col] if c in df.columns]
        grouped = df.groupby(group_cols, dropna=False)[weight_col].sum().reset_index()
        grouped = grouped[grouped[weight_col] >= threshold]
    else:
        group_cols = [c for c in [module_col, function_col] if c in df.columns]
        grouped = df.groupby(group_cols, dropna=False)[weight_col].sum().reset_index()

    if grouped.empty:
        return f"*No functions above {min_weight_pct}% threshold.*"

    grouped = grouped.sort_values(weight_col, ascending=False).head(max_rows).reset_index(drop=True)
    grouped["% Weight"] = (grouped[weight_col] / total_weight * 100).apply(format_pct)

    header_parts = ["**Hot Functions (exclusive weight only — no call stack data)**"]
    if module_filter:
        header_parts.append(f"Module: {module_filter}")
    if function_filter:
        header_parts.append(f"Function: {function_filter}")
    header = "\n".join(header_parts)
    header += f"\nTotal weight: {total_weight:,.0f}"
    header += "\n*Tip: For inclusive/exclusive breakdown, re-load with `load_trace` to generate butterfly stacks.*"

    return f"{header}\n\n{format_table(grouped, max_rows=max_rows)}"
