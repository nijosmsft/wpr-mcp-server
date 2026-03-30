"""Trace management tools: list_traces, load_trace, trace_info."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import TraceData, get_trace, set_trace, require_trace
from etw_analyzer.parsing.wpa_exporter import (
    export_all_profiles,
    find_xperf,
    parse_stack_butterfly_callers,
)
from etw_analyzer.parsing.csv_loader import load_csv
from etw_analyzer.formatting.markdown import format_table

import pandas as pd


@mcp.tool()
def list_traces(directory: str = r"C:\traces", pattern: str = "*.etl") -> str:
    """List ETL trace files in a directory.

    Args:
        directory: Directory to search for trace files. Default: C:\\traces
        pattern: Glob pattern for trace files. Default: *.etl
    """
    trace_dir = Path(directory)
    if not trace_dir.exists():
        return f"Directory not found: {directory}"

    files = sorted(trace_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return f"No {pattern} files found in {directory}"

    rows = []
    for f in files:
        stat = f.stat()
        size_mb = stat.st_size / (1024 * 1024)
        mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        rows.append({
            "Name": f.name,
            "Size": f"{size_mb:.1f} MB",
            "Modified": mtime.strftime("%Y-%m-%d %H:%M"),
            "Path": str(f),
        })

    df = pd.DataFrame(rows)
    return f"**ETL Traces in {directory}** ({len(files)} files)\n\n{format_table(df)}"


@mcp.tool()
def load_trace(
    etl_path: str,
    symbol_path: str | None = None,
    timeout_seconds: int = 300,
) -> str:
    """Load an ETL trace file for analysis.

    Runs xperf to extract CPU sampling, DPC/ISR, and context switch data,
    then caches the results in memory. Takes 30-180 seconds depending on
    trace size and symbol resolution.

    Args:
        etl_path: Full path to the .etl file.
        symbol_path: NT symbol path (e.g. 'srv*C:\\symbols*https://msdl.microsoft.com/download/symbols').
                     If not set, uses _NT_SYMBOL_PATH env var.
        timeout_seconds: Max seconds per xperf invocation. Default: 300.
    """
    path = Path(etl_path)
    if not path.exists():
        return f"File not found: {etl_path}"
    if not path.suffix.lower() == ".etl":
        return f"Expected .etl file, got: {path.suffix}"

    # Resolve symbol path
    sym_path = symbol_path or os.environ.get("_NT_SYMBOL_PATH")

    # Export directory next to the ETL file
    export_dir = path.parent / f".etw-export-{path.stem}"

    xperf = find_xperf()
    if xperf is None:
        return (
            "xperf.exe not found. Install Windows Performance Toolkit "
            "(part of Windows SDK/ADK) or add it to PATH.\n\n"
            "Expected at: C:\\Program Files (x86)\\Windows Kits\\10\\Windows Performance Toolkit\\xperf.exe"
        )

    # Build symcache first to ensure symbols are available for export
    from etw_analyzer.parsing.wpa_exporter import _run_xperf
    try:
        _run_xperf(
            path, "symcache", ["-build"],
            symbol_path=sym_path,
            symbols=True,
            timeout_seconds=timeout_seconds,
        )
    except Exception:
        pass  # Non-fatal — continue with whatever symbols are available

    # Run exports
    results: dict[str, pd.DataFrame] = {}
    errors: list[str] = []

    try:
        csv_paths = export_all_profiles(
            path, export_dir,
            symbol_path=sym_path,
            timeout_seconds=timeout_seconds,
        )
    except Exception as e:
        return f"Export failed: {e}"

    for profile_name, csv_path in csv_paths.items():
        try:
            if csv_path.suffix == ".csv":
                df = load_csv(csv_path)
                results[profile_name] = df
            elif csv_path.suffix == ".txt":
                # Raw text files (dpcisr, cswitch, tracestats) — store as-is
                # for tools that parse them directly
                results[profile_name] = pd.DataFrame({"raw_text": [csv_path.read_text(encoding="utf-8")]})
        except Exception as e:
            errors.append(f"{profile_name}: {e}")

    # If stacks_callers wasn't exported (old export), parse from cached HTML
    if "stacks_callers" not in results:
        butterfly_html = export_dir / "stack-butterfly.html"
        if butterfly_html.exists():
            try:
                callers_df = parse_stack_butterfly_callers(
                    butterfly_html.read_text(encoding="utf-8")
                )
                if not callers_df.empty:
                    csv_path = export_dir / "stacks_callers.csv"
                    callers_df.to_csv(csv_path, index=False)
                    results["stacks_callers"] = callers_df
            except Exception as e:
                errors.append(f"stacks_callers: {e}")

    # Always set trace state — even with no standard datasets,
    # on-demand tools (like get_memory_pools) can extract data later.
    # Build trace data
    trace = TraceData(
        etl_path=path,
        export_dir=export_dir,
        symbol_path=sym_path,
        raw_csv=results,
        export_errors=errors,
    )

    # Extract metadata from the data
    _populate_metadata(trace)
    set_trace(trace)

    return _format_load_summary(trace)


def _populate_metadata(trace: TraceData) -> None:
    """Extract metadata from loaded DataFrames."""
    for name, df in trace.raw_csv.items():
        trace.event_counts[name] = len(df)

        # Try to find CPU count from CPU column
        if trace.cpu_count is None and "CPU" in df.columns:
            try:
                trace.cpu_count = int(df["CPU"].max()) + 1
            except (ValueError, TypeError):
                pass

        # Try to find trace duration from timestamp column
        if trace.duration_seconds is None:
            for col in ["TimeStamp", "Time", "Timestamp (s)"]:
                if col in df.columns:
                    try:
                        vals = pd.to_numeric(df[col], errors="coerce").dropna()
                        if not vals.empty:
                            trace.duration_seconds = float(vals.max() - vals.min())
                            break
                    except Exception:
                        pass


def _format_load_summary(trace: TraceData) -> str:
    """Format a summary of the loaded trace."""
    lines = [
        f"**Trace loaded:** `{trace.etl_path.name}`",
        "",
    ]

    if trace.duration_seconds:
        lines.append(f"- **Duration:** {trace.duration_seconds:.1f}s")
    if trace.cpu_count:
        lines.append(f"- **CPUs:** {trace.cpu_count}")
    if trace.symbol_path:
        lines.append(f"- **Symbols:** `{trace.symbol_path[:80]}...`" if len(trace.symbol_path or "") > 80 else f"- **Symbols:** `{trace.symbol_path}`")

    lines.append("")
    lines.append("**Exported datasets:**")
    for name, df in trace.raw_csv.items():
        cols_preview = ", ".join(df.columns[:6])
        if len(df.columns) > 6:
            cols_preview += f", ... (+{len(df.columns) - 6} more)"
        lines.append(f"- `{name}`: {len(df):,} rows — columns: {cols_preview}")

    if trace.export_errors:
        lines.append("")
        lines.append("**Export warnings:**")
        for err in trace.export_errors:
            lines.append(f"- {err}")

    lines.append("")
    lines.append("Ready for analysis. Try: `get_cpu_samples`, `get_hot_functions`, `get_dpc_summary`")

    return "\n".join(lines)


@mcp.tool()
def trace_info() -> str:
    """Show metadata about the currently loaded trace.

    Returns duration, CPU count, event counts, symbol status, and available datasets.
    """
    trace = require_trace()
    return _format_load_summary(trace)


@mcp.tool()
def check_symbols(etl_path: str | None = None) -> str:
    """Check symbol resolution status for a trace.

    Loads the trace automatically if not already loaded.

    Reports:
    - Each path in _NT_SYMBOL_PATH: exists/accessible, contains PDBs
    - Per-module symbol resolution: resolved vs Unknown functions
    - Top unresolved modules (likely missing PDBs)
    - Recommendations for fixing symbol issues

    Args:
        etl_path: Path to .etl file. If omitted, uses the currently loaded trace.
    """
    if etl_path:
        result = load_trace(etl_path)
        if "File not found" in result or "not found" in result.lower():
            return result

    trace = require_trace()
    lines: list[str] = ["**Symbol Resolution Check**", ""]

    # 1. Symbol path analysis
    sym_path = trace.symbol_path or os.environ.get("_NT_SYMBOL_PATH", "")
    lines.append("**Symbol Path (`_NT_SYMBOL_PATH`):**")
    if not sym_path:
        lines.append("- **NOT SET** — xperf cannot resolve function names without symbols")
        lines.append("- Set via: `_NT_SYMBOL_PATH=srv*C:\\symbols*https://msdl.microsoft.com/download/symbols`")
        lines.append("")
    else:
        # Parse the semicolon-separated path entries
        entries = [e.strip() for e in sym_path.split(";") if e.strip()]
        for entry in entries:
            status = _check_symbol_entry(entry)
            lines.append(f"- `{entry}`")
            lines.append(f"  {status}")
        lines.append("")

    # 2. Per-module resolution stats from CPU sampling data
    cpu_df = None
    for key in ["cpu_sampling", "CpuSampling", "CPU Usage (Sampled)"]:
        if key in trace.raw_csv:
            cpu_df = trace.raw_csv[key]
            break

    if cpu_df is not None and "Module" in cpu_df.columns and "Function" in cpu_df.columns:
        lines.append("**Per-Module Symbol Resolution:**")
        lines.append("")

        weight_col = "Weight" if "Weight" in cpu_df.columns else None

        # Group by module, check resolved vs unknown
        rows = []
        for module, group in cpu_df.groupby("Module", dropna=False):
            mod_str = str(module)
            total_funcs = len(group)
            unknown = group["Function"].astype(str).str.contains(
                r"^Unknown$|^\*\*\*unknown\*\*\*$|^$", case=False, na=True
            ).sum()
            resolved = total_funcs - unknown
            pct_resolved = (resolved / total_funcs * 100) if total_funcs > 0 else 0

            mod_weight = int(group[weight_col].sum()) if weight_col else total_funcs

            if pct_resolved >= 90:
                status_icon = "OK"
            elif pct_resolved > 0:
                status_icon = "PARTIAL"
            else:
                status_icon = "MISSING"

            rows.append({
                "Module": mod_str,
                "Functions": total_funcs,
                "Resolved": resolved,
                "Unknown": unknown,
                "% Resolved": f"{pct_resolved:.0f}%",
                "Weight": mod_weight,
                "Status": status_icon,
            })

        result_df = pd.DataFrame(rows)
        result_df = result_df.sort_values("Weight", ascending=False).reset_index(drop=True)
        lines.append(format_table(result_df, max_rows=25))
        lines.append("")

        # 3. Summary and recommendations
        total_weight = result_df["Weight"].sum()
        missing_df = result_df[result_df["Status"] == "MISSING"]
        missing_weight = missing_df["Weight"].sum()
        missing_pct = (missing_weight / total_weight * 100) if total_weight > 0 else 0

        lines.append("**Summary:**")
        lines.append(f"- Total modules: {len(result_df)}")
        lines.append(f"- Fully resolved: {len(result_df[result_df['Status'] == 'OK'])}")
        lines.append(f"- Partially resolved: {len(result_df[result_df['Status'] == 'PARTIAL'])}")
        lines.append(f"- No symbols: {len(missing_df)}")
        lines.append(f"- Unresolved weight: {missing_pct:.1f}% of total CPU samples")
        lines.append("")

        if not missing_df.empty:
            lines.append("**Top Unresolved Modules (need PDBs):**")
            top_missing = missing_df.head(10)
            for _, row in top_missing.iterrows():
                lines.append(f"- `{row['Module']}` — {row['Weight']:,} weight ({row['Weight']/total_weight*100:.1f}%)")
            lines.append("")

            lines.append("**Recommendations:**")
            # Check for common modules
            missing_names = set(missing_df["Module"].str.lower())
            if any(m in missing_names for m in ["ntoskrnl.exe", "ntkrnlmp.exe"]):
                lines.append("- **ntoskrnl.exe**: Download from symbol server — "
                           "`symchk /s srv*C:\\symbols*https://msdl.microsoft.com/download/symbols "
                           "C:\\Windows\\System32\\ntoskrnl.exe`")
            if "afd.sys" in missing_names:
                lines.append("- **afd.sys**: `symchk /s srv*C:\\symbols*https://msdl.microsoft.com/download/symbols "
                           "C:\\Windows\\System32\\drivers\\afd.sys`")
            if "ndis.sys" in missing_names:
                lines.append("- **ndis.sys**: `symchk /s srv*C:\\symbols*https://msdl.microsoft.com/download/symbols "
                           "C:\\Windows\\System32\\drivers\\ndis.sys`")
            if any("xdp" in m for m in missing_names):
                lines.append("- **xdp.sys**: Add XDP build artifacts directory to `_NT_SYMBOL_PATH`")
            lines.append("- For Microsoft internal builds: add `https://symweb.azurefd.net` to symbol path")
            lines.append("- After downloading PDBs, re-run `load_trace` to re-analyze with symbols")

    else:
        lines.append("*No CPU sampling data loaded — load a trace first with `load_trace`.*")

    return "\n".join(lines)


@mcp.tool()
def resolve_symbols(etl_path: str | None = None, modules: str | None = None) -> str:
    """Build symbol cache for a trace using xperf.

    Runs xperf -a symcache -build which uses dbghelp.dll to download PDBs
    from the symbol servers configured in _NT_SYMBOL_PATH. Also shows debug
    IDs for any modules that fail to resolve.

    Args:
        etl_path: Path to .etl file. If omitted, uses the currently loaded trace.
        modules: Comma-separated module names to focus on (e.g. 'ntoskrnl.exe,ndis.sys').
                 Default: all modules in the trace.
    """
    try:
        return _resolve_symbols_impl(etl_path, modules)
    except Exception as e:
        return f"Symbol resolution failed: {e}"


def _resolve_symbols_impl(etl_path: str | None, modules: str | None) -> str:
    import re
    from etw_analyzer.parsing.wpa_exporter import find_xperf, _run_xperf

    # Resolve trace path
    if etl_path:
        path = Path(etl_path).resolve()
    else:
        trace = require_trace()
        path = trace.etl_path

    if not path.exists():
        return f"File not found: {path}"

    sym_path = os.environ.get("_NT_SYMBOL_PATH", "")
    lines = ["**Symbol Resolver**", ""]
    lines.append(f"Trace: `{path.name}`")
    lines.append(f"Symbol path: `{sym_path[:120]}{'...' if len(sym_path) > 120 else ''}`")
    lines.append("")

    xperf = find_xperf()
    if xperf is None:
        return "xperf.exe not found."

    if not sym_path:
        lines.append("**WARNING:** `_NT_SYMBOL_PATH` is not set. Configure it in `.mcp.json` env.")
        lines.append("")

    # Parse module filter
    image_args: list[str] = []
    if modules:
        mod_list = [m.strip() for m in modules.split(",") if m.strip()]
        image_args = ["-image"] + mod_list
        lines.append(f"Modules: {', '.join(mod_list)}")
    else:
        lines.append("Modules: all")
    lines.append("")

    # Step 1: Build symcache (downloads PDBs via dbghelp.dll)
    lines.append("**Building symcache (downloading PDBs)...**")
    try:
        text = _run_xperf(
            path, "symcache", ["-build"] + image_args,
            symbol_path=sym_path or None,
            symbols=True,
            timeout_seconds=300,
        )
        warnings = [l.strip() for l in text.splitlines()
                    if "warning" in l.lower() or "not found" in l.lower()]
        progress = [l.strip() for l in text.splitlines()
                    if "%" in l or l.strip().startswith("[")]

        if progress:
            for p in progress[:5]:
                lines.append(f"  {p}")

        if warnings:
            lines.append("")
            lines.append(f"**Failed to resolve ({len(warnings)} modules):**")
            for w in warnings[:20]:
                lines.append(f"- {w}")
        elif not text.strip():
            lines.append("Completed (symbols may already be cached)")
        else:
            lines.append("All symbols resolved successfully")
    except Exception as e:
        lines.append(f"symcache build error: {e}")

    lines.append("")

    # Step 2: Show debug IDs for unresolved modules
    lines.append("**Debug IDs (PDB GUID/Age from trace):**")
    try:
        text = _run_xperf(
            path, "symcache", ["-dbgid"] + image_args,
            symbol_path=sym_path or None,
            symbols=False,
            timeout_seconds=60,
        )
        dbg_lines = [l.strip().strip('"') for l in text.splitlines() if "[RSDS]" in l]
        if dbg_lines:
            for dl in dbg_lines[:30]:
                lines.append(f"- `{dl}`")
        else:
            lines.append("No RSDS debug records found")
    except Exception as e:
        lines.append(f"dbgid query error: {e}")

    # Step 3: Re-export trace with newly resolved symbols
    lines.append("")
    lines.append("**Re-loading trace with resolved symbols...**")
    try:
        import shutil
        export_dir = path.parent / f".etw-export-{path.stem}"
        if export_dir.exists():
            shutil.rmtree(export_dir)
        reload_result = load_trace(str(path))
        lines.append(reload_result)
    except Exception as e:
        lines.append(f"Re-load failed: {e}")
        lines.append("Run `load_trace` manually to re-analyze.")

    return "\n".join(lines)


def _check_symbol_entry(entry: str) -> str:
    """Check a single _NT_SYMBOL_PATH entry and return status string."""
    # srv*cache*server format
    if entry.lower().startswith("srv*"):
        parts = entry.split("*")
        statuses = []

        # Check cache directory
        if len(parts) >= 2 and parts[1]:
            cache_path = Path(parts[1])
            if cache_path.exists():
                # Count PDB files
                pdbs = list(cache_path.glob("**/*.pdb"))
                statuses.append(f"Cache `{parts[1]}`: {len(pdbs)} PDBs cached")
            else:
                statuses.append(f"Cache `{parts[1]}`: directory does not exist (will be created on first use)")

        # Check server URL
        if len(parts) >= 3 and parts[2]:
            server = parts[2]
            if "msdl.microsoft.com" in server:
                statuses.append(f"Server: Microsoft public symbol server")
            elif "symweb" in server:
                statuses.append(f"Server: Microsoft internal symbol server (requires corpnet)")
            else:
                statuses.append(f"Server: `{server}`")

        return " | ".join(statuses) if statuses else "Symbol server entry"

    # Plain directory path
    path = Path(entry)
    if path.exists():
        if path.is_dir():
            pdbs = list(path.glob("*.pdb"))
            sys_pdbs = list(path.glob("**/*.pdb"))
            if sys_pdbs:
                return f"OK — directory exists, {len(sys_pdbs)} PDB files found"
            else:
                return f"WARNING — directory exists but no .pdb files found"
        elif path.is_file():
            return f"OK — file exists ({path.stat().st_size / 1024:.0f} KB)"
        else:
            return f"EXISTS — unknown type"
    else:
        return f"NOT FOUND — `{entry}` does not exist"
