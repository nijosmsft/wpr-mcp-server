"""FastMCP application instance — imported by all tool modules."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "etw-trace-analyzer",
    instructions=(
        "Analyze Windows ETW/WPR traces (.etl files). "
        "Always load a trace with load_trace before running analysis tools. "
        "Available analysis: get_cpu_samples, get_hot_functions, get_hot_stacks, "
        "get_dpc_summary, get_dpc_per_cpu, get_per_cpu_summary, get_cpu_timeline, "
        "get_lock_contention."
    ),
)
