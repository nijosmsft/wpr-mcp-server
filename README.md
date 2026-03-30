# WPR Trace Analyzer MCP Server

An [MCP](https://modelcontextprotocol.io/) server that lets AI coding assistants analyze Windows WPR/ETW traces (`.etl` files). Load a trace, then ask questions in natural language — the server calls `xperf.exe` under the hood and returns structured results.

Works with any Windows performance trace: networking (tcpip.sys, NDIS, NIC drivers, HTTP.sys), kernel (DPCs, ISRs, context switches), and application workloads.

## Features

- **CPU sampling** — hot functions by module, process, or call stack
- **Per-CPU breakdown** — utilization per logical processor, identify hot/idle CPUs
- **Per-CPU filtering** — drill into what's running on a specific CPU (e.g. "what's saturating CPU 0?")
- **DPC/ISR analysis** — duration histograms, per-CPU distribution, watchdog risk detection
- **Lock contention** — spinlock contention from ReadyThread/context switch stacks
- **Symbol resolution** — automatic PDB download from symbol servers
- **Call stacks** — butterfly stacks with caller/callee relationships

## Prerequisites

- **Windows** — this server uses Windows-only tools (`xperf.exe`)
- **[Windows Performance Toolkit](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/)** — part of the Windows SDK or ADK:
  ```powershell
  winget install Microsoft.WindowsSDK
  ```
- **[uv](https://docs.astral.sh/uv/)** — Python package manager:
  ```powershell
  winget install astral-sh.uv
  ```

## Setup

### Claude Code

Add to your `.mcp.json` (project root or `~/.claude/.mcp.json`):

```json
{
  "mcpServers": {
    "wpr-trace-analyzer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--directory", "C:\\path\\to\\wpr-mcp-server", "python", "-m", "etw_analyzer.server"],
      "env": {
        "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
      }
    }
  }
}
```

### VS Code (GitHub Copilot)

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "wpr-trace-analyzer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--directory", "C:\\path\\to\\wpr-mcp-server", "python", "-m", "etw_analyzer.server"],
      "env": {
        "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
      }
    }
  }
}
```

Replace `C:\\path\\to\\wpr-mcp-server` with the actual path to this repo.

## Usage

### Just Ask

You don't need to know tool names. Just describe what you want:

```
"Load the trace at C:\traces\mytrace.etl"
"Where is CPU time being spent?"
"What's running on CPU 0?"
"Show me the hottest functions in tcpip.sys"
"What are the DPC durations for the NIC driver?"
"Which CPUs are active and which are idle?"
"Is there lock contention in the networking stack?"
"Is CPU 0 saturated? What's causing it?"
```

### Workflow

```
load_trace(path)     → Parse ETL via xperf, cache in memory (30-180s)
analysis tools       → Query the cached data
```

### Available Tools

| Tool | Purpose |
|------|---------|
| `list_traces` | Find `.etl` files in a directory |
| `load_trace` | Load an ETL file — runs xperf to extract CPU sampling, DPC/ISR, stacks |
| `trace_info` | Show loaded trace metadata |
| `check_symbols` | Check symbol resolution status, identify missing PDBs |
| `resolve_symbols` | Download PDBs from symbol servers and reload trace |
| `get_cpu_samples` | CPU sampling grouped by process, module, or function. Per-CPU filtering supported. |
| `get_hot_functions` | Hot functions filtered to networking modules (customizable). Per-CPU filtering supported. |
| `get_hot_stacks` | Call stack tree with inclusive/exclusive weights |
| `get_function_callers` | Who calls a function and what it calls |
| `get_dpc_summary` | DPC/ISR duration histogram per module |
| `get_dpc_per_cpu` | Per-CPU DPC breakdown |
| `get_per_cpu_summary` | Per-CPU utilization — average, max, role classification |
| `get_cpu_timeline` | Per-CPU utilization over time — find steady state, hot CPUs |
| `get_lock_contention` | Spinlock contention from ReadyThread stacks |
| `get_memory_pools` | Kernel pool allocations by module and tag |

### Common Parameters

Most tools accept:

- `cpu_filter` — CPU range, e.g. `"0"` or `"18-39"`. Enables per-CPU extraction from raw events.
- `start_time` / `end_time` — seconds from trace start
- `module_filter` — substring match, e.g. `"tcpip.sys"`
- `process_filter` — substring match, e.g. `"echo_server"`
- `max_rows` — limit output rows

## Architecture

```
AI Assistant ←stdio→ wpr-mcp-server (Python)
                         │
                         ├── xperf.exe
                         │   ├── profile -detail  → CPU sampling (module!function)
                         │   ├── profile -util    → Per-CPU utilization timeline
                         │   ├── dpcisr           → DPC/ISR histograms
                         │   ├── stack -butterfly  → Call stacks with callers/callees
                         │   ├── dumper           → Raw events (per-CPU sampling)
                         │   └── symcache -build  → Symbol resolution
                         │
                         ├── pandas (aggregation + filtering)
                         └── FastMCP (stdio transport)
```

On `load_trace`, the server runs multiple `xperf` actions to extract different datasets from the ETL file. Results are parsed into pandas DataFrames and cached in memory. Analysis tools query the cached data with filters and return markdown tables.

When `cpu_filter` is specified on `get_cpu_samples` or `get_hot_functions`, the server runs `xperf -a dumper` on-demand to extract raw `SampledProfile` events with per-CPU information, enabling true per-CPU function-level breakdown.

## Project Structure

```
wpr-mcp-server/
├── pyproject.toml
├── README.md
├── LICENSE
└── src/etw_analyzer/
    ├── server.py                ← MCP server entry point
    ├── app.py                   ← FastMCP instance
    ├── trace_state.py           ← Global loaded-trace cache
    ├── tools/
    │   ├── trace_mgmt.py        ← load_trace, list_traces, check_symbols, resolve_symbols
    │   ├── cpu_sampling.py      ← get_cpu_samples, get_hot_functions
    │   ├── per_cpu.py           ← get_per_cpu_summary, get_cpu_timeline
    │   ├── stack_analysis.py    ← get_hot_stacks, get_function_callers
    │   ├── dpc_isr.py           ← get_dpc_summary, get_dpc_per_cpu
    │   ├── context_switch.py    ← get_lock_contention
    │   └── memory.py            ← get_memory_pools
    ├── parsing/
    │   ├── wpa_exporter.py      ← xperf subprocess wrapper + output parsers
    │   ├── csv_loader.py        ← CSV parsing + normalization
    │   └── aggregator.py        ← Filters, group-by, percentiles
    └── formatting/
        └── markdown.py          ← Table formatting for MCP responses
```

## Symbol Configuration

For Microsoft system binaries, use the public symbol server:

```
_NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
```

For internal Microsoft builds, use the internal server:

```
_NT_SYMBOL_PATH=srv*C:\symbols*https://symweb.azurefd.net
```

Multiple paths can be combined with semicolons. Add local PDB directories for your own binaries:

```
_NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols;C:\myproject\build\bin
```

## Contributing

Contributions welcome. Please open an issue first to discuss what you'd like to change.

## License

[MIT](LICENSE)
