# WPR Trace Analyzer MCP Server

An [MCP](https://modelcontextprotocol.io/) server that lets AI coding assistants analyze Windows WPR/ETW traces (`.etl` files). Load a trace, then ask questions in natural language — the server calls `xperf.exe` under the hood and returns structured results.

Works with any Windows performance trace: networking (tcpip.sys, NDIS, NIC drivers, HTTP.sys), kernel (DPCs, ISRs, context switches), and application workloads.

### Quick Install

Copy-paste this into Claude Code, Copilot, or any AI assistant to install automatically:

```
Install the WPR trace analyzer MCP server on this Windows machine:
1. Run: winget install astral-sh.uv (skip if uv is already installed)
2. Check if xperf.exe exists at "C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe". If not, run: winget install Microsoft.WindowsSDK
3. Run: git clone https://github.com/nijosmsft/wpr-mcp-server.git C:\tools\wpr-mcp-server
4. Add this MCP server config to .mcp.json:
   {"mcpServers":{"wpr-trace-analyzer":{"type":"stdio","command":"uv","args":["run","--directory","C:\\tools\\wpr-mcp-server","python","-m","etw_analyzer.server"],"env":{"_NT_SYMBOL_PATH":"srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"}}}}
5. Verify: run "uv run --directory C:\tools\wpr-mcp-server python -m etw_analyzer.server" and confirm it starts
```

## Features

- **Auto-summary** — one-call comprehensive analysis: system config, per-CPU utilization, hot functions, symbol status, DPC health
- **CPU sampling** — hot functions by module, process, or call stack
- **Per-CPU breakdown** — utilization per logical processor, identify hot/idle/saturated CPUs
- **Per-CPU filtering** — drill into what's running on a specific CPU (e.g. "what's saturating CPU 0?")
- **Trace comparison** — diff two traces to find regressions (hot functions, modules, or per-CPU utilization)
- **DPC/ISR analysis** — duration histograms, per-CPU distribution, watchdog risk detection
- **Lock contention** — spinlock contention from ReadyThread/context switch stacks
- **Symbol resolution** — automatic PDB download from symbol servers
- **Call stacks** — butterfly stacks with caller/callee relationships
- **System info** — CPU model, NIC details, memory, disk config from trace metadata
- **Process info** — running processes, command lines, loaded driver versions
- **Disk I/O** — per-file I/O summary to rule out storage bottlenecks
- **Export** — save analysis to markdown for sharing via email
- **Caching** — parquet-based disk cache for instant reload, parallel xperf extraction

## Installation

**Windows only** — this server requires `xperf.exe` which is a Windows-only tool.

```powershell
# 1. Install prerequisites — skip any you already have
winget install astral-sh.uv              # Python package manager
winget install Microsoft.WindowsSDK      # Includes xperf.exe (Windows Performance Toolkit)

# 2. Clone and verify
git clone https://github.com/nijosmsft/wpr-mcp-server.git
cd wpr-mcp-server
uv run python -m etw_analyzer.server     # verify it starts (Ctrl+C to stop)
```

- **uv** automatically downloads Python, creates a virtual environment, and installs all dependencies on first run. No separate Python install needed.
- **xperf.exe** is installed as part of the Windows Performance Toolkit (included in the Windows SDK). Expected location: `C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe`

## Setup

Configure your AI assistant to use the server:

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
"Give me a summary of this trace"
"Where is CPU time being spent?"
"What's running on CPU 0?"
"Which CPUs have echo_server active?"
"Show me the hottest functions in tcpip.sys"
"What are the DPC durations for the NIC driver?"
"Which CPUs are active and which are idle?"
"Is there lock contention in the networking stack?"
"Compare this trace with the baseline"
"Export the analysis to a markdown file"
"What hardware is this trace from?"
"Which processes were running during the trace?"
```

### Workflow

```
load_trace(path)     → Parse ETL via xperf, cache as parquet (30-180s first time, instant after)
analyze()            → One-call comprehensive report
detailed tools       → Drill into specific areas
export_analysis()    → Save to .md for sharing
```

### Available Tools

#### Trace Management

| Tool | Purpose |
|------|---------|
| `list_traces` | Find `.etl` files in a directory |
| `load_trace` | Load an ETL file. Runs xperf in parallel, caches as parquet. Set `force=True` to re-export. |
| `trace_info` | Show loaded trace metadata |
| `check_symbols` | Check symbol resolution status, identify missing PDBs |
| `resolve_symbols` | Download PDBs from symbol servers and reload trace |

#### Analysis

| Tool | Purpose |
|------|---------|
| `analyze` | One-call comprehensive report: sysconfig, per-CPU, hot functions, symbols, DPC health |
| `get_cpu_samples` | CPU sampling grouped by process, module, function, or CPU. Per-CPU filtering supported. |
| `get_hot_functions` | Hot functions filtered to networking modules (customizable). Per-CPU filtering supported. |
| `get_per_cpu_summary` | Per-CPU utilization with role classification (saturated/active/idle) |
| `get_cpu_timeline` | Per-CPU utilization over time with hot CPU identification |
| `get_hot_stacks` | Call stack tree with inclusive/exclusive weights |
| `get_function_callers` | Who calls a function and what it calls |
| `get_dpc_summary` | DPC/ISR duration histogram per module with watchdog risk assessment |
| `get_dpc_per_cpu` | Per-CPU DPC breakdown |
| `get_lock_contention` | Spinlock contention from ReadyThread stacks |
| `get_memory_pools` | Kernel pool allocations by module and tag |

#### System & Process Info

| Tool | Purpose |
|------|---------|
| `get_sysconfig` | CPU model, core count, memory, NIC details, disk config from trace |
| `get_process_info` | Running processes, command lines, loaded images. Filterable by process name. |
| `get_diskio_summary` | Per-file disk I/O counts, bytes, and latency |
| `get_trace_stats` | Which ETW providers/events are in the trace. Diagnose missing data. |

#### Comparison & Export

| Tool | Purpose |
|------|---------|
| `compare_traces` | Diff two traces: hot functions, modules, or per-CPU utilization. Shows delta. |
| `export_analysis` | Save the auto-summary analysis to a .md file for sharing |

### Common Parameters

Most analysis tools accept:

- `cpu_filter` — CPU range, e.g. `"0"` or `"18-39"`. Enables per-CPU extraction from raw events.
- `start_time` / `end_time` — seconds from trace start
- `module_filter` — substring match, e.g. `"tcpip.sys"`
- `process_filter` — substring match, e.g. `"echo_server"`
- `max_rows` — limit output rows

## Architecture

```
AI Assistant ←stdio→ wpr-mcp-server (Python)
                         │
                         ├── xperf.exe (9 parallel actions on load)
                         │   ├── profile -detail   → CPU sampling (module!function)
                         │   ├── profile -util     → Per-CPU utilization timeline
                         │   ├── dpcisr            → DPC/ISR histograms
                         │   ├── stack -butterfly   → Call stacks with callers/callees
                         │   ├── cswitch           → Context switch data
                         │   ├── sysconfig         → Hardware configuration
                         │   ├── process           → Process/thread/image info
                         │   ├── diskio            → Disk I/O summary
                         │   ├── tracestats        → Trace metadata
                         │   └── dumper            → Raw events (on-demand, cached)
                         │
                         ├── parquet cache (.etw-export-<name>/)
                         │   Structured data saved as .parquet for instant reload.
                         │   Raw text saved as .txt. Cache invalidated when ETL is newer.
                         │
                         ├── pandas (aggregation + filtering)
                         └── FastMCP (stdio transport)
```

### Performance

- **First load:** 30-180s (9 xperf actions run in parallel with 4 workers)
- **Subsequent loads:** Instant (reads from parquet cache)
- **Per-CPU queries:** First query parses all SampledProfile events (~30s), subsequent queries filter in-memory (<1s)
- **Trace comparison:** Uses cache from both traces — instant if both were previously loaded

## Project Structure

```
wpr-mcp-server/
├── pyproject.toml
├── README.md
├── LICENSE
├── tests/                           ← 71 tests (synthetic data, no xperf needed)
└── src/etw_analyzer/
    ├── server.py                    ← MCP server entry point
    ├── app.py                       ← FastMCP instance
    ├── trace_state.py               ← Global trace cache + dumper cache
    ├── tools/
    │   ├── trace_mgmt.py            ← load_trace, list_traces, check/resolve_symbols
    │   ├── cpu_sampling.py          ← get_cpu_samples, get_hot_functions
    │   ├── per_cpu.py               ← get_per_cpu_summary, get_cpu_timeline
    │   ├── stack_analysis.py        ← get_hot_stacks, get_function_callers
    │   ├── dpc_isr.py               ← get_dpc_summary, get_dpc_per_cpu
    │   ├── context_switch.py        ← get_lock_contention
    │   ├── memory.py                ← get_memory_pools
    │   ├── system_info.py           ← get_sysconfig, get_process_info, get_diskio_summary, get_trace_stats
    │   ├── compare.py               ← compare_traces
    │   └── summary.py               ← analyze, export_analysis
    ├── parsing/
    │   ├── wpa_exporter.py          ← xperf subprocess wrapper + output parsers
    │   ├── csv_loader.py            ← CSV parsing + normalization
    │   └── aggregator.py            ← Filters, group-by, percentiles
    └── formatting/
        └── markdown.py              ← Table formatting for MCP responses
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

## Development

### Running Tests

```powershell
uv run --group dev pytest tests/ -v
```

Tests use synthetic data and don't require `xperf.exe` or ETL trace files.

## Contributing

Contributions welcome. Please open an issue first to discuss what you'd like to change.

## License

[MIT](LICENSE)
