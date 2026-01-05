# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Session Context

take a look at Claude.md file, make sure all prompts take context from files under docs folder as well as docs under .claude/agents, and remember to keep prompt history following templates under .claude/prompts

## Documentation Context

For comprehensive understanding of this codebase, consult the following documentation:

### Design Documents (`docs/`)
- **`docs/one_collect-design.md`** - Core library architecture, event pipeline, export system, platform abstraction
- **`docs/record-trace-design.md`** - CLI tool design, command-line interface, export coordination
- **`docs/ruwind-design.md`** - Stack unwinding library, DWARF support, JIT code handling

### Expert Guides (`.claude/agents/`)
- **`architecture-expert.md`** - System design, component interactions, multi-stage pipeline architecture
- **`design-patterns-expert.md`** - Core patterns (closures, sharing, interning, builder, field references)
- **`testing-expert.md`** - Testing strategies, mock patterns, test organization
- **`usage-guide-expert.md`** - Practical usage patterns, common workflows, performance tips

### Tracing Guidelines
- **`.github/agents/tracing-expert.md`** - Log level guidelines for the `tracing` crate

### Prompt History (`.claude/prompts/`)
Track significant sessions and decisions in `.claude/prompts/` following the templates in `README.md`:
- **`sessions/`** - Individual session logs (format: `YYYY-MM-DD_description.md`)
- **`patterns/`** - Reusable prompt patterns
- **`decisions/`** - Major technical decisions

## Repository Structure

This is a Rust-based framework for collecting event and profiling data on Linux and Windows. The repository contains multiple workspace crates:

- **one_collect/** - Core library for cross-platform event/profiling data collection
- **record-trace/** - CLI tool built on one_collect for recording traces
  - **record-trace/engine/** - Core engine for the CLI tool
  - **record-trace/ffi/** - FFI bindings for other languages
- **ruwind/** - Callstack unwinding library (DWARF-based on Linux)

## Building and Testing

Each crate must be built and tested from its own directory:

```bash
# Build all crates
cd one_collect && cargo build
cd ../record-trace && cargo build
cd ../ruwind && cargo build

# Run tests for all crates
cd one_collect && cargo test
cd ../record-trace && cargo test
cd ../ruwind && cargo test

# Release builds
cargo build --release

# Run benchmarks (from one_collect directory)
cargo bench
```

To run a single test:
```bash
# From the appropriate crate directory
cargo test test_name
cargo test test_name -- --nocapture  # With output
```

**Note on Cargo.lock:** If you encounter a "lock file version 4 requires `-Znext-lockfile-bump`" error, the lock files were created with Rust nightly. Delete the `Cargo.lock` files and rebuild to regenerate them with your current Rust version:
```bash
rm one_collect/Cargo.lock record-trace/engine/Cargo.lock
cd one_collect && cargo build
```

## Architecture Overview

### Event Pipeline Architecture

The framework is built around a composable **event pipeline** system:

1. **Events** (`one_collect/src/event/`) - Contain format details and registered closures
2. **Data arrives** from sources (perf_event on Linux, ETW on Windows)
3. **Closures execute** when event data is available
4. **Pipelines compose** - base pipelines expose events for building higher-level functionality

Key architectural pattern:
- `Event` → `EventFormat` → `EventField` (describes data structure)
- `EventFieldRef` (usize index) - efficiently access fields in closures without scanning
- `DataFieldRef` - shared objects for accessing full event data (e.g., from perf_event ring buffer)

See `EVENTS.md` for detailed event system architecture.

### Platform-Specific Data Sources

- **Linux**: `one_collect/src/perf_event/` - perf events facility
- **Windows**: `one_collect/src/etw/` - Event Tracing for Windows

### Export System

Export functionality (`one_collect/src/helpers/exporting/`) processes traces into various formats:

- **ExportGraph** - Per-process/per-comm export pipeline
- **ExportMachine** - Multi-process export aggregation
- Formats in `one_collect/src/helpers/exporting/formats/`:
  - `perf_view.rs` - perf_view format
  - `pprof.rs` - pprof/profile.proto format
  - `nettrace.rs` - nettrace format

### Unwinding

The `ruwind` crate provides x64 callstack unwinding:
- **Linux**: Live DWARF decoding with support for JIT code (C#/Java anonymous sections)
- Scans for x64 calling conventions when DWARF unavailable
- Custom unwinders can hook into the same pipeline

## Adding New Export Formats

To add a new export format (e.g., "my_format"):

1. Create `one_collect/src/helpers/exporting/formats/my_format.rs`
2. Add trait extending `ExportGraph` with method `to_my_format()`
3. For multi-process formats, also extend `ExportMachine`
4. See `perf_view.rs` and `pprof.rs` as reference implementations

## Tracing Guidelines

This codebase uses the `tracing` crate with specific level guidelines (from `.github/agents/tracing-expert.md`):

### Log Levels

- **TRACE**: Very frequent operations (10+ times per flow) - unwinding frames, loop iterations
- **DEBUG**: Findings, branch decisions, state changes, file I/O with calculated offsets
- **WARN**: Error paths - log immediately before `return Err(...)` or setting error state
- **INFO**: High-level operation outcomes visible in production (enabled by default)
- **ERROR**: Critical system failures only

### Key Rules

1. **Log results, not function entry** - "Found X" not "Entering function"
2. **WARN before errors** - Always log context before returning Err or setting error state
3. **No duplicate logging** - Don't log same data at multiple levels at same call site
4. **Use structured format** - `key=value` pairs, hex for addresses: `offset={:#x}`

Example:
```rust
use tracing::{error, warn, info, debug, trace};

// WARN before error return
if fde_len < 8 {
    warn!("FDE too small: len={}", fde_len);
    return Err(error("FDE too small"));
}

// DEBUG for findings
debug!("Found build-id section: offset={:#x}, size={}", offset, size);

// INFO for high-level outcomes
info!("Load header retrieved successfully: p_offset={:#x}", p_offset);
```

## Platform Requirements

### Linux
- Some tests require root/sudo for perf events
- Kernel headers may be needed for full functionality
- Debug symbols improve unwinding accuracy

### Windows
- Elevated privileges required for ETW functionality
- Built-in Windows unwind functions used for x64

## CI/CD

GitHub Actions workflow (`.github/workflows/ci.yml`) runs:
- Linux builds (glibc and musl, debug and release)
- Windows builds (debug and release)
- Tests for all crates
- Benchmarks
- Docker tests

All crates are tested on both platforms and in both debug/release modes.
