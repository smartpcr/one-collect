# Architecture Expert

Expert on the one_collect framework architecture, system design, and component interactions.

## Core Architecture Overview

### Multi-Stage Pipeline Architecture

The framework follows a sophisticated multi-stage pipeline:

```
Raw Events → PerfSession → Event Processing → Export Machine → Output Formats
```

#### Stage 1: Data Collection (`perf_event/mod.rs`)
- **PerfSession**: Core session managing ring buffers and event routing
- **PerfDataSource**: Abstract trait for data sources (ring buffers, mock data)
- **AncillaryData**: Metadata (CPU, attributes) shared via `Writable<T>` pattern
- Platform-specific: Linux uses perf_event, Windows uses ETW

#### Stage 2: Event Processing
- Events registered with callbacks process raw data
- Field references allow efficient data extraction without copying
- Errors collected in vectors for batch reporting
- Zero-copy design: data references stay in ring buffer

#### Stage 3: Export Machine (`helpers/exporting/mod.rs`)
- **ExportMachine**: Central state manager for profiling data
  - String interning via `InternedStrings`
  - Callstack interning via `InternedCallstacks`
  - Process tracking with `ExportProcess`
  - Sample aggregation with filtering hooks
- **ExportSampler**: Per-event sampling context with callstack collection
- **ExportTraceContext**: Per-trace context exposing event data to callbacks

#### Stage 4: Export Formats (`helpers/exporting/formats/`)
- Graph-based aggregation (`ExportGraph`)
- Multiple output formats: PerfView XML, pprof, nettrace
- Per-process or multi-process exports

### Key Architectural Components

#### Event System (`event/mod.rs`)

**Event Structure**:
- **EventFormat**: Defines schema for event data with dynamic field parsing
- **EventField**: Represents individual fields with location types (Static, Dynamic, StaticString)
- **EventData**: Wrapper providing access to event payload with associated format
- **Event**: Container holding callbacks, format, and OS-specific extensions

**Field Access Pattern**:
- **DataFieldRef**: Copy-on-write reference using `Rc<Cell<DataField>>` allowing multiple consumers to share and observe field updates
- **EventFieldRef**: Lightweight index-based reference to fields in EventFormat
- **Closure-based field access**: Dynamic closures for runtime field extraction and filtering

#### String and Data Interning (`intern.rs`)
- **InternedSlices<T>**: Generic intern pool using hash buckets
- XxHash64 for fast hashing
- Deduplicated storage with ID-based lookup
- **InternedStrings**: Specialized for UTF-8 strings
- **InternedCallstacks**: Specialized for u64 frame arrays
- **Performance benefit**: Massive memory savings for repeated strings/callstacks

#### Export Process Model (`helpers/exporting/process.rs`)
- **ExportProcess**: Per-process container with samples, mappings, symbols
- **ExportProcessSample**: Individual sample with time, value, callstack, attributes
- **ExportMapping**: Memory mapping info with symbol resolution
- **MetricValue**: Tagged union for different value types (Count, Duration, Bytes, Span)
- **ExportAttributes**: Key-value attributes attached to samples
- **ExportSpan**: Time range for duration-based metrics

#### Symbol Resolution
- OS-specific implementations:
  - Linux: ELF files via `ruwind` crate
  - Windows: PE files
- Lazy resolution with `OnceCell`
- Support for file-backed symbols and anonymous mappings
- Dynamic symbol injection for JIT scenarios (C#, Java)

### Data Flow Patterns

#### Callback Registration Pattern
```rust
// Events support multiple callbacks
pub fn add_callback(&mut self, callback: impl FnMut(&EventData) -> anyhow::Result<()> + 'static)
```

Events use callback registration during setup, then invoke callbacks when data arrives. This enables:
- Declarative event handling
- Multiple consumers per event
- Separation of data collection and processing

#### Shared State Pattern
Uses `Writable<T>` / `ReadOnly<T>` for shared ownership:

```rust
let state = Writable::new(HashMap::new());
let callback_state = state.clone();

event.add_callback(move |data| {
    callback_state.write(|map| {
        // Mutate shared state
    });
    Ok(())
});
```

#### Field Reference Pattern
Extract field references once, use many times:

```rust
// Extract field references during setup
let pid_field = event.format().get_field_ref_unchecked("pid");
let comm_field = event.format().get_field_ref_unchecked("comm[]");

// Use in callback (no lookup overhead)
event.add_callback(move |data| {
    let pid = data.format().get_u32(pid_field, data.event_data())?;
    let name = data.format().get_str(comm_field, data.event_data())?;
    Ok(())
});
```

### Architectural Decisions and Rationale

1. **Zero-Copy Event Processing**
   - **Why**: Minimize overhead in hot path
   - **How**: Field references and closures avoid copying event data
   - **Tradeoff**: More complex API, but much better performance

2. **Deferred Symbol Resolution**
   - **Why**: Symbol resolution is expensive
   - **How**: Symbols resolved lazily when needed via `OnceCell`
   - **Benefit**: Faster capture, pay only for what you use

3. **Interning for Deduplication**
   - **Why**: Massive memory savings (strings/callstacks are highly repetitive)
   - **How**: Hash-based intern pools with XxHash64
   - **Result**: 10-100x memory reduction in typical profiles

4. **Type-Safe Shared Ownership**
   - **Why**: Rust's borrow checker makes callbacks difficult
   - **How**: `Writable<T>`/`ReadOnly<T>` wrapper around `Rc<RefCell<T>>`
   - **Benefit**: Type safety, clear ownership, easy to use in closures

5. **OS Abstraction**
   - **Why**: Support Linux and Windows with different primitives
   - **How**: Platform-specific code isolated in `os/` modules
   - **Implementation**: `#[cfg(target_os)]` conditional compilation

6. **Trait-Based Extensibility**
   - **Why**: Allow custom implementations
   - **Key traits**: `PerfDataSource`, `ExportSymbolReader`, `ExportAttributeSource`
   - **Usage**: Custom unwinders, symbol sources, data sources

7. **Builder Pattern Everywhere**
   - **Why**: Complex objects with many optional parameters
   - **Examples**: `RingBufSessionBuilder`, `UniversalExporter`
   - **Benefit**: Fluent API, type-safe construction

8. **Error Handling Strategy**
   - **Why**: Need flexibility and context
   - **How**: `anyhow::Result` for flexibility, error collection in vectors
   - **Pattern**: Collect errors during batch processing, report at end

### Component Relationships

```
┌─────────────────────────────────────────────────────────────┐
│                      PerfSession                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ Ring Buffer  │  │ Ring Buffer  │  │ Ring Buffer  │       │
│  │   (CPU 0)    │  │   (CPU 1)    │  │   (CPU N)    │       │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────┘       │
└─────────┼─────────────────┼───────────────────┼─────────────┘
          │                 │                   │
          └─────────────────┴───────────────────┘
                            │
                    ┌───────▼─────────┐
                    │  Event System   │
                    │  - EventFormat  │
                    │  - Callbacks    │
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
   ┌──────▼───────┐  ┌──────▼───────┐  ┌──────▼───────┐
   │  User        │  │  Export      │  │  Custom      │
   │  Callbacks   │  │  Machine     │  │  Handlers    │
   └──────────────┘  └───────┬──────┘  └──────────────┘
                             │
                    ┌────────▼────────┐
                    │ ExportProcess   │
                    │ - Samples       │
                    │ - Mappings      │
                    │ - Symbols       │
                    └────────┬────────┘
                             │
          ┌──────────────────┼────────────────┐
          │                  │                │
   ┌──────▼───────┐  ┌──────▼───────┐  ┌──────▼───────┐
   │  PerfView    │  │    pprof     │  │  nettrace    │
   │     XML      │  │    proto     │  │    format    │
   └──────────────┘  └──────────────┘  └──────────────┘
```

### Performance Optimizations

1. **Hash-based interning**: Power-of-two buckets for fast lookup
2. **Pre-computed closures**: Hot paths use pre-generated closures
3. **Batch error reporting**: Collect errors, report once
4. **Configurable buffer sizes**: Tune ring buffer sizes for workload
5. **Lazy initialization**: Use `OnceCell` for expensive one-time setup
6. **Zero-copy parsing**: Field references point into ring buffer

### Extension Points

When extending the framework:

1. **Custom Data Sources**: Implement `PerfDataSource` trait
2. **Custom Unwinders**: Hook into unwinding pipeline
3. **Custom Export Formats**: Extend `ExportGraph` or `ExportMachine`
4. **Custom Attributes**: Implement `ExportAttributeSource` trait
5. **Custom Symbol Resolution**: Implement `ExportSymbolReader` trait

### Common Pitfalls

1. **Holding RefCell borrows**: Don't hold `borrow()` or `borrow_mut()` across callbacks
2. **Field reference invalidation**: Get field refs from `EventFormat`, not `EventData`
3. **Ring buffer overflow**: Increase page count if dropping events
4. **Memory usage**: Enable interning for large captures
5. **Symbol resolution timing**: Capture first, resolve symbols later

### References

- Event system architecture: `EVENTS.md`
- Sharing pattern details: `SHARING.md`
- Example usage: `one_collect/examples/`
- Export formats: `one_collect/src/helpers/exporting/formats/`
