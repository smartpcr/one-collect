# Usage Guide Expert

Expert on practical usage patterns, examples, and common workflows for the one_collect framework.

## Quick Start Guide

### Basic CPU Profiling

Simplest use case - track CPU usage per core:

```rust
use one_collect::perf_event::*;
use one_collect::sharing::Writable;

fn main() -> anyhow::Result<()> {
    // Configure profiling at 1000Hz
    let freq = 1000;
    let cpu = RingBufBuilder::for_profiling(freq);

    // Create session with ring buffer
    let mut session = RingBufSessionBuilder::new()
        .with_page_count(4)
        .with_profiling_events(cpu)
        .build()?;

    // Shared state for tracking
    let util = Writable::new(HashMap::new());
    let session_util = util.clone();

    // Register callback
    session.cpu_profile_event()
        .add_callback(move |_| {
            session_util.write(|map| {
                let cpu = /* get cpu from data */;
                *map.entry(cpu).or_insert(0) += 1;
            });
            Ok(())
        });

    // Profile for duration
    session.enable()?;
    std::thread::sleep(Duration::from_secs(10));
    session.disable()?;
    session.parse_all()?;

    // Print results
    util.read(|map| {
        for (cpu, count) in map.iter() {
            println!("CPU {}: {} samples", cpu, count);
        }
    });

    Ok(())
}
```

**Key concepts**:
- `RingBufBuilder`: Configures what to profile
- `RingBufSessionBuilder`: Creates the session
- `Writable<T>`: Shares state between callback and main thread
- `enable()/disable()`: Controls data collection
- `parse_all()`: Processes accumulated events

### Event Processing with State

Track process names and events:

```rust
use one_collect::perf_event::*;
use one_collect::sharing::Writable;
use std::collections::HashMap;

fn main() -> anyhow::Result<()> {
    // Create session with context switch tracking
    let switch_builder = RingBufBuilder::for_cswitches();
    let mut session = RingBufSessionBuilder::new()
        .with_kernel_events(switch_builder)
        .build()?;

    // Track process names
    let comm_map: HashMap<u32, String> = HashMap::new();
    let state = Writable::new(comm_map);

    // Extract field references once (performance)
    let comm_event = session.comm_event();
    let pid_ref = comm_event.format().get_field_ref_unchecked("pid");
    let name_ref = comm_event.format().get_field_ref_unchecked("comm[]");

    // Register callback for process name events
    let comm_state = state.clone();
    comm_event.add_callback(move |data| {
        let pid = data.format().get_u32(pid_ref, data.event_data())?;
        let name = data.format().get_str(name_ref, data.event_data())?;

        comm_state.write(|map| {
            map.insert(pid, name.to_string());
        });
        Ok(())
    });

    // Track context switches
    let switch_count = Writable::new(HashMap::new());
    let switch_state = switch_count.clone();
    let switch_comm_map = state.clone();

    session.sched_switch_event()
        .add_callback(move |data| {
            let prev_pid = /* extract from data */;

            switch_state.write(|counts| {
                *counts.entry(prev_pid).or_insert(0) += 1;
            });
            Ok(())
        });

    // Run profiling
    session.enable()?;
    std::thread::sleep(Duration::from_secs(10));
    session.disable()?;
    session.parse_all()?;

    // Report results
    switch_count.read(|counts| {
        state.read(|names| {
            for (pid, count) in counts.iter() {
                let name = names.get(pid).map(|s| s.as_str()).unwrap_or("unknown");
                println!("{} ({}): {} switches", name, pid, count);
            }
        });
    });

    Ok(())
}
```

**Key concepts**:
- Multiple event types in one session
- Field references for performance (`get_field_ref_unchecked`)
- Shared state across multiple callbacks
- Coordinating data from multiple events

### Full Export Pipeline

Capture, process, resolve symbols, and export:

```rust
use one_collect::helpers::exporting::*;

fn main() -> anyhow::Result<()> {
    // Configure what to capture
    let settings = ExportSettings::default()
        .with_cpu_profiling(1000)  // 1000Hz CPU profiling
        .with_cswitches()           // Context switches
        .with_duration(Duration::from_secs(30));

    // Create universal exporter
    let universal = UniversalExporter::new(settings);

    // Capture trace
    println!("Capturing 30 second trace...");
    let exporter = universal.parse_for_duration("my_app", Duration::from_secs(30))?;

    // Resolve symbols
    println!("Resolving symbols...");
    let mut exporter = exporter.borrow_mut();
    exporter.capture_and_resolve_symbols();

    // Export to multiple formats
    let cpu_samples = exporter.find_sample_kind("cpu")?;
    let processes = exporter.split_processes_by_comm();

    // Export each process to PerfView format
    let mut graph = ExportGraph::new();
    for (comm_id, pids) in processes {
        let comm_name = exporter.get_interned_string(comm_id);

        for pid in pids {
            let process = exporter.get_process(pid)?;

            graph.reset();
            graph.add_samples(&exporter, process, cpu_samples, None);

            let filename = format!("{}_{}.perfview.xml", comm_name, pid);
            graph.to_perf_view_xml(&filename)?;
            println!("Wrote: {}", filename);
        }
    }

    // Also export to pprof format
    for (comm_id, pids) in processes {
        for pid in pids {
            let process = exporter.get_process(pid)?;

            graph.reset();
            graph.add_samples(&exporter, process, cpu_samples, None);

            let filename = format!("{}_{}.pb.gz", comm_name, pid);
            graph.to_pprof(&filename)?;
            println!("Wrote: {}", filename);
        }
    }

    Ok(())
}
```

**Key concepts**:
- `ExportSettings`: Configures capture
- `UniversalExporter`: High-level export API
- `capture_and_resolve_symbols()`: Resolves ELF/PE symbols
- `ExportGraph`: Aggregates samples
- Multiple output formats: PerfView, pprof, nettrace

## Common Usage Patterns

### Pattern 1: Filtering Samples

Filter samples by attributes:

```rust
// Add samples with filter
let filter = Some(|attrs: &ExportAttributes| {
    attrs.get("thread_name")
        .map(|name| name == "worker_thread")
        .unwrap_or(false)
});

graph.add_samples(&exporter, process, sample_kind, filter);
```

### Pattern 2: Custom Metrics

Define custom metric types:

```rust
use one_collect::helpers::exporting::MetricValue;

// Create metric extraction closure
let metric_fn = |data: &EventData| -> anyhow::Result<MetricValue> {
    let bytes = data.format().get_u64(bytes_ref, data.event_data())?;
    Ok(MetricValue::Bytes(bytes))
};

// Use in export sampler
sampler.set_metric_converter(metric_fn);
```

### Pattern 3: Per-Process Symbol Resolution

Resolve symbols only for specific processes:

```rust
// Get process list
let processes = exporter.get_all_processes();

// Selectively resolve
for process in processes {
    if process.get_pid() == target_pid {
        exporter.resolve_symbols_for_process(process)?;
    }
}
```

### Pattern 4: Callstack Collection

Collect and aggregate callstacks:

```rust
// Enable callstack collection
let mut sampler = ExportSampler::new();
sampler.enable_callstack_collection();

// Register with event
event.add_callback(move |data| {
    let callstack = extract_callstack(data)?;
    sampler.add_sample_with_callstack(
        timestamp,
        value,
        callstack,
        attributes,
    );
    Ok(())
});
```

### Pattern 5: Time-Range Filtering

Filter samples by time range:

```rust
use one_collect::helpers::exporting::ExportSpan;

let start_time = 1000000;  // nanoseconds
let end_time = 2000000;
let time_span = ExportSpan::new(start_time, end_time);

// Filter samples in time range
graph.add_samples_in_range(&exporter, process, sample_kind, time_span, None);
```

### Pattern 6: Attribute Chaining

Chain attributes for hierarchical context:

```rust
// Create process-level attributes
let process_attrs = ExportAttributes::new();
process_attrs.insert("process", "my_app");
process_attrs.insert("pid", "12345");

// Create thread-level attributes
let thread_attrs = ExportAttributes::new();
thread_attrs.insert("thread", "worker_1");
thread_attrs.insert("tid", "12346");

// Associate thread with process
thread_attrs.associate(process_attrs.clone());

// Thread attributes now include process attributes
thread_attrs.walk(|key, value| {
    println!("{} = {}", key, value);
    // Output includes both thread and process attributes
});
```

### Pattern 7: Dynamic Event Configuration

Configure events at runtime:

```rust
let mut session_builder = RingBufSessionBuilder::new();

// Add profiling conditionally
if config.enable_cpu_profiling {
    let cpu = RingBufBuilder::for_profiling(config.frequency);
    session_builder = session_builder.with_profiling_events(cpu);
}

// Add context switches conditionally
if config.track_switches {
    let switches = RingBufBuilder::for_cswitches();
    session_builder = session_builder.with_kernel_events(switches);
}

let mut session = session_builder.build()?;
```

## Advanced Patterns

### Custom Data Source

Implement custom data source for testing or replay:

```rust
use one_collect::perf_event::PerfDataSource;

struct ReplayDataSource {
    data: Vec<u8>,
    position: usize,
}

impl PerfDataSource for ReplayDataSource {
    fn read_data(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.data.len() - self.position;
        let to_read = std::cmp::min(buf.len(), remaining);

        if to_read == 0 {
            return Ok(0);
        }

        buf[..to_read].copy_from_slice(
            &self.data[self.position..self.position + to_read]
        );
        self.position += to_read;
        Ok(to_read)
    }

    fn get_id(&self) -> u64 {
        self.id
    }
}

// Use custom source
let source = Box::new(ReplayDataSource::from_file("trace.dat")?);
session.add_data_source(source)?;
```

### Custom Export Format

Add custom export format:

```rust
use one_collect::helpers::exporting::{ExportGraph, ExportMachine};

// Extend ExportGraph with custom format
trait CustomFormat {
    fn to_custom_format(&self, path: &str) -> anyhow::Result<()>;
}

impl CustomFormat for ExportGraph {
    fn to_custom_format(&self, path: &str) -> anyhow::Result<()> {
        let mut file = File::create(path)?;

        // Write custom format header
        writeln!(file, "CUSTOM_FORMAT_V1")?;

        // Iterate samples
        for sample in self.iter_samples() {
            // Write sample in custom format
            writeln!(file, "{},{},{}",
                sample.timestamp,
                sample.value,
                sample.callstack
            )?;
        }

        Ok(())
    }
}

// Use custom format
graph.to_custom_format("output.custom")?;
```

### Scripting Integration (Feature: "scripting")

Use Rhai scripts for custom processing:

```rust
#[cfg(feature = "scripting")]
use one_collect::scripting::*;

#[cfg(feature = "scripting")]
fn process_with_script() -> anyhow::Result<()> {
    let script = r#"
        fn process_sample(timestamp, value, callstack) {
            if value > 1000 {
                print("High value sample: " + value);
            }
        }
    "#;

    let engine = ScriptEngine::new();
    engine.load_script(script)?;

    // Use script in callback
    event.add_callback(move |data| {
        let timestamp = extract_timestamp(data)?;
        let value = extract_value(data)?;

        engine.call_function("process_sample", (timestamp, value))?;
        Ok(())
    });

    Ok(())
}
```

## Performance Tips

### 1. Extract Field References Once

```rust
// GOOD: Extract once, use many times
let pid_ref = format.get_field_ref_unchecked("pid");
for _ in 0..1000000 {
    let pid = format.get_u32(pid_ref, data)?;
}

// BAD: Lookup every time
for _ in 0..1000000 {
    let pid = format.get_field("pid")?.get_u32(data)?;
}
```

### 2. Use Appropriate Ring Buffer Size

```rust
// Small workload: 4 pages (16KB)
.with_page_count(4)

// Medium workload: 128 pages (512KB)
.with_page_count(128)

// High frequency: 1024 pages (4MB)
.with_page_count(1024)
```

### 3. Enable Interning for Large Captures

```rust
// Interning saves memory for repetitive data
let exporter = ExportMachine::new()
    .with_string_interning()
    .with_callstack_interning();
```

### 4. Batch Symbol Resolution

```rust
// Resolve all at once (parallelizable)
exporter.capture_and_resolve_symbols();

// Instead of per-sample (slow)
for sample in samples {
    resolve_symbols_for_sample(sample);  // Don't do this
}
```

### 5. Use Read-Only References

```rust
// If callback doesn't mutate, use ReadOnly
let readonly_state = state.to_read_only();

event.add_callback(move |data| {
    readonly_state.read(|map| {
        // Can't accidentally mutate
    });
    Ok(())
});
```

## Common Pitfalls

### Pitfall 1: Holding RefCell Borrows

```rust
// DON'T: Holding borrow across operations
let borrow = state.borrow();
process_events();  // Might panic if events try to borrow

// DO: Use read/write closures
state.read(|data| {
    // Borrow held only in closure
});
```

### Pitfall 2: Not Parsing Events

```rust
// DON'T: Forget to parse
session.enable()?;
std::thread::sleep(duration);
session.disable()?;
// Missing: session.parse_all()?;

// DO: Always parse after collection
session.enable()?;
std::thread::sleep(duration);
session.disable()?;
session.parse_all()?;  // This executes callbacks
```

### Pitfall 3: Dropping Event References

```rust
// DON'T: Field reference from wrong format
let wrong_ref = other_format.get_field_ref("pid")?;
let value = event_format.get_u32(wrong_ref, data)?;  // Wrong!

// DO: Use matching format
let correct_ref = event_format.get_field_ref("pid")?;
let value = event_format.get_u32(correct_ref, data)?;
```

### Pitfall 4: Insufficient Ring Buffer

```rust
// DON'T: Too small for high-frequency events
RingBufSessionBuilder::new()
    .with_page_count(1)  // Only 4KB, will drop events
    .with_profiling_events(RingBufBuilder::for_profiling(10000))

// DO: Size appropriately
RingBufSessionBuilder::new()
    .with_page_count(512)  // 2MB for high frequency
    .with_profiling_events(RingBufBuilder::for_profiling(10000))
```

### Pitfall 5: Ignoring Errors

```rust
// DON'T: Ignore Result
session.parse_all();  // Warning: unused Result

// DO: Handle errors
if let Err(e) = session.parse_all() {
    eprintln!("Parse error: {}", e);
}
```

## Debugging Tips

### Enable Tracing

```rust
use tracing_subscriber;

// Enable logging
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();

// Now framework logs will be visible
```

### Check for Dropped Events

```rust
// Monitor for event loss
let stats = session.get_statistics()?;
if stats.dropped_events > 0 {
    eprintln!("Warning: {} events dropped", stats.dropped_events);
    eprintln!("Consider increasing page_count");
}
```

### Validate Field References

```rust
// Use checked methods during development
let field = format.get_field_ref("pid")?;  // Returns Result

// Switch to unchecked in production hot paths
let field = format.get_field_ref_unchecked("pid");  // Panics if missing
```

### Print Event Data

```rust
event.add_callback(|data| {
    println!("Event data: {:?}", data.event_data());
    println!("Full data: {:?}", data.full_data());
    Ok(())
});
```

## Examples Reference

- **perf_cpu.rs**: Basic CPU profiling with utilization tracking
- **perf_switch.rs**: Context switch tracking with JSON output
- **perf_export.rs**: Full pipeline with symbol resolution and export
- **perf_bpf.rs**: BPF program integration
- **uprobe_allocs.rs**: Userspace probe for allocation tracking

Each example demonstrates progressively more complex usage patterns.
