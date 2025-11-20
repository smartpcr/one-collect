# Design Patterns Expert

Expert on design patterns and coding conventions used throughout the one_collect codebase.

## Core Design Patterns

### 1. Event-Driven Architecture Pattern

The entire framework is built around an event-driven model where events carry callbacks that execute when data arrives.

**Pattern Structure**:
```rust
// Event with multiple callbacks
pub struct Event {
    format: EventFormat,
    callbacks: Vec<Box<dyn FnMut(&EventData) -> anyhow::Result<()>>>,
    // ... other fields
}

// Registration
event.add_callback(move |data| {
    // Process event data
    Ok(())
});
```

**Key Characteristics**:
- Multiple callbacks per event (observer pattern)
- Callbacks registered during setup phase
- Executed synchronously when event fires
- Errors collected and reported in batch

**Usage Guidelines**:
- Extract field references before creating callbacks (performance)
- Use `move` closures to capture state
- Return `anyhow::Result` for error propagation
- Keep callbacks fast; defer expensive work

### 2. Closures Pattern (Higher-Order Functions)

Closures are extensively used for dynamic behavior with pre-computed optimization.

#### Field Access Closures

**Pattern**: Generate closures that extract data from variable-length event formats

```rust
// Returns closure for field access
pub fn try_get_field_data_closure(
    &self,
    field_ref: EventFieldRef,
) -> anyhow::Result<Box<dyn Fn(&[u8]) -> anyhow::Result<&[u8]>>> {
    // Pre-compute skip information
    let skips = self.build_field_skips(field_ref)?;

    // Return optimized closure
    Ok(Box::new(move |data: &[u8]| {
        // Use pre-computed skips for efficient traversal
    }))
}
```

**When to use**:
- Dynamic field access in callbacks
- Performance-critical hot paths
- Variable-length data structures

#### Field Filter Closures

**Pattern**: Generate predicate closures with pre-parsed values

```rust
pub fn try_get_field_filter_closure(
    &self,
    field_ref: EventFieldRef,
    operator: &str,
    value: &str,
) -> anyhow::Result<Box<dyn Fn(&[u8]) -> bool>> {
    // Pre-parse the comparison value
    let parsed_value = self.parse_value(field_ref, value)?;

    // Return optimized predicate
    Ok(Box::new(move |data: &[u8]| {
        // Compare using pre-parsed value
    }))
}
```

**Benefits**:
- Parse once, filter many times
- Type-aware comparisons
- No allocation in hot path

### 3. Sharing Pattern (Type-Safe Interior Mutability)

Custom wrapper around `Rc<RefCell<T>>` providing type-safe shared ownership.

**Pattern Definition** (`sharing.rs`):
```rust
#[derive(Clone)]
pub struct Writable<T>(Rc<RefCell<T>>);

#[derive(Clone)]
pub struct ReadOnly<T>(Rc<RefCell<T>>);

impl<T> Writable<T> {
    pub fn new(value: T) -> Self { /* ... */ }

    pub fn read<F, R>(&self, f: F) -> R
    where F: FnOnce(&T) -> R { /* ... */ }

    pub fn write<F, R>(&self, f: F) -> R
    where F: FnOnce(&mut T) -> R { /* ... */ }

    pub fn to_read_only(&self) -> ReadOnly<T> { /* ... */ }
}
```

**Usage Pattern**:
```rust
// Create shared state
let state = Writable::new(HashMap::new());

// Clone for callback
let callback_state = state.clone();

event.add_callback(move |data| {
    callback_state.write(|map| {
        map.insert(key, value);
    });
    Ok(())
});

// Later, read from main thread
state.read(|map| {
    println!("{:?}", map);
});
```

**When to use**:
- Sharing state between callbacks and main thread
- Ancillary data in sessions
- Accumulating results across events

**Safety Rules**:
- Use `read()` and `write()` methods (not `borrow()` directly)
- Don't hold borrows across callbacks
- Downgrade to `ReadOnly<T>` when mutation not needed

### 4. Builder Pattern

Used extensively for complex object construction with optional parameters.

**Standard Builder Pattern**:
```rust
pub struct RingBufSessionBuilder {
    page_count: Option<usize>,
    profiling_events: Vec<RingBufBuilder>,
    kernel_events: Vec<RingBufBuilder>,
    // ... other fields
}

impl RingBufSessionBuilder {
    pub fn new() -> Self { /* ... */ }

    pub fn with_page_count(mut self, count: usize) -> Self {
        self.page_count = Some(count);
        self
    }

    pub fn with_profiling_events(mut self, builder: RingBufBuilder) -> Self {
        self.profiling_events.push(builder);
        self
    }

    pub fn build(self) -> Result<PerfSession> {
        // Validate and construct
    }
}
```

**Usage Pattern**:
```rust
let session = RingBufSessionBuilder::new()
    .with_page_count(4)
    .with_profiling_events(cpu_builder)
    .with_kernel_events(kernel_builder)
    .build()?;
```

**When to create builders**:
- 3+ optional parameters
- Complex validation logic
- Multi-step construction process

### 5. Interning Pattern (Deduplication)

Hash-based interning for memory efficiency with large datasets.

**Pattern Structure** (`intern.rs`):
```rust
pub struct InternedSlices<T> {
    buckets: Vec<Vec<(Arc<[T]>, u64)>>,  // (data, hash)
    hasher: XxHash64,
}

impl<T: PartialEq> InternedSlices<T> {
    pub fn intern(&mut self, data: &[T]) -> (Arc<[T]>, u64) {
        let hash = self.hash(data);
        let bucket = &mut self.buckets[bucket_index(hash)];

        // Check if already interned
        for (existing, existing_hash) in bucket.iter() {
            if *existing_hash == hash && &**existing == data {
                return (Arc::clone(existing), *existing_hash);
            }
        }

        // Insert new
        let arc = Arc::from(data);
        bucket.push((Arc::clone(&arc), hash));
        (arc, hash)
    }
}
```

**Usage Pattern**:
```rust
let mut strings = InternedStrings::new();

// Intern many strings
let (str1, hash1) = strings.intern("repeated_string");
let (str2, hash2) = strings.intern("repeated_string");

assert!(Arc::ptr_eq(&str1, &str2));  // Same allocation
```

**When to use**:
- Repetitive strings (process names, file paths)
- Callstacks (highly repetitive)
- Large datasets with duplication

**Performance characteristics**:
- O(1) average lookup (hash table)
- O(n) worst case (hash collision)
- Power-of-two bucket count for fast modulo

### 6. Field Reference Pattern

Lightweight references to event fields using indices.

**Pattern Structure**:
```rust
// Opaque index type
#[derive(Copy, Clone)]
pub struct EventFieldRef(usize);

// Obtained from EventFormat
let field_ref = event_format.get_field_ref("field_name")?;

// Used for fast access
let value = event_format.get_u32(field_ref, data)?;
```

**Benefits**:
- No string lookups in hot path
- Copy-able (stack allocation)
- Type-safe (can't use wrong format)

**Usage Pattern**:
```rust
// Setup phase: extract references
let pid_ref = format.get_field_ref_unchecked("pid");
let tid_ref = format.get_field_ref_unchecked("tid");

// Hot path: use references (no lookup overhead)
for _ in 0..1000000 {
    let pid = format.get_u32(pid_ref, data)?;
    let tid = format.get_u32(tid_ref, data)?;
}
```

### 7. DataFieldRef Pattern (Shared Field Reference)

Copy-on-write field reference using `Rc<Cell<DataField>>`.

**Pattern Structure**:
```rust
#[derive(Clone)]
pub struct DataFieldRef(Rc<Cell<DataField>>);

impl DataFieldRef {
    pub fn get(&self) -> DataField {
        self.0.get()
    }

    pub fn set(&self, field: DataField) {
        self.0.set(field);
    }
}
```

**Usage Pattern**:
```rust
// Create and share
let field_ref = DataFieldRef::new(DataField { offset: 0, size: 4 });
let callback_ref = field_ref.clone();

// Pipeline updates the field
field_ref.set(DataField { offset: 8, size: 4 });

// Callback sees updated value
event.add_callback(move |data| {
    let field = callback_ref.get();  // Gets updated value
    let value = data.read_at(field.offset, field.size);
    Ok(())
});
```

**When to use**:
- Fields with dynamic offsets (perf_event attributes)
- Shared field definitions across callbacks
- Pipeline-managed field updates

### 8. Error Collection Pattern

Batch error collection for performance-critical loops.

**Pattern**:
```rust
let mut errors = Vec::new();

for item in large_collection {
    if let Err(e) = process_item(item) {
        errors.push(e);
    }
}

if !errors.is_empty() {
    return Err(anyhow!("Encountered {} errors: {:?}", errors.len(), errors));
}
```

**When to use**:
- Processing many events
- Batch operations
- Performance-critical loops where early exit is expensive

### 9. Trait-Based Extensibility

Define traits for key extension points.

**Common Traits**:
```rust
// Custom data sources
pub trait PerfDataSource {
    fn read_data(&mut self, buf: &mut [u8]) -> IOResult<usize>;
    fn get_id(&self) -> u64;
}

// Custom symbol readers
pub trait ExportSymbolReader {
    fn read_symbols(&mut self, mapping: &ExportMapping) -> Result<Vec<Symbol>>;
}

// Custom attribute sources
pub trait ExportAttributeSource {
    fn get_attributes(&self, sample: &ExportProcessSample) -> ExportAttributes;
}
```

**Implementation Pattern**:
```rust
// Implement for custom type
struct CustomDataSource { /* ... */ }

impl PerfDataSource for CustomDataSource {
    fn read_data(&mut self, buf: &mut [u8]) -> IOResult<usize> {
        // Custom implementation
    }

    fn get_id(&self) -> u64 {
        // Custom implementation
    }
}

// Use with framework
let source = Box::new(CustomDataSource::new());
session.add_data_source(source)?;
```

### 10. Lazy Initialization Pattern

Use `OnceCell` for expensive one-time initialization.

**Pattern**:
```rust
use std::cell::OnceCell;

pub struct CachedData {
    expensive_data: OnceCell<ExpensiveType>,
}

impl CachedData {
    pub fn get_data(&self) -> &ExpensiveType {
        self.expensive_data.get_or_init(|| {
            // Expensive computation happens once
            compute_expensive_data()
        })
    }
}
```

**When to use**:
- Symbol resolution (lazy per-process)
- File I/O (load on demand)
- Expensive computations with caching

## Coding Conventions

### Naming Conventions

1. **Builders**: `*Builder` suffix (e.g., `RingBufSessionBuilder`)
2. **Field references**: `*_ref` or `*_field` suffix (e.g., `pid_ref`, `comm_field`)
3. **Shared state**: `*_state` or descriptive name (e.g., `session_util`)
4. **Closures**: `*_closure` when returned from functions
5. **Interned data**: `Interned*` prefix (e.g., `InternedStrings`)

### Module Organization

```
src/
  event/           # Event system core
  helpers/         # High-level helpers
    exporting/     # Export pipeline
      formats/     # Export format implementations
    callstack/     # Callstack helpers
  perf_event/      # Linux perf events
  etw/             # Windows ETW
  os/              # OS-specific implementations
  intern.rs        # Interning utilities
  sharing.rs       # Sharing pattern types
```

### Error Handling

1. **Use `anyhow::Result`** for flexibility
2. **Collect errors in batches** for performance
3. **Log before returning errors** at WARN level (see tracing-expert)
4. **Include context** in error messages

### Performance Patterns

1. **Pre-compute outside closures**: Parse values, build skips
2. **Use field references**: Avoid string lookups in hot paths
3. **Intern repetitive data**: Strings, callstacks
4. **Batch operations**: Collect errors, process in bulk
5. **Zero-copy when possible**: Use references into ring buffer

### Testing Patterns

1. **Use `Arc<AtomicUsize>`** for callback verification
2. **Mock data sources** for deterministic testing
3. **Test closures separately** from event processing
4. **Integration via examples**: Examples double as integration tests

## Anti-Patterns to Avoid

1. **Holding RefCell borrows**: Don't use `.borrow()` across function calls
   ```rust
   // DON'T
   let borrow = state.borrow();
   do_something();  // Might try to borrow again

   // DO
   state.read(|data| {
       // Borrow held only in closure
   });
   ```

2. **String lookups in hot paths**: Use field references
   ```rust
   // DON'T
   for _ in 0..1000000 {
       let value = format.get_field("pid")?;  // String lookup each time
   }

   // DO
   let pid_ref = format.get_field_ref("pid")?;
   for _ in 0..1000000 {
       let value = format.get_u32(pid_ref, data)?;  // Index lookup
   }
   ```

3. **Cloning Arc unnecessarily**: Use references
   ```rust
   // DON'T
   fn process(data: Arc<Vec<u8>>) {  // Clones Arc

   // DO
   fn process(data: &Arc<Vec<u8>>) {  // Borrows Arc
   ```

4. **Early error returns in batch processing**: Collect errors
   ```rust
   // DON'T (loses partial results)
   for item in items {
       process(item)?;  // Stops on first error
   }

   // DO (collects all errors)
   let mut errors = Vec::new();
   for item in items {
       if let Err(e) = process(item) {
           errors.push(e);
       }
   }
   ```

## Pattern Selection Guide

| Requirement | Pattern | Example |
|-------------|---------|---------|
| Shared mutable state | Sharing Pattern | `Writable<HashMap>` |
| Complex construction | Builder Pattern | `RingBufSessionBuilder` |
| Dynamic field access | Closures Pattern | `try_get_field_data_closure` |
| Memory efficiency | Interning Pattern | `InternedStrings` |
| Fast field lookup | Field Reference | `EventFieldRef` |
| Extension points | Trait-Based | `PerfDataSource` trait |
| Lazy computation | Lazy Init | `OnceCell` |
| Batch processing | Error Collection | `Vec<Error>` |
