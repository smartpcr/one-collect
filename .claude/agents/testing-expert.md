# Testing Expert

Expert on testing strategies, patterns, and conventions used in the one_collect codebase.

## Testing Philosophy

The one_collect framework uses a multi-layered testing approach:

1. **Unit tests**: Embedded `#[cfg(test)]` modules testing individual components
2. **Mock-based tests**: Deterministic testing without system dependencies
3. **Integration tests**: Examples serve as executable integration tests
4. **Platform-specific tests**: Conditional compilation for OS-specific functionality

## Test Organization

### Unit Test Placement

Tests are co-located with implementation in `#[cfg(test)]` modules:

```rust
// In src/event/mod.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_field_access() {
        // Test implementation
    }
}
```

**Benefits**:
- Tests close to code they verify
- Access to private items
- Compiled only in test builds
- No separate test files to maintain

### Test Discovery

Tests found across 31+ files including:
- `event/mod.rs` (comprehensive event system tests)
- `helpers/exporting/attributes.rs`
- `helpers/exporting/mod.rs`
- `perf_event/mod.rs` (mock data source tests)
- `intern.rs` (interning tests)

## Core Testing Patterns

### Pattern 1: Atomic Counter Verification

**Purpose**: Verify callbacks executed correct number of times

**Pattern**:
```rust
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

#[test]
fn test_callback_execution() {
    let count = Arc::new(AtomicUsize::new(0));
    let callback_count = Arc::clone(&count);

    event.add_callback(move |_data| {
        callback_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });

    // Process events
    process_events(&mut session);

    // Verify callback executed
    assert_eq!(count.load(Ordering::Relaxed), expected_count);
}
```

**When to use**:
- Verifying callback invocation count
- Testing event routing
- Validating filtering logic

**Key points**:
- Use `Arc` for shared ownership across threads/closures
- `AtomicUsize` is thread-safe without locks
- `Relaxed` ordering sufficient for simple counters
- Clone the `Arc` before moving into closure

### Pattern 2: Mock Data Sources

**Purpose**: Test parsing logic without system dependencies

**Pattern** (from `perf_event/mod.rs:1220-1304`):
```rust
struct MockData {
    data: Vec<u8>,
    position: usize,
}

impl PerfDataSource for MockData {
    fn read_data(&mut self, buf: &mut [u8]) -> IOResult<usize> {
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
        123  // Fixed ID for testing
    }
}

#[test]
fn test_parsing_with_mock() {
    let mock_data = MockData {
        data: vec![/* pre-recorded event data */],
        position: 0,
    };

    let mut session = create_session_with_source(Box::new(mock_data));
    session.parse_all()?;

    // Verify parsing results
}
```

**When to use**:
- Testing parsers without kernel dependencies
- Deterministic test data
- Testing error handling with malformed data
- Cross-platform testing

**Benefits**:
- No root/admin privileges needed
- Reproducible test data
- Fast test execution
- Can test edge cases

### Pattern 3: Field Access Testing

**Purpose**: Verify field extraction and type conversions

**Pattern**:
```rust
#[test]
fn test_field_extraction() {
    // Create event format
    let mut format = EventFormat::new();
    format.add_field("pid", LocationType::Static(0), 4);
    format.add_field("name", LocationType::StaticString(4, 16));

    // Create test data
    let data: Vec<u8> = vec![
        0x01, 0x02, 0x03, 0x04,  // pid = 0x04030201
        b't', b'e', b's', b't', 0x00, /* padding */
    ];

    // Get field references
    let pid_ref = format.get_field_ref("pid").unwrap();
    let name_ref = format.get_field_ref("name").unwrap();

    // Extract and verify
    let pid = format.get_u32(pid_ref, &data).unwrap();
    assert_eq!(pid, 0x04030201);

    let name = format.get_str(name_ref, &data).unwrap();
    assert_eq!(name, "test");
}
```

**Test cases to cover**:
- All numeric types (u8, u16, u32, u64, i8, i16, i32, i64)
- String types (null-terminated, fixed-length, UTF-16)
- Dynamic offsets
- Variable-length fields
- Boundary conditions

### Pattern 4: Filter Closure Testing

**Purpose**: Test filtering logic comprehensively

**Pattern** (from `event/mod.rs:1962-2461`):
```rust
#[test]
fn test_numeric_filters() {
    let format = create_test_format();
    let field_ref = format.get_field_ref("value").unwrap();

    // Test equality
    let filter = format.try_get_field_filter_closure(
        field_ref, "==", "42"
    ).unwrap();
    assert!(filter(&create_data(42)));
    assert!(!filter(&create_data(43)));

    // Test inequality
    let filter = format.try_get_field_filter_closure(
        field_ref, "!=", "42"
    ).unwrap();
    assert!(!filter(&create_data(42)));
    assert!(filter(&create_data(43)));

    // Test comparisons
    test_comparison_operator(">", 42, 43, true, false);
    test_comparison_operator("<", 43, 42, true, false);
    test_comparison_operator(">=", 42, 42, true, false);
    test_comparison_operator("<=", 42, 42, true, false);
}

#[test]
fn test_string_filters() {
    let format = create_test_format();
    let field_ref = format.get_field_ref("name").unwrap();

    // Test contains
    let filter = format.try_get_field_filter_closure(
        field_ref, "contains", "test"
    ).unwrap();
    assert!(filter(&create_string_data("testing")));
    assert!(!filter(&create_string_data("example")));

    // Test starts_with
    let filter = format.try_get_field_filter_closure(
        field_ref, "starts_with", "test"
    ).unwrap();
    assert!(filter(&create_string_data("testing")));
    assert!(!filter(&create_string_data("example")));

    // Test ends_with, equals
    // ... similar pattern
}
```

**Coverage requirements**:
- All comparison operators: ==, !=, <, >, <=, >=
- All string operations: contains, starts_with, ends_with, equals
- Both UTF-8 and UTF-16 strings
- Edge cases: empty strings, boundary values
- Error cases: invalid operators, type mismatches

### Pattern 5: Attribute System Testing

**Purpose**: Test attribute associations and traversal

**Pattern** (from `attributes.rs:336-411`):
```rust
#[test]
fn test_attribute_walker() {
    let mut attrs = ExportAttributes::new();
    attrs.insert("key1", "value1");
    attrs.insert("key2", "value2");

    // Associate with parent
    let parent_attrs = ExportAttributes::new();
    attrs.associate(parent_attrs);

    // Walk attributes
    let mut visited = Vec::new();
    attrs.walk(|key, value| {
        visited.push((key.to_string(), value.to_string()));
    });

    assert_eq!(visited.len(), 2);
    assert!(visited.contains(&("key1".to_string(), "value1".to_string())));
    assert!(visited.contains(&("key2".to_string(), "value2".to_string())));
}

#[test]
fn test_attribute_filtering() {
    let attrs1 = create_attrs(&[("env", "prod"), ("region", "us")]);
    let attrs2 = create_attrs(&[("env", "dev"), ("region", "eu")]);

    let filter = AttributeFilter::new()
        .with_key_value("env", "prod");

    assert!(filter.matches(&attrs1));
    assert!(!filter.matches(&attrs2));
}

#[test]
fn test_cycle_prevention() {
    let mut attrs1 = ExportAttributes::new();
    let mut attrs2 = ExportAttributes::new();

    attrs1.associate(attrs2.clone());
    attrs2.associate(attrs1.clone());  // Create cycle

    // Should not infinite loop
    let mut count = 0;
    attrs1.walk(|_, _| {
        count += 1;
        if count > 100 {
            panic!("Infinite loop detected");
        }
    });
}
```

**Test coverage**:
- Attribute insertion and retrieval
- Association chaining
- Walker pattern traversal
- Filtering logic
- Cycle prevention
- Empty attribute sets

### Pattern 6: Interning Tests

**Purpose**: Verify deduplication and hash correctness

**Pattern** (from `intern.rs`):
```rust
#[test]
fn test_string_interning() {
    let mut intern = InternedStrings::new();

    // Intern same string twice
    let (str1, hash1) = intern.intern("test_string");
    let (str2, hash2) = intern.intern("test_string");

    // Should return same Arc
    assert!(Arc::ptr_eq(&str1, &str2));
    assert_eq!(hash1, hash2);

    // Different strings should have different Arcs
    let (str3, hash3) = intern.intern("different");
    assert!(!Arc::ptr_eq(&str1, &str3));
}

#[test]
fn test_callstack_interning() {
    let mut intern = InternedCallstacks::new();

    let stack1 = vec![0x1000, 0x2000, 0x3000];
    let stack2 = vec![0x1000, 0x2000, 0x3000];
    let stack3 = vec![0x4000, 0x5000];

    let (arc1, _) = intern.intern(&stack1);
    let (arc2, _) = intern.intern(&stack2);
    let (arc3, _) = intern.intern(&stack3);

    assert!(Arc::ptr_eq(&arc1, &arc2));
    assert!(!Arc::ptr_eq(&arc1, &arc3));
}

#[test]
fn test_interning_capacity() {
    let mut intern = InternedStrings::new();

    // Intern many strings
    for i in 0..10000 {
        intern.intern(&format!("string_{}", i));
    }

    // Verify deduplication
    let initial = intern.bucket_count();
    intern.intern("string_0");  // Already interned
    assert_eq!(intern.bucket_count(), initial);
}
```

## Integration Testing via Examples

Examples in `one_collect/examples/` serve as integration tests:

### Example: `perf_cpu.rs`
**Tests**:
- Ring buffer creation
- CPU profiling event registration
- Callback execution with shared state
- Enable/disable cycling
- Data aggregation

**Verification**: Manual inspection of output

### Example: `perf_switch.rs`
**Tests**:
- Context switch tracking
- Process name resolution
- JSON output generation
- Multiple event coordination

**Verification**: JSON schema validation

### Example: `perf_export.rs`
**Tests**:
- Full export pipeline
- Symbol resolution
- Multiple output formats
- Process splitting
- Graph aggregation

**Verification**: Output file validation

## Platform-Specific Testing

### Conditional Compilation

```rust
#[cfg(target_os = "linux")]
#[test]
fn test_perf_event_creation() {
    // Linux-specific test
}

#[cfg(target_os = "windows")]
#[test]
fn test_etw_session() {
    // Windows-specific test
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    // Module of Linux-only tests
}
```

### Platform Test Coverage

- **Linux**: perf_event ring buffers, ELF symbol resolution, DWARF unwinding
- **Windows**: ETW sessions, PE file parsing
- **Cross-platform**: Event system, interning, export formats

## Test Execution

### Running Tests

```bash
# All tests
cd one_collect && cargo test

# Specific test
cargo test test_name

# With output
cargo test test_name -- --nocapture

# Release mode tests
cargo test --release

# Ignored tests (may require permissions)
cargo test -- --ignored

# Single-threaded (for debugging)
cargo test -- --test-threads=1
```

### Test Organization

- Unit tests: `cargo test --lib`
- Integration tests: Run examples manually
- Doc tests: `cargo test --doc`
- Benchmarks: `cargo bench`

## Testing Best Practices

### 1. Test Data Construction

Create helper functions for test data:

```rust
fn create_test_event(pid: u32, name: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&pid.to_le_bytes());
    data.extend_from_slice(name.as_bytes());
    data.push(0);  // Null terminator
    data
}

#[test]
fn test_with_helper() {
    let data = create_test_event(123, "test_process");
    // Use data in test
}
```

### 2. Test Naming

Use descriptive test names:

```rust
// Good
#[test]
fn test_event_callback_executes_on_parse() { }

#[test]
fn test_field_ref_returns_none_for_missing_field() { }

// Less clear
#[test]
fn test_callback() { }

#[test]
fn test_field() { }
```

### 3. Test Organization

Group related tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    mod event_tests {
        use super::*;

        #[test]
        fn test_event_creation() { }

        #[test]
        fn test_event_callback() { }
    }

    mod field_tests {
        use super::*;

        #[test]
        fn test_field_extraction() { }

        #[test]
        fn test_field_filtering() { }
    }
}
```

### 4. Error Testing

Test error conditions:

```rust
#[test]
fn test_invalid_field_reference() {
    let format = EventFormat::new();
    let result = format.get_field_ref("nonexistent");
    assert!(result.is_err());
}

#[test]
#[should_panic(expected = "Buffer too small")]
fn test_buffer_overflow() {
    let small_buffer = vec![0u8; 4];
    read_large_data(&small_buffer);  // Should panic
}
```

### 5. Boundary Testing

Test edge cases:

```rust
#[test]
fn test_empty_string() {
    let data = create_string_data("");
    assert_eq!(extract_string(&data), "");
}

#[test]
fn test_max_value() {
    let data = create_u64_data(u64::MAX);
    assert_eq!(extract_u64(&data), u64::MAX);
}

#[test]
fn test_zero_length_array() {
    let data = create_array_data(&[]);
    assert_eq!(extract_array(&data).len(), 0);
}
```

## Test Coverage Goals

### Critical Paths (100% coverage)
- Event field extraction
- Filter closure generation
- Interning correctness
- Attribute associations

### Common Paths (>90% coverage)
- Export pipeline
- Symbol resolution
- Data parsing

### Error Paths (>80% coverage)
- Malformed data handling
- Invalid field references
- Permission errors

## Debugging Tests

### Enable Logging

```rust
#[test]
fn test_with_logging() {
    env_logger::init();  // Enable logging in tests
    // Test code
}
```

### Print Debug Info

```rust
#[test]
fn test_with_debug_output() {
    let result = function_under_test();
    println!("Result: {:?}", result);
    assert!(result.is_ok());
}
```

### Use `--nocapture`

```bash
cargo test test_name -- --nocapture
```

## Common Test Issues

### Issue 1: Permission Errors

**Problem**: Tests requiring perf_event fail without root

**Solution**:
```rust
#[test]
#[ignore]  // Ignore by default, run with --ignored
fn test_perf_event_requires_root() {
    // Test requiring permissions
}
```

### Issue 2: Flaky Tests

**Problem**: Race conditions in multi-threaded tests

**Solution**: Use atomic operations or run single-threaded
```bash
cargo test -- --test-threads=1
```

### Issue 3: Test Data Maintenance

**Problem**: Mock data becomes stale

**Solution**: Generate test data from real sessions, save to files

## Test Writing Checklist

- [ ] Test covers happy path
- [ ] Test covers error conditions
- [ ] Test covers boundary cases
- [ ] Test is deterministic (no randomness)
- [ ] Test is independent (no shared state)
- [ ] Test name is descriptive
- [ ] Test uses appropriate assertions
- [ ] Test has no side effects
- [ ] Test runs fast (<1ms for unit tests)
- [ ] Test cleanup (if needed)
