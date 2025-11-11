// Example to verify tracing instrumentation works
fn main() {
    // Initialize tracing subscriber for testing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("Testing ruwind tracing instrumentation...\n");

    // Test module creation
    let module = ruwind::Module::new(
        0x1000,
        0x2000,
        0,
        1,
        2,
        ruwind::UnwindType::DWARF,
    );
    println!("Module created successfully\n");

    // Test anonymous module
    let _anon = ruwind::Module::new_anon(0x3000, 0x4000);
    println!("Anonymous module created successfully\n");

    // Test process operations
    let mut process = ruwind::Process::new();
    process.add_module(module);
    process.sort();
    
    // Test module finding
    match process.find(0x1500) {
        Some(_) => println!("Module found successfully\n"),
        None => println!("Module not found (unexpected)\n"),
    }
    
    // Test machine operations
    let mut machine = ruwind::Machine::new();
    machine.add_process(1, process);
    println!("Process added to machine\n");
    
    machine.remove_process(1);
    println!("Process removed from machine\n");
    
    println!("All tracing tests completed successfully!");
}
