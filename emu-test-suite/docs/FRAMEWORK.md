# Generic Test Framework

Trait-based system for adding new tests and emulators.

## Quick Start

### Adding a New Test

1. Add to `src/tests.rs`:

```rust
pub struct MyTest;

impl Test for MyTest {
    fn name(&self) -> &str { "my_test" }
    
    fn c_code(&self) -> &str {
        r#"
#include <stdio.h>
int main() {
    unsigned int result = 0x1234;
    printf("%04x\n", result);
    return 0;
}
"#
    }
    
    fn parse_output(&self, stdout: &str) -> Result<TestResult, Box<dyn std::error::Error>> {
        let value = u32::from_str_radix(stdout.trim(), 16)?;
        Ok(TestResult::Custom { raw: format!("{}", value) })
    }
    
    fn format_result(&self, result: &TestResult) -> String {
        match result {
            TestResult::Custom { raw } => format!("Result: {}", raw),
            _ => "Invalid".to_string()
        }
    }
}
```

2. Use in `main.rs`:
```rust
match run_test(&MyTest, &BlinkEmulator) {
    Ok((_, msg)) => println!("{}", msg),
    Err(e) => eprintln!("{}", e),
}
```

### Adding a New Emulator

**Option 1: Generic Framework** (for standard emulators)

Add to `src/emulators.rs`:

```rust
pub struct MyEmulator;

impl Emulator for MyEmulator {
    fn name(&self) -> &str { "MyEmu" }
    fn command(&self) -> &str { "myemu" }  // "" = native
    fn args(&self, binary_path: &str) -> Vec<String> {
        vec![binary_path.to_string()]
    }
    fn needs_dynamic_linking(&self) -> bool { false }
    fn env_vars(&self) -> Vec<(&str, &str)> { vec![] }
}
```

**Option 2: Custom Module** (for special cases: PTY, FFI, JIT config)

Create `src/myemu.rs`:

```rust
pub fn test_fpu_in_myemu() -> Result<(u16, String), Box<dyn std::error::Error>> {
    let temp_bin = crate::c_based::compile_fpu_test_binary()?;
    // Custom logic here
    Ok((fpu_status, result))
}
```

See `src/box64.rs` (PTY), `src/icicle.rs` (JIT config), or `src/unicorn.rs` (FFI) for examples.

## Emulator Status

**Generic Framework**: Native, Blink, QEMU  
**Custom Implementation**: Box64 (PTY), Icicle (JIT), Unicorn (FFI), MWEMU (panic), KUBERA (C++)

## Trait Reference

```rust
pub trait Test {
    fn name(&self) -> &str;
    fn c_code(&self) -> &str;
    fn parse_output(&self, stdout: &str) -> Result<TestResult, Box<dyn std::error::Error>>;
    fn format_result(&self, result: &TestResult) -> String;
}

pub trait Emulator {
    fn name(&self) -> &str;
    fn command(&self) -> &str;  // "" for native
    fn args(&self, binary_path: &str) -> Vec<String>;
    fn needs_dynamic_linking(&self) -> bool { false }
    fn ignore_exit_code(&self) -> bool { false }
    fn env_vars(&self) -> Vec<(&str, &str)> { vec![] }
}
```
