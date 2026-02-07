use crate::test_framework::Emulator;
use std::process::Command;

/// Blink Emulator
pub struct BlinkEmulator;

impl Emulator for BlinkEmulator {
    fn name(&self) -> &str {
        "Blink"
    }
    
    fn command(&self) -> &str {
        "blink"
    }
    
    fn args(&self, binary_path: &str) -> Vec<String> {
        vec![
            "-L".to_string(),
            "/dev/null".to_string(),
            binary_path.to_string()
        ]
    }
    
    fn needs_dynamic_linking(&self) -> bool {
        true // Blink needs dynamically linked binaries
    }
    
    fn is_available(&self) -> bool {
        Command::new(self.command())
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// QEMU User Mode Emulator
pub struct QemuEmulator;

impl Emulator for QemuEmulator {
    fn name(&self) -> &str {
        "QEMU TCG"
    }
    
    fn command(&self) -> &str {
        "qemu-x86_64"
    }
    
    fn args(&self, binary_path: &str) -> Vec<String> {
        vec![binary_path.to_string()]
    }
    
    fn is_available(&self) -> bool {
        Command::new(self.command())
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Native execution (no emulator)
pub struct NativeExecutor;

impl Emulator for NativeExecutor {
    fn name(&self) -> &str {
        "Native Hardware"
    }
    
    fn command(&self) -> &str {
        "" // Not used - will execute binary directly
    }

    fn args(&self, _binary_path: &str) -> Vec<String> {
        vec![]
    }
    
    fn is_available(&self) -> bool {
        true // Native is always available
    }
}

