use crate::test_framework::Emulator;

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
            binary_path.to_string(),
        ]
    }

    fn needs_dynamic_linking(&self) -> bool {
        true // Blink needs dynamically linked binaries
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
}
