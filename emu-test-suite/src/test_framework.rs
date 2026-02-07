use std::process::Command;
use std::fs;

/// Represents the result of a test execution
#[derive(Debug, Clone)]
pub enum TestResult {
    Fpu { status: u16, invalid_op: bool, stack_fault: bool, c1_bit: bool },
    Lahf { flags: u8 },
    Rdtscp { aux: u32 },
    Custom { raw: String },
}

/// Trait for defining a test case
pub trait Test {
    /// Name of the test
    fn name(&self) -> &str;
    
    /// C code for the test
    fn c_code(&self) -> &str;
    
    /// Parse the stdout output into a TestResult
    fn parse_output(&self, stdout: &str) -> Result<TestResult, Box<dyn std::error::Error>>;
    
    /// Format the test result for display
    fn format_result(&self, result: &TestResult) -> String;
    
    /// Whether this test requires dynamic linking (default: false)
    /// Some tests like RDTSCP need dynamic linking for proper kernel initialization
    fn requires_dynamic_linking(&self) -> bool {
        false
    }
}

/// Trait for defining an emulator
pub trait Emulator {
    /// Name of the emulator
    fn name(&self) -> &str;
    
    /// Command to run the emulator
    fn command(&self) -> &str;
    
    /// Arguments to pass to the emulator (binary path will be provided)
    fn args(&self, binary_path: &str) -> Vec<String>;
    
    /// Whether the emulator requires dynamic linking (default: false = static)
    fn needs_dynamic_linking(&self) -> bool {
        false
    }
    
    /// Whether to ignore exit code (some emulators like Box64 always return non-zero)
    fn ignore_exit_code(&self) -> bool {
        false
    }
    
    /// Environment variables to set for the emulator
    fn env_vars(&self) -> Vec<(&str, &str)> {
        vec![]
    }
    
    /// Check if the emulator is available
    fn is_available(&self) -> bool {
        Command::new(self.command())
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Generic test runner
pub fn run_test<T: Test, E: Emulator>(
    test: &T, 
    emulator: &E
) -> Result<(TestResult, String), Box<dyn std::error::Error>> {
    // Compile the test - use dynamic linking if either test or emulator requires it
    let flags = if test.requires_dynamic_linking() || emulator.needs_dynamic_linking() {
        vec![]
    } else {
        vec!["-static"]
    };
    
    let temp_c = format!("/tmp/test_{}.c", test.name());
    let temp_bin = format!("/tmp/test_{}", test.name());
    
    fs::write(&temp_c, test.c_code())?;
    
    let mut compile_args = vec!["-o", &temp_bin, &temp_c];
    compile_args.extend_from_slice(&flags);
    
    let compile = Command::new("gcc")
        .args(&compile_args)
        .output()?;
    
    let _ = fs::remove_file(&temp_c);
    
    if !compile.status.success() {
        return Err(format!("gcc failed: {}", String::from_utf8_lossy(&compile.stderr)).into());
    }
    
    // Run on emulator
    let output = if emulator.command().is_empty() {
        // Native execution - run binary directly
        Command::new(&temp_bin)
            .output()
    } else {
        // Emulator execution
        let args = emulator.args(&temp_bin);
        let mut cmd = Command::new(emulator.command());
        cmd.args(&args);
        
        // Set environment variables
        let env_vars = emulator.env_vars();
        if !env_vars.is_empty() {
            cmd.envs(env_vars.iter().map(|(k, v)| (*k, *v)));
        }
        
        cmd.output()
    };
    
    let output = match output {
        Ok(o) => o,
        Err(e) => {
            let _ = fs::remove_file(&temp_bin);
            if e.kind() == std::io::ErrorKind::NotFound {
                return Err(format!("{} not found", emulator.command()).into());
            }
            return Err(format!("Failed to run {}: {}", emulator.name(), e).into());
        }
    };
    
    let _ = fs::remove_file(&temp_bin);
    
    // Check exit code unless emulator ignores it (e.g., Box64 always returns 128)
    if !output.status.success() && !emulator.ignore_exit_code() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}{}", stdout, stderr);
        
        return Err(format!("{} failed (exit {}): {}", 
            emulator.name(),
            output.status.code().unwrap_or(-1), 
            if !combined.is_empty() { combined } else { "unknown error".to_string() }
        ).into());
    }
    
    // Parse and format results
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    // Debug: show what we got if parsing fails
    if stdout.trim().is_empty() {
        return Err(format!("{} returned empty output. stderr: {}", 
            emulator.name(), 
            if !stderr.is_empty() { stderr.to_string() } else { "(empty)".to_string() }
        ).into());
    }
    
    let result = test.parse_output(&stdout)?;
    let formatted = test.format_result(&result);

    
    Ok((result, formatted))
}

/// Helper to compile a test without running it
pub fn compile_test<T: Test>(
    test: &T,
    static_linking: bool
) -> Result<String, Box<dyn std::error::Error>> {
    let flags = if static_linking {
        vec!["-static"]
    } else {
        vec![]
    };
    
    let temp_c = format!("/tmp/test_{}.c", test.name());
    let temp_bin = format!("/tmp/test_{}", test.name());
    
    fs::write(&temp_c, test.c_code())?;
    
    let mut compile_args = vec!["-o", &temp_bin, &temp_c];
    compile_args.extend_from_slice(&flags);
    
    let compile = Command::new("gcc")
        .args(&compile_args)
        .output()?;
    
    let _ = fs::remove_file(&temp_c);
    
    if !compile.status.success() {
        return Err(format!("gcc failed: {}", String::from_utf8_lossy(&compile.stderr)).into());
    }
    
    Ok(temp_bin)
}
