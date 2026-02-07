mod shellcode_based;
mod unicorn;
mod box64;
mod icicle;
mod c_based;
mod mwemu;
mod kubera;

// Generic test framework
mod test_framework;
mod tests;
mod emulators;

use test_framework::run_test;
use tests::{FpuTest, LahfTest, RdtscpTest};
use emulators::{NativeExecutor, QemuEmulator, BlinkEmulator};

fn main() {
    println!("=== Emulator's TestSuite ===\n");
    
    // Initialize Unicorn once (still uses legacy API)
    let mut unicorn_env = match unicorn::init() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Unicorn init failed: {}", e);
            return;
        }
    };

    // ========================================
    // FPU Stack Fault Tests
    // ========================================
    
    let fpu_test = FpuTest;
    
    // Native hardware (using generic framework)
    println!("[NATIVE HARDWARE]");
    match run_test(&fpu_test, &NativeExecutor) {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }
    
    // Blink (using generic framework)
    println!("[BLINK EMULATOR]");
    match run_test(&fpu_test, &BlinkEmulator) {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }
    
    // QEMU TCG (using generic framework)
    println!("[QEMU TCG]");
    match run_test(&fpu_test, &QemuEmulator) {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }
    
    // Box64 (legacy API - requires PTY for output)
    println!("[BOX64 EMULATOR]");
    match box64::test_fpu_in_box64() {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }
    
    // Icicle (legacy API - requires special handling)
    println!("[ICICLE EMULATOR]");
    match icicle::test_fpu_in_icicle() {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }

    // Unicorn (legacy API - requires special handling)
    println!("[UNICORN EMULATOR]");
    match test_fpu_unicorn(&mut unicorn_env) {
        Ok(msg) => println!("{}", msg),
        Err(e) => eprintln!("{}", e),
    }

    // MWEmu (legacy API - requires special panic handling)
    println!("\n[MWEMU EMULATOR]");
    match mwemu::test_fpu_in_mwemu() {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }

    // KUBERA (legacy API - requires C++ compilation)
    println!("[KUBERA EMULATOR]");
    match kubera::test_fpu_in_kubera() {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }

    // ========================================
    // LAHF Flag Tests
    // ========================================
    
    println!("\n=== LAHF Flag Tests ===\n");
    
    let lahf_test = LahfTest;
    
    println!("[NATIVE HARDWARE]");
    match run_test(&lahf_test, &NativeExecutor) {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }
    
    println!("[BLINK EMULATOR]");
    match run_test(&lahf_test, &BlinkEmulator) {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }
    
    println!("[QEMU TCG]");
    match run_test(&lahf_test, &QemuEmulator) {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }
    
    println!("[BOX64 EMULATOR]");
    match box64::test_lahf_in_box64() {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }
    
    // ========================================
    // RDTSCP Tests
    // ========================================
    
    println!("=== RDTSCP Tests ===\n");
    
    let rdtscp_test = RdtscpTest;
    
    println!("[NATIVE HARDWARE]");
    match run_test(&rdtscp_test, &NativeExecutor) {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }
    
    println!("[BLINK EMULATOR]");
    match run_test(&rdtscp_test, &BlinkEmulator) {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }
    
    println!("[QEMU TCG]");
    match run_test(&rdtscp_test, &QemuEmulator) {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }
    
    println!("[BOX64 EMULATOR]");
    match box64::test_rdtscp_in_box64() {
        Ok((_, msg)) => println!("{}\n", msg),
        Err(e) => eprintln!("{}\n", e),
    }
}

// Legacy Unicorn test function - kept for compatibility
fn test_fpu_unicorn(env: &mut unicorn::EmulationEnv) -> Result<String, Box<dyn std::error::Error>> {
    // Generate shellcode with virtual address for emulator
    let shellcode = shellcode_based::generate_shellcode_fpu_sf(env.result_address)?;
    
    env.emu.mem_write(env.code_address, &shellcode)
        .map_err(|e| format!("Failed to write shellcode: {:?}", e))?;
    
    // Execute shellcode
    let return_address = env.code_address + 0x1000;
    match env.emu.emu_start(env.code_address, return_address, 0, 0) {
        Ok(_) => {},
        Err(e) => {
            if !format!("{:?}", e).contains("FETCH_UNMAPPED") && !format!("{:?}", e).contains("FETCH_PROT") {
                return Err(format!("Emulation failed: {:?}", e).into());
            }
        }
    }
    
    // Read and analyze FPU status
    let mut result_buffer = vec![0u8; 2];
    env.emu.mem_read(env.result_address, &mut result_buffer)
        .map_err(|e| format!("Failed to read result: {:?}", e))?;
    
    let fpu_status = u16::from_le_bytes([result_buffer[0], result_buffer[1]]);
    let (invalid_op, stack_fault, c1_bit) = c_based::parse_fpu_status(fpu_status);
    Ok(c_based::format_fpu_result(fpu_status, invalid_op, stack_fault, c1_bit))
}
