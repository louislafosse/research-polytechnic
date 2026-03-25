mod box64;
mod c_based;
mod icicle;
mod kubera;
mod mwemu;
mod shellcode_based;
mod unicorn;

// Generic test framework
mod emulators;
mod test_framework;
mod tests;

use emulators::{BlinkEmulator, NativeExecutor, QemuEmulator};
use test_framework::run_test;
use test_framework::{Test, TestResult};
use tests::{
    FpuTest, IdivOverflowTest, LahfTest, MovdqaUnalignedTest, MxcsrRoundingTest, RdtscpTest,
    SystemStateTest, TscMonotonicTest, X87EmptyFstpTest,
};

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

    // ========================================
    // Native Comparison Edge-Case Tests
    // ========================================

    println!("=== Native Comparison Edge-Case Tests ===\n");
    compare_custom_test("TSC Monotonicity", &TscMonotonicTest);
    compare_custom_test("IDIV Overflow Fault", &IdivOverflowTest);
    compare_custom_test("MOVDQA Unaligned Fault", &MovdqaUnalignedTest);
    compare_custom_test("x87 Empty FSTP", &X87EmptyFstpTest);
    compare_custom_test("MXCSR Round-Down", &MxcsrRoundingTest);
    compare_custom_test("System State Snapshot", &SystemStateTest);

    // ========================================
    // Custom Emulator Low-Level Edge Checks
    // ========================================

    println!("=== Custom Emulator Low-Level Edge Checks ===\n");
    run_custom_low_level_checks();
}

// Legacy Unicorn test function - kept for compatibility
fn test_fpu_unicorn(env: &mut unicorn::EmulationEnv) -> Result<String, Box<dyn std::error::Error>> {
    // Generate shellcode with virtual address for emulator
    let shellcode = shellcode_based::generate_shellcode_fpu_sf(env.result_address)?;

    env.emu
        .mem_write(env.code_address, &shellcode)
        .map_err(|e| format!("Failed to write shellcode: {:?}", e))?;

    // Execute shellcode
    let return_address = env.code_address + 0x1000;
    match env.emu.emu_start(env.code_address, return_address, 0, 0) {
        Ok(_) => {}
        Err(e) => {
            if !format!("{:?}", e).contains("FETCH_UNMAPPED")
                && !format!("{:?}", e).contains("FETCH_PROT")
            {
                return Err(format!("Emulation failed: {:?}", e).into());
            }
        }
    }

    // Read and analyze FPU status
    let mut result_buffer = vec![0u8; 2];
    env.emu
        .mem_read(env.result_address, &mut result_buffer)
        .map_err(|e| format!("Failed to read result: {:?}", e))?;

    let fpu_status = u16::from_le_bytes([result_buffer[0], result_buffer[1]]);
    let (invalid_op, stack_fault, c1_bit) = c_based::parse_fpu_status(fpu_status);
    Ok(c_based::format_fpu_result(
        fpu_status,
        invalid_op,
        stack_fault,
        c1_bit,
    ))
}

fn custom_raw(result: &TestResult) -> Result<&str, Box<dyn std::error::Error>> {
    match result {
        TestResult::Custom { raw } => Ok(raw.as_str()),
        _ => Err("expected custom/raw result type".into()),
    }
}

fn compare_custom_test<T: Test>(title: &str, test: &T) {
    println!("-- {} --\n", title);

    let native = run_test(test, &NativeExecutor)
        .and_then(|(result, _)| custom_raw(&result).map(|raw| raw.to_string()));

    match &native {
        Ok(raw) => println!("[NATIVE HARDWARE]\n{}\n", raw),
        Err(e) => {
            eprintln!("[NATIVE HARDWARE]\n{}\n", e);
            return;
        }
    }

    let native_raw = native.unwrap();
    compare_custom_result(
        "[BLINK EMULATOR]",
        run_test(test, &BlinkEmulator),
        &native_raw,
    );
    compare_custom_result("[QEMU TCG]", run_test(test, &QemuEmulator), &native_raw);
    compare_custom_result(
        "[BOX64 EMULATOR]",
        box64::run_test_in_box64(test),
        &native_raw,
    );
}

fn compare_custom_result(
    label: &str,
    result: Result<(TestResult, String), Box<dyn std::error::Error>>,
    native_raw: &str,
) {
    println!("{}", label);
    match result {
        Ok((parsed, _)) => match custom_raw(&parsed) {
            Ok(raw) if raw == native_raw => {
                println!("{}\nMATCH vs native\n", raw);
            }
            Ok(raw) => {
                if native_raw.contains('\n') {
                    println!("{}\nMISMATCH vs native\nNative:\n{}\n", raw, native_raw);
                } else {
                    println!("{}\nMISMATCH vs native\nNative: {}\n", raw, native_raw);
                }
            }
            Err(e) => println!("{}\n", e),
        },
        Err(e) => println!("{}\n", e),
    }
}

fn run_custom_low_level_checks() {
    run_shellcode_probe(
        "FPU Stack Overflow (shellcode)",
        "fpu_overflow",
        &shellcode_based::shellcode_fpu_overflow_status()
            .expect("failed to assemble FPU overflow probe"),
        |value| format!("{:04x}", value as u16),
        format_fpu_shellcode_result,
    );
    run_shellcode_probe(
        "LAHF Flags (shellcode)",
        "lahf_flags",
        &shellcode_based::shellcode_lahf_flags().expect("failed to assemble LAHF probe"),
        |value| format!("{:02x}", value as u8),
        format_lahf_shellcode_result,
    );
    run_shellcode_probe(
        "RDTSCP AUX (shellcode)",
        "rdtscp_aux",
        &shellcode_based::shellcode_rdtscp_aux().expect("failed to assemble RDTSCP probe"),
        |value| format!("{:08x}", value as u32),
        format_rdtscp_shellcode_result,
    );
    run_shellcode_probe(
        "TSC Monotonicity (shellcode)",
        "tsc_monotonic",
        &shellcode_based::shellcode_tsc_monotonic().expect("failed to assemble TSC probe"),
        |value| format!("{}", value),
        format_tsc_shellcode_result,
    );
    run_shellcode_probe(
        "x87 Empty FSTP (shellcode)",
        "x87_empty_fstp",
        &shellcode_based::shellcode_x87_empty_fstp().expect("failed to assemble x87 probe"),
        |value| format!("{:04x}", value as u16),
        format_x87_empty_fstp_shellcode_result,
    );
    run_shellcode_probe(
        "MXCSR Round-Down (shellcode)",
        "mxcsr_round_down",
        &shellcode_based::shellcode_mxcsr_round_down().expect("failed to assemble MXCSR probe"),
        |value| format!("{}", value as u32),
        format_mxcsr_shellcode_result,
    );
    run_shellcode_probe(
        "SLDT (shellcode)",
        "sldt",
        &shellcode_based::shellcode_sldt().expect("failed to assemble SLDT probe"),
        |value| format!("{:04x}", value as u16),
        |value| format!("SLDT selector: 0x{:04x}", value as u16),
    );
    run_shellcode_probe(
        "STR (shellcode)",
        "str",
        &shellcode_based::shellcode_str().expect("failed to assemble STR probe"),
        |value| format!("{:04x}", value as u16),
        |value| format!("STR selector: 0x{:04x}", value as u16),
    );
    run_shellcode_probe(
        "SMSW (shellcode)",
        "smsw",
        &shellcode_based::shellcode_smsw().expect("failed to assemble SMSW probe"),
        |value| format!("{:04x}", value as u16),
        |value| format!("SMSW value: 0x{:04x}", value as u16),
    );
}

fn run_shellcode_probe<FRaw, FDisplay>(
    title: &str,
    probe_name: &str,
    shellcode: &[u8],
    format_raw: FRaw,
    format_display: FDisplay,
) where
    FRaw: Fn(u64) -> String,
    FDisplay: Fn(u64) -> String,
{
    println!("-- {} --\n", title);

    println!("[NATIVE HARDWARE]");
    let (native_raw, native_display) = match shellcode_based::run_natively_return_rax(shellcode) {
        Ok(value) => {
            let raw = format_raw(value);
            let display = format_display(value);
            println!("{}\n", display);
            (raw, display)
        }
        Err(e) => {
            println!("{}\n", e);
            return;
        }
    };

    print_shellcode_probe_result(
        "[ICICLE EMULATOR]",
        icicle::run_shellcode_return_rax(shellcode),
        &native_raw,
        &native_display,
        &format_raw,
        &format_display,
    );
    print_shellcode_probe_result(
        "[UNICORN EMULATOR]",
        unicorn::run_shellcode_return_rax(shellcode),
        &native_raw,
        &native_display,
        &format_raw,
        &format_display,
    );
    print_shellcode_probe_result(
        "[MWEMU EMULATOR]",
        mwemu::run_shellcode_return_rax(probe_name, shellcode),
        &native_raw,
        &native_display,
        &format_raw,
        &format_display,
    );
    print_shellcode_probe_result(
        "[KUBERA EMULATOR]",
        kubera::run_shellcode_return_rax(probe_name, shellcode),
        &native_raw,
        &native_display,
        &format_raw,
        &format_display,
    );
}

fn print_shellcode_probe_result<FRaw, FDisplay>(
    label: &str,
    result: Result<u64, Box<dyn std::error::Error>>,
    native_raw: &str,
    native_display: &str,
    format_raw: &FRaw,
    format_display: &FDisplay,
) where
    FRaw: Fn(u64) -> String,
    FDisplay: Fn(u64) -> String,
{
    println!("{}", label);
    match result {
        Ok(value) => {
            let raw = format_raw(value);
            let display = format_display(value);
            if raw == native_raw {
                println!("{}\nBehavior matches native hardware.\n", display);
            } else {
                println!(
                    "{}\nBehavior differs from native hardware.\nNative hardware:\n{}\n",
                    display, native_display
                );
            }
        }
        Err(e) => {
            println!("{}\nNative hardware:\n{}\n", e, native_display);
        }
    }
}

fn bool_icon(value: bool) -> &'static str {
    if value { "✓" } else { "✗" }
}

fn format_fpu_shellcode_result(value: u64) -> String {
    let status = value as u16;
    let (invalid_op, stack_fault, c1_bit) = c_based::parse_fpu_status(status);
    c_based::format_fpu_result(status, invalid_op, stack_fault, c1_bit)
}

fn format_lahf_shellcode_result(value: u64) -> String {
    c_based::format_lahf_result(value as u8)
}

fn format_rdtscp_shellcode_result(value: u64) -> String {
    c_based::format_rdtscp_result(value as u32)
}

fn format_tsc_shellcode_result(value: u64) -> String {
    if value == 1 {
        "TSC monotonicity: ✓\nSecond RDTSC value is greater than the first.".to_string()
    } else {
        "TSC monotonicity: ✗\nSecond RDTSC value is not greater than the first.".to_string()
    }
}

fn format_x87_empty_fstp_shellcode_result(value: u64) -> String {
    let status = value as u16;
    let (invalid_op, stack_fault, c1_bit) = c_based::parse_fpu_status(status);
    let mut result = format!(
        "x87 Empty FSTP Status: 0x{:04x} | IE:{} SF:{} C1:{}",
        status,
        bool_icon(invalid_op),
        bool_icon(stack_fault),
        bool_icon(c1_bit)
    );

    if invalid_op && stack_fault {
        result.push_str("\nEmpty-stack fault reported correctly.");
    } else {
        result.push_str("\nEmpty-stack fault flags are missing or incomplete.");
    }

    result
}

fn format_mxcsr_shellcode_result(value: u64) -> String {
    let rounded = value as u32;
    if rounded == 1 {
        "MXCSR round-down result: 1 ✓\nRounding mode was honored.".to_string()
    } else {
        format!(
            "MXCSR round-down result: {} | MXCSR:✗\nRounding mode was not honored.",
            rounded
        )
    }
}
