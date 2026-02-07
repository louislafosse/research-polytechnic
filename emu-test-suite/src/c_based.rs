use std::process::Command;
use std::fs;

pub fn compile_fpu_test_binary() -> Result<String, Box<dyn std::error::Error>> {
    compile_fpu_test_binary_with_flags(&["-static"])
}

fn compile_fpu_test_binary_with_flags(flags: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let c_code = r#"
#include <stdio.h>

int main() {
    unsigned short fpu_status;
    __asm__ __volatile__(
        "finit\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"
        "fld1\n"  // 9th fld1 - overflow!
        "fnstsw %0\n"
        : "=a"(fpu_status)
    );
    printf("%04x\n", fpu_status);
    // unsigned int stack_fault, invalid_op, c1_bit;
    // stack_fault = fpu_status & 0x0040;
    // invalid_op = fpu_status & 0x0001;
    // c1_bit = fpu_status & 0x0200;
    // printf("Stack Fault: %s\n", stack_fault ? "Yes" : "No");
    // printf("Invalid Operation: %s\n", invalid_op ? "Yes" : "No");
    // printf("C1 Bit: %s\n", c1_bit ? "Set" : "Not Set");
    return 0;
    
}
"#;
    
    let temp_c = "/tmp/fpu_test_c_based.c";
    let temp_bin = "/tmp/fpu_test_c_based";
    
    fs::write(temp_c, c_code)?;
    
    let mut args = vec!["-o", temp_bin, temp_c];
    args.extend_from_slice(flags);
    
    let compile = Command::new("gcc")
        .args(&args)
        .output()?;
    
    let _ = fs::remove_file(temp_c);
    
    if !compile.status.success() {
        return Err(format!("gcc failed: {}", String::from_utf8_lossy(&compile.stderr)).into());
    }
    
    Ok(temp_bin.to_string())
}

pub fn parse_fpu_status(status: u16) -> (bool, bool, bool) {
    let stack_fault = (status & 0x0040) != 0;
    let invalid_op = (status & 0x0001) != 0;
    let c1_bit = (status & 0x0200) != 0;
    (invalid_op, stack_fault, c1_bit)
}

pub fn format_fpu_result(fpu_status: u16, invalid_op: bool, stack_fault: bool, c1_bit: bool) -> String {
    let mut result = format!("FPU Status: 0x{:04x} | IE:{} SF:{} C1:{}", 
             fpu_status, 
             if invalid_op { "✓" } else { "✗" },
             if stack_fault { "✓" } else { "✗" },
             if c1_bit { "✓" } else { "✗" });

    if invalid_op && stack_fault && c1_bit {
        result.push_str("\nFPU overflow DETECTED - vulnerability patched!");
    } else if invalid_op || stack_fault {
        result.push_str(&format!("\nPartial detection: IE={} SF={} C1={}", invalid_op, stack_fault, c1_bit));
    } else {
        result.push_str("\nFPU overflow NOT detected (expected)");
    }
    
    result
}

// LAHF test functions
pub fn compile_lahf_test_binary() -> Result<String, Box<dyn std::error::Error>> {
    compile_lahf_test_binary_with_flags(&["-static"])
}

fn compile_lahf_test_binary_with_flags(flags: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let c_code = r#"
#include <stdio.h>
#include <stdint.h>

int main() {
    uint8_t flags_result;
    uint32_t tmp;
    
    __asm__ __volatile__(
        "xor %%eax, %%eax\n"  // Clear all flags (ZF=1, others=0)
        "add $127, %%al\n"    // AL=127, no flags set
        "stc\n"               // Set only CF
        "lahf\n"
        "movzbl %%ah, %0\n"
        : "=r"(tmp)
        :: "eax", "ah"
    );
    
    flags_result = (uint8_t)tmp;
    printf("%02x\n", flags_result);
    return 0;
}
"#;
    
    let temp_c = "/tmp/lahf_test_c_based.c";
    let temp_bin = "/tmp/lahf_test_c_based";
    
    fs::write(temp_c, c_code)?;
    
    let mut args = vec!["-o", temp_bin, temp_c];
    args.extend_from_slice(flags);
    
    let compile = Command::new("gcc")
        .args(&args)
        .output()?;
    
    let _ = fs::remove_file(temp_c);
    
    if !compile.status.success() {
        return Err(format!("gcc failed: {}", String::from_utf8_lossy(&compile.stderr)).into());
    }
    
    Ok(temp_bin.to_string())
}

pub fn format_lahf_result(flags: u8) -> String {
    let expected = 0x03;
    let mut result = format!("LAHF Flags: 0x{:02x}", flags);
    
    if flags == expected {
        result.push_str(" ✓ (correct - native CPU / Good emulation)");
    } else if flags == 0x0b {
        result.push_str(" | LAHF:✗\nBlink emulator detected (AF flag bug)");
    } else {
        result.push_str(&format!(" ⚠ Unexpected value (expected 0x{:02x})", expected));
    }
    
    result
}

// RDTSCP test functions
pub fn compile_rdtscp_test_binary() -> Result<String, Box<dyn std::error::Error>> {
    compile_rdtscp_test_binary_with_flags(&["-static"])
}

fn compile_rdtscp_test_binary_with_flags(flags: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let c_code = r#"
#include <stdio.h>
#include <stdint.h>

int main() {
    uint32_t aux;
    uint32_t lo, hi;
    
    __asm__ __volatile__(
        "rdtscp"
        : "=a"(lo), "=d"(hi), "=c"(aux)
    );
    
    printf("%08x\n", aux);
    return 0;
}
"#;
    
    let temp_c = "/tmp/rdtscp_test_c_based.c";
    let temp_bin = "/tmp/rdtscp_test_c_based";
    
    fs::write(temp_c, c_code)?;
    
    let mut args = vec!["-o", temp_bin, temp_c];
    args.extend_from_slice(flags);
    
    let compile = Command::new("gcc")
        .args(&args)
        .output()?;
    
    let _ = fs::remove_file(temp_c);
    
    if !compile.status.success() {
        return Err(format!("gcc failed: {}", String::from_utf8_lossy(&compile.stderr)).into());
    }
    
    Ok(temp_bin.to_string())
}

pub fn format_rdtscp_result(aux: u32) -> String {
    let mut result = format!("RDTSCP AUX: 0x{:08x}", aux);
    
    if aux == 0 {
        result.push_str(" | RDTSCP:✗\nBlink emulator detected (TSC_AUX always zero)");
    } else {
        result.push_str(&format!(" ✓ (processor ID: {})", aux));
    }
    
    result
}
