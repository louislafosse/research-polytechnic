use std::process::Command;
use std::fs;

pub fn test_fpu_in_kubera() -> Result<(u16, String), Box<dyn std::error::Error>> {
    // Create temporary C++ test file
    let cpp_code = r#"#include <KUBERA/KUBERA.hpp>
#include <iostream>
#include <cstdint>

static inline uint64_t read_rflags() {
    uint64_t flags;
    asm volatile(
        "pushfq\n\t"
        "pop %0"
        : "=r"(flags)
        :
        : "memory"
    );
    return flags;
}

const uint8_t fpu_sf_shellcode[] = {
    0x50,                         // push rax
    0x51,                         // push rcx
    0x90, 0x90, 0x90, 0x90,       // nop sled
    0x9B, 0xDB, 0xE3,             // finit
    0xD9, 0xE8,                   // fld1 (1)
    0xD9, 0xE8,                   // fld1 (2)
    0xD9, 0xE8,                   // fld1 (3)
    0xD9, 0xE8,                   // fld1 (4)
    0xD9, 0xE8,                   // fld1 (5)
    0xD9, 0xE8,                   // fld1 (6)
    0xD9, 0xE8,                   // fld1 (7)
    0xD9, 0xE8,                   // fld1 (8)
    0xD9, 0xE8,                   // fld1 (9) -> overflow
    0x9B, 0xDF, 0xE0,             // fstsw ax
    0x59,                         // pop rcx
    0x58,                         // pop rax
    0xC3                          // ret
};

uint16_t run_kubera_fpu_sf(kubera::KUBERA& ctx) {
    ctx.decoder->reconfigure(
        fpu_sf_shellcode,
        sizeof(fpu_sf_shellcode),
        0
    );

    ctx.get_flags().value = read_rflags();

    while (ctx.decoder->can_decode()) {
        auto instr = ctx.decoder->decode();
        ctx.execute(instr);
    }

    uint64_t rax = ctx.get_reg(Register::RAX);
    return static_cast<uint16_t>(rax & 0xFFFF);
}

int main() {
    kubera::KUBERA ctx{};
    uint16_t status = run_kubera_fpu_sf(ctx);
    std::cout << std::hex << status << std::endl;
    return 0;
}
"#;
    
    let temp_cpp = "/tmp/kubera_fpu_test.cpp";
    let temp_bin = "/tmp/kubera_fpu_test";
    
    // Check if binary already exists
    let needs_compile = !std::path::Path::new(temp_bin).exists();
    
    if needs_compile {
        fs::write(temp_cpp, cpp_code)?;
        
        // Compile with KUBERA
        let compile = Command::new("g++")
            .args(&[
                "-std=gnu++23",
                temp_cpp,
                "-lKUBERA",
                "-lIced_Wrapper",
                "-lpthread",
                "-ldl",
                "-o", temp_bin
            ])
            .output();
        
        let compile = match compile {
            Ok(o) => o,
            Err(e) => {
                let _ = fs::remove_file(temp_cpp);
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Err("g++ not found".into());
                }
                return Err(format!("Failed to run g++: {}", e).into());
            }
        };
        
        if !compile.status.success() {
            let _ = fs::remove_file(temp_cpp);
            let stderr = String::from_utf8_lossy(&compile.stderr);
            if stderr.contains("KUBERA.hpp") || stderr.contains("libKUBERA") {
                return Err("KUBERA not installed. Run: cd local && ./kubera.sh".into());
            }
            return Err(format!("Compilation failed: {}", stderr).into());
        }
        
        let _ = fs::remove_file(temp_cpp);
    }
    
    // Run the test
    let output = Command::new(temp_bin)
        .output();
    
    let output = match output {
        Ok(o) => o,
        Err(e) => {
            return Err(format!("Failed to run test: {}", e).into());
        }
    };
    
    // Parse output - KUBERA prints debug to stdout, hex value is on last line
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    // Get the last non-empty line (the hex value)
    let status_str = stdout
        .lines()
        .filter(|line| !line.is_empty() && !line.contains("KUBERA") && !line.contains("Access violation"))
        .last()
        .unwrap_or("0")
        .trim();
    
    let fpu_status = u16::from_str_radix(status_str, 16)
        .unwrap_or(0);
    
    let (invalid_op, stack_fault, c1_bit) = crate::c_based::parse_fpu_status(fpu_status);
    
    // Check if FPU instructions were actually unsupported (check both stdout and stderr)
    // Note: After patching, KUBERA outputs "Unsupported instruction" messages
    let has_unsupported = stdout.contains("Unsupported instruction") || 
                          stderr.contains("Unsupported instruction");
    
    let msg = if has_unsupported {
        "KUBERA does not support FPU instructions (all FPU ops skipped)".to_string()
    } else {
        crate::c_based::format_fpu_result(fpu_status, invalid_op, stack_fault, c1_bit)
    };
    
    Ok((fpu_status, msg))
}
