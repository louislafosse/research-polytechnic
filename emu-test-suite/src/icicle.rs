use icicle_vm::cpu::mem::perm;

// https://github.com/momo5502/sogen/blob/main/src/backends/icicle-emulator/icicle-bridge/src/icicle.rs
pub fn test_fpu_in_icicle() -> Result<(u16, String), Box<dyn std::error::Error>> {
    let mut cpu_config = icicle_vm::cpu::Config::from_target_triple("x86_64-none");
    
    cpu_config.enable_jit = false;           // Disable full JIT compilation
    cpu_config.enable_jit_mem = true;        // Enable JIT for memory operations
    cpu_config.enable_shadow_stack = false;
    cpu_config.enable_recompilation = true;  // Allow recompilation of blocks
    cpu_config.track_uninitialized = false;
    cpu_config.optimize_instructions = true;
    cpu_config.optimize_block = false;
    
    let vm = match icicle_vm::build_with_path(&cpu_config, std::path::Path::new("./data/Ghidra/Processors")) {
        Ok(v) => v,
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("Sleigh spec not found") || err_str.contains("sleigh") {
                return Err("Icicle test skipped (requires Ghidra processor specs: download from https://github.com/NationalSecurityAgency/ghidra and extract Ghidra/Processors to ./data/Ghidra/Processors/)".into());
            }
            return Err(Box::new(e));
        }
    };
    let mut vm = vm;
    
    // Memory capacity must be set, without this, JIT fails silently
    let capacity = 8 * 2 * 50_000; // ~800MB 
    vm.cpu.mem.set_capacity(capacity);
    
    // Generate FPU test shellcode - allocate space for result at non-zero address
    let result_addr = 0x400000u64;
    let shellcode = crate::shellcode_based::generate_shellcode_fpu_sf(result_addr)?;
    

    // Allocate memory for the shellcode with proper permissions
    let code_addr = 0x10000u64;
    let code_size = ((shellcode.len() + 0xfff) / 0x1000) * 0x1000; // Round up to page size
    
    // Use Mapping struct with proper flags instead of UnallocatedMemory
    // MAP | INIT | IN_CODE_CACHE flags are critical for JIT to work correctly
    const MAPPING_PERMISSIONS: u8 = icicle_vm::cpu::mem::perm::MAP
        | icicle_vm::cpu::mem::perm::INIT
        | icicle_vm::cpu::mem::perm::IN_CODE_CACHE;
    
    let code_mapping = icicle_vm::cpu::mem::Mapping {
        perm: perm::EXEC | perm::READ | MAPPING_PERMISSIONS,
        value: 0,
    };
    
    if !vm.cpu.mem.map_memory_len(code_addr, code_size as u64, code_mapping) {
        return Err("Failed to map code memory".into());
    }
    
    // Write shellcode to memory
    vm.cpu.mem.write_bytes(code_addr, &shellcode, perm::NONE)
        .map_err(|e| format!("Failed to write shellcode: {:?}", e))?;
    
    // Allocate result memory (where FPU status will be written)
    let result_size = 0x1000u64;
    let result_mapping = icicle_vm::cpu::mem::Mapping {
        perm: perm::READ | perm::WRITE | MAPPING_PERMISSIONS,
        value: 0,
    };
    if !vm.cpu.mem.map_memory_len(result_addr, result_size, result_mapping) {
        return Err("Failed to map result memory".into());
    }
    
    // Set up stack with proper mapping
    let stack_addr = 0x200000u64;
    let stack_size = 0x10000u64; // 64KB stack
    let stack_mapping = icicle_vm::cpu::mem::Mapping {
        perm: perm::READ | perm::WRITE | MAPPING_PERMISSIONS,
        value: 0,
    };
    if !vm.cpu.mem.map_memory_len(stack_addr, stack_size, stack_mapping) {
        return Err("Failed to map stack memory".into());
    }
    let stack_top = stack_addr + stack_size - 8;
    
    // Set up halt address for clean exit (shellcode ends with ret which will jump here)
    let halt_addr = 0x300000u64;
    let halt_mapping = icicle_vm::cpu::mem::Mapping {
        perm: perm::EXEC | perm::READ | MAPPING_PERMISSIONS,
        value: 0,
    };
    if !vm.cpu.mem.map_memory_len(halt_addr, 0x1000, halt_mapping) {
        return Err("Failed to map halt memory".into());
    }
    // Write HLT instruction (0xf4) at halt address
    vm.cpu.mem.write_bytes(halt_addr, &[0xf4], perm::NONE)
        .map_err(|e| format!("Failed to write halt instruction: {:?}", e))?;
    
    // Write return address to stack
    vm.cpu.mem.write_bytes(stack_top, &halt_addr.to_le_bytes(), perm::NONE)
        .map_err(|e| format!("Failed to write return address: {:?}", e))?;
    
    // Get register var nodes
    let rip_var = vm.cpu.arch.sleigh.get_reg("RIP").ok_or("RIP register not found")?;
    let rsp_var = vm.cpu.arch.sleigh.get_reg("RSP").ok_or("RSP register not found")?;
    
    // Get the VarNodes immediately to avoid borrow checker issues
    let rip_node = rip_var.get_var().ok_or("Failed to get RIP variable")?;
    let rsp_node = rsp_var.get_var().ok_or("Failed to get RSP variable")?;
    
    // Initialize CPU registers
    vm.cpu.write_reg(rip_node, code_addr);
    vm.cpu.write_reg(rsp_node, stack_top);
    
    // Set instruction limit using Sogen's pattern
    // Use saturating_add instead of directly setting icount_limit
    vm.icount_limit = vm.cpu.icount.saturating_add(10000); // Allow up to 10k instructions
    
    // Execute the shellcode
    match vm.run() {
        icicle_vm::VmExit::InstructionLimit => {}
        icicle_vm::VmExit::Halt => {}
        icicle_vm::VmExit::Interrupted => {
            return Err("VM execution was interrupted".into());
        }
        icicle_vm::VmExit::Breakpoint => {
            return Err("Hit breakpoint".into());
        }
        icicle_vm::VmExit::UnhandledException(code) => {
            return Err(format!("Unhandled exception: {:?}", code).into());
        }
        icicle_vm::VmExit::Unimplemented => {
            return Err("Icicle test skipped".into());
        }
        icicle_vm::VmExit::OutOfMemory => {
            return Err("Out of memory".into());
        }
        icicle_vm::VmExit::Killed => {
            return Err("VM was killed".into());
        }
        other => {
            return Err(format!("Unexpected VM exit: {:?}", other).into());
        }
    }
    
    // Read FPU status word from result memory (shellcode writes it there)
    let mut result_bytes = [0u8; 2];
    vm.cpu.mem.read_bytes(result_addr, &mut result_bytes, perm::NONE)
        .map_err(|e| format!("Failed to read result: {:?}", e))?;
    
    let fpu_status = u16::from_le_bytes(result_bytes);
    
    let (invalid_op, stack_fault, c1_bit) = crate::c_based::parse_fpu_status(fpu_status);
    let result = crate::c_based::format_fpu_result(fpu_status, invalid_op, stack_fault, c1_bit);
    
    Ok((fpu_status, result))
}
