use std::panic;

// https://github.com/sha0coder/mwemu
pub fn test_fpu_in_mwemu() -> Result<(u16, String), Box<dyn std::error::Error>> {
    // MWEMU panics on FPU stack overflow instead of setting proper flags
    // This is actually good detection but not proper emulation behavior
    // We catch the panic to report it as detected overflow
    
    // Suppress panic output to stderr
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {
        // Silent panic handler - suppresses panic messages
    }));
    
    let result = panic::catch_unwind(|| -> Result<(u16, String), Box<dyn std::error::Error>> {
        // Initialize MWEMU x86-64 emulator
        let mut emu = libmwemu::emu64();
        
        // MWEMU doesn't need maps folder for basic shellcode emulation
        // emu.set_maps_folder() is only needed for PE/ELF with Win32/Linux simulation
        
        // Allocate result memory (where FPU status will be written)
        let result_addr = 0x400000u64;
        let result_size = 0x1000u64;
        
        // Generate FPU test shellcode
        let shellcode = crate::shellcode_based::generate_shellcode_fpu_sf(result_addr)?;
        
        // Load shellcode into MWEMU - this also initializes the emulator
        emu.init_linux64(false);
        emu.load_code_bytes(&shellcode);
        
        // Allocate memory for result after loading code
        let _result_map = emu.alloc("result", result_size, libmwemu::maps::mem64::Permission::READ_WRITE);
        
        // Run the emulator - shellcode ends with ret
        match emu.run(None) {
            Ok(_) => {},
            Err(e) => {
                return Err(format!("MWEMU execution failed: {:?}", e).into());
            }
        }
        
        // Read FPU status word from result memory
        let fpu_status = match emu.maps.read_word(result_addr) {
            Some(status) => status,
            None => {
                return Err("Failed to read FPU status from MWEMU memory".into());
            }
        };
        
        let (invalid_op, stack_fault, c1_bit) = crate::c_based::parse_fpu_status(fpu_status);
        let result = crate::c_based::format_fpu_result(fpu_status, invalid_op, stack_fault, c1_bit);
        
        Ok((fpu_status, result))
    });

    // // Restore the original panic hook
    std::panic::set_hook(prev_hook);
    
    match result {
        Ok(inner_result) => inner_result,
        Err(panic_info) => {
            // MWEMU panicked, likely due to FPU stack overflow
            // This means it detected the overflow (good!) but handled it by panicking (not realistic)
            let panic_msg = if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "Unknown panic".to_string()
            };
            
            if panic_msg.contains("FPU stack overflow") {
                // MWEMU detected the overflow by panicking
                // Return 0xFFFF to indicate "detected but handled incorrectly (panic)"
                // This distinguishes it from 0x0000 (not detected) and 0x3a41 (properly detected)
                Ok((0xffff, "MWEMU detected FPU overflow but panicked instead of setting flags (IE:? SF:? C1:?)".to_string()))
            } else {
                Err(format!("MWEMU panicked: {}", panic_msg).into())
            }
        }
    }
}
