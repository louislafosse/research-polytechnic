use iced_x86::{self, Formatter};

/// Generate shellcode that detects FPU stack faults
pub fn generate_shellcode_fpu_sf(result_ptr: u64) -> Result<Vec<u8>, iced_x86::IcedError> {
    let mut a = iced_x86::code_asm::CodeAssembler::new(64)?;
    
    // Create label for result pointer storage
    let mut store_result = a.create_label();
    
    // Prolog - save registers
    a.push(iced_x86::code_asm::rax)?;
    a.push(iced_x86::code_asm::rcx)?;

    // NOP sled for stability
    a.nop()?;
    a.nop()?;
    a.nop()?;
    a.nop()?;
    
    // Initialize FPU
    a.finit()?;
    
    // Push 9 values onto FPU stack (should cause overflow)
    a.fld1()?; // 1
    a.fld1()?; // 2
    a.fld1()?; // 3
    a.fld1()?; // 4
    a.fld1()?; // 5
    a.fld1()?; // 6
    a.fld1()?; // 7
    a.fld1()?; // 8
    a.fld1()?; // 9 - This should trigger stack overflow
    
    // Get FPU status word
    a.fstsw(iced_x86::code_asm::ax)?;
    
    // Store result at the given pointer
    a.mov(iced_x86::code_asm::rcx, result_ptr)?;
    a.test(iced_x86::code_asm::rcx, iced_x86::code_asm::rcx)?; // Check if pointer is valid
    a.jz(store_result)?; // Jump if zero (null pointer)
    a.mov(iced_x86::code_asm::word_ptr(iced_x86::code_asm::rcx), iced_x86::code_asm::ax)?; // Store FPU status

    a.set_label(&mut store_result)?;
    
    // Epilog - restore registers
    a.pop(iced_x86::code_asm::rcx)?;
    a.pop(iced_x86::code_asm::rax)?;
    a.ret()?;
    
    // Assemble to bytes
    Ok(a.assemble(0x0)?)
}

/// Disassemble shellcode and print it
pub fn disassemble(shellcode: &[u8], base_address: u64) {
    let mut decoder = iced_x86::Decoder::with_ip(64, shellcode, base_address, iced_x86::DecoderOptions::NONE);
    let mut formatter = iced_x86::NasmFormatter::new();
    let mut output = String::new();
    
    while decoder.can_decode() {
        let instr = decoder.decode();
        output.clear();
        formatter.format(&instr, &mut output);
        println!("   {:016X} {}", instr.ip(), output);
    }
    println!();
}

