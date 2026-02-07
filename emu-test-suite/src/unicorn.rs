use unicorn_engine::{Unicorn, RegisterX86, Prot};
use unicorn_engine::unicorn_const::{Arch, Mode};

#[allow(unused)]
pub struct EmulationEnv {
    pub emu: Unicorn<'static, ()>,
    pub code_address: u64,
    pub result_address: u64,
    pub stack_address: u64,
    pub stack_size: u64,
}

// Memory layout constants
const CODE_ADDRESS: u64 = 0x100000;
const RESULT_ADDRESS: u64 = 0x200000;
const STACK_ADDRESS: u64 = 0x300000;
const STACK_SIZE: u64 = 0x10000;

/// Initialize the Unicorn emulator and set up the emulation environment
pub fn init() 
    -> Result<EmulationEnv, Box<dyn std::error::Error>> {
    
    println!("Initializing Unicorn emulator (x86-64 mode)...\n");
    let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64)
        .map_err(|e| format!("Failed to create emulator: {:?}", e))?;
    
    
    // Map code region
    emu.mem_map(CODE_ADDRESS, 0x10000, Prot::ALL)
        .map_err(|e| format!("Failed to map code memory: {:?}", e))?;
    
    // Map result region
    emu.mem_map(RESULT_ADDRESS, 0x1000, Prot::READ | Prot::WRITE)
        .map_err(|e| format!("Failed to map result memory: {:?}", e))?;
    
    // Map stack region
    emu.mem_map(STACK_ADDRESS, STACK_SIZE, Prot::READ | Prot::WRITE)
        .map_err(|e| format!("Failed to map stack memory: {:?}", e))?;
    
    // Set up stack pointer
    let rsp = STACK_ADDRESS + STACK_SIZE - 0x100;
    emu.reg_write(RegisterX86::RSP, rsp)
        .map_err(|e| format!("Failed to set RSP: {:?}", e))?;
    
    // Set instruction pointer
    emu.reg_write(RegisterX86::RIP, CODE_ADDRESS)
        .map_err(|e| format!("Failed to set RIP: {:?}", e))?;
    
    // Set up return address on stack
    let return_address = CODE_ADDRESS + 0x1000; // Point to unmapped area to stop execution
    let stack_data = return_address.to_le_bytes();
    emu.mem_write(rsp, &stack_data)
        .map_err(|e| format!("Failed to write return address: {:?}", e))?;
    
    Ok(EmulationEnv {
        emu,
        code_address: CODE_ADDRESS,
        result_address: RESULT_ADDRESS,
        stack_address: STACK_ADDRESS,
        stack_size: STACK_SIZE,
    })
}
