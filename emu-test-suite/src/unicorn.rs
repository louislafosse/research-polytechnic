use unicorn_engine::unicorn_const::{Arch, Mode};
use unicorn_engine::{Prot, RegisterX86, Unicorn};

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
pub fn init() -> Result<EmulationEnv, Box<dyn std::error::Error>> {
    init_with_logging(true)
}

fn init_with_logging(verbose: bool) -> Result<EmulationEnv, Box<dyn std::error::Error>> {
    if verbose {
        println!("Initializing Unicorn emulator (x86-64 mode)...\n");
    }

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

pub fn run_shellcode_return_rax(shellcode: &[u8]) -> Result<u64, Box<dyn std::error::Error>> {
    let mut env = init_with_logging(false)?;
    let rsp = env.stack_address + env.stack_size - 0x100;
    let return_address = env.code_address + 0x1000;

    env.emu
        .reg_write(RegisterX86::RSP, rsp)
        .map_err(|e| format!("Failed to reset RSP: {:?}", e))?;
    env.emu
        .reg_write(RegisterX86::RIP, env.code_address)
        .map_err(|e| format!("Failed to reset RIP: {:?}", e))?;
    env.emu
        .reg_write(RegisterX86::RAX, 0)
        .map_err(|e| format!("Failed to clear RAX: {:?}", e))?;
    env.emu
        .reg_write(RegisterX86::RCX, 0)
        .map_err(|e| format!("Failed to clear RCX: {:?}", e))?;
    env.emu
        .reg_write(RegisterX86::RDX, 0)
        .map_err(|e| format!("Failed to clear RDX: {:?}", e))?;

    env.emu
        .mem_write(env.code_address, shellcode)
        .map_err(|e| format!("Failed to write shellcode: {:?}", e))?;
    env.emu
        .mem_write(rsp, &return_address.to_le_bytes())
        .map_err(|e| format!("Failed to write return address: {:?}", e))?;

    match env.emu.emu_start(env.code_address, return_address, 0, 0) {
        Ok(_) => {}
        Err(e) => {
            let err = format!("{:?}", e);
            if !err.contains("FETCH_UNMAPPED") && !err.contains("FETCH_PROT") {
                return Err(format!("Unicorn execution failed: {}", err).into());
            }
        }
    }

    env.emu
        .reg_read(RegisterX86::RAX)
        .map_err(|e| format!("Failed to read RAX: {:?}", e).into())
}
