use std::fs;
use std::io::Read;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

pub fn test_fpu_in_box64() -> Result<(u16, String), Box<dyn std::error::Error>> {
    let temp_bin = crate::c_based::compile_fpu_test_binary()?;
    
    let pty_system = native_pty_system();
    let pair = pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    })?;
    
    let mut cmd = CommandBuilder::new("box64");
    cmd.arg(&temp_bin);
    cmd.env("BOX64_LOG", "0");
    cmd.env("BOX64_NOBANNER", "1");
    
    let mut child = pair.slave.spawn_command(cmd)?;
    drop(pair.slave);
    
    // Read output from the master PTY
    let mut reader = pair.master.try_clone_reader()?;
    let mut output_str = String::new();
    reader.read_to_string(&mut output_str)?;
    
    let _exit_status = child.wait()?;
    
    let _ = fs::remove_file(&temp_bin);
    
    // Filter out [BOX64] debug lines to get just the hex output
    let filtered: String = output_str
        .lines()
        .filter(|line| !line.starts_with("[BOX64]"))
        .collect::<Vec<_>>()
        .join("\n");
    
    // Try to parse the output
    let fpu_status = match u16::from_str_radix(filtered.trim(), 16) {
        Ok(status) => status,
        Err(_) => {
            return Err(format!("box64 failed to produce valid output: {}", 
                if !filtered.trim().is_empty() { filtered.trim() } else { "no output" }
            ).into());
        }
    };
    
    let (invalid_op, stack_fault, c1_bit) = crate::c_based::parse_fpu_status(fpu_status);
    let result = crate::c_based::format_fpu_result(fpu_status, invalid_op, stack_fault, c1_bit);
    
    Ok((fpu_status, result))
}

pub fn test_lahf_in_box64() -> Result<(u8, String), Box<dyn std::error::Error>> {
    let temp_bin = crate::c_based::compile_lahf_test_binary()?;
    
    let pty_system = native_pty_system();
    let pair = pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    })?;
    
    let mut cmd = CommandBuilder::new("box64");
    cmd.arg(&temp_bin);
    cmd.env("BOX64_LOG", "0");
    cmd.env("BOX64_NOBANNER", "1");
    
    let mut child = pair.slave.spawn_command(cmd)?;
    drop(pair.slave);
    
    let mut reader = pair.master.try_clone_reader()?;
    let mut output_str = String::new();
    reader.read_to_string(&mut output_str)?;
    
    let _exit_status = child.wait()?;
    let _ = fs::remove_file(&temp_bin);
    
    let filtered: String = output_str
        .lines()
        .filter(|line| !line.starts_with("[BOX64]"))
        .collect::<Vec<_>>()
        .join("\n");
    
    let flags = match u8::from_str_radix(filtered.trim(), 16) {
        Ok(f) => f,
        Err(_) => {
            return Err(format!("box64 failed to produce valid output: {}", 
                if !filtered.trim().is_empty() { filtered.trim() } else { "no output" }
            ).into());
        }
    };
    
    let result = crate::c_based::format_lahf_result(flags);
    Ok((flags, result))
}

pub fn test_rdtscp_in_box64() -> Result<(u32, String), Box<dyn std::error::Error>> {
    let temp_bin = crate::c_based::compile_rdtscp_test_binary()?;
    
    let pty_system = native_pty_system();
    let pair = pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    })?;
    
    let mut cmd = CommandBuilder::new("box64");
    cmd.arg(&temp_bin);
    cmd.env("BOX64_LOG", "0");
    cmd.env("BOX64_NOBANNER", "1");
    
    let mut child = pair.slave.spawn_command(cmd)?;
    drop(pair.slave);
    
    let mut reader = pair.master.try_clone_reader()?;
    let mut output_str = String::new();
    reader.read_to_string(&mut output_str)?;
    
    let _exit_status = child.wait()?;
    let _ = fs::remove_file(&temp_bin);
    
    let filtered: String = output_str
        .lines()
        .filter(|line| !line.starts_with("[BOX64]"))
        .collect::<Vec<_>>()
        .join("\n");
    
    let aux = match u32::from_str_radix(filtered.trim(), 16) {
        Ok(a) => a,
        Err(_) => {
            return Err(format!("box64 failed to produce valid output: {}", 
                if !filtered.trim().is_empty() { filtered.trim() } else { "no output" }
            ).into());
        }
    };
    
    let result = crate::c_based::format_rdtscp_result(aux);
    Ok((aux, result))
}
