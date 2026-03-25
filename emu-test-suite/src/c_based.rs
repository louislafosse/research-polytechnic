pub fn parse_fpu_status(status: u16) -> (bool, bool, bool) {
    let stack_fault = (status & 0x0040) != 0;
    let invalid_op = (status & 0x0001) != 0;
    let c1_bit = (status & 0x0200) != 0;
    (invalid_op, stack_fault, c1_bit)
}

pub fn format_fpu_result(
    fpu_status: u16,
    invalid_op: bool,
    stack_fault: bool,
    c1_bit: bool,
) -> String {
    let mut result = format!(
        "FPU Status: 0x{:04x} | IE:{} SF:{} C1:{}",
        fpu_status,
        if invalid_op { "✓" } else { "✗" },
        if stack_fault { "✓" } else { "✗" },
        if c1_bit { "✓" } else { "✗" }
    );

    if invalid_op && stack_fault && c1_bit {
        result.push_str("\nFPU overflow DETECTED - vulnerability patched!");
    } else if invalid_op || stack_fault {
        result.push_str(&format!(
            "\nPartial detection: IE={} SF={} C1={}",
            invalid_op, stack_fault, c1_bit
        ));
    } else {
        result.push_str("\nFPU overflow NOT detected (expected)");
    }

    result
}

pub fn format_lahf_result(flags: u8) -> String {
    let expected = 0x03;
    let mut result = format!("LAHF Flags: 0x{:02x}", flags);

    if flags == expected {
        result.push_str(" ✓ (correct - native CPU / Good emulation)");
    } else if flags == 0x0b {
        result.push_str(" | LAHF:✗\nBlink emulator detected (AF flag bug)");
    } else {
        result.push_str(&format!(
            " ⚠ Unexpected value (expected 0x{:02x})",
            expected
        ));
    }

    result
}

pub fn format_rdtscp_result(aux: u32) -> String {
    let mut result = format!("RDTSCP AUX: 0x{:08x}", aux);

    if aux == 0 {
        result.push_str(
            " | RDTSCP:⚠\nTSC_AUX is zero (can indicate emulation or host/kernel configuration)",
        );
    } else {
        result.push_str(&format!(" ✓ (processor ID: {})", aux));
    }

    result
}
