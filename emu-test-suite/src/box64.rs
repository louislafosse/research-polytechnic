use crate::test_framework::{Test, TestResult, compile_test};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::fs;
use std::io::Read;

fn sanitize_box64_output(output: &str) -> String {
    let mut lines = Vec::new();

    for raw_line in output.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.starts_with("[BOX64]") || line.is_empty() {
            continue;
        }
        if lines.last().is_some_and(|prev: &String| prev == line) {
            continue;
        }
        lines.push(line.to_string());
    }

    lines.join("\n")
}

pub fn run_test_in_box64<T: Test>(
    test: &T,
) -> Result<(TestResult, String), Box<dyn std::error::Error>> {
    let temp_bin = compile_test(test, !test.requires_dynamic_linking())?;

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

    let filtered = sanitize_box64_output(&output_str);
    let trimmed = filtered.trim();
    if trimmed.is_empty() {
        return Err("box64 failed to produce valid output: no output".into());
    }

    let result = test.parse_output(trimmed)?;
    let formatted = test.format_result(&result);
    Ok((result, formatted))
}

pub fn test_fpu_in_box64() -> Result<(u16, String), Box<dyn std::error::Error>> {
    let test = crate::tests::FpuTest;
    let (result, formatted) = run_test_in_box64(&test)?;
    match result {
        TestResult::Fpu { status, .. } => Ok((status, formatted)),
        _ => Err("box64 returned unexpected FPU result type".into()),
    }
}

pub fn test_lahf_in_box64() -> Result<(u8, String), Box<dyn std::error::Error>> {
    let test = crate::tests::LahfTest;
    let (result, formatted) = run_test_in_box64(&test)?;
    match result {
        TestResult::Lahf { flags } => Ok((flags, formatted)),
        _ => Err("box64 returned unexpected LAHF result type".into()),
    }
}

pub fn test_rdtscp_in_box64() -> Result<(u32, String), Box<dyn std::error::Error>> {
    let test = crate::tests::RdtscpTest;
    let (result, formatted) = run_test_in_box64(&test)?;
    match result {
        TestResult::Rdtscp { aux } => Ok((aux, formatted)),
        _ => Err("box64 returned unexpected RDTSCP result type".into()),
    }
}
