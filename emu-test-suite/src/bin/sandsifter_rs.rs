use std::arch::asm;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::RawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};

#[allow(dead_code)]
#[path = "../c_based.rs"]
mod c_based;
#[allow(dead_code)]
#[path = "../icicle.rs"]
mod icicle_backend;
#[allow(dead_code)]
#[path = "../kubera.rs"]
mod kubera_backend;
#[allow(dead_code)]
#[path = "../mwemu.rs"]
mod mwemu_backend;
#[allow(dead_code)]
#[path = "../shellcode_based.rs"]
mod shellcode_based;
#[allow(dead_code)]
#[path = "../unicorn.rs"]
mod unicorn_backend;

const MAX_INSN_LEN: usize = 15;
const EXEC_PAGE_SIZE: usize = 4096;
const EXEC_STACK_SIZE: usize = 0x10000;
const SIGNAL_STACK_SIZE: usize = 0x10000;
const EXEC_DATA_SIZE: usize = 0x10000;
const STATE_VERSION: &str = "1";
const TUI_RECENT_LIMIT: usize = 10;
const TF_PREAMBLE: &[u8] = &[
    0x9c, // pushfq
    0x48, 0x81, 0x0c, 0x24, 0x00, 0x01, 0x00, 0x00, // or qword ptr [rsp], 0x100
    0x9d, // popfq
];
const SHELLCODE_BACKEND_DONE: u64 = 0x8877_6655_4433_2211;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Random,
    Brute,
    Tunnel,
    Mutate,
}

impl Mode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "random" | "rand" | "r" => Ok(Self::Random),
            "brute" | "b" => Ok(Self::Brute),
            "tunnel" | "t" => Ok(Self::Tunnel),
            "mutate" | "m" => Ok(Self::Mutate),
            other => Err(format!("unsupported mode: {}", other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum Backend {
    Native,
    Qemu,
    Blink,
    Box64,
    Unicorn,
    Icicle,
    Mwemu,
    Kubera,
}

impl Backend {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "native" | "host" => Ok(Self::Native),
            "qemu" | "qemu-x86_64" => Ok(Self::Qemu),
            "blink" => Ok(Self::Blink),
            "box64" => Ok(Self::Box64),
            "unicorn" => Ok(Self::Unicorn),
            "icicle" => Ok(Self::Icicle),
            "mwemu" => Ok(Self::Mwemu),
            "kubera" => Ok(Self::Kubera),
            other => Err(format!("unsupported backend: {}", other)),
        }
    }

    fn parse_list(value: &str) -> Result<Vec<Self>, String> {
        let mut out = Vec::new();
        for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let backend = Self::parse(item)?;
            if !out.contains(&backend) {
                out.push(backend);
            }
        }
        Ok(out)
    }

    fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Qemu => "qemu",
            Self::Blink => "blink",
            Self::Box64 => "box64",
            Self::Unicorn => "unicorn",
            Self::Icicle => "icicle",
            Self::Mwemu => "mwemu",
            Self::Kubera => "kubera",
        }
    }
}

#[derive(Debug)]
struct Config {
    mode: Mode,
    backend: Backend,
    compare_backends: Vec<Backend>,
    count: u64,
    max_len: usize,
    seed: u64,
    tick_every: u64,
    output: Option<String>,
    rare_log: Option<String>,
    workers: usize,
    max_prefix: usize,
    allow_dup_prefix: bool,
    mutation_seeds: usize,
    mutations_per_seed: usize,
    save_state: Option<String>,
    resume_state: Option<String>,
    tui: bool,
    no_color: bool,
    search_unk: bool,
    search_len: bool,
    search_dis: bool,
    search_ill: bool,
    worker_internal: bool,
    event_stream: bool,
    worker_range_start: u8,
    worker_range_end: u8,
    worker_label: Option<String>,
    exec_hex: Option<String>,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut mode = Mode::Random;
        let mut backend = Backend::Native;
        let mut compare_backends = Vec::new();
        let mut count = 10_000u64;
        let mut max_len = 4usize;
        let mut seed = default_seed();
        let mut tick_every = 1_000u64;
        let mut output = None;
        let mut rare_log = None;
        let mut workers = 1usize;
        let mut max_prefix = 1usize;
        let mut allow_dup_prefix = false;
        let mut mutation_seeds = 16usize;
        let mut mutations_per_seed = 8usize;
        let mut save_state = None;
        let mut resume_state = None;
        let mut tui = false;
        let mut no_color = false;
        let mut search_unk = false;
        let mut search_len = false;
        let mut search_dis = false;
        let mut search_ill = false;
        let mut worker_internal = false;
        let mut event_stream = false;
        let mut worker_range_start = 0u8;
        let mut worker_range_end = u8::MAX;
        let mut worker_label = None;
        let mut exec_hex = None;

        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--mode" => {
                    let value = args.next().ok_or("--mode requires a value")?;
                    mode = Mode::parse(&value)?;
                }
                "--backend" => {
                    let value = args.next().ok_or("--backend requires a value")?;
                    backend = Backend::parse(&value)?;
                }
                "--compare-backends" => {
                    let value = args.next().ok_or("--compare-backends requires a value")?;
                    compare_backends = Backend::parse_list(&value)?;
                }
                "--count" => {
                    let value = args.next().ok_or("--count requires a value")?;
                    count = value
                        .parse()
                        .map_err(|_| "invalid --count value".to_string())?;
                }
                "--max-len" => {
                    let value = args.next().ok_or("--max-len requires a value")?;
                    max_len = value
                        .parse()
                        .map_err(|_| "invalid --max-len value".to_string())?;
                    if max_len == 0 || max_len > MAX_INSN_LEN {
                        return Err(format!("--max-len must be between 1 and {}", MAX_INSN_LEN));
                    }
                }
                "--seed" => {
                    let value = args.next().ok_or("--seed requires a value")?;
                    seed = value
                        .parse()
                        .map_err(|_| "invalid --seed value".to_string())?;
                }
                "--tick" => {
                    let value = args.next().ok_or("--tick requires a value")?;
                    tick_every = value
                        .parse()
                        .map_err(|_| "invalid --tick value".to_string())?;
                }
                "--output" => {
                    output = Some(args.next().ok_or("--output requires a path")?);
                }
                "--workers" | "--threads" => {
                    let value = args.next().ok_or("--workers requires a value")?;
                    workers = value
                        .parse()
                        .map_err(|_| "invalid --workers value".to_string())?;
                    if workers == 0 {
                        return Err("--workers must be at least 1".to_string());
                    }
                }
                "--max-prefix" => {
                    let value = args.next().ok_or("--max-prefix requires a value")?;
                    max_prefix = value
                        .parse()
                        .map_err(|_| "invalid --max-prefix value".to_string())?;
                }
                "--allow-dup-prefix" => allow_dup_prefix = true,
                "--mut-seeds" => {
                    let value = args.next().ok_or("--mut-seeds requires a value")?;
                    mutation_seeds = value
                        .parse()
                        .map_err(|_| "invalid --mut-seeds value".to_string())?;
                }
                "--mutations" => {
                    let value = args.next().ok_or("--mutations requires a value")?;
                    mutations_per_seed = value
                        .parse()
                        .map_err(|_| "invalid --mutations value".to_string())?;
                }
                "--save-state" => {
                    save_state = Some(args.next().ok_or("--save-state requires a path")?);
                }
                "--rare-log" => {
                    rare_log = Some(args.next().ok_or("--rare-log requires a path")?);
                }
                "--resume-state" => {
                    resume_state = Some(args.next().ok_or("--resume-state requires a path")?);
                }
                "--tui" => tui = true,
                "--no-color" => no_color = true,
                "--unk" => search_unk = true,
                "--len" => search_len = true,
                "--dis" => search_dis = true,
                "--ill" => search_ill = true,
                "--worker-internal" => worker_internal = true,
                "--event-stream" => event_stream = true,
                "--worker-range-start" => {
                    let value = args.next().ok_or("--worker-range-start requires a value")?;
                    worker_range_start = value
                        .parse()
                        .map_err(|_| "invalid --worker-range-start value".to_string())?;
                }
                "--worker-range-end" => {
                    let value = args.next().ok_or("--worker-range-end requires a value")?;
                    worker_range_end = value
                        .parse()
                        .map_err(|_| "invalid --worker-range-end value".to_string())?;
                }
                "--worker-label" => {
                    worker_label = Some(args.next().ok_or("--worker-label requires a value")?);
                }
                "--exec-hex" => {
                    exec_hex = Some(args.next().ok_or("--exec-hex requires a value")?);
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {}", other)),
            }
        }

        compare_backends.retain(|candidate| *candidate != backend);

        if !search_unk && !search_len && !search_dis && !search_ill {
            search_unk = true;
            search_len = true;
            search_dis = true;
            search_ill = true;
        }

        Ok(Self {
            mode,
            backend,
            compare_backends,
            count,
            max_len,
            seed,
            tick_every,
            output,
            rare_log,
            workers,
            max_prefix,
            allow_dup_prefix,
            mutation_seeds,
            mutations_per_seed,
            save_state,
            resume_state,
            tui,
            no_color,
            search_unk,
            search_len,
            search_dis,
            search_ill,
            worker_internal,
            event_stream,
            worker_range_start,
            worker_range_end,
            worker_label,
            exec_hex,
        })
    }
}

#[derive(Clone, Debug)]
struct DisasInfo {
    known: bool,
    length: usize,
    mnemonic: String,
    operands: String,
    touches_memory: bool,
}

impl DisasInfo {
    fn text(&self) -> String {
        if self.known {
            if self.operands.is_empty() {
                self.mnemonic.clone()
            } else {
                format!("{} {}", self.mnemonic, self.operands)
            }
        } else {
            "(unk)".to_string()
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct ExecResult {
    valid: u32,
    length: u32,
    signum: i32,
    si_code: i32,
    si_addr: usize,
}

#[derive(Clone, Debug)]
struct BackendObservation {
    backend: Backend,
    exec: Option<ExecResult>,
    note: Option<String>,
}

#[derive(Clone, Debug)]
struct Anomaly {
    bytes: Vec<u8>,
    disas: DisasInfo,
    exec: ExecResult,
    reasons: Vec<String>,
    rare_tag: Option<String>,
    baseline_backend: Backend,
    compare_results: Vec<BackendObservation>,
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "bytes: {}", hex_bytes(&self.bytes))?;
        writeln!(
            f,
            "disas: {} (known={} len={})",
            self.disas.text(),
            self.disas.known,
            self.disas.length
        )?;
        writeln!(
            f,
            "exec[{}]: {}",
            self.baseline_backend.name(),
            exec_signature(&self.exec)
        )?;
        if let Some(tag) = &self.rare_tag {
            writeln!(f, "rare: {}", tag)?;
        }
        for observation in &self.compare_results {
            match (&observation.exec, &observation.note) {
                (Some(exec), _) => {
                    writeln!(
                        f,
                        "exec[{}]: {}",
                        observation.backend.name(),
                        exec_signature(exec)
                    )?;
                }
                (None, Some(note)) => {
                    writeln!(f, "exec[{}]: {}", observation.backend.name(), note)?;
                }
                (None, None) => {}
            }
        }
        write!(f, "reasons: {}", self.reasons.join(", "))
    }
}

#[derive(Debug)]
struct Summary {
    tested: u64,
    anomalies: u64,
    rare_hits: u64,
    resumed: bool,
    start: Instant,
    groups: HashMap<String, AnomalyGroup>,
}

impl Summary {
    fn new(tested: u64, anomalies: u64, resumed: bool) -> Self {
        Self {
            tested,
            anomalies,
            rare_hits: 0,
            resumed,
            start: Instant::now(),
            groups: HashMap::new(),
        }
    }
}

#[derive(Debug)]
struct AnomalyGroup {
    count: u64,
    sample_bytes: String,
    sample_disas: String,
    reasons: String,
    signal: i32,
    exec_len: u32,
}

#[derive(Clone, Copy)]
struct ChildRuntime {
    write_fd: RawFd,
    instr_start: usize,
}

#[derive(Default)]
struct TuiState {
    recent: VecDeque<String>,
    last_rendered: Option<(u64, u64)>,
}

#[derive(Default, Clone)]
struct WorkerProgress {
    tested: u64,
    anomalies: u64,
    rare_hits: u64,
    done: bool,
}

#[derive(Default)]
struct MultiTuiState {
    recent: VecDeque<String>,
    workers: HashMap<String, WorkerProgress>,
    last_rendered: Option<(u64, u64, u64, usize)>,
}

enum WorkerEvent {
    Tick {
        label: String,
        tested: u64,
        anomalies: u64,
        rare_hits: u64,
    },
    Anomaly {
        label: String,
        text: String,
    },
    Done {
        label: String,
        tested: u64,
        anomalies: u64,
        rare_hits: u64,
    },
    Stderr {
        label: String,
        text: String,
    },
}

struct TuiSession {
    active: bool,
}

impl TuiSession {
    fn enter() -> io::Result<Self> {
        let active = unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 };
        if active {
            let mut out = io::stdout().lock();
            write!(out, "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H")?;
            out.flush()?;
        }
        Ok(Self { active })
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for TuiSession {
    fn drop(&mut self) {
        if self.active {
            let mut out = io::stdout().lock();
            let _ = write!(out, "\x1b[?25h\x1b[?1049l");
            let _ = out.flush();
        }
    }
}

static mut CHILD_RUNTIME: ChildRuntime = ChildRuntime {
    write_fd: -1,
    instr_start: 0,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse().map_err(io::Error::other)?;

    if !cfg!(target_os = "linux") || !cfg!(target_arch = "x86_64") {
        return Err("sandsifter_rs currently supports linux x86_64 only".into());
    }

    if let Some(hex) = &config.exec_hex {
        let bytes = bytes_from_hex(hex)?;
        let result = execute_instruction(&bytes)?;
        println!("EXEC_RESULT {}", exec_signature(&result));
        return Ok(());
    }

    if config.worker_internal || config.workers == 1 {
        return run_single(config);
    }

    run_multi_worker(config)
}

fn run_single(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let mut logger = open_log_file(config.output.as_deref(), config.resume_state.is_some())?;
    let mut rare_logger = open_log_file(config.rare_log.as_deref(), config.resume_state.is_some())?;
    let (mut summary, mut generator) = load_or_create_state(&config)?;
    let tui_session = if config.tui {
        Some(TuiSession::enter()?)
    } else {
        None
    };
    let tui_active = tui_session.as_ref().is_some_and(TuiSession::is_active);
    let mut tui = if tui_active {
        Some(TuiState::default())
    } else {
        None
    };

    if config.tui && !tui_active {
        eprintln!("[tui] stdout is not a TTY; falling back to plain output.");
    }

    if config.event_stream {
        emit_worker_tick(&config, &summary)?;
    } else if tui_active {
        draw_tui(&config, &summary, tui.as_mut().expect("tui state exists"))?;
    } else {
        print_run_header(&config, &summary);
    }

    while summary.tested < config.count {
        let candidate = generator.next();
        if violates_prefix_rules(&candidate, config.max_prefix, config.allow_dup_prefix)
            || is_blacklisted(&candidate)
        {
            generator.reject();
            continue;
        }

        let disas = disassemble(&candidate);
        let exec = execute_with_backend(&candidate, config.backend)?;
        let mut reasons = classify(&config, &candidate, &disas, &exec);
        let compare_results = execute_comparisons(&config, &candidate, &exec, &mut reasons)?;
        let rare_tag = detect_rare_instruction(&disas, &exec, &reasons);
        if rare_tag.is_some() && !reasons.iter().any(|reason| reason == "rare_instruction") {
            reasons.push("rare_instruction".to_string());
            summary.rare_hits += 1;
        }
        generator.observe(&candidate, &exec, &reasons);

        summary.tested += 1;

        if !reasons.is_empty() {
            summary.anomalies += 1;
            let anomaly = Anomaly {
                bytes: candidate.clone(),
                disas,
                exec,
                reasons,
                rare_tag,
                baseline_backend: config.backend,
                compare_results,
            };
            record_group(&mut summary, &anomaly);

            if config.event_stream {
                emit_worker_anomaly(&config, &anomaly)?;
            } else if let Some(tui_state) = tui.as_mut() {
                push_tui_event(tui_state, &anomaly);
                draw_tui(&config, &summary, tui_state)?;
            } else {
                println!("{}", anomaly);
                println!();
            }

            if let Some(file) = logger.as_mut() {
                writeln!(file, "{}", anomaly)?;
                writeln!(file)?;
            }
            if let Some(file) = rare_logger.as_mut()
                && anomaly.rare_tag.is_some()
            {
                writeln!(file, "{}", anomaly)?;
                writeln!(file)?;
            }
        }

        if config.tick_every != 0 && summary.tested % config.tick_every == 0 {
            if config.event_stream {
                emit_worker_tick(&config, &summary)?;
            } else if let Some(tui_state) = tui.as_mut() {
                draw_tui(&config, &summary, tui_state)?;
            } else {
                print_progress(&config, &summary)?;
            }
            persist_state_if_needed(&config, &summary, &generator)?;
        }
    }

    if config.tick_every == 0 || summary.tested % config.tick_every != 0 {
        if config.event_stream {
            emit_worker_tick(&config, &summary)?;
        } else if let Some(tui_state) = tui.as_mut() {
            draw_tui(&config, &summary, tui_state)?;
        } else {
            print_progress(&config, &summary)?;
        }
    }

    persist_state_if_needed(&config, &summary, &generator)?;

    if config.event_stream {
        emit_worker_done(&config, &summary)?;
        return Ok(());
    }

    drop(tui_session);
    print_group_summary(&summary);
    println!("done.");
    Ok(())
}

fn run_multi_worker(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    if config.tui {
        return run_multi_worker_tui(config);
    }

    let exe = env::current_exe()?;
    let mut child_handles = Vec::new();
    let mut io_threads = Vec::new();

    println!("=== sandsifter_rs multi-worker ===");
    println!("workers: {}", config.workers);
    println!("mode: {:?}", config.mode);
    println!("backend: {}", config.backend.name());
    if !config.compare_backends.is_empty() {
        println!(
            "compare_backends: {}",
            backend_list_text(&config.compare_backends)
        );
    }
    println!();

    let base_count = config.count / config.workers as u64;
    let remainder = config.count % config.workers as u64;

    for worker_id in 0..config.workers {
        let start = ((worker_id * 256) / config.workers) as u8;
        let end = (((worker_id + 1) * 256) / config.workers).saturating_sub(1) as u8;
        let worker_count = base_count + u64::from((worker_id as u64) < remainder);
        let label = format!("worker-{} [{:02x}-{:02x}]", worker_id, start, end);

        let mut cmd = Command::new(&exe);
        cmd.arg("--worker-internal")
            .arg("--mode")
            .arg(mode_name(config.mode))
            .arg("--backend")
            .arg(config.backend.name())
            .arg("--count")
            .arg(worker_count.to_string())
            .arg("--max-len")
            .arg(config.max_len.to_string())
            .arg("--seed")
            .arg(config.seed.wrapping_add(worker_id as u64).to_string())
            .arg("--tick")
            .arg(config.tick_every.to_string())
            .arg("--max-prefix")
            .arg(config.max_prefix.to_string())
            .arg("--mut-seeds")
            .arg(config.mutation_seeds.to_string())
            .arg("--mutations")
            .arg(config.mutations_per_seed.to_string())
            .arg("--worker-range-start")
            .arg(start.to_string())
            .arg("--worker-range-end")
            .arg(end.to_string())
            .arg("--worker-label")
            .arg(label.clone())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if !config.compare_backends.is_empty() {
            cmd.arg("--compare-backends")
                .arg(backend_list_text(&config.compare_backends));
        }
        if config.allow_dup_prefix {
            cmd.arg("--allow-dup-prefix");
        }
        if config.search_unk {
            cmd.arg("--unk");
        }
        if config.search_len {
            cmd.arg("--len");
        }
        if config.search_dis {
            cmd.arg("--dis");
        }
        if config.search_ill {
            cmd.arg("--ill");
        }
        if config.no_color {
            cmd.arg("--no-color");
        }
        if let Some(path) = &config.output {
            cmd.arg("--output")
                .arg(format!("{}.worker{}", path, worker_id));
        }
        if let Some(path) = &config.rare_log {
            cmd.arg("--rare-log")
                .arg(format!("{}.worker{}", path, worker_id));
        }
        if let Some(path) = &config.save_state {
            cmd.arg("--save-state")
                .arg(format!("{}.worker{}", path, worker_id));
        }
        if let Some(path) = &config.resume_state {
            cmd.arg("--resume-state")
                .arg(format!("{}.worker{}", path, worker_id));
        }

        let mut child = cmd.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or("failed to capture worker stdout")?;
        let stderr = child
            .stderr
            .take()
            .ok_or("failed to capture worker stderr")?;

        let stdout_label = label.clone();
        io_threads.push(thread::spawn(move || -> io::Result<()> {
            for line in BufReader::new(stdout).lines() {
                println!("[{}] {}", stdout_label, line?);
            }
            Ok(())
        }));

        let stderr_label = label.clone();
        io_threads.push(thread::spawn(move || -> io::Result<()> {
            for line in BufReader::new(stderr).lines() {
                eprintln!("[{}] {}", stderr_label, line?);
            }
            Ok(())
        }));

        child_handles.push((label, child));
    }

    let mut failed = false;
    for (label, mut child) in child_handles {
        let status = child.wait()?;
        if !status.success() {
            failed = true;
            eprintln!("{} exited with {}", label, status);
        }
    }

    for thread in io_threads {
        thread.join().map_err(|_| "worker I/O thread panicked")??;
    }

    if failed {
        Err("one or more workers failed".into())
    } else {
        println!("all workers completed.");
        Ok(())
    }
}

fn run_multi_worker_tui(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let tui_session = TuiSession::enter()?;
    if !tui_session.is_active() {
        eprintln!("[tui] stdout is not a TTY; falling back to plain multi-worker output.");
        drop(tui_session);
        let mut plain_config = config;
        plain_config.tui = false;
        return run_multi_worker(plain_config);
    }

    let exe = env::current_exe()?;
    let (tx, rx) = mpsc::channel::<WorkerEvent>();
    let mut child_handles = Vec::new();
    let mut io_threads = Vec::new();
    let mut tui = MultiTuiState::default();
    let worker_total = config.workers;

    let base_count = config.count / config.workers as u64;
    let remainder = config.count % config.workers as u64;

    for worker_id in 0..config.workers {
        let start = ((worker_id * 256) / config.workers) as u8;
        let end = (((worker_id + 1) * 256) / config.workers).saturating_sub(1) as u8;
        let worker_count = base_count + u64::from((worker_id as u64) < remainder);
        let label = format!("worker-{} [{:02x}-{:02x}]", worker_id, start, end);

        tui.workers.insert(label.clone(), WorkerProgress::default());

        let mut cmd = Command::new(&exe);
        cmd.arg("--worker-internal")
            .arg("--event-stream")
            .arg("--mode")
            .arg(mode_name(config.mode))
            .arg("--backend")
            .arg(config.backend.name())
            .arg("--count")
            .arg(worker_count.to_string())
            .arg("--max-len")
            .arg(config.max_len.to_string())
            .arg("--seed")
            .arg(config.seed.wrapping_add(worker_id as u64).to_string())
            .arg("--tick")
            .arg(config.tick_every.to_string())
            .arg("--max-prefix")
            .arg(config.max_prefix.to_string())
            .arg("--mut-seeds")
            .arg(config.mutation_seeds.to_string())
            .arg("--mutations")
            .arg(config.mutations_per_seed.to_string())
            .arg("--worker-range-start")
            .arg(start.to_string())
            .arg("--worker-range-end")
            .arg(end.to_string())
            .arg("--worker-label")
            .arg(label.clone())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if !config.compare_backends.is_empty() {
            cmd.arg("--compare-backends")
                .arg(backend_list_text(&config.compare_backends));
        }
        if config.allow_dup_prefix {
            cmd.arg("--allow-dup-prefix");
        }
        if config.search_unk {
            cmd.arg("--unk");
        }
        if config.search_len {
            cmd.arg("--len");
        }
        if config.search_dis {
            cmd.arg("--dis");
        }
        if config.search_ill {
            cmd.arg("--ill");
        }
        if config.no_color {
            cmd.arg("--no-color");
        }
        if let Some(path) = &config.output {
            cmd.arg("--output")
                .arg(format!("{}.worker{}", path, worker_id));
        }
        if let Some(path) = &config.rare_log {
            cmd.arg("--rare-log")
                .arg(format!("{}.worker{}", path, worker_id));
        }
        if let Some(path) = &config.save_state {
            cmd.arg("--save-state")
                .arg(format!("{}.worker{}", path, worker_id));
        }
        if let Some(path) = &config.resume_state {
            cmd.arg("--resume-state")
                .arg(format!("{}.worker{}", path, worker_id));
        }

        let mut child = cmd.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or("failed to capture worker stdout")?;
        let stderr = child
            .stderr
            .take()
            .ok_or("failed to capture worker stderr")?;

        let stdout_label = label.clone();
        let stdout_tx = tx.clone();
        io_threads.push(thread::spawn(move || -> io::Result<()> {
            for line in BufReader::new(stdout).lines() {
                let line = line?;
                if let Some(event) = parse_worker_event(&stdout_label, &line) {
                    let _ = stdout_tx.send(event);
                }
            }
            Ok(())
        }));

        let stderr_label = label.clone();
        let stderr_tx = tx.clone();
        io_threads.push(thread::spawn(move || -> io::Result<()> {
            for line in BufReader::new(stderr).lines() {
                let _ = stderr_tx.send(WorkerEvent::Stderr {
                    label: stderr_label.clone(),
                    text: line?,
                });
            }
            Ok(())
        }));

        child_handles.push((label, child));
    }
    drop(tx);

    draw_multi_worker_tui(&config, &mut tui)?;

    let mut completed = 0usize;
    while completed < worker_total {
        match rx.recv() {
            Ok(event) => {
                if apply_worker_event(&mut tui, event) {
                    completed += 1;
                }
                draw_multi_worker_tui(&config, &mut tui)?;
            }
            Err(_) => break,
        }
    }

    let mut failed = false;
    for (label, mut child) in child_handles {
        let status = child.wait()?;
        if !status.success() {
            failed = true;
            push_multi_tui_line(&mut tui, format!("{} exited with {}", label, status));
        }
    }

    for thread in io_threads {
        thread.join().map_err(|_| "worker I/O thread panicked")??;
    }

    draw_multi_worker_tui(&config, &mut tui)?;
    drop(tui_session);

    if failed {
        Err("one or more workers failed".into())
    } else {
        println!("all workers completed.");
        Ok(())
    }
}

fn print_run_header(config: &Config, summary: &Summary) {
    println!("=== sandsifter_rs ===");
    if let Some(label) = &config.worker_label {
        println!("worker: {}", label);
    }
    println!("mode: {:?}", config.mode);
    println!("backend: {}", config.backend.name());
    if !config.compare_backends.is_empty() {
        println!(
            "compare_backends: {}",
            backend_list_text(&config.compare_backends)
        );
    }
    println!("count: {}", config.count);
    println!("max_len: {}", config.max_len);
    println!("seed: {}", config.seed);
    println!(
        "range: 0x{:02x}..=0x{:02x}",
        config.worker_range_start, config.worker_range_end
    );
    println!("workers: {}", config.workers);
    if let Some(path) = &config.rare_log {
        println!("rare_log: {}", path);
    }
    println!("max_prefix: {}", config.max_prefix);
    println!("allow_dup_prefix: {}", config.allow_dup_prefix);
    println!("mut_seeds: {}", config.mutation_seeds);
    println!("mutations_per_seed: {}", config.mutations_per_seed);
    println!(
        "filters: unk={} len={} dis={} ill={}",
        config.search_unk, config.search_len, config.search_dis, config.search_ill
    );
    if summary.resumed {
        println!(
            "resume: restored tested={} anomalies={} from state",
            summary.tested, summary.anomalies
        );
    }
    println!();
}

fn print_help() {
    println!("sandsifter_rs - safe-first Rust MVP of sandsifter");
    println!();
    println!("Usage:");
    println!("  cargo run --release --bin sandsifter_rs -- [options]");
    println!();
    println!("Options:");
    println!("  --mode <random|brute|tunnel|mutate> Search mode (default: random)");
    println!(
        "  --backend <native|qemu|blink|box64|unicorn|icicle|mwemu|kubera> Execution backend (default: native)"
    );
    println!(
        "  --compare-backends <list>          Compare baseline against comma-separated backends"
    );
    println!(
        "  --count <n>                        Number of instructions to test (default: 10000)"
    );
    println!("  --max-len <n>                      Maximum instruction length in bytes, 1..15");
    println!("  --workers <n>                      Number of scan workers (default: 1)");
    println!("  --threads <n>                      Alias for --workers");
    println!("  --max-prefix <n>                   Maximum prefix bytes to explore (default: 1)");
    println!("  --allow-dup-prefix                 Allow duplicate instruction prefixes");
    println!("  --seed <n>                         RNG seed");
    println!("  --tick <n>                         Progress interval (default: 1000)");
    println!("  --output <path>                    Write anomaly log to a file");
    println!("  --rare-log <path>                  Write rare/unusual hits to a separate log");
    println!("  --mut-seeds <n>                    Random seeds for mutate mode (default: 16)");
    println!("  --mutations <n>                    Mutations per interesting seed (default: 8)");
    println!("  --save-state <path>                Persist generator state for resume");
    println!("  --resume-state <path>              Resume generator state from disk");
    println!("  --tui                              Use a live colored terminal view");
    println!("  --no-color                         Disable ANSI colors in TUI mode");
    println!("  --unk                              Report unknown instructions that execute");
    println!("  --len                              Report disassembly length mismatches");
    println!("  --dis                              Report valid disassembly disagreements");
    println!(
        "  --ill                              Report instructions accepted by the disassembler but raising SIGILL"
    );
}

fn emit_worker_tick(config: &Config, summary: &Summary) -> io::Result<()> {
    let label = config.worker_label.as_deref().unwrap_or("worker");
    println!(
        "@@EVENT kind=tick label={} tested={} anomalies={} rare_hits={}",
        hex_bytes(label.as_bytes()),
        summary.tested,
        summary.anomalies,
        summary.rare_hits
    );
    io::stdout().flush()
}

fn emit_worker_anomaly(config: &Config, anomaly: &Anomaly) -> io::Result<()> {
    let label = config.worker_label.as_deref().unwrap_or("worker");
    println!(
        "@@EVENT kind=anomaly label={} text={}",
        hex_bytes(label.as_bytes()),
        hex_bytes(format_anomaly_line(anomaly).as_bytes())
    );
    io::stdout().flush()
}

fn emit_worker_done(config: &Config, summary: &Summary) -> io::Result<()> {
    let label = config.worker_label.as_deref().unwrap_or("worker");
    println!(
        "@@EVENT kind=done label={} tested={} anomalies={} rare_hits={}",
        hex_bytes(label.as_bytes()),
        summary.tested,
        summary.anomalies,
        summary.rare_hits
    );
    io::stdout().flush()
}

fn print_progress(config: &Config, summary: &Summary) -> io::Result<()> {
    let elapsed = summary.start.elapsed();
    let rate = if elapsed.as_secs_f64() > 0.0 {
        summary.tested as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "[tick] backend={} compare={} tested={} anomalies={} rare_hits={} elapsed={} rate={:.1}/s",
        config.backend.name(),
        if config.compare_backends.is_empty() {
            "-".to_string()
        } else {
            backend_list_text(&config.compare_backends)
        },
        summary.tested,
        summary.anomalies,
        summary.rare_hits,
        format_duration(elapsed),
        rate
    )
}

fn record_group(summary: &mut Summary, anomaly: &Anomaly) {
    let key = format!(
        "{}|{}|{}|{}|{}",
        anomaly.reasons.join(","),
        anomaly.exec.signum,
        anomaly.exec.length,
        anomaly.disas.text(),
        anomaly.disas.known
    );
    let entry = summary.groups.entry(key).or_insert_with(|| AnomalyGroup {
        count: 0,
        sample_bytes: hex_bytes(&anomaly.bytes),
        sample_disas: anomaly.disas.text(),
        reasons: anomaly.reasons.join(","),
        signal: anomaly.exec.signum,
        exec_len: anomaly.exec.length,
    });
    entry.count += 1;
}

fn print_group_summary(summary: &Summary) {
    if summary.groups.is_empty() {
        return;
    }

    let mut groups = summary.groups.values().collect::<Vec<_>>();
    groups.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.reasons.cmp(&b.reasons))
    });

    println!();
    println!("=== Anomaly Groups ===");
    for group in groups.into_iter().take(20) {
        println!(
            "{}x | reasons={} | signal={} | exec_len={} | disas={} | sample={}",
            group.count,
            group.reasons,
            group.signal,
            group.exec_len,
            group.sample_disas,
            group.sample_bytes
        );
    }
    println!();
}

fn classify(
    config: &Config,
    candidate: &[u8],
    disas: &DisasInfo,
    exec: &ExecResult,
) -> Vec<String> {
    let mut reasons = Vec::new();

    if exec.valid == 0 {
        return reasons;
    }

    if (exec.signum == libc::SIGSEGV || exec.signum == libc::SIGBUS)
        && disas.known
        && disas.touches_memory
    {
        reasons.push("memory_touching_fault".to_string());
        return reasons;
    }

    if config.search_unk && !disas.known && exec.signum != libc::SIGILL {
        let ran_past_candidate = exec.length as usize > candidate.len();
        if ran_past_candidate {
            if exec.signum == libc::SIGSEGV || exec.signum == libc::SIGBUS {
                reasons.push("incomplete_stream_faults".to_string());
            } else {
                reasons.push("incomplete_stream_executes".to_string());
            }
        } else if exec.signum == libc::SIGSEGV || exec.signum == libc::SIGBUS {
            reasons.push("unknown_instruction_faults".to_string());
        } else {
            reasons.push("potential_hidden_instruction".to_string());
        }
    }
    if config.search_len && disas.known && disas.length != exec.length as usize {
        reasons.push("length_mismatch".to_string());
    }
    if config.search_dis
        && disas.known
        && disas.length != exec.length as usize
        && exec.signum != libc::SIGILL
    {
        reasons.push("disassembly_disagreement".to_string());
    }
    if config.search_ill && disas.known && exec.signum == libc::SIGILL {
        reasons.push("disassembler_accepts_sigill".to_string());
    }

    reasons
}

fn detect_rare_instruction(
    disas: &DisasInfo,
    exec: &ExecResult,
    reasons: &[String],
) -> Option<String> {
    if reasons
        .iter()
        .any(|reason| reason == "potential_hidden_instruction")
    {
        return Some("invalid_decode_executes_within_candidate".to_string());
    }

    if reasons
        .iter()
        .any(|reason| reason == "disassembler_accepts_sigill")
    {
        return Some("decoder_accepts_but_cpu_sigill".to_string());
    }

    if disas.known && is_uncommon_mnemonic(&disas.mnemonic) {
        let category = uncommon_mnemonic_category(&disas.mnemonic);
        return Some(format!("{}:{}", category, disas.text()));
    }

    if disas.known && exec.signum == libc::SIGILL {
        return Some(format!("known_instruction_sigill:{}", disas.text()));
    }

    None
}

fn disassemble(bytes: &[u8]) -> DisasInfo {
    let mut decoder = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
    let instruction = decoder.decode();
    let known = !instruction.is_invalid();
    let length = if known { instruction.len() } else { 0 };

    let mut formatter = NasmFormatter::new();
    let mut text = String::new();
    formatter.format(&instruction, &mut text);

    let (mnemonic, operands) = if known {
        match text.split_once(' ') {
            Some((mne, ops)) => (mne.to_string(), ops.to_string()),
            None => (text, String::new()),
        }
    } else {
        ("(unk)".to_string(), String::new())
    };

    let touches_memory =
        known && (operands.contains('[') || mnemonic_has_implicit_memory(&mnemonic));

    DisasInfo {
        known,
        length,
        mnemonic,
        operands,
        touches_memory,
    }
}

fn execute_comparisons(
    config: &Config,
    candidate: &[u8],
    baseline: &ExecResult,
    reasons: &mut Vec<String>,
) -> io::Result<Vec<BackendObservation>> {
    let mut results = Vec::new();
    let compare_backends = config.compare_backends.clone();
    let candidate = candidate.to_vec();

    let observations = thread::scope(|scope| {
        let mut handles = Vec::new();
        for backend in compare_backends {
            let bytes = candidate.clone();
            handles.push((
                backend,
                scope.spawn(move || execute_with_backend(&bytes, backend)),
            ));
        }

        let mut collected = Vec::new();
        for (backend, handle) in handles {
            let result = handle
                .join()
                .map_err(|_| io::Error::other("backend comparison thread panicked"))?;
            collected.push((backend, result));
        }
        Ok::<_, io::Error>(collected)
    })?;

    for (backend, result) in observations {
        match result {
            Ok(exec) => {
                if !exec_equivalent(baseline, &exec) {
                    reasons.push(format!("backend_mismatch_{}", backend.name()));
                    results.push(BackendObservation {
                        backend,
                        exec: Some(exec),
                        note: None,
                    });
                }
            }
            Err(err) => {
                reasons.push(format!("backend_unavailable_{}", backend.name()));
                results.push(BackendObservation {
                    backend,
                    exec: None,
                    note: Some(err.to_string()),
                });
            }
        }
    }
    Ok(results)
}

fn execute_with_backend(bytes: &[u8], backend: Backend) -> io::Result<ExecResult> {
    match backend {
        Backend::Native => execute_instruction(bytes),
        Backend::Qemu | Backend::Blink | Backend::Box64 => {
            execute_instruction_via_backend(bytes, backend)
        }
        Backend::Unicorn | Backend::Icicle | Backend::Mwemu | Backend::Kubera => {
            execute_instruction_via_shellcode_backend(bytes, backend)
        }
    }
}

fn execute_instruction_via_backend(bytes: &[u8], backend: Backend) -> io::Result<ExecResult> {
    let exe = env::current_exe()?;
    let mut cmd = match backend {
        Backend::Qemu => {
            let mut cmd = Command::new("qemu-x86_64");
            cmd.arg(&exe);
            cmd
        }
        Backend::Blink => {
            let mut cmd = Command::new("blink");
            cmd.arg("-L").arg("/dev/null").arg(&exe);
            cmd
        }
        Backend::Box64 => {
            let mut cmd = Command::new("box64");
            cmd.arg(&exe);
            cmd
        }
        Backend::Native | Backend::Unicorn | Backend::Icicle | Backend::Mwemu | Backend::Kubera => {
            unreachable!("handled elsewhere")
        }
    };

    let output = cmd.arg("--exec-hex").arg(hex_bytes(bytes)).output()?;
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    for line in combined.lines().rev() {
        if let Some(rest) = line.trim().strip_prefix("EXEC_RESULT ") {
            return parse_exec_signature(rest);
        }
    }

    Err(io::Error::other(format!(
        "{} did not return a parseable exec result (status: {})",
        backend.name(),
        output.status
    )))
}

fn execute_instruction_via_shellcode_backend(
    bytes: &[u8],
    backend: Backend,
) -> io::Result<ExecResult> {
    let shellcode = wrap_candidate_for_shellcode_backend(bytes);
    let result = match backend {
        Backend::Unicorn => unicorn_backend::run_shellcode_return_rax(&shellcode),
        Backend::Icicle => icicle_backend::run_shellcode_return_rax(&shellcode),
        Backend::Mwemu => {
            mwemu_backend::run_shellcode_return_rax("sandsifter_candidate", &shellcode)
        }
        Backend::Kubera => {
            kubera_backend::run_shellcode_return_rax("sandsifter_candidate", &shellcode)
        }
        Backend::Native | Backend::Qemu | Backend::Blink | Backend::Box64 => {
            unreachable!("handled elsewhere")
        }
    };

    match result {
        Ok(rax) => Ok(exec_result_from_shellcode_backend(bytes, rax)),
        Err(err) => map_shellcode_backend_error(&err.to_string())
            .ok_or_else(|| io::Error::other(format!("{} backend failed: {}", backend.name(), err))),
    }
}

fn wrap_candidate_for_shellcode_backend(bytes: &[u8]) -> Vec<u8> {
    let mut shellcode = Vec::with_capacity(96 + bytes.len());
    shellcode.extend_from_slice(&[0x48, 0x8D, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00]); // lea rax, [rsp+0x100]
    shellcode.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax
    shellcode.extend_from_slice(&[0x48, 0x89, 0xC1]); // mov rcx, rax
    shellcode.extend_from_slice(&[0x48, 0x89, 0xC2]); // mov rdx, rax
    shellcode.extend_from_slice(&[0x48, 0x89, 0xC6]); // mov rsi, rax
    shellcode.extend_from_slice(&[0x48, 0x89, 0xC7]); // mov rdi, rax
    shellcode.extend_from_slice(&[0x48, 0x89, 0xC5]); // mov rbp, rax
    shellcode.extend_from_slice(&[0x49, 0x89, 0xC0]); // mov r8, rax
    shellcode.extend_from_slice(&[0x49, 0x89, 0xC1]); // mov r9, rax
    shellcode.extend_from_slice(&[0x49, 0x89, 0xC2]); // mov r10, rax
    shellcode.extend_from_slice(&[0x49, 0x89, 0xC3]); // mov r11, rax
    shellcode.extend_from_slice(&[0x49, 0x89, 0xC4]); // mov r12, rax
    shellcode.extend_from_slice(&[0x49, 0x89, 0xC5]); // mov r13, rax
    shellcode.extend_from_slice(&[0x49, 0x89, 0xC6]); // mov r14, rax
    shellcode.extend_from_slice(&[0x49, 0x89, 0xC7]); // mov r15, rax
    shellcode.extend_from_slice(bytes);
    shellcode.extend_from_slice(&[0x48, 0xB8]);
    shellcode.extend_from_slice(&SHELLCODE_BACKEND_DONE.to_le_bytes());
    shellcode.push(0xC3);
    shellcode
}

fn exec_result_from_shellcode_backend(bytes: &[u8], rax: u64) -> ExecResult {
    if rax == SHELLCODE_BACKEND_DONE {
        ExecResult {
            valid: 1,
            length: bytes.len() as u32,
            signum: libc::SIGTRAP,
            si_code: libc::TRAP_TRACE,
            si_addr: 0,
        }
    } else {
        ExecResult {
            valid: 1,
            length: 0,
            signum: 0,
            si_code: 0,
            si_addr: rax as usize,
        }
    }
}

fn map_shellcode_backend_error(err: &str) -> Option<ExecResult> {
    let lower = err.to_ascii_lowercase();
    if lower.contains("unsupported")
        || lower.contains("unimplemented")
        || lower.contains("sigill")
        || lower.contains("unsupported instruction")
        || lower.contains("does not support")
    {
        return Some(ExecResult {
            valid: 1,
            length: 0,
            signum: libc::SIGILL,
            si_code: 0,
            si_addr: 0,
        });
    }

    if lower.contains("exception") || lower.contains("access violation") {
        return Some(ExecResult {
            valid: 1,
            length: 0,
            signum: libc::SIGSEGV,
            si_code: 0,
            si_addr: 0,
        });
    }

    if lower.contains("read_unmapped")
        || lower.contains("write_unmapped")
        || lower.contains("handle_memory")
        || lower.contains("failed for add op")
    {
        return Some(ExecResult {
            valid: 1,
            length: 0,
            signum: libc::SIGSEGV,
            si_code: 0,
            si_addr: 0,
        });
    }

    None
}

fn exec_equivalent(left: &ExecResult, right: &ExecResult) -> bool {
    left.valid == right.valid && left.length == right.length && left.signum == right.signum
}

fn execute_instruction(bytes: &[u8]) -> io::Result<ExecResult> {
    let mut pipe_fds = [0; 2];
    let pipe_rc = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
    if pipe_rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        unsafe {
            libc::close(pipe_fds[0]);
            let _ = child_execute(pipe_fds[1], bytes);
            libc::_exit(1);
        }
    }

    unsafe {
        libc::close(pipe_fds[1]);
    }

    let result = read_exec_result(pipe_fds[0])?;
    unsafe {
        libc::close(pipe_fds[0]);
    }

    let mut status = 0;
    let wait_rc = unsafe { libc::waitpid(pid, &mut status, 0) };
    if wait_rc < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(result.unwrap_or_default())
}

unsafe fn child_execute(write_fd: RawFd, bytes: &[u8]) -> io::Result<()> {
    unsafe {
        setup_signal_stack()?;
        install_signal_handlers()?;
        libc::alarm(1);
    }

    let code_map = unsafe {
        map_region(
            EXEC_PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )?
    };
    let stack_map = unsafe { map_region(EXEC_STACK_SIZE, libc::PROT_READ | libc::PROT_WRITE)? };
    let data_map = unsafe { map_region(EXEC_DATA_SIZE, libc::PROT_READ | libc::PROT_WRITE)? };

    unsafe {
        initialize_data_region(data_map.cast::<u8>());
    }

    let mut wrapper = Vec::with_capacity(TF_PREAMBLE.len() + bytes.len() + 1);
    wrapper.extend_from_slice(TF_PREAMBLE);
    wrapper.extend_from_slice(bytes);
    wrapper.push(0xcc);

    unsafe {
        ptr::copy_nonoverlapping(wrapper.as_ptr(), code_map.cast::<u8>(), wrapper.len());
    }

    let instr_start = code_map as usize + TF_PREAMBLE.len();
    unsafe {
        CHILD_RUNTIME = ChildRuntime {
            write_fd,
            instr_start,
        };
    }

    let data_base = data_map as usize;
    let stack_top = stack_map as usize + EXEC_STACK_SIZE - 0x100;
    let entry = code_map as usize;

    unsafe {
        asm!(
            "mov r15, {entry}",
            "mov rsp, {stack_top}",
            "mov rax, {data_base}",
            "lea rax, [rax + 0x100]",
            "mov rbx, rax",
            "lea rbx, [rbx + 0x80]",
            "mov rcx, rax",
            "lea rcx, [rcx + 0x100]",
            "mov rdx, rax",
            "lea rdx, [rdx + 0x180]",
            "mov rsi, rax",
            "lea rsi, [rsi + 0x200]",
            "mov rdi, rax",
            "lea rdi, [rdi + 0x280]",
            "mov rbp, rax",
            "lea rbp, [rbp + 0x300]",
            "mov r8, rax",
            "lea r8, [r8 + 0x380]",
            "mov r9, rax",
            "lea r9, [r9 + 0x400]",
            "mov r10, rax",
            "lea r10, [r10 + 0x480]",
            "mov r11, rax",
            "lea r11, [r11 + 0x500]",
            "mov r12, rax",
            "lea r12, [r12 + 0x580]",
            "mov r13, rax",
            "lea r13, [r13 + 0x600]",
            "mov r14, rax",
            "lea r14, [r14 + 0x680]",
            "jmp r15",
            data_base = in(reg) aligned_ptr(data_base, 0),
            stack_top = in(reg) stack_top,
            entry = in(reg) entry,
            options(noreturn)
        );
    }
}

unsafe extern "C" fn signal_handler(
    signum: libc::c_int,
    info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    let mut length = 0usize;
    let mut si_code = 0i32;

    if !info.is_null() {
        unsafe {
            si_code = (*info).si_code;
        }
    }

    if !ucontext.is_null() {
        let uc = unsafe { &*(ucontext as *const libc::ucontext_t) };
        let rip = uc.uc_mcontext.gregs[libc::REG_RIP as usize] as usize;
        let instr_start = unsafe { CHILD_RUNTIME.instr_start };
        if rip >= instr_start {
            length = rip - instr_start;
            if signum == libc::SIGTRAP && si_code == libc::TRAP_BRKPT && length > 0 {
                length -= 1;
            }
        }
    }

    let result = ExecResult {
        valid: 1,
        length: length as u32,
        signum,
        si_code,
        si_addr: 0,
    };

    unsafe {
        let _ = libc::write(
            CHILD_RUNTIME.write_fd,
            &result as *const ExecResult as *const libc::c_void,
            size_of::<ExecResult>(),
        );
        libc::_exit(0);
    }
}

unsafe fn setup_signal_stack() -> io::Result<()> {
    let stack = unsafe {
        libc::mmap(
            ptr::null_mut(),
            SIGNAL_STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if stack == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }

    let alt_stack = libc::stack_t {
        ss_sp: stack,
        ss_flags: 0,
        ss_size: SIGNAL_STACK_SIZE,
    };

    if unsafe { libc::sigaltstack(&alt_stack, ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

unsafe fn install_signal_handlers() -> io::Result<()> {
    let mut sa: libc::sigaction = unsafe { zeroed() };
    sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
    sa.sa_sigaction = signal_handler as *const () as usize;
    unsafe {
        libc::sigemptyset(&mut sa.sa_mask);
    }

    for sig in [
        libc::SIGILL,
        libc::SIGSEGV,
        libc::SIGBUS,
        libc::SIGFPE,
        libc::SIGTRAP,
        libc::SIGALRM,
    ] {
        if unsafe { libc::sigaction(sig, &sa, ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

unsafe fn map_region(size: usize, prot: i32) -> io::Result<*mut libc::c_void> {
    let ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        Err(io::Error::last_os_error())
    } else {
        Ok(ptr)
    }
}

unsafe fn initialize_data_region(base: *mut u8) {
    for i in 0..EXEC_DATA_SIZE {
        unsafe {
            ptr::write(base.add(i), (i as u8).wrapping_mul(17).wrapping_add(3));
        }
    }

    for i in (0..EXEC_DATA_SIZE).step_by(8) {
        let offset = (i + 0x80) % (EXEC_DATA_SIZE - 8);
        let ptr_value = aligned_ptr(base as usize, offset) as u64;
        unsafe {
            ptr::write_unaligned(base.add(i) as *mut u64, ptr_value);
        }
    }
}

fn aligned_ptr(base: usize, offset: usize) -> usize {
    (base + offset + 0x0f) & !0x0f
}

fn read_exec_result(fd: RawFd) -> io::Result<Option<ExecResult>> {
    let mut result = ExecResult::default();
    let result_bytes = unsafe {
        std::slice::from_raw_parts_mut(
            &mut result as *mut ExecResult as *mut u8,
            size_of::<ExecResult>(),
        )
    };

    let mut read_total = 0usize;
    while read_total < result_bytes.len() {
        let read_rc = unsafe {
            libc::read(
                fd,
                result_bytes[read_total..].as_mut_ptr() as *mut libc::c_void,
                result_bytes.len() - read_total,
            )
        };

        if read_rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if read_rc == 0 {
            break;
        }
        read_total += read_rc as usize;
    }

    if read_total == size_of::<ExecResult>() {
        Ok(Some(result))
    } else {
        Ok(None)
    }
}

struct Generator {
    mode: Mode,
    max_len: usize,
    rng: XorShift64,
    range_start: u8,
    range_end: u8,
    brute_len: usize,
    brute_state: [u8; MAX_INSN_LEN],
    brute_started: bool,
    tunnel_state: [u8; MAX_INSN_LEN],
    tunnel_index: usize,
    tunnel_last_len: Option<u32>,
    tunnel_started: bool,
    mutate_queue: VecDeque<Vec<u8>>,
    mutate_seed_budget: usize,
    mutations_per_seed: usize,
}

impl Generator {
    fn new(
        mode: Mode,
        max_len: usize,
        seed: u64,
        range_start: u8,
        range_end: u8,
        mutate_seed_budget: usize,
        mutations_per_seed: usize,
    ) -> Self {
        let mut brute_state = [0; MAX_INSN_LEN];
        brute_state[0] = range_start;
        let mut tunnel_state = [0; MAX_INSN_LEN];
        tunnel_state[0] = range_start;

        Self {
            mode,
            max_len,
            rng: XorShift64::new(seed),
            range_start,
            range_end,
            brute_len: 1,
            brute_state,
            brute_started: false,
            tunnel_state,
            tunnel_index: 0,
            tunnel_last_len: None,
            tunnel_started: false,
            mutate_queue: VecDeque::new(),
            mutate_seed_budget,
            mutations_per_seed,
        }
    }

    fn next(&mut self) -> Vec<u8> {
        match self.mode {
            Mode::Random => self.next_random(),
            Mode::Brute => self.next_brute(),
            Mode::Tunnel => self.next_tunnel(),
            Mode::Mutate => self.next_mutate(),
        }
    }

    fn observe(&mut self, candidate: &[u8], exec: &ExecResult, reasons: &[String]) {
        match self.mode {
            Mode::Tunnel => {
                let changed_len = self
                    .tunnel_last_len
                    .map(|previous| previous != exec.length)
                    .unwrap_or(true);
                if changed_len
                    && exec.length > 0
                    && self.tunnel_index + 1 < self.max_len
                    && self.tunnel_index < exec.length.saturating_sub(1) as usize
                {
                    self.tunnel_index += 1;
                } else if !reasons.is_empty()
                    && self.tunnel_index + 1 < self.max_len
                    && candidate.len() <= 2
                {
                    self.tunnel_index += 1;
                }
                self.tunnel_last_len = Some(exec.length);
                self.advance_tunnel();
            }
            Mode::Mutate => {
                let interesting = !reasons.is_empty()
                    || exec.signum == libc::SIGILL
                    || exec.signum == libc::SIGFPE
                    || exec.length > 1;
                if interesting {
                    for _ in 0..self.mutations_per_seed {
                        let mutated = self.mutate_candidate(candidate);
                        if in_worker_range(&mutated, self.range_start, self.range_end) {
                            self.mutate_queue.push_back(mutated);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn reject(&mut self) {
        if self.mode == Mode::Tunnel {
            self.advance_tunnel();
        }
    }

    fn next_random(&mut self) -> Vec<u8> {
        let len = (self.rng.next_u64() as usize % self.max_len) + 1;
        let mut bytes = vec![0u8; len];
        bytes[0] = self.rand_in_range();
        for byte in bytes.iter_mut().skip(1) {
            *byte = self.rng.next_u64() as u8;
        }
        bytes
    }

    fn next_brute(&mut self) -> Vec<u8> {
        if !self.brute_started {
            self.brute_started = true;
            return self.brute_state[..self.brute_len].to_vec();
        }

        let mut index = self.brute_len;
        while index > 0 {
            index -= 1;
            self.brute_state[index] = self.brute_state[index].wrapping_add(1);
            if index == 0 && !in_range_byte(self.brute_state[0], self.range_start, self.range_end) {
                self.brute_state[0] = self.range_start;
                continue;
            }
            if self.brute_state[index] != 0 {
                return self.brute_state[..self.brute_len].to_vec();
            }
        }

        self.brute_len += 1;
        if self.brute_len > self.max_len {
            self.brute_len = 1;
        }
        self.brute_state = [0; MAX_INSN_LEN];
        self.brute_state[0] = self.range_start;
        self.brute_state[..self.brute_len].to_vec()
    }

    fn next_tunnel(&mut self) -> Vec<u8> {
        if !self.tunnel_started {
            self.tunnel_started = true;
        }
        self.tunnel_state[..=self.tunnel_index].to_vec()
    }

    fn advance_tunnel(&mut self) {
        if self.tunnel_index >= self.max_len {
            self.tunnel_index = self.max_len.saturating_sub(1);
        }

        self.tunnel_state[self.tunnel_index] = self.tunnel_state[self.tunnel_index].wrapping_add(1);
        while self.tunnel_state[self.tunnel_index] == 0 {
            if self.tunnel_index == 0 {
                self.tunnel_state = [0; MAX_INSN_LEN];
                self.tunnel_state[0] = self.range_start;
                self.tunnel_last_len = None;
                self.tunnel_index = 0;
                return;
            }
            self.tunnel_index -= 1;
            self.tunnel_state[self.tunnel_index] =
                self.tunnel_state[self.tunnel_index].wrapping_add(1);
            self.tunnel_last_len = None;
        }

        if self.tunnel_index == 0
            && !in_range_byte(self.tunnel_state[0], self.range_start, self.range_end)
        {
            self.tunnel_state[0] = self.range_start;
        }
    }

    fn next_mutate(&mut self) -> Vec<u8> {
        if let Some(candidate) = self.mutate_queue.pop_front() {
            return candidate;
        }

        if self.mutate_seed_budget > 0 {
            self.mutate_seed_budget -= 1;
            return self.next_random();
        }

        self.next_random()
    }

    fn mutate_candidate(&mut self, candidate: &[u8]) -> Vec<u8> {
        let mut bytes = candidate.to_vec();
        let mutation = (self.rng.next_u64() % 5) as u8;

        match mutation {
            0 => {
                let idx = (self.rng.next_u64() as usize) % (bytes.len() + 1);
                bytes.insert(idx, self.rng.next_u64() as u8);
            }
            1 => {
                if bytes.len() > 1 {
                    let idx = (self.rng.next_u64() as usize) % bytes.len();
                    bytes.remove(idx);
                }
            }
            2 => {
                let idx = (self.rng.next_u64() as usize) % bytes.len();
                bytes[idx] = bytes[idx].wrapping_add(1);
            }
            3 => {
                let idx = (self.rng.next_u64() as usize) % bytes.len();
                bytes[idx] = bytes[idx].wrapping_sub(1);
            }
            _ => {
                let idx = (self.rng.next_u64() as usize) % bytes.len();
                bytes[idx] = self.rng.next_u64() as u8;
            }
        }

        if bytes.is_empty() {
            bytes.push(self.rand_in_range());
        }
        if bytes.len() > self.max_len {
            bytes.truncate(self.max_len);
        }
        bytes[0] = normalize_first_byte(bytes[0], self.range_start, self.range_end);
        bytes
    }

    fn rand_in_range(&mut self) -> u8 {
        let width = self
            .range_end
            .wrapping_sub(self.range_start)
            .wrapping_add(1);
        self.range_start
            .wrapping_add((self.rng.next_u64() as u8) % width.max(1))
    }
}

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let seed = if seed == 0 { 0x9e3779b97f4a7c15 } else { seed };
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

fn load_or_create_state(config: &Config) -> io::Result<(Summary, Generator)> {
    if let Some(path) = config.resume_state.as_deref() {
        let state_path = Path::new(path);
        if state_path.exists() {
            return load_state_file(path, config);
        }
    }

    Ok((
        Summary::new(0, 0, false),
        Generator::new(
            config.mode,
            config.max_len,
            config.seed,
            config.worker_range_start,
            config.worker_range_end,
            config.mutation_seeds,
            config.mutations_per_seed,
        ),
    ))
}

fn load_state_file(path: &str, config: &Config) -> io::Result<(Summary, Generator)> {
    let text = std::fs::read_to_string(path)?;
    let mut fields = HashMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            fields.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    if fields.get("version").map(String::as_str) != Some(STATE_VERSION) {
        return Err(io::Error::other("unsupported state file version"));
    }

    let saved_mode = Mode::parse(required_field(&fields, "mode")?).map_err(io::Error::other)?;
    if saved_mode != config.mode {
        return Err(io::Error::other(
            "resume state mode does not match current --mode",
        ));
    }

    let saved_max_len = parse_usize_field(&fields, "max_len")?;
    if saved_max_len != config.max_len {
        return Err(io::Error::other(
            "resume state max_len does not match current --max-len",
        ));
    }

    let saved_range_start = parse_u8_field(&fields, "range_start")?;
    let saved_range_end = parse_u8_field(&fields, "range_end")?;
    if saved_range_start != config.worker_range_start || saved_range_end != config.worker_range_end
    {
        return Err(io::Error::other(
            "resume state worker range does not match current worker range",
        ));
    }

    let mut generator = Generator::new(
        config.mode,
        config.max_len,
        config.seed,
        config.worker_range_start,
        config.worker_range_end,
        config.mutation_seeds,
        config.mutations_per_seed,
    );

    generator.rng.state = parse_u64_field(&fields, "rng_state")?;
    generator.brute_len = parse_usize_field(&fields, "brute_len")?;
    generator.brute_started = parse_bool_field(&fields, "brute_started")?;
    generator.brute_state = parse_state_array(&fields, "brute_state")?;
    generator.tunnel_state = parse_state_array(&fields, "tunnel_state")?;
    generator.tunnel_index = parse_usize_field(&fields, "tunnel_index")?;
    generator.tunnel_last_len = parse_optional_u32_field(&fields, "tunnel_last_len")?;
    generator.tunnel_started = parse_bool_field(&fields, "tunnel_started")?;
    generator.mutate_seed_budget = parse_usize_field(&fields, "mutate_seed_budget")?;
    generator.mutations_per_seed = parse_usize_field(&fields, "mutations_per_seed")?;
    generator.mutate_queue = parse_queue_field(&fields, "mutate_queue")?;

    let tested = parse_u64_field(&fields, "tested")?;
    let anomalies = parse_u64_field(&fields, "anomalies")?;

    Ok((Summary::new(tested, anomalies, true), generator))
}

fn persist_state_if_needed(
    config: &Config,
    summary: &Summary,
    generator: &Generator,
) -> io::Result<()> {
    if let Some(path) = config
        .save_state
        .as_deref()
        .or(config.resume_state.as_deref())
    {
        save_state_file(path, config, summary, generator)?;
    }
    Ok(())
}

fn save_state_file(
    path: &str,
    config: &Config,
    summary: &Summary,
    generator: &Generator,
) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;

    writeln!(file, "version={}", STATE_VERSION)?;
    writeln!(file, "mode={}", mode_name(config.mode))?;
    writeln!(file, "max_len={}", config.max_len)?;
    writeln!(file, "range_start={}", config.worker_range_start)?;
    writeln!(file, "range_end={}", config.worker_range_end)?;
    writeln!(file, "tested={}", summary.tested)?;
    writeln!(file, "anomalies={}", summary.anomalies)?;
    writeln!(file, "rng_state={}", generator.rng.state)?;
    writeln!(file, "brute_len={}", generator.brute_len)?;
    writeln!(file, "brute_started={}", bool_num(generator.brute_started))?;
    writeln!(file, "brute_state={}", hex_bytes(&generator.brute_state))?;
    writeln!(file, "tunnel_state={}", hex_bytes(&generator.tunnel_state))?;
    writeln!(file, "tunnel_index={}", generator.tunnel_index)?;
    writeln!(
        file,
        "tunnel_last_len={}",
        generator
            .tunnel_last_len
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string())
    )?;
    writeln!(
        file,
        "tunnel_started={}",
        bool_num(generator.tunnel_started)
    )?;
    writeln!(file, "mutate_seed_budget={}", generator.mutate_seed_budget)?;
    writeln!(file, "mutations_per_seed={}", generator.mutations_per_seed)?;
    writeln!(
        file,
        "mutate_queue={}",
        generator
            .mutate_queue
            .iter()
            .map(|bytes| hex_bytes(bytes))
            .collect::<Vec<_>>()
            .join(",")
    )?;
    Ok(())
}

fn open_log_file(path: Option<&str>, append: bool) -> io::Result<Option<File>> {
    let Some(path) = path else {
        return Ok(None);
    };

    let file = if append {
        OpenOptions::new().create(true).append(true).open(path)?
    } else {
        File::create(path)?
    };
    Ok(Some(file))
}

fn push_tui_event(tui: &mut TuiState, anomaly: &Anomaly) {
    tui.recent.push_front(format_anomaly_line(anomaly));
    while tui.recent.len() > TUI_RECENT_LIMIT {
        tui.recent.pop_back();
    }
}

fn draw_tui(config: &Config, summary: &Summary, tui: &mut TuiState) -> io::Result<()> {
    let snapshot = (summary.tested, summary.anomalies);
    if tui.last_rendered == Some(snapshot) {
        return Ok(());
    }
    tui.last_rendered = Some(snapshot);

    let elapsed = summary.start.elapsed();
    let rate = if elapsed.as_secs_f64() > 0.0 {
        summary.tested as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    let mut out = io::stdout().lock();
    write!(out, "\x1b[H\x1b[2J")?;
    writeln!(
        out,
        "{}",
        colorize(config, "1;36", "=== sandsifter_rs TUI ===")
    )?;
    writeln!(
        out,
        "mode: {}  backend: {}  compare: {}",
        mode_name(config.mode),
        colorize(config, "1;33", config.backend.name()),
        if config.compare_backends.is_empty() {
            "-".to_string()
        } else {
            backend_list_text(&config.compare_backends)
        }
    )?;
    writeln!(
        out,
        "tested: {} / {}  anomalies: {}  rare: {}  rate: {:.1}/s  elapsed: {}",
        colorize(config, "1;37", summary.tested.to_string()),
        config.count,
        colorize(config, "1;31", summary.anomalies.to_string()),
        colorize(config, "1;33", summary.rare_hits.to_string()),
        rate,
        format_duration(elapsed)
    )?;
    writeln!(
        out,
        "range: 0x{:02x}..=0x{:02x}  prefixes<= {}  dup_prefix={}  resumed={}",
        config.worker_range_start,
        config.worker_range_end,
        config.max_prefix,
        config.allow_dup_prefix,
        summary.resumed
    )?;
    writeln!(out)?;
    writeln!(out, "{}", colorize(config, "1;35", "Recent anomalies"))?;
    if tui.recent.is_empty() {
        writeln!(out, "  none yet")?;
    } else {
        for line in &tui.recent {
            writeln!(out, "  {}", colorize(config, "0;31", line))?;
        }
    }
    write!(out, "\x1b[J")?;
    out.flush()
}

fn format_anomaly_line(anomaly: &Anomaly) -> String {
    let mut line = format!(
        "{} | {} | {} | {}",
        hex_bytes(&anomaly.bytes),
        anomaly.reasons.join(","),
        anomaly.disas.text(),
        compact_exec_signature(&anomaly.exec)
    );
    if !anomaly.compare_results.is_empty() {
        let compare = anomaly
            .compare_results
            .iter()
            .map(|item| match (&item.exec, &item.note) {
                (Some(exec), _) => {
                    format!("{}:{}", item.backend.name(), compact_exec_signature(exec))
                }
                (None, Some(note)) => format!("{}:{}", item.backend.name(), note),
                (None, None) => format!("{}:unavailable", item.backend.name()),
            })
            .collect::<Vec<_>>()
            .join(" ");
        line.push_str(" | ");
        line.push_str(&compare);
    }
    if let Some(tag) = &anomaly.rare_tag {
        line.push_str(" | rare=");
        line.push_str(tag);
    }
    line
}

fn parse_worker_event(expected_label: &str, line: &str) -> Option<WorkerEvent> {
    let rest = line.strip_prefix("@@EVENT ")?;
    let mut fields = HashMap::new();
    for part in rest.split_whitespace() {
        let (key, value) = part.split_once('=')?;
        fields.insert(key, value);
    }

    let label = fields
        .get("label")
        .and_then(|value| bytes_from_hex(value).ok())
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_else(|| expected_label.to_string());

    match *fields.get("kind")? {
        "tick" => Some(WorkerEvent::Tick {
            label,
            tested: fields.get("tested")?.parse().ok()?,
            anomalies: fields.get("anomalies")?.parse().ok()?,
            rare_hits: fields.get("rare_hits")?.parse().ok()?,
        }),
        "anomaly" => {
            let text = fields
                .get("text")
                .and_then(|value| bytes_from_hex(value).ok())
                .map(|bytes| String::from_utf8_lossy(&bytes).to_string())?;
            Some(WorkerEvent::Anomaly { label, text })
        }
        "done" => Some(WorkerEvent::Done {
            label,
            tested: fields.get("tested")?.parse().ok()?,
            anomalies: fields.get("anomalies")?.parse().ok()?,
            rare_hits: fields.get("rare_hits")?.parse().ok()?,
        }),
        _ => None,
    }
}

fn apply_worker_event(tui: &mut MultiTuiState, event: WorkerEvent) -> bool {
    match event {
        WorkerEvent::Tick {
            label,
            tested,
            anomalies,
            rare_hits,
        } => {
            let entry = tui.workers.entry(label).or_default();
            entry.tested = tested;
            entry.anomalies = anomalies;
            entry.rare_hits = rare_hits;
            false
        }
        WorkerEvent::Anomaly { label, text } => {
            push_multi_tui_line(tui, format!("[{}] {}", label, text));
            false
        }
        WorkerEvent::Done {
            label,
            tested,
            anomalies,
            rare_hits,
        } => {
            let entry = tui.workers.entry(label).or_default();
            entry.tested = tested;
            entry.anomalies = anomalies;
            entry.rare_hits = rare_hits;
            if !entry.done {
                entry.done = true;
                return true;
            }
            false
        }
        WorkerEvent::Stderr { label, text } => {
            push_multi_tui_line(tui, format!("[{}] stderr: {}", label, text));
            false
        }
    }
}

fn push_multi_tui_line(tui: &mut MultiTuiState, line: String) {
    tui.recent.push_front(line);
    while tui.recent.len() > TUI_RECENT_LIMIT {
        tui.recent.pop_back();
    }
}

fn draw_multi_worker_tui(config: &Config, tui: &mut MultiTuiState) -> io::Result<()> {
    let total_tested: u64 = tui.workers.values().map(|worker| worker.tested).sum();
    let total_anomalies: u64 = tui.workers.values().map(|worker| worker.anomalies).sum();
    let total_rare: u64 = tui.workers.values().map(|worker| worker.rare_hits).sum();
    let done_workers = tui.workers.values().filter(|worker| worker.done).count();
    let snapshot = (total_tested, total_anomalies, total_rare, done_workers);
    if tui.last_rendered == Some(snapshot) {
        return Ok(());
    }
    tui.last_rendered = Some(snapshot);

    let mut out = io::stdout().lock();
    write!(out, "\x1b[H\x1b[2J")?;
    writeln!(
        out,
        "{}",
        colorize(config, "1;36", "=== sandsifter_rs Multi-Worker TUI ===")
    )?;
    writeln!(
        out,
        "mode: {}  backend: {}  compare: {}  workers: {}",
        mode_name(config.mode),
        colorize(config, "1;33", config.backend.name()),
        if config.compare_backends.is_empty() {
            "-".to_string()
        } else {
            backend_list_text(&config.compare_backends)
        },
        config.workers
    )?;
    writeln!(
        out,
        "tested: {} / {}  anomalies: {}  rare: {}  completed: {}/{}",
        colorize(config, "1;37", total_tested.to_string()),
        config.count,
        colorize(config, "1;31", total_anomalies.to_string()),
        colorize(config, "1;33", total_rare.to_string()),
        done_workers,
        config.workers
    )?;
    writeln!(out)?;
    writeln!(out, "{}", colorize(config, "1;35", "Workers"))?;

    let mut labels = tui.workers.keys().cloned().collect::<Vec<_>>();
    labels.sort();
    for label in labels {
        let worker = tui.workers.get(&label).expect("worker exists");
        writeln!(
            out,
            "  {}  tested={} anomalies={} rare={} status={}",
            label,
            worker.tested,
            worker.anomalies,
            worker.rare_hits,
            if worker.done { "done" } else { "running" }
        )?;
    }

    writeln!(out)?;
    writeln!(out, "{}", colorize(config, "1;35", "Recent anomalies"))?;
    if tui.recent.is_empty() {
        writeln!(out, "  none yet")?;
    } else {
        for line in &tui.recent {
            writeln!(out, "  {}", colorize(config, "0;31", line))?;
        }
    }
    write!(out, "\x1b[J")?;
    out.flush()
}

fn colorize(config: &Config, code: &str, text: impl AsRef<str>) -> String {
    let text = text.as_ref();
    if config.no_color {
        text.to_string()
    } else {
        format!("\x1b[{}m{}\x1b[0m", code, text)
    }
}

fn required_field<'a>(fields: &'a HashMap<String, String>, key: &str) -> io::Result<&'a str> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| io::Error::other(format!("missing state field: {}", key)))
}

fn parse_u64_field(fields: &HashMap<String, String>, key: &str) -> io::Result<u64> {
    required_field(fields, key)?
        .parse()
        .map_err(|_| io::Error::other(format!("invalid numeric state field: {}", key)))
}

fn parse_u32_field(fields: &HashMap<String, String>, key: &str) -> io::Result<u32> {
    required_field(fields, key)?
        .parse()
        .map_err(|_| io::Error::other(format!("invalid numeric state field: {}", key)))
}

fn parse_usize_field(fields: &HashMap<String, String>, key: &str) -> io::Result<usize> {
    required_field(fields, key)?
        .parse()
        .map_err(|_| io::Error::other(format!("invalid numeric state field: {}", key)))
}

fn parse_u8_field(fields: &HashMap<String, String>, key: &str) -> io::Result<u8> {
    required_field(fields, key)?
        .parse()
        .map_err(|_| io::Error::other(format!("invalid numeric state field: {}", key)))
}

fn parse_bool_field(fields: &HashMap<String, String>, key: &str) -> io::Result<bool> {
    match required_field(fields, key)? {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(io::Error::other(format!(
            "invalid bool state field: {}",
            key
        ))),
    }
}

fn parse_optional_u32_field(
    fields: &HashMap<String, String>,
    key: &str,
) -> io::Result<Option<u32>> {
    match required_field(fields, key)? {
        "none" => Ok(None),
        _ => Ok(Some(parse_u32_field(fields, key)?)),
    }
}

fn parse_state_array(
    fields: &HashMap<String, String>,
    key: &str,
) -> io::Result<[u8; MAX_INSN_LEN]> {
    let bytes = bytes_from_hex(required_field(fields, key)?)?;
    if bytes.len() != MAX_INSN_LEN {
        return Err(io::Error::other(format!(
            "invalid state array length for {}",
            key
        )));
    }
    let mut out = [0u8; MAX_INSN_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_queue_field(fields: &HashMap<String, String>, key: &str) -> io::Result<VecDeque<Vec<u8>>> {
    let raw = required_field(fields, key)?;
    if raw.is_empty() {
        return Ok(VecDeque::new());
    }

    let mut queue = VecDeque::new();
    for item in raw.split(',').filter(|item| !item.is_empty()) {
        queue.push_back(bytes_from_hex(item)?);
    }
    Ok(queue)
}

fn parse_exec_signature(text: &str) -> io::Result<ExecResult> {
    let mut result = ExecResult::default();
    for part in text.split_whitespace() {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        match key {
            "valid" => {
                result.valid = value
                    .parse()
                    .map_err(|_| io::Error::other("invalid exec valid field"))?
            }
            "len" => {
                result.length = value
                    .parse()
                    .map_err(|_| io::Error::other("invalid exec len field"))?
            }
            "signum" => {
                result.signum = value
                    .parse()
                    .map_err(|_| io::Error::other("invalid exec signum field"))?
            }
            "si_code" => {
                result.si_code = value
                    .parse()
                    .map_err(|_| io::Error::other("invalid exec si_code field"))?
            }
            "si_addr" => {
                result.si_addr = if let Some(hex) = value.strip_prefix("0x") {
                    usize::from_str_radix(hex, 16)
                        .map_err(|_| io::Error::other("invalid exec si_addr field"))?
                } else {
                    value
                        .parse()
                        .map_err(|_| io::Error::other("invalid exec si_addr field"))?
                };
            }
            _ => {}
        }
    }
    Ok(result)
}

fn exec_signature(exec: &ExecResult) -> String {
    format!(
        "valid={} len={} signum={} si_code={} si_addr=0x{:x}",
        exec.valid, exec.length, exec.signum, exec.si_code, exec.si_addr
    )
}

fn compact_exec_signature(exec: &ExecResult) -> String {
    format!("sig{} len{}", exec.signum, exec.length)
}

fn backend_list_text(backends: &[Backend]) -> String {
    backends
        .iter()
        .map(|backend| backend.name())
        .collect::<Vec<_>>()
        .join(",")
}

fn bool_num(value: bool) -> u8 {
    if value { 1 } else { 0 }
}

fn bytes_from_hex(text: &str) -> io::Result<Vec<u8>> {
    let trimmed = text.trim();
    if trimmed.len() % 2 != 0 {
        return Err(io::Error::other(
            "hex input must have an even number of digits",
        ));
    }

    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let hi = from_hex_digit(bytes[index])?;
        let lo = from_hex_digit(bytes[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

fn from_hex_digit(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(io::Error::other("invalid hex digit")),
    }
}

fn is_blacklisted(bytes: &[u8]) -> bool {
    const BLACKLIST: &[&[u8]] = &[
        &[0x0f, 0x05], // syscall
        &[0x0f, 0x34], // sysenter
        &[0xcd],       // int imm8
        &[0xcc],       // int3
        &[0xce],       // into
        &[0xcf],       // iret
        &[0xf1],       // icebp
        &[0xf4],       // hlt
        &[0xfa],       // cli
        &[0xfb],       // sti
        &[0xe4],
        &[0xe5],
        &[0xe6],
        &[0xe7], // in/out imm8
        &[0xec],
        &[0xed],
        &[0xee],
        &[0xef], // in/out dx
    ];

    BLACKLIST.iter().any(|prefix| bytes.starts_with(prefix))
}

fn in_range_byte(byte: u8, start: u8, end: u8) -> bool {
    byte >= start && byte <= end
}

fn normalize_first_byte(byte: u8, start: u8, end: u8) -> u8 {
    if in_range_byte(byte, start, end) {
        byte
    } else {
        start
    }
}

fn in_worker_range(bytes: &[u8], start: u8, end: u8) -> bool {
    bytes
        .first()
        .copied()
        .map(|byte| in_range_byte(byte, start, end))
        .unwrap_or(false)
}

fn is_prefix(byte: u8) -> bool {
    matches!(
        byte,
        0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67 | 0x40..=0x4f
    )
}

fn prefix_count(bytes: &[u8]) -> usize {
    bytes.iter().take_while(|&&byte| is_prefix(byte)).count()
}

fn has_dup_prefix(bytes: &[u8]) -> bool {
    let mut seen = [0u8; 256];
    for byte in bytes.iter().copied().take_while(|byte| is_prefix(*byte)) {
        let slot = &mut seen[byte as usize];
        *slot = slot.saturating_add(1);
        if *slot > 1 {
            return true;
        }
    }
    false
}

fn violates_prefix_rules(bytes: &[u8], max_prefix: usize, allow_dup_prefix: bool) -> bool {
    prefix_count(bytes) > max_prefix || (!allow_dup_prefix && has_dup_prefix(bytes))
}

fn mnemonic_has_implicit_memory(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "push"
            | "pop"
            | "pushfq"
            | "popfq"
            | "call"
            | "ret"
            | "iret"
            | "enter"
            | "leave"
            | "stosb"
            | "stosw"
            | "stosd"
            | "stosq"
            | "lodsb"
            | "lodsw"
            | "lodsd"
            | "lodsq"
            | "movsb"
            | "movsw"
            | "movsd"
            | "movsq"
            | "cmpsb"
            | "cmpsw"
            | "cmpsd"
            | "cmpsq"
            | "scasb"
            | "scasw"
            | "scasd"
            | "scasq"
            | "insb"
            | "insw"
            | "insd"
            | "outsb"
            | "outsw"
            | "outsd"
    )
}

fn is_uncommon_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "ud0"
            | "ud1"
            | "rsm"
            | "getsec"
            | "skinit"
            | "monitor"
            | "mwait"
            | "monitorx"
            | "mwaitx"
            | "umonitor"
            | "umwait"
            | "tpause"
            | "vmcall"
            | "vmmcall"
            | "vmrun"
            | "invlpga"
            | "clgi"
            | "stgi"
            | "encls"
            | "enclu"
            | "enclv"
            | "vmfunc"
            | "xsetbv"
            | "xgetbv"
            | "wrmsr"
            | "rdmsr"
            | "wrpkru"
            | "rdpkru"
            | "pconfig"
            | "serialize"
            | "clzero"
            | "mcommit"
            | "enqcmd"
            | "enqcmds"
            | "rmpadjust"
            | "rmpupdate"
            | "psmash"
            | "pvalidate"
            | "tileloadd"
            | "tileloaddt1"
            | "tilerelease"
            | "tilezero"
            | "tdcall"
            | "seamcall"
            | "seamret"
            | "testui"
            | "clac"
            | "stac"
            | "swapgs"
            | "invpcid"
            | "invept"
            | "invvpid"
            | "iret"
            | "iretq"
            | "sysret"
            | "sysretq"
    )
}

fn uncommon_mnemonic_category(mnemonic: &str) -> &'static str {
    match mnemonic {
        "ud0" | "ud1" => "explicit_undefined_opcode",
        "wrmsr" | "rdmsr" | "xsetbv" | "xgetbv" | "wrpkru" | "rdpkru" | "pconfig" => {
            "privileged_or_control_register"
        }
        "vmcall" | "vmmcall" | "vmrun" | "vmfunc" | "invept" | "invvpid" | "invlpga" => {
            "virtualization_specific"
        }
        "encls" | "enclu" | "enclv" | "tdcall" | "seamcall" | "seamret" => "trusted_execution",
        "monitor" | "mwait" | "monitorx" | "mwaitx" | "umonitor" | "umwait" | "tpause" => {
            "power_wait_or_monitor"
        }
        "tileloadd" | "tileloaddt1" | "tilerelease" | "tilezero" | "enqcmd" | "enqcmds" => {
            "accelerator_or_queue_instruction"
        }
        "serialize" | "clzero" | "mcommit" | "rmpadjust" | "rmpupdate" | "psmash" | "pvalidate" => {
            "rare_platform_extension"
        }
        "rsm" | "getsec" | "skinit" | "swapgs" | "invpcid" | "clac" | "stac" => {
            "system_level_instruction"
        }
        _ => "uncommon_instruction",
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Random => "random",
        Mode::Brute => "brute",
        Mode::Tunnel => "tunnel",
        Mode::Mutate => "mutate",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
}

fn default_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
