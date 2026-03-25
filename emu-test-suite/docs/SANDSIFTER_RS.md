# sandsifter_rs

`sandsifter_rs` is a safe-first Rust MVP inspired by the original `sandsifter`.

It lives as a separate binary inside this crate:

```bash
cargo run --release --bin sandsifter_rs -- --mode random --count 1000 --max-len 4
```

```bash
cargo run --release --bin sandsifter_rs -- --mode tunnel --count 5000 --max-len 4 --max-prefix 1 --tick 250
```

```bash
cargo run --release --bin sandsifter_rs -- --mode mutate --count 5000 --max-len 4 --mut-seeds 32 --mutations 8 --tick 250
```

```bash
cargo run --release --bin sandsifter_rs -- --mode random --count 20000 --max-len 3 --workers 4 --tick 500
```

```bash
cargo run --release --bin sandsifter_rs -- --mode random --count 2000 --max-len 2 --workers 4 --backend native --compare-backends qemu,blink
```

```bash
cargo run --release --bin sandsifter_rs -- --mode random --count 2000 --max-len 2 --workers 4 --backend native --compare-backends qemu,blink,box64,unicorn,icicle,mwemu,kubera
```

```bash
cargo run --release --bin sandsifter_rs -- --mode mutate --count 5000 --max-len 4 --mut-seeds 32 --mutations 8 --save-state /tmp/sandsifter.state
```

```bash
cargo run --release --bin sandsifter_rs -- --mode mutate --count 10000 --max-len 4 --mut-seeds 32 --mutations 8 --resume-state /tmp/sandsifter.state
```

```bash
cargo run --release --bin sandsifter_rs -- --mode random --count 1000 --max-len 2 --backend native --compare-backends qemu,blink
```

```bash
cargo run --release --bin sandsifter_rs -- --mode tunnel --count 500 --max-len 3 --tui
```

```bash
cargo run --release --bin sandsifter_rs -- --mode random --count 200000 --max-len 3 --workers 4 --tick 500 --tui
```

```bash
cargo run --release --bin sandsifter_rs -- --mode brute --count 2000 --max-len 3 --rare-log /tmp/sandsifter_rare.log --worker-range-start 15 --worker-range-end 15
```

## What It Does

- Generates candidate x86-64 instruction byte sequences
- Disassembles them with `iced-x86`
- Executes each candidate in a forked child process on native hardware
- Can launch the same execution helper under `qemu-x86_64`, `blink`, and `box64` for direct comparison
- Can also compare against `unicorn`, `icicle`, `mwemu`, and `kubera` by wrapping each candidate in shellcode and using the existing emulator shellcode runners
- Uses Linux signals to capture execution behavior
- Can fan out across multiple scan workers and run backend comparisons concurrently
- Reports anomalies similar to sandsifter categories:
  - incomplete instruction streams that only execute by running past the provided candidate bytes
  - unknown instructions that fault without `SIGILL`
  - potential hidden instructions where invalid bytes appear to execute without needing bytes beyond the candidate
  - memory-touching instructions that fault in a likely data-access path
  - disassembly length mismatches
  - valid disassembly disagreements
  - instructions accepted by the disassembler but raising `SIGILL`
  - backend mismatches versus the selected baseline backend
  - backend unavailability when an emulator cannot run the helper
  - rare or unusual instructions, including hidden-instruction candidates and uncommon privileged/system opcodes

## Implemented

- Random search mode
- Brute-force search mode
- Tunnel search mode inspired by the original sandsifter injector
- Mutation-driven search mode inspired by `mutator.py`
- Native x86-64 Linux execution backend
- Emulator comparison backends for `qemu-x86_64`, `blink`, and `box64`
- Shellcode-backed comparison backends for `unicorn`, `icicle`, `mwemu`, and `kubera`
- Multi-worker scanning via subprocess workers
- First-byte range partitioning across workers
- Parallel backend comparison inside each worker when `--compare-backends` is used
- Progress ticks
- Optional anomaly log file
- Optional rare-hit log with `--rare-log`
- Persistent save/resume state for `mutate` and `tunnel`
- End-of-run anomaly grouping summary
- Prefix filtering with `--max-prefix` and `--allow-dup-prefix`
- Lightweight ANSI TUI with colors and recent-anomaly tracking
- Multi-worker TUI supervisor that aggregates worker progress and recent findings on one screen
- Basic blacklist for obviously risky instructions like `syscall`, `sysenter`, `int`, `hlt`, `cli`, `sti`, and port-I/O opcodes
- Improved executor setup with mapped data pages and initialized general-purpose registers
- Improved executed-length estimation by distinguishing single-step traps from breakpoint traps

## Not Yet Ported

- Curses GUI
- Prefix-specific search heuristics from the original tool
- Cross-checking with multiple disassemblers
- 32-bit mode
- Shared in-memory scheduler for multi-worker mode

## Notes

- This is intentionally a conservative MVP, not a full drop-in replacement for the original Python+C sandsifter.
- The executor uses a trap-flag preamble plus signal handling to estimate how an instruction behaved after one step, but it now seeds registers with valid pointers into a mapped data region so memory operands are more likely to execute meaningfully before faulting.
- `native`, `qemu`, `blink`, and `box64` use the full fork/signal executor, so their `ExecResult` values are directly comparable.
- `unicorn`, `icicle`, `mwemu`, and `kubera` use a shellcode wrapper that returns through `RAX`, so their `ExecResult` values are best treated as approximate semantic comparisons rather than literal Linux signal equivalents.
- Because this is native instruction fuzzing, keep scan counts modest while iterating and review the blacklist before widening the search space.
- Tunnel mode is currently a simplified Rust port of the original length-change-driven idea, not a byte-for-byte clone of `injector.c`.
- Multi-worker mode currently uses multiple `sandsifter_rs` subprocesses with prefixed output rather than a shared in-memory scheduler.
- `--workers` controls scan parallelism. `--threads` is accepted as an alias for the same setting.
- `--tui` now works with `--workers > 1` in a real terminal. If stdout is not a TTY, it falls back to plain output instead of trying to render a broken screen.
- The SIGSEGV/SIGBUS classifier now separates probable memory-access faults from more interesting decoder and length anomalies.
- `incomplete_stream_executes` and `incomplete_stream_faults` are usually truncated-encoding artifacts, not secret instructions. The more interesting bucket for hidden-opcode hunting is `potential_hidden_instruction`.
- Rare hits are promoted into findings with `rare_instruction` and can be written separately with `--rare-log`. The current heuristic favors hidden-instruction candidates plus uncommon system, virtualization, trusted-execution, and control-register mnemonics.
- Resume files are plain text and are meant to be reused with the same mode, `--max-len`, and worker-range settings that created them.
- In this environment, `qemu` and `blink` helper execution work directly. `box64` support depends on whether it can load the Rust helper binary and may show up as `backend_unavailable_box64` if the local box64 runtime cannot launch it.
- The shellcode-backed emulator adapters rely on the project’s existing per-emulator probe runners. If a backend reports unsupported instructions or internal emulator errors, sandsifter_rs folds that into the comparison result instead of aborting the scan.
