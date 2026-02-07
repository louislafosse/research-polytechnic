# Emulator FPU Test Suite

Tests FPU stack overflow detection across multiple x86-64 emulators.

## Installation

### Docker (Recommended)
```bash
docker build --no-cache -t kubera-fpu-test -f Dockerfile . && docker run --rm kubera-fpu-test
```

### Local (Tested on Fedora mainly)
```bash
# Check line 5 of Dockerfile for dependencies but those ones should be sufficient
sudo dnf install -y \
    @development-tools \
    cmake \
    git \
    pkgconf-pkg-config \
    ca-certificates \
    curl \
    wget \
    gcc \
    gcc-c++ \
    boost-devel \
    clang-devel \
    llvm-devel

# Rust, core of the test-suite
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
PATH="/root/.cargo/bin:${PATH}"

# For the rest you have to install everything under ./local/
```

## Running

```bash
cargo run
```

## Contribute

See [FRAMEWORK.md](./docs/FRAMEWORK.md) to implement a new test or emu
