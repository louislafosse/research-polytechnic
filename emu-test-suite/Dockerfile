FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-user \
        build-essential \
        cmake \
        git \
        pkg-config \
        ca-certificates \
        curl \
        wget \
        gcc-13 \
        g++-13 \
        libboost-all-dev \
        libclang-dev \
        llvm-dev \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 100 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 100 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
                
RUN git clone --recurse-submodules https://github.com/binsnake/KUBERA.git /opt/KUBERA

WORKDIR /opt/KUBERA

# Patch KUBERA for GCC 13 compatibility (replace C++23 print with iostream)
# Replace <print> with <iostream> and convert std::println to std::cerr
RUN sed -i 's/#include <print>/#include <iostream>/' memory.hpp \
    && find . -type f \( -name "*.cpp" -o -name "*.hpp" \) -exec perl -i -p0e 's/std::println\s*\(\s*"([^"]*)"(.*?)\s*\);/std::cerr << "$1" << std::endl;/gs' {} \; \
    && find . -type f \( -name "*.cpp" -o -name "*.hpp" \) -exec perl -i -p0e 's/std::println\s*\(\s*"([^"]*)",\s*(.*?)\s*\);/std::cerr << "$1 " << $2 << std::endl;/gs' {} \;

RUN rm -rf build && mkdir build && cd build && cmake -DCMAKE_CXX_STANDARD=23 .. && make -j$(nproc)

WORKDIR /opt/KUBERA/build

# Install headers and libraries to standard locations
RUN mkdir -p /usr/local/include/KUBERA && \
    cp /opt/KUBERA/*.hpp /usr/local/include/KUBERA/ && \
    cp /opt/KUBERA/build/libKUBERA.a /usr/local/lib/ && \
    cp /opt/KUBERA/build/deps/icedpp/libIced_Wrapper.a /usr/local/lib/ && \
    ldconfig

RUN git clone https://github.com/ptitSeb/box64 /opt/box64 && \
    cd /opt/box64 && mkdir build && cd build && \
    cmake .. ${OPTIONS} && \
    make -j4 && \
    cp box64 /usr/local/bin/

RUN git clone https://github.com/jart/blink.git /opt/blink && \
    cd /opt/blink && \
    ./configure && \
    make -j4 && make install

# Copy and build Rust test suite
WORKDIR /opt/emu-test-suite

COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
COPY data/ ./data/

RUN cargo build --release

CMD ["./target/release/emu-test-suite"]
