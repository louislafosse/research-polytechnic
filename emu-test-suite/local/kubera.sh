#!/usr/bin/env bash

if [ "$1" = "uninstall" ] || [ "$1" = "remove" ]; then
    echo "Removing KUBERA from system..."
    sudo rm -rf /usr/local/include/KUBERA
    sudo rm -f /usr/local/lib/libKUBERA.a
    sudo rm -f /usr/local/lib/libIced_Wrapper.a
    sudo ldconfig
    echo "KUBERA uninstalled successfully"
    exit 0
fi

git clone --recurse-submodules https://github.com/binsnake/KUBERA.git
cd KUBERA/
mkdir build ; cd build ; cmake .. ; make -j$(nproc)

# Install to system locations
sudo mkdir -p /usr/local/include/KUBERA && \
    sudo cp ../*.hpp /usr/local/include/KUBERA/ && \
    sudo cp libKUBERA.a /usr/local/lib/ && \
    sudo cp deps/icedpp/libIced_Wrapper.a /usr/local/lib/ && \
    sudo ldconfig

echo "KUBERA installed successfully"
echo "To uninstall: $0 uninstall"

# g++ -std=gnu++23 \
#     kubera_fpu_test.cpp \
#     -lKUBERA -lIced_Wrapper \
#     -lpthread -ldl \
#     -o fpu_sf_test

# ./fpu_sf_test
# cd ../.. ; rm -rf KUBERA/