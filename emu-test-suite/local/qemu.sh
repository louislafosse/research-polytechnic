#!/usr/bin/env bash
set -e

. /etc/os-release

case "$ID" in
    ubuntu|debian)
        sudo apt update && sudo apt install -y qemu-user
        ;;
    fedora)
        sudo dnf install -y qemu-user
        ;;
    arch|manjaro)
        sudo pacman -Sy --noconfirm qemu-user
        ;;
    *)
        echo "Unsupported distro: $ID"
        exit 1
        ;;
esac
