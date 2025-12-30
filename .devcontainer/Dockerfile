FROM mcr.microsoft.com/devcontainers/rust:1-bookworm

# System dependencies required to build and test:
# - pkg-config + dbus headers for libdbus-sys (bluer)
# - bluez/ble headers for bluer (libbluetooth-dev, libudev-dev)
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        pkg-config \
        libdbus-1-dev \
        libbluetooth-dev \
        libudev-dev \
        bluez \
    && rm -rf /var/lib/apt/lists/*
