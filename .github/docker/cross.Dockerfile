# Parameterized Dockerfile for cross-compilation images
# Used by cross-rs via Cross.toml configuration

ARG CROSS_BASE_IMAGE
FROM ${CROSS_BASE_IMAGE}

ARG CROSS_DEB_ARCH
ARG PKG_CONFIG_LIBDIR

# Add the foreign architecture for cross-compilation
RUN dpkg --add-architecture ${CROSS_DEB_ARCH}

# Install system dependencies for the target architecture
RUN apt-get update && \
  apt-get install -y --no-install-recommends \
  libdbus-1-dev:${CROSS_DEB_ARCH} \
  libbluetooth-dev:${CROSS_DEB_ARCH} \
  libudev-dev:${CROSS_DEB_ARCH} && \
  rm -rf /var/lib/apt/lists/*

# Configure pkg-config to find libraries for the target architecture
ENV PKG_CONFIG_ALLOW_CROSS=1
ENV PKG_CONFIG_LIBDIR=${PKG_CONFIG_LIBDIR}
