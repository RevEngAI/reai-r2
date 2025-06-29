# Multi-stage build to support multiple architectures (x86_64, ARM64)
FROM ubuntu:latest as builder

# Build arguments for configuration
ARG REVENG_APIKEY="CHANGEME"
ARG REVENG_HOST="https://api.reveng.ai"
ARG BRANCH_NAME="master"

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /tmp

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    make \
    gcc \
    g++ \
    curl \
    libcurl4-openssl-dev \
    git \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    python3-yaml \
    wget \
    tar \
    xz-utils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create user early so we can use their home directory for installations
RUN useradd -ms /bin/bash revengai

# Set up installation path in user's home directory
ENV InstallPath="/home/revengai/.local"

# Create directories with proper ownership
RUN mkdir -pv "$InstallPath/lib" && \
    mkdir -pv "$InstallPath/include" && \
    mkdir -pv "$InstallPath/bin" && \
    mkdir -pv "$InstallPath/share" && \
    chown -R revengai:revengai /home/revengai

# Install radare2 from deb packages (both runtime and dev packages needed for plugin building)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        wget -O radare2.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_amd64.deb && \
        wget -O radare2-dev.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2-dev_5.9.8_amd64.deb; \
    elif [ "$ARCH" = "arm64" ]; then \
        wget -O radare2.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_arm64.deb && \
        wget -O radare2-dev.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2-dev_5.9.8_arm64.deb; \
    fi && \
    dpkg -i radare2.deb radare2-dev.deb && \
    apt-get install -f -y

# Clean up temporary workdir and follow Build.sh exactly
WORKDIR /tmp
RUN rm -rf /tmp/reai-r2 && \
    rm -rf /tmp/creait

# Clone and build creait (following Build.sh exactly)
RUN git clone https://github.com/revengai/creait && \
    cmake -S "/tmp/creait" \
        -B "/tmp/creait/Build" \
        -D CMAKE_BUILD_TYPE=Release \
        -D CMAKE_PREFIX_PATH="$InstallPath" \
        -D CMAKE_INSTALL_PREFIX="$InstallPath" && \
    cmake --build "/tmp/creait/Build" --config Release && \
    cmake --install "/tmp/creait/Build" --prefix "$InstallPath" --config Release && \
    chown -R revengai:revengai "$InstallPath"

# Clone and build reai-r2 (following Build.sh exactly)
RUN git clone -b "$BRANCH_NAME" https://github.com/revengai/reai-r2 && \
    cmake -S "/tmp/reai-r2" \
        -B "/tmp/reai-r2/Build" \
        -D CMAKE_BUILD_TYPE=Release \
        -D CMAKE_PREFIX_PATH="$InstallPath" \
        -D CMAKE_MODULE_PATH="$InstallPath/lib/cmake/Modules" \
        -D CMAKE_INSTALL_PREFIX="$InstallPath" && \
    cmake --build "/tmp/reai-r2/Build" --config Release && \
    cmake --install "/tmp/reai-r2/Build" --prefix "$InstallPath" --config Release && \
    chown -R revengai:revengai "$InstallPath"

# Runtime stage - minimal image with only runtime dependencies
FROM ubuntu:latest

# Build arguments for configuration (passed to runtime)
ARG REVENG_APIKEY="CHANGEME"
ARG REVENG_HOST="https://api.reveng.ai"

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV REVENG_APIKEY=${REVENG_APIKEY}
ENV REVENG_HOST=${REVENG_HOST}

# Install radare2 and runtime dependencies (need both runtime and dev for plugin loading)
RUN apt-get update && \
    apt-get install -y \
    libcurl4-openssl-dev \
    libc6-dev \
    python3 \
    python3-yaml \
    ca-certificates \
    vim \
    sudo \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install radare2 from deb packages (both runtime and dev packages)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        wget -O radare2.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_amd64.deb && \
        wget -O radare2-dev.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2-dev_5.9.8_amd64.deb; \
    elif [ "$ARCH" = "arm64" ]; then \
        wget -O radare2.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_arm64.deb && \
        wget -O radare2-dev.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2-dev_5.9.8_arm64.deb; \
    fi && \
    dpkg -i radare2.deb radare2-dev.deb && \
    apt-get install -f -y && \
    rm radare2.deb radare2-dev.deb

# Create user for running the application
RUN useradd -ms /bin/bash revengai && \
    echo 'revengai ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Switch to user and create directories
USER revengai
WORKDIR /home/revengai

# Create local directories
RUN mkdir -p /home/revengai/.local/bin && \
    mkdir -p /home/revengai/.local/lib && \
    mkdir -p /home/revengai/.local/include && \
    mkdir -p /home/revengai/.local/share

# Copy built binaries and libraries from builder stage to user's local directory
COPY --from=builder --chown=revengai:revengai /home/revengai/.local/ /home/revengai/.local/

# Copy the plugin from root's directory (where it was installed during build) to revengai's directory
RUN mkdir -p /home/revengai/.local/share/radare2/plugins
COPY --from=builder --chown=revengai:revengai /root/.local/share/radare2/plugins/libreai_radare.so /home/revengai/.local/share/radare2/plugins/

# Create configuration file
RUN printf "api_key = %s\nhost = %s\n" "$REVENG_APIKEY" "$REVENG_HOST" > /home/revengai/.creait

# Set up environment for radare2 plugins and libraries
ENV LD_LIBRARY_PATH="/home/revengai/.local/lib:$LD_LIBRARY_PATH"
ENV PATH="/home/revengai/.local/bin:$PATH"
ENV PKG_CONFIG_PATH="/home/revengai/.local/lib/pkgconfig:$PKG_CONFIG_PATH"

# Verify installation and show debugging information
RUN r2 -v && \
    echo "=== Installation Verification ===" && \
    echo "Radare2 plugin directory: $(r2 -H R2_USER_PLUGINS)" && \
    echo "Files in plugin directory:" && \
    ls -la "$(r2 -H R2_USER_PLUGINS)" 2>/dev/null || echo "Plugin directory not accessible" && \
    echo "Files in ~/.local/lib:" && \
    ls -la /home/revengai/.local/lib/ | grep -i reai || echo "No reai files in lib" && \
    echo "Testing plugin loading..." && \
    echo "L" | r2 -q - 2>/dev/null | grep -i reai || echo "Plugin not detected in plugin list"

# Set final working directory
WORKDIR /home/revengai

# Display usage information when container starts
CMD echo "=== RevEng.AI Radare2 Plugin Docker Container ===" && \
    echo "" && \
    echo "Architecture: $(uname -m)" && \
    echo "Radare2 version: $(r2 -v | head -1)" && \
    echo "Installation path: /home/revengai/.local" && \
    echo "" && \
    echo "Usage:" && \
    echo "  docker run -v /path/to/binary:/home/revengai/binary -it <image> r2 binary" && \
    echo "" && \
    echo "Available commands:" && \
    echo "  r2 binary    - Start radare2 with your binary" && \
    echo "  r2 -AA binary - Start radare2 with auto-analysis" && \
    echo "" && \
    echo "RevEng.AI commands (inside r2):" && \
    echo "  RE  - Show all RevEng.AI commands" && \
    echo "" && \
    echo "Configuration:" && \
    echo "  API Key: ${REVENG_APIKEY}" && \
    echo "  Host: ${REVENG_HOST}" && \
    echo "  Config file: ~/.creait" && \
    echo "" && \
    echo "Installation details:" && \
    echo "  Radare2: $(which r2)" && \
    echo "  Libraries: /home/revengai/.local/lib/" && \
    echo "  Plugins: $(r2 -H R2_USER_PLUGINS 2>/dev/null)" && \
    echo "" && \
    echo "Documentation: https://github.com/RevEngAI/reai-r2" && \
    echo "" && \
    exec /bin/bash
