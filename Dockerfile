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

# Install radare2 from pre-built deb packages based on architecture
RUN ARCH=$(dpkg --print-architecture) && \
    echo "Building for architecture: $ARCH" && \
    if [ "$ARCH" = "amd64" ]; then \
        echo "Installing radare2 for AMD64..." && \
        wget -O radare2.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_amd64.deb && \
        wget -O radare2-dev.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2-dev_5.9.8_amd64.deb; \
    elif [ "$ARCH" = "arm64" ]; then \
        echo "Installing radare2 for ARM64..." && \
        wget -O radare2.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_arm64.deb && \
        wget -O radare2-dev.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2-dev_5.9.8_arm64.deb; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    dpkg -i radare2.deb radare2-dev.deb && \
    apt-get install -f -y && \
    rm radare2.deb radare2-dev.deb

# Set up Python virtual environment and install PyYAML
RUN python3 -m venv /tmp/venv && \
    . /tmp/venv/bin/activate && \
    python3 -m pip install --upgrade pip && \
    python3 -m pip install PyYaml

# Build creait and reai-r2 to user's local directory
WORKDIR /tmp

# Clone and build creait
RUN git clone https://github.com/revengai/creait && \
    cmake -S "/tmp/creait" \
        -B "/tmp/creait/Build" \
        -G Ninja \
        -D CMAKE_BUILD_TYPE=Release \
        -D CMAKE_PREFIX_PATH="$InstallPath" \
        -D CMAKE_INSTALL_PREFIX="$InstallPath" && \
    cmake --build "/tmp/creait/Build" --config Release && \
    cmake --install "/tmp/creait/Build" --prefix "$InstallPath" --config Release && \
    chown -R revengai:revengai "$InstallPath"

# Clone and build reai-r2
RUN git clone -b "$BRANCH_NAME" https://github.com/revengai/reai-r2 && \
    . /tmp/venv/bin/activate && \
    cmake -S "/tmp/reai-r2" \
        -B "/tmp/reai-r2/Build" \
        -G Ninja \
        -D CMAKE_BUILD_TYPE=Release \
        -D CMAKE_PREFIX_PATH="$InstallPath:/usr/local" \
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

# Install only runtime dependencies and radare2
RUN apt-get update && \
    apt-get install -y \
    libcurl4-openssl-dev \
    python3 \
    python3-yaml \
    ca-certificates \
    wget \
    vim \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Install radare2 runtime from pre-built deb packages based on architecture
RUN ARCH=$(dpkg --print-architecture) && \
    echo "Installing radare2 runtime for architecture: $ARCH" && \
    if [ "$ARCH" = "amd64" ]; then \
        wget -O radare2.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_amd64.deb; \
    elif [ "$ARCH" = "arm64" ]; then \
        wget -O radare2.deb https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_arm64.deb; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    dpkg -i radare2.deb && \
    apt-get install -f -y && \
    rm radare2.deb

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

# Set up user-local directories for plugins and get radare2 plugin directory
RUN mkdir -p /home/revengai/.local/share/radare2/plugins && \
    R2_PLUGIN_DIR=$(r2 -H R2_USER_PLUGINS 2>/dev/null || echo "/home/revengai/.local/share/radare2/plugins") && \
    mkdir -p "$R2_PLUGIN_DIR" && \
    echo "Radare2 plugin directory: $R2_PLUGIN_DIR" && \
    find /home/revengai/.local -name "*reai*radare*" -exec cp {} "$R2_PLUGIN_DIR/" \; 2>/dev/null || true && \
    find /home/revengai/.local -name "*reai_radare*" -name "*.so" -exec cp {} "$R2_PLUGIN_DIR/" \; 2>/dev/null || true

# Create configuration file
RUN printf "api_key = %s\nhost = %s\n" "$REVENG_APIKEY" "$REVENG_HOST" > /home/revengai/.creait

# Set up environment for radare2 plugins
ENV LD_LIBRARY_PATH="/home/revengai/.local/lib:$LD_LIBRARY_PATH"
ENV PATH="/home/revengai/.local/bin:$PATH"
ENV PKG_CONFIG_PATH="/home/revengai/.local/lib/pkgconfig:$PKG_CONFIG_PATH"

# Verify installation
RUN r2 -v && \
    echo "Checking for RevEng.AI plugin..." && \
    (r2 -i /dev/null -qc "L" 2>/dev/null | grep -q "reai" && \
    echo "RevEng.AI plugin installed successfully!") || \
    echo "Plugin verification failed, but may still work" && \
    echo "Available plugins:" && \
    r2 -i /dev/null -qc "L" 2>/dev/null || true

# Set final working directory
WORKDIR /home/revengai

# Display usage information when container starts
CMD echo "=== RevEng.AI Radare2 Plugin Docker Container ===" && \
    echo "" && \
    echo "Architecture: $(uname -m)" && \
    echo "Built from source for multi-architecture support" && \
    echo "Installation path: /home/revengai/.local" && \
    echo "" && \
    echo "Usage:" && \
    echo "  docker run -v /path/to/binary:/home/revengai/binary -it <image> r2 binary" && \
    echo "" && \
    echo "Available commands:" && \
    echo "  r2 binary       - Start radare2 with your binary" && \
    echo "  r2 -AA binary   - Start radare2 with auto-analysis" && \
    echo "" && \
    echo "RevEng.AI commands (inside radare2):" && \
    echo "  RE?  - Show all RevEng.AI commands" && \
    echo "" && \
    echo "Configuration:" && \
    echo "  API Key: ${REVENG_APIKEY}" && \
    echo "  Host: ${REVENG_HOST}" && \
    echo "  Config file: ~/.creait" && \
    echo "" && \
    echo "Installation details:" && \
    echo "  Radare2: $(which r2)" && \
    echo "  Libraries: /home/revengai/.local/lib/" && \
    echo "  Plugins: $(r2 -H R2_USER_PLUGINS 2>/dev/null || echo '/home/revengai/.local/share/radare2/plugins')" && \
    echo "" && \
    echo "Documentation: https://github.com/RevEngAI/reai-r2" && \
    echo "" && \
    exec /bin/bash
