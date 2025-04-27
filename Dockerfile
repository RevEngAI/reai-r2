FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive

ARG REVENG_APIKEY="CHANGEME"
ARG REVENG_HOST="https://api.reveng.ai"

# Install all required packages
RUN apt-get update && \
    apt-get install -y \
    cmake \
    meson \
    ninja-build \
    make \
    gcc \
    g++ \
    curl \
    libcurl4-openssl-dev \
    vim \
    git \
    pkg-config \
    python3-yaml \
    wget \
    sudo

# Create a new user and set up a password
RUN useradd -ms /bin/bash revengai && \
    echo 'revengai:revengai' | chpasswd

# Add a sudo capability without password requirement
RUN echo 'revengai ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Change to new created user
USER revengai

# Where we build all the things reveng.ai
WORKDIR /home/revengai

# Download, build and install radare.
RUN git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh

# Build and install cJSON dependency
RUN git clone https://github.com/DaveGamble/cJSON.git
RUN cmake -S /home/revengai/cJSON \
    -B /home/revengai/cJSON/build \
    -G Ninja \
    -D CMAKE_INSTALL_PREFIX=/usr/local \
    -D BUILD_SHARED_LIBS=ON \
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
RUN ninja -C /home/revengai/cJSON/build
RUN sudo ninja -C /home/revengai/cJSON/build install

# Build and install tomlc99 dependency
RUN git clone https://github.com/brightprogrammer/tomlc99
RUN cmake -S /home/revengai/tomlc99 \
    -B /home/revengai/tomlc99/build \
    -G Ninja \
    -D CMAKE_INSTALL_PREFIX=/usr/local \
    -D BUILD_SHARED_LIBS=ON \
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
RUN ninja -C /home/revengai/tomlc99/build
RUN sudo ninja -C /home/revengai/tomlc99/build install

# Copy plugin code from host 
RUN mkdir reai-r2
COPY . reai-r2/
RUN sudo chown -R revengai:revengai reai-r2

WORKDIR /home/revengai/reai-r2/creait
RUN cmake -B build -G Ninja -D CMAKE_INSTALL_PREFIX=/usr/local -D BUILD_SHARED_LIBS=ON && \
    ninja -C build && \
    sudo ninja -C build install

WORKDIR /home/revengai/reai-r2
RUN cmake -B build -G Ninja -D CMAKE_INSTALL_PREFIX=/usr/local && \
    ninja -C build && \
    sudo ninja -C build install

# TODO: (FOR THE USER) Create config file
RUN printf "\
host         = \"$REVENG_HOST\"\n\
apikey       = \"$REVENG_APIKEY\"\n\
" > /home/revengai/.creait.toml

RUN printf "export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH" > /home/revengai/.bashrc
RUN sudo ldconfig

# Ready to use!
ENTRYPOINT ["/bin/bash", "-c", "r2 --"]
