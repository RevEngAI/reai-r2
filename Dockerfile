FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive

ARG apikey

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

# RevEngAI user needs to be a sudoser
RUN echo 'revengai ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# TODO: (FOR THE USER) Create config file
RUN printf "\
  host         =\"https://api.reveng.ai\"\n \
  apikey       = \"$apikey\"\n \
  " > /home/revengai/.creait.toml

RUN printf "export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH" > /home/revengai/.bashrc
RUN ldconfig

# Change to new created user
USER revengai

# Go back to where we start
WORKDIR /home/revengai

# Download, build and install radare.
RUN git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh

# creait needs either $TMP or $TMPDIR or write access to $PWD
ENV TMPDIR="/tmp"

# Download, build and install the latest creait library
RUN git clone https://github.com/RevEngAI/creait && \
  cd creait && \
  cmake -B build -G Ninja -D CMAKE_INSTALL_PREFIX=/usr/local -D BUILD_SHARED_LIBS=ON && \
  ninja -C build && \
  sudo ninja -C build install

# Go back to where we start
WORKDIR /home/revengai

# Download, build and install latest plugin.
# By default, this builds radare plugin only.
RUN git clone https://github.com/RevEngAI/reai-r2 && \
  cd reai-r2 && \
  cmake -B build -G Ninja -D CMAKE_INSTALL_PREFIX=/usr/local && \
  ninja -C build && \
  sudo ninja -C build install

# Ready to use!
CMD ["bash"]
