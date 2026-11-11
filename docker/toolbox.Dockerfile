# ctfsolver toolbox image -- the toolchain a specialist runs inside the container sandbox.
#
#   docker build -f docker/toolbox.Dockerfile -t ctfsolver/toolbox:latest .
#
# The ContainerSandbox runs this read-only with a tmpfs /tmp, all caps dropped, and
# egress confined to the target (the pwn path adds SYS_PTRACE for gdb). Keep it lean;
# the heavyweights (Ghidra, SageMath, a headless browser) are left commented so a base
# build stays small -- uncomment the ones your challenges need.
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

# --- system packages: shared + per-category CLI tools -------------------------
# radare2 and upx are not available in bookworm's repos, so both are installed from
# their upstream release artifacts below (pinned, overridable via build-args).
ARG RADARE2_VERSION=6.2.6
ARG UPX_VERSION=5.3.0
RUN apt-get update && apt-get install -y --no-install-recommends \
      # shared
      build-essential git curl wget file xxd jq unzip xz-utils p7zip-full ca-certificates \
      netcat-openbsd socat ltrace \
      # pwn / rev
      gdb binutils patchelf nasm \
      # forensics
      tshark binwalk foremost exiftool steghide sleuthkit \
      # ruby (for one_gadget, zsteg)
      ruby ruby-dev \
  && wget -q "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2_${RADARE2_VERSION}_amd64.deb" -O /tmp/radare2.deb \
  && apt-get install -y --no-install-recommends /tmp/radare2.deb \
  && wget -q "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz" -O /tmp/upx.tar.xz \
  && tar -xJf /tmp/upx.tar.xz -C /tmp \
  && install -m 0755 "/tmp/upx-${UPX_VERSION}-amd64_linux/upx" /usr/local/bin/upx \
  && rm -rf /tmp/radare2.deb /tmp/upx.tar.xz "/tmp/upx-${UPX_VERSION}-amd64_linux" \
  && rm -rf /var/lib/apt/lists/*

# --- UPX (rev: unpack packed binaries) ---------------------------------------
# Not in Debian bookworm, so install the official static release.
RUN wget -q https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-amd64_linux.tar.xz -O /tmp/upx.tar.xz \
 && tar xJf /tmp/upx.tar.xz -C /tmp \
 && mv /tmp/upx-4.2.4-amd64_linux/upx /usr/local/bin/upx \
 && rm -rf /tmp/upx*

# --- radare2 (optional; dropped from Debian, so not apt-installable) ----------
# Uncomment to add it from the project's own release (check the latest version/asset):
#   RUN wget -q https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_amd64.deb -O /tmp/r2.deb \
#    && apt-get update && apt-get install -y /tmp/r2.deb \
#    && rm -rf /tmp/r2.deb /var/lib/apt/lists/*

# --- ruby gems: one_gadget (pwn), zsteg (stego) ------------------------------
RUN gem install --no-document one_gadget zsteg

# --- python tooling: one layer per category ----------------------------------
# pwn
RUN pip install "pwntools==4.13.1" "ROPgadget==7.5" "unicorn==2.1.1" "capstone==5.0.1"
# crypto
RUN pip install "pycryptodome==3.21.0" "sympy==1.13.3" "gmpy2==2.2.1" "z3-solver==4.13.0.0"
# rev (angr is large; pin it and let it pull its deps). Pins keep its old deps working on
# Python 3.12:
#   - pyvex uses bitstring.ConstBitStream, removed in bitstring 5.0 → pin the 4.x API
#   - angr's sim_type CLexer sets .filename, which pycparser 2.22 made read-only → pin 2.21
#   - angr pins unicorn 2.0.1, which imports distutils (gone in 3.12) → setuptools<81 restores it
RUN pip install "angr==9.2.123" "bitstring<5" "pycparser==2.21" "setuptools<81"
# forensics / web / misc
RUN pip install "volatility3==2.11.0" "requests==2.32.3" "pyOpenSSL==24.2.1" "scapy==2.6.0"
# smb (file-share instances): impacket for anonymous enumeration + file retrieval
RUN pip install "impacket==0.12.0"

# --- optional heavyweights (uncomment as needed) -----------------------------
# Ghidra (headless decompiler) -- ~1GB incl. JDK:
#   RUN apt-get update && apt-get install -y openjdk-17-jdk-headless unzip \
#    && wget -q <ghidra-release.zip> -O /tmp/ghidra.zip \
#    && unzip -q /tmp/ghidra.zip -d /opt && rm /tmp/ghidra.zip
# SageMath (algebra/number theory for hard crypto):  apt-get install -y sagemath
# Headless browser for stateful web:                 apt-get install -y chromium
# sqlmap / feroxbuster for web:                       pip install sqlmap ; apt-get install -y feroxbuster

# --- unprivileged user; /work is bind-mounted by the sandbox -----------------
RUN useradd -m -u 1000 solver
WORKDIR /work
USER solver

# The sandbox keeps the container alive and drives it via `docker exec`.
CMD ["sleep", "infinity"]
