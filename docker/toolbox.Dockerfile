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
RUN apt-get update && apt-get install -y --no-install-recommends \
      # shared
      build-essential git curl wget file xxd jq unzip p7zip-full ca-certificates \
      netcat-openbsd socat ltrace \
      # pwn / rev
      gdb binutils patchelf nasm radare2 upx-ucl \
      # forensics
      tshark binwalk foremost exiftool steghide sleuthkit \
      # ruby (for one_gadget, zsteg)
      ruby ruby-dev \
  && rm -rf /var/lib/apt/lists/*

# --- ruby gems: one_gadget (pwn), zsteg (stego) ------------------------------
RUN gem install --no-document one_gadget zsteg

# --- python tooling: one layer per category ----------------------------------
# pwn
RUN pip install "pwntools==4.13.1" "ROPgadget==7.5" "unicorn==2.1.1" "capstone==5.0.1"
# crypto
RUN pip install "pycryptodome==3.21.0" "sympy==1.13.3" "gmpy2==2.2.1" "z3-solver==4.13.0.0"
# rev (angr is large; pin it and let it pull its deps)
RUN pip install "angr==9.2.123"
# forensics / web / misc
RUN pip install "volatility3==2.11.0" "requests==2.32.3" "pyOpenSSL==24.2.1" "scapy==2.6.0"

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
