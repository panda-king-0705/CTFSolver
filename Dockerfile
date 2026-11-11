# ctfsolver control-plane image -- runs the orchestrator / CLI (the `ctfsolver` entry point).
#
#   docker build -t ctfsolver/app:latest .
#   docker run --rm -p 8000:8000 ctfsolver/app:latest    # web console on :8000 (default CMD)
#   docker run --rm ctfsolver/app:latest demo            # or the offline toy challenge
#
# The control plane is stdlib-only, so the base install needs no dependencies. This image
# adds the Docker *client* so the ContainerSandbox can drive the toolbox image through a
# mounted daemon socket (docker-outside-of-docker).
#
# Offline (no socket) the solver runs on the LocalSandbox: demo, eval, crypto/misc all work
# with a plain `docker run --rm ctfsolver/app:latest <cmd>`.
#
# For a real container-backed solve (--container), the daemon is on the HOST, so the
# sandbox workdir must be a path the host can see too. Share one dir at an IDENTICAL path
# on host and container and point TMPDIR at it (mkdtemp honors TMPDIR); otherwise the
# nested -v {workdir}:/work mounts an empty host path and the solve fails silently:
#
#   docker build -f docker/toolbox.Dockerfile -t ctfsolver/toolbox:latest .   # once
#   SBX=/tmp/ctfsbx-shared; mkdir -p "$SBX"
#   docker run --rm \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     --group-add "$(getent group docker | cut -d: -f3)" \
#     -v "$SBX:$SBX" -e TMPDIR="$SBX" \
#     -v "$PWD/chall:/chall:ro" \
#     ctfsolver/app:latest solve --spec /chall/challenge.json --container
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Docker CLI only (no daemon) -- lets ContainerSandbox reach a mounted /var/run/docker.sock.
ARG DOCKER_CLI_VERSION=29.9.3
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
  && curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.tgz" \
       | tar -xz -C /usr/local/bin --strip-components=1 docker/docker \
  && apt-get purge -y curl && apt-get autoremove -y \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the package editable, keeping the repo layout under /app. The demo and the
# memory seed resolve examples/ and data/ *relative to the source tree* (parents[3]),
# so the tree must stay intact rather than collapse into site-packages.
# The 'smb' extra (impacket) ships by default so live SMB instances solve out of the box.
# EXTRAS adds more, e.g. --build-arg EXTRAS='[smb,providers]' for the Anthropic/OpenAI SDKs.
ARG EXTRAS="[smb]"
COPY pyproject.toml README.md ./
COPY src ./src
COPY data ./data
COPY examples ./examples
RUN pip install -e ".${EXTRAS}"

# Unprivileged by default; /app must be writable for generated writeups.
# (A socket-mounted run may need the host docker gid; see the header.)
RUN useradd -m -u 1000 solver \
  && mkdir -p /app/writeups \
  && chown -R solver:solver /app
USER solver

# The web console/API is the default. It binds 0.0.0.0 so a published port works;
# publish it with `-p 8000:8000`. Override with any other subcommand (demo, solve, eval).
EXPOSE 8000
ENTRYPOINT ["ctfsolver"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
