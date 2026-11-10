# Toolbox image

The container sandbox (`ctfsolver.sandbox.ContainerSandbox` + `DockerDriver`) runs a
specialist's tools inside this image.

```sh
docker build -f docker/toolbox.Dockerfile -t ctfsolver/toolbox:latest .
```

The default image name is `ctfsolver/toolbox:latest` (see `SandboxLimits.image`). Override
it with the `CTFSOLVER_TOOLBOX_IMAGE` env var or by passing `SandboxLimits(image=...)`.

## How the sandbox runs it

Each challenge gets a fresh container, started by `DockerDriver.build_run_argv`:

- `--network none` when the challenge has no targets; otherwise an `--internal` bridge
  with the egress allow-list applied at the host firewall (`sandbox/egress.py`).
- `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only`, tmpfs `/tmp`,
  and `--memory/--cpus/--pids-limit` from `SandboxLimits`.
- The sandbox workdir is bind-mounted at `/work`; files staged in and results read back
  use the same directory the container sees.
- The container is force-removed on close (disposable).

## Debugging-capable runs (pwn/rev)

`gdb`/`ptrace`-based exploitation needs `CAP_SYS_PTRACE`, which the locked-down default
drops. The pwn live path requests it per challenge:

```python
from ctfsolver.sandbox import SandboxLimits, auto_sandbox_factory
limits = SandboxLimits(cap_add=["SYS_PTRACE"])            # and seccomp="unconfined" if a tool needs it
factory = auto_sandbox_factory(limits=limits)
```

This adds only the ptrace capability; it does not loosen the network confinement.

## Keeping it lean

The base image installs the common CLI tools plus pwntools, pycryptodome/sympy/z3, angr,
volatility3 and scapy. Ghidra, SageMath, a headless browser and sqlmap/feroxbuster are
left commented in the Dockerfile — uncomment the ones your event's challenges actually
need rather than shipping a multi-GB image.
