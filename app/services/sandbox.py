"""Run scanner binaries without a shell. Never pass user input as argv[0]."""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)

SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    not_found: bool = False


def run_cmd(
    argv: list[str],
    timeout: int,
    cwd: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> SandboxResult:
    if not argv or not all(isinstance(x, str) and x for x in argv):
        raise ValueError("argv must be a non-empty list of non-empty strings")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    home = os.environ.get("HOME") or str(Path.cwd() / "data" / "home")
    env = {
        "PATH": os.environ.get("PATH", SAFE_PATH),
        "HOME": home,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "dumb",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true",
    }
    if extra_env:
        env.update(extra_env)

    logger.info("sandbox: %s (timeout=%ss cwd=%s)", " ".join(argv[:6]), timeout, cwd)
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
        return SandboxResult(proc.returncode, proc.stdout or "", proc.stderr or "")
    except FileNotFoundError:
        return SandboxResult(127, "", f"{argv[0]} not found", not_found=True)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return SandboxResult(124, stdout, stderr or "timeout", timed_out=True)
