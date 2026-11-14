"""Run the published Linux engine on a Mac.

invisible-playwright publishes Windows x86_64 and Linux x86_64. On macOS the
package stops before it downloads. oby then runs the same command in a
linux/amd64 container. The recording directory is the host's ``--out``.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path

IMAGE = "oby-linux:firefox"
ENGINE_PLATFORM = "linux/amd64"
CONTAINER_SRC = "/src"
CONTAINER_OUT = "/out"

_NO_DOCKER = (
    "oby: macOS has no published Firefox engine. "
    "Install Docker Desktop, then run this again."
)
_NO_CHECKOUT = (
    "oby: on a Mac the Linux engine is built from a checkout of this repo. "
    "Run oby from that checkout."
)


def needs_linux_engine(
    platform: str | None = None,
    env: Mapping[str, str] | None = None,
) -> bool:
    """True when this process must hand the command to the Linux container.

    The container sets ``OBY_LINUX_HOST`` so the same code does not start
    another container.
    """
    host = sys.platform if platform is None else platform
    variables = os.environ if env is None else env
    return host == "darwin" and variables.get("OBY_LINUX_HOST") != "1"


def project_root() -> Path | None:
    root = Path(__file__).resolve().parents[1]
    if (root / "docker" / "Dockerfile").is_file() and (root / "oby" / "__main__.py").is_file():
        return root
    return None


def rewrite_argv(argv: list[str]) -> list[str]:
    """Point the container at the mounted recording and drop ``--proxy``.

    The proxy URL is passed in the environment. On the command line it would
    show up in ``docker ps`` with the password in it.
    """
    rewritten: list[str] = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--proxy":
            index += 2
            continue
        if arg.startswith("--proxy="):
            index += 1
            continue
        if arg == "--out":
            rewritten.extend(["--out", CONTAINER_OUT])
            index += 2
            continue
        if arg.startswith("--out="):
            rewritten.extend(["--out", CONTAINER_OUT])
            index += 1
            continue
        rewritten.append(arg)
        index += 1
    if "--out" not in rewritten:
        rewritten.extend(["--out", CONTAINER_OUT])
    return rewritten


def docker_build_argv(repo: Path) -> list[str]:
    return [
        "docker", "build",
        "--platform", ENGINE_PLATFORM,
        "--progress", "plain",
        "-t", IMAGE,
        "-f", str(repo / "docker" / "Dockerfile"),
        str(repo),
    ]


def docker_run_argv(
    *,
    repo: Path,
    out: Path,
    inner: list[str],
    headless: bool,
    vnc_port: int | None,
    name: str,
    user: str,
    forward_proxy: bool,
) -> list[str]:
    command = [
        "docker", "run", "--rm", "-i", "--init",
        "--platform", ENGINE_PLATFORM,
        "--shm-size", "2g",
        "--name", name,
        "--user", user,
        "--stop-signal", "SIGINT",
        "--stop-timeout", "40",
        "-v", f"{repo}:{CONTAINER_SRC}",
        "-v", f"{out}:{CONTAINER_OUT}",
        "-w", CONTAINER_SRC,
        "-e", "OBY_LINUX_HOST=1",
        "-e", "PYTHONPATH=/src",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-e", "HOME=/tmp/oby-home",
        "-e", f"OBY_HOST_OUT={out}",
    ]
    if forward_proxy:
        # No value: docker copies OBY_PROXY from this process. The password
        # is not part of the argv `ps` and `docker ps` show.
        command.extend(["-e", "OBY_PROXY"])
    if not headless:
        if vnc_port is None:
            raise ValueError("a visible session needs a screen-sharing port")
        command.extend(["-e", "OBY_HEADED=1", "-p", f"127.0.0.1:{vnc_port}:5900"])
    command.append(IMAGE)
    command.extend(["sh", f"{CONTAINER_SRC}/docker/entry.sh", "python", "-m", "oby", *inner])
    return command


def run_in_linux(
    argv: list[str],
    *,
    proxy: str | None,
    out: Path,
    headless: bool,
) -> int:
    if shutil.which("docker") is None:
        print(_NO_DOCKER, file=sys.stderr)
        return 1
    repo = project_root()
    if repo is None:
        print(_NO_CHECKOUT, file=sys.stderr)
        return 1
    out = out.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    print(
        "oby: no macOS Firefox engine is published. Running the Linux engine in Docker.",
        file=sys.stderr,
    )
    build = subprocess.run(
        docker_build_argv(repo),
        stdout=sys.stderr,
        stderr=sys.stderr,
        check=False,
    )
    if build.returncode != 0:
        print("oby: the Linux engine image did not build.", file=sys.stderr)
        return build.returncode or 1
    vnc_port = None if headless else _free_port()
    name = f"oby-{os.getpid()}"
    cmd = docker_run_argv(
        repo=repo,
        out=out,
        inner=rewrite_argv(argv),
        headless=headless,
        vnc_port=vnc_port,
        name=name,
        user=f"{os.getuid()}:{os.getgid()}",
        forward_proxy=proxy is not None,
    )
    env = os.environ.copy()
    if proxy:
        env["OBY_PROXY"] = proxy
    else:
        env.pop("OBY_PROXY", None)
    return _run(cmd, env, vnc_port=vnc_port, name=name)


def _run(cmd: list[str], env: dict[str, str], *, vnc_port: int | None, name: str) -> int:
    proc = subprocess.Popen(cmd, env=env)
    try:
        if vnc_port is not None:
            _announce_screen(vnc_port)
        return proc.wait()
    except KeyboardInterrupt:
        # Without a tty, Ctrl+C stops at the docker client. Tell the
        # container directly so it can write the recording.
        _interrupt_container(name)
        return _stop(proc, name)


def _interrupt_container(name: str) -> None:
    subprocess.run(
        ["docker", "kill", "--signal=SIGINT", name],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _stop(proc: subprocess.Popen[bytes], name: str) -> int:
    # The terminal already delivered SIGINT to the docker client. The
    # container was signaled directly. Wait for it to write the recording.
    try:
        return proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        try:
            return proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait()
            # A killed client never runs --rm, so the container would stay up.
            subprocess.run(
                ["docker", "rm", "-f", name],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return code


def _announce_screen(port: int) -> None:
    url = f"vnc://127.0.0.1:{port}"
    if not _wait_port(port, 30):
        print(
            "oby: the screen share port did not open. The browser is still running in Docker.",
            file=sys.stderr,
        )
        return
    print(f"oby: the window is in Screen Sharing at {url}", file=sys.stderr)
    if os.environ.get("OBY_NO_OPEN") == "1":
        return
    subprocess.run(
        ["open", url],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_port(port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return True
        except OSError:
            time.sleep(0.2)
    return False
