"""The Mac hands the command to the published Linux engine."""

from pathlib import Path

import pytest

from oby.__main__ import main
from oby.linuxbox import (
    docker_build_argv,
    docker_run_argv,
    needs_linux_engine,
    rewrite_argv,
    run_in_linux,
)


def test_only_darwin_needs_the_linux_engine():
    assert needs_linux_engine("linux", {}) is False
    assert needs_linux_engine("win32", {}) is False
    assert needs_linux_engine("darwin", {}) is True
    assert needs_linux_engine("darwin", {"OBY_LINUX_HOST": "1"}) is False


def test_rewrite_mounts_the_recording_and_drops_the_proxy():
    argv = rewrite_argv(
        [
            "browse",
            "--proxy",
            "http://user:secret@proxy.example:9",
            "--out",
            "session",
            "--url",
            "https://example.com",
            "--headless",
        ]
    )
    assert argv == [
        "browse",
        "--out",
        "/out",
        "--url",
        "https://example.com",
        "--headless",
    ]
    assert "secret" not in " ".join(argv)


def test_rewrite_accepts_equals_form_and_adds_a_missing_out():
    assert rewrite_argv(["mcp", "--proxy=http://user:secret@h:1", "--headless"]) == [
        "mcp",
        "--headless",
        "--out",
        "/out",
    ]


def test_docker_command_keeps_the_password_out_of_argv(tmp_path: Path):
    out = tmp_path / "session"
    cmd = docker_run_argv(
        repo=tmp_path,
        out=out,
        inner=["mcp", "--headless", "--out", "/out"],
        headless=True,
        vnc_port=None,
        name="oby-test",
        user="501:20",
        forward_proxy=True,
    )
    text = " ".join(cmd)
    assert "secret" not in text
    assert "user:pass" not in text
    assert "--proxy" not in cmd
    assert "-t" not in cmd
    proxy_at = cmd.index("OBY_PROXY")
    assert cmd[proxy_at - 1] == "-e"
    assert cmd[proxy_at + 1] != "http://user:secret@proxy.example:9"
    assert "--platform" in cmd and "linux/amd64" in cmd
    assert "--shm-size" in cmd and "2g" in cmd
    assert "--user" in cmd and "501:20" in cmd
    assert "--init" in cmd and "-i" in cmd and "--rm" in cmd
    assert "--stop-signal" in cmd and "SIGINT" in cmd
    assert "--stop-timeout" in cmd and "40" in cmd
    assert f"{tmp_path}:/src" in cmd
    assert f"{out}:/out" in cmd
    assert f"OBY_HOST_OUT={out}" in cmd
    assert "OBY_HEADED=1" not in cmd
    assert "-p" not in cmd
    start = cmd.index("sh")
    assert cmd[start:] == [
        "sh",
        "/src/docker/entry.sh",
        "python",
        "-m",
        "oby",
        "mcp",
        "--headless",
        "--out",
        "/out",
    ]


def test_visible_session_publishes_screen_sharing(tmp_path: Path):
    cmd = docker_run_argv(
        repo=tmp_path,
        out=tmp_path / "out",
        inner=["browse", "--out", "/out"],
        headless=False,
        vnc_port=5901,
        name="oby-test",
        user="501:20",
        forward_proxy=False,
    )
    assert "OBY_PROXY" not in cmd
    assert "OBY_HEADED=1" in cmd
    assert "127.0.0.1:5901:5900" in cmd
    assert "/src/docker/entry.sh" in cmd


def test_build_uses_the_linux_dockerfile(tmp_path: Path):
    cmd = docker_build_argv(tmp_path)
    assert cmd[:4] == ["docker", "build", "--platform", "linux/amd64"]
    assert "-t" in cmd and "oby-linux:firefox" in cmd
    assert str(tmp_path / "docker" / "Dockerfile") in cmd
    assert cmd[-1] == str(tmp_path)


def test_missing_docker_is_a_clean_error(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    monkeypatch.setattr("oby.linuxbox.shutil.which", lambda _name: None)
    code = run_in_linux(["mcp", "--headless"], proxy=None, out=Path("session"), headless=True)
    assert code == 1
    assert "Docker" in capsys.readouterr().err


def test_help_does_not_start_docker(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "JavaScript that ran" in out
    assert "browse" in out
    assert "mcp" in out


def test_darwin_hands_the_command_over(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    seen: dict[str, object] = {}

    def fake(argv: list[str], *, proxy: str | None, out: Path, headless: bool) -> int:
        seen["argv"] = argv
        seen["proxy"] = proxy
        seen["out"] = out
        seen["headless"] = headless
        return 7

    monkeypatch.setattr("oby.linuxbox.needs_linux_engine", lambda: True)
    monkeypatch.setattr("oby.linuxbox.run_in_linux", fake)
    code = main(
        [
            "mcp",
            "--headless",
            "--out",
            str(tmp_path),
            "--proxy",
            "http://user:secret@proxy.example:9",
        ]
    )
    assert code == 7
    assert seen["headless"] is True
    assert seen["proxy"] == "http://user:secret@proxy.example:9"
    assert seen["out"] == tmp_path
    assert list(seen["argv"])[0] == "mcp"


def test_inside_the_container_the_command_stays_here(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OBY_LINUX_HOST", "1")

    def refuse(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("handed off")

    monkeypatch.setattr("oby.linuxbox.run_in_linux", refuse)
    monkeypatch.setattr("oby.__main__._browse", lambda *_args, **_kwargs: 0)
    assert main(["browse", "--headless"]) == 0
