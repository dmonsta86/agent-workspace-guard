#!/usr/bin/env python3
"""Build and independently verify the ZIP, Git bundle, and Python wheel release."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import venv
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
VERSION = str(PROJECT["version"])
TAG = f"v{VERSION}"
ZIP_NAME = "agent-workspace-guard-submission.zip"
BUNDLE_NAME = "agent-workspace-guard.bundle"
CHECKSUM_NAME = "ARTIFACTS.sha256"
ARCHIVE_PREFIX = "agent-workspace-guard"

FORBIDDEN_ARCHIVE_PARTS = {
    ".git",
    ".venv",
    ".awg-state",
    "__pycache__",
    "build",
    "dist",
    "release",
}
FORBIDDEN_ARCHIVE_NAMES = {"secret.key", ".env", ".coverage"}


def run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command))
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        capture_output=capture,
    )


def python_environment(root: Path) -> dict[str, str]:
    env = os.environ.copy()
    source = str(root / "src")
    if env.get("PYTHONPATH"):
        env["PYTHONPATH"] = source + os.pathsep + env["PYTHONPATH"]
    else:
        env["PYTHONPATH"] = source
    return env


def verify_source(root: Path, *, include_demo: bool) -> None:
    env = python_environment(root)
    run([sys.executable, "scripts/verify_manifest.py"], cwd=root, env=env)
    run(
        [sys.executable, "-m", "compileall", "-q", "src", "tests", "scripts"],
        cwd=root,
        env=env,
    )
    run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=root,
        env=env,
    )
    run([sys.executable, "scripts/run_replay.py"], cwd=root, env=env)
    run(
        [sys.executable, "-m", "agent_workspace_guard", "--help"],
        cwd=root,
        env=env,
        capture=True,
    )
    if include_demo:
        run([sys.executable, "examples/demo.py"], cwd=root, env=env)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def venv_python(root: Path) -> Path:
    if os.name == "nt":
        return root / "Scripts" / "python.exe"
    return root / "bin" / "python"


def ensure_clean_release_commit() -> tuple[str, str]:
    status = run(
        ["git", "status", "--porcelain", "--untracked-files=all"], capture=True
    ).stdout.strip()
    if status:
        raise RuntimeError("release packaging requires a clean Git working tree")

    head = run(["git", "rev-parse", "HEAD"], capture=True).stdout.strip()
    tag_target = run(["git", "rev-list", "-n", "1", TAG], capture=True).stdout.strip()
    if head != tag_target:
        raise RuntimeError(f"{TAG} must point at HEAD before packaging")

    commit_epoch = run(
        ["git", "show", "-s", "--format=%ct", "HEAD"], capture=True
    ).stdout.strip()
    if not commit_epoch.isdigit():
        raise RuntimeError("could not obtain the release commit timestamp")
    return head, commit_epoch


def verify_zip_structure(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if not members:
            raise RuntimeError("release ZIP is empty")
        for member in members:
            name = member.filename
            if "\\" in name or name.startswith("/"):
                raise RuntimeError(f"unsafe ZIP member name: {name!r}")
            pure = PurePosixPath(name)
            if any(part in {"", ".", ".."} for part in pure.parts):
                raise RuntimeError(f"non-normalized ZIP member name: {name!r}")
            if not pure.parts or pure.parts[0] != ARCHIVE_PREFIX:
                raise RuntimeError(f"ZIP member is outside the release prefix: {name!r}")
            relative_parts = pure.parts[1:]
            if any(part in FORBIDDEN_ARCHIVE_PARTS for part in relative_parts):
                raise RuntimeError(f"generated state leaked into ZIP: {name!r}")
            if pure.name in FORBIDDEN_ARCHIVE_NAMES or pure.suffix in {".pyc", ".pyo"}:
                raise RuntimeError(f"forbidden file leaked into ZIP: {name!r}")

            unix_mode = member.external_attr >> 16
            if unix_mode and stat.S_ISLNK(unix_mode):
                raise RuntimeError(f"release ZIP may not contain symlinks: {name!r}")


def verify_wheel_structure(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            pure = PurePosixPath(member.filename)
            if (
                member.filename.startswith("/")
                or "\\" in member.filename
                or any(part in {"", ".", ".."} for part in pure.parts)
            ):
                raise RuntimeError(f"unsafe wheel member: {member.filename!r}")
            if pure.name in FORBIDDEN_ARCHIVE_NAMES:
                raise RuntimeError(f"forbidden file leaked into wheel: {member.filename!r}")


def build_wheel(destination: Path, *, build_env: dict[str, str]) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(destination),
            ".",
        ],
        env=build_env,
    )
    wheels = list(destination.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one wheel, found {len(wheels)}")
    return wheels[0]


def verify_installed_wheel(wheel_path: Path, scratch: Path) -> None:
    environment_root = scratch / "wheel-venv"
    venv.EnvBuilder(with_pip=True, clear=True).create(environment_root)
    isolated_python = venv_python(environment_root)
    run(
        [str(isolated_python), "-m", "pip", "install", "--no-deps", str(wheel_path)],
        cwd=scratch,
    )
    secret_command = 'rm -rf "${TARGET:-/}" # release-secret-marker'
    result = run(
        [
            str(isolated_python),
            "-m",
            "agent_workspace_guard",
            "inspect",
            "--shell",
            "bash",
            "--command-text",
            secret_command,
        ],
        cwd=scratch,
        capture=True,
    )
    if '"decision": "deny"' not in result.stdout:
        raise RuntimeError("installed wheel failed the destructive-command smoke test")
    if "release-secret-marker" in result.stdout:
        raise RuntimeError("installed wheel echoed raw command content")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "release",
        help="directory for release artifacts (default: ./release)",
    )
    args = parser.parse_args(argv)
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)

    try:
        source_head, commit_epoch = ensure_clean_release_commit()
        verify_source(ROOT, include_demo=True)

        zip_path = output / ZIP_NAME
        bundle_path = output / BUNDLE_NAME
        checksum_path = output / CHECKSUM_NAME
        for path in (zip_path, bundle_path, checksum_path):
            path.unlink(missing_ok=True)

        run(
            [
                "git",
                "archive",
                "--format=zip",
                f"--prefix={ARCHIVE_PREFIX}/",
                "-o",
                str(zip_path),
                TAG,
            ]
        )
        verify_zip_structure(zip_path)

        run(["git", "bundle", "create", str(bundle_path), "--all"])
        run(["git", "bundle", "verify", str(bundle_path)])

        build_env = os.environ.copy()
        build_env["SOURCE_DATE_EPOCH"] = commit_epoch
        build_env["PYTHONHASHSEED"] = "0"

        with tempfile.TemporaryDirectory(prefix="awg-release-build-") as temporary:
            build_root = Path(temporary)
            first_wheel = build_wheel(build_root / "wheel-a", build_env=build_env)
            second_wheel = build_wheel(build_root / "wheel-b", build_env=build_env)
            if sha256(first_wheel) != sha256(second_wheel):
                raise RuntimeError("two release wheel builds were not byte-for-byte reproducible")
            verify_wheel_structure(first_wheel)
            wheel_path = output / first_wheel.name
            wheel_path.unlink(missing_ok=True)
            shutil.copy2(first_wheel, wheel_path)

        with tempfile.TemporaryDirectory(prefix="awg-release-verify-") as temporary:
            scratch = Path(temporary)

            extracted = scratch / "zip"
            extracted.mkdir()
            with zipfile.ZipFile(zip_path) as archive:
                archive.extractall(extracted)
            verify_source(extracted / ARCHIVE_PREFIX, include_demo=True)

            cloned = scratch / "bundle-clone"
            run(["git", "clone", "--quiet", str(bundle_path), str(cloned)], cwd=scratch)
            cloned_head = run(
                ["git", "rev-parse", "HEAD"], cwd=cloned, capture=True
            ).stdout.strip()
            if cloned_head != source_head:
                raise RuntimeError("Git bundle clone does not match release HEAD")
            verify_source(cloned, include_demo=False)

            verify_installed_wheel(wheel_path, scratch)

        artifacts = [zip_path, bundle_path, wheel_path]
        checksum_path.write_text(
            "".join(f"{sha256(path)}  {path.name}\n" for path in artifacts),
            encoding="utf-8",
            newline="\n",
        )

        print("\nRelease artifacts verified:")
        for path in artifacts:
            print(f"  {sha256(path)}  {path}")
        print(f"  checksums: {checksum_path}")
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError, zipfile.BadZipFile) as exc:
        print(f"release error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
