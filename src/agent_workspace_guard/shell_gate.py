"""Defense-in-depth shell inspection.

This module intentionally does *not* claim to prove command safety. Shells are
programming languages, commands can invoke other interpreters, and evaluated
paths depend on runtime state. The authoritative boundary is the transactional
workspace plus commit broker. This gate catches obvious catastrophic intent,
routes destructive activity to review, and supplies replayable diagnostics.
"""

from __future__ import annotations

import hashlib
import re

from .models import CommandInspection, Decision, Finding


BOUNDARY_NOTE = (
    "Heuristic inspection is not the security boundary. Execute only inside the "
    "disposable worktree with OS-enforced denial of writes to the real workspace; "
    "commit exact diffs through the broker."
)

_RESERVED_ASSIGNMENTS = [
    re.compile(
        r"(?im)(?:^|[;&|\s])(?:export\s+)?(?:HOME|USERPROFILE|TMPDIR|TMP|TEMP|CODEX_HOME|"
        r"XDG_CONFIG_HOME|XDG_CACHE_HOME|XDG_DATA_HOME|XDG_STATE_HOME|XDG_RUNTIME_DIR|"
        r"APPDATA|LOCALAPPDATA)\s*="
    ),
    re.compile(
        r"(?im)(?:^|[;&|\s])\$(?:env:)?(?:HOME|USERPROFILE|TMPDIR|TMP|TEMP|CODEX_HOME|"
        r"XDG_CONFIG_HOME|XDG_CACHE_HOME|XDG_DATA_HOME|XDG_STATE_HOME|XDG_RUNTIME_DIR|"
        r"APPDATA|LOCALAPPDATA)\s*="
    ),
    re.compile(
        r"(?im)(?:^|[;&|\s])set\s+(?:HOME|USERPROFILE|TMPDIR|TMP|TEMP|CODEX_HOME|"
        r"XDG_CONFIG_HOME|XDG_CACHE_HOME|XDG_DATA_HOME|XDG_STATE_HOME|XDG_RUNTIME_DIR|"
        r"APPDATA|LOCALAPPDATA)\s*="
    ),
]

_HOST_ESCAPE = re.compile(
    r"(?im)(?:^|[;&|\s])(?:sudo|doas|mount|umount|chroot|pivot_root|mkfs(?:\.[a-z0-9]+)?|"
    r"diskutil\s+erase|format(?:\.com)?\s+[a-z]:|takeown|icacls)\b"
)

_POSIX_RM = re.compile(r"(?im)(?:^|[;&|])\s*(?:command\s+)?(?:/[^\s;]+/)?(?:rm|unlink|rmdir|shred)\b")
_FIND_DELETE = re.compile(r"(?im)\bfind\b[^\n;]*(?:-delete|-exec(?:dir)?\s+(?:rm|unlink|rmdir)\b)")
_GIT_DESTRUCTIVE = re.compile(
    r"(?im)\bgit\s+(?:clean\b|reset\s+--hard\b|checkout\s+--\s+\.|restore\b|rm\b)"
)
_SYNC_DELETE = re.compile(r"(?im)\b(?:rsync\b[^\n;]*--delete\b|robocopy\b[^\n;]*/(?:mir|purge)\b)")
_POWERSHELL_DELETE = re.compile(
    r"(?im)(?:^|[;&|\s])(?:Remove-Item|Clear-Content|ri|del|erase|rd|rmdir)\b"
)
_CMD_DELETE = re.compile(r"(?im)(?:^|[&|\s])(?:del|erase|rd|rmdir)\b[^\n]*(?:/s|/q)")
_INLINE_DELETE_API = re.compile(
    r"(?im)(?:shutil\.rmtree|os\.(?:remove|unlink|rmdir)|Path\([^\n]*\)\.unlink|"
    r"fs\.(?:rm|rmdir|unlink)|FileUtils\.rm_rf|std::fs::remove_(?:file|dir_all)|"
    r"System\.IO\.(?:File|Directory)\.Delete|Remove-Item)"
)
_TRUNCATION = re.compile(
    r"(?im)(?:^|[;&|\s])(?:truncate\b|dd\b[^\n;]*\bof=|Set-Content\b|Clear-Content\b)"
)
_DYNAMIC_SHELL = re.compile(
    r"(?im)(?:\b(?:bash|sh|zsh)\s+-c\b|\b(?:powershell|pwsh)(?:\.exe)?\b[^\n;]*-(?:command|c)\b|\beval\b)"
)

# Explicit targets that should not be runnable even inside a disposable session:
# they usually signal a malformed cleanup and can destroy the session or attack
# mounted host paths in a misconfigured sandbox.
_CATASTROPHIC_TARGET = re.compile(
    r"(?ix)(?:"
    r"(?:^|[\s'\"])(?:/|/\*|~/?|\.\.?/?\*?)(?:[\s'\"]|$)|"
    r"\$(?:HOME|USERPROFILE)(?:[/\\]\*)?|"
    r"\$\{(?:HOME|USERPROFILE)\}|"
    r"\$env:(?:HOME|USERPROFILE)|"
    r"%(?:HOME|USERPROFILE)%|"
    r"[A-Z]:\\(?:\*|\s|['\"]|$)|"
    r"\$\{[A-Za-z_][A-Za-z0-9_]*:-/\}"
    r")"
)


def inspect_shell_command(command: str, shell: str = "unknown") -> CommandInspection:
    raw = command if isinstance(command, str) else repr(command)
    command_sha256 = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()
    command_length = len(raw)
    if not isinstance(command, str) or not command.strip():
        return CommandInspection(
            decision=Decision.DENY,
            findings=[
                Finding(
                    code="empty_command",
                    severity="error",
                    message="empty shell payloads are rejected",
                )
            ],
            shell=shell,
            command_sha256=command_sha256,
            command_length=command_length,
            boundary_note=BOUNDARY_NOTE,
        )
    if len(command) > 1_000_000:
        return CommandInspection(
            decision=Decision.DENY,
            findings=[
                Finding(
                    code="command_too_large",
                    severity="error",
                    message="shell payload exceeds the inspection budget",
                )
            ],
            shell=shell,
            command_sha256=command_sha256,
            command_length=command_length,
            boundary_note=BOUNDARY_NOTE,
        )

    findings: list[Finding] = []
    decision = Decision.ALLOW

    def add(code: str, severity: str, message: str, target: Decision) -> None:
        nonlocal decision
        if not any(item.code == code for item in findings):
            findings.append(Finding(code=code, severity=severity, message=message))
        if target is Decision.DENY:
            decision = Decision.DENY
        elif target is Decision.REQUIRE_APPROVAL and decision is Decision.ALLOW:
            decision = Decision.REQUIRE_APPROVAL

    if any(pattern.search(command) for pattern in _RESERVED_ASSIGNMENTS):
        add(
            "reserved_environment_mutation",
            "error",
            "the command assigns to broker-owned home, temp, or user-state identity",
            Decision.DENY,
        )

    if _HOST_ESCAPE.search(command):
        add(
            "sandbox_boundary_mutation",
            "error",
            "privilege, mount, filesystem-format, or ACL mutation is outside the task capability",
            Decision.DENY,
        )

    destructive_patterns = (
        _POSIX_RM,
        _FIND_DELETE,
        _GIT_DESTRUCTIVE,
        _SYNC_DELETE,
        _POWERSHELL_DELETE,
        _CMD_DELETE,
        _INLINE_DELETE_API,
        _TRUNCATION,
    )
    destructive = any(pattern.search(command) for pattern in destructive_patterns)
    if destructive:
        add(
            "destructive_intent",
            "warning",
            "destructive or overwrite-capable activity must remain inside the transaction and be reviewed as an exact diff",
            Decision.REQUIRE_APPROVAL,
        )
        if _CATASTROPHIC_TARGET.search(command):
            add(
                "catastrophic_target",
                "error",
                "the payload references a root, home/profile, parent, current-directory, or default-to-root target",
                Decision.DENY,
            )

    if _DYNAMIC_SHELL.search(command) and destructive:
        add(
            "nested_dynamic_destructive_shell",
            "warning",
            "nested or evaluated shell code prevents reliable lexical interpretation",
            Decision.REQUIRE_APPROVAL,
        )

    lower_shell = shell.lower()
    if lower_shell in {"powershell", "pwsh"} and "2>/dev/null" in command:
        findings.append(
            Finding(
                code="cross_shell_redirection",
                severity="warning",
                message="Bash redirection was used in PowerShell; use 2>$null",
            )
        )

    return CommandInspection(
        decision=decision,
        findings=findings,
        shell=shell,
        command_sha256=command_sha256,
        command_length=command_length,
        boundary_note=BOUNDARY_NOTE,
    )
