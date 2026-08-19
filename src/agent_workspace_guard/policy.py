"""Policy evaluation over exact workspace diffs.

Unlike a shell-command classifier, this policy sees the evaluated result: exact
paths, entry types, content hashes, and byte counts. It therefore gates the
thing that would be committed rather than guessing what a command might do.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from .models import Change, ChangeKind, Decision, EntryKind, Finding, TreeManifest
from .util import digest_json


@dataclass(frozen=True)
class GuardPolicy:
    auto_add_max_entries: int = 200
    auto_add_max_bytes: int = 20 * 1024 * 1024
    max_total_changes: int = 20_000
    hard_delete_entries: int = 5_000
    hard_delete_fraction: float = 0.50
    mass_delete_min_baseline_entries: int = 20
    allow_mass_delete: bool = False
    protected_top_level: tuple[str, ...] = (".git", ".agent-workspace-guard")
    sensitive_names: tuple[str, ...] = (
        ".env",
        ".env.local",
        "credentials",
        "credentials.json",
        "id_rsa",
        "id_ed25519",
        "secrets.json",
    )
    executable_suffixes: tuple[str, ...] = (
        ".bat",
        ".cmd",
        ".com",
        ".exe",
        ".ps1",
        ".sh",
    )
    policy_name: str = "awg-default"
    policy_version: int = 1

    def fingerprint(self) -> str:
        """Return a stable digest that binds plans and approvals to this policy."""
        return digest_json(
            {
                "kind": "guard_policy",
                "configuration": asdict(self),
            }
        )

    def evaluate(
        self,
        baseline: TreeManifest,
        staged: TreeManifest,
        changes: list[Change],
    ) -> tuple[Decision, list[Finding], dict[str, int]]:
        findings: list[Finding] = []
        counts = {kind.value: 0 for kind in ChangeKind}
        added_bytes = 0
        replacement_bytes = 0
        removed_bytes = 0
        destructive = False
        hard_deny = False
        sensitive_names = {name.lower() for name in self.sensitive_names}
        protected_names = {name.casefold() for name in self.protected_top_level}

        for change in changes:
            counts[change.kind.value] += 1
            top = Path(change.path).parts[0]
            if top.casefold() in protected_names:
                hard_deny = True
                findings.append(
                    Finding(
                        code="protected_path_change",
                        severity="error",
                        path=change.path,
                        message=f"broker metadata or VCS internals may not be committed: {change.path}",
                    )
                )

            before = change.before
            after = change.after
            if change.kind is ChangeKind.ADD and after and after.kind is EntryKind.FILE:
                added_bytes += after.size
            if (
                change.kind in (ChangeKind.MODIFY, ChangeKind.TYPE_CHANGE)
                and after
                and after.kind is EntryKind.FILE
            ):
                replacement_bytes += after.size
            if (
                change.kind in (ChangeKind.DELETE, ChangeKind.TYPE_CHANGE)
                and before
                and before.kind is EntryKind.FILE
            ):
                removed_bytes += before.size

            if change.kind in (ChangeKind.MODIFY, ChangeKind.DELETE, ChangeKind.TYPE_CHANGE):
                destructive = True

            entry = after or before
            if entry and entry.kind is EntryKind.SPECIAL:
                hard_deny = True
                findings.append(
                    Finding(
                        code="special_file_change",
                        severity="error",
                        path=change.path,
                        message="device nodes, sockets, and other special files are not commit-capable",
                    )
                )

            if after and after.kind is EntryKind.SYMLINK and (
                change.kind is not ChangeKind.DELETE
            ):
                destructive = True
                unsafe_reason = _unsafe_symlink_reason(
                    change.path,
                    after.link_target,
                    protected_top_level=tuple(protected_names),
                )
                if unsafe_reason:
                    hard_deny = True
                    findings.append(
                        Finding(
                            code="unsafe_symlink_target",
                            severity="error",
                            path=change.path,
                            message=unsafe_reason,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            code="symlink_change",
                            severity="warning",
                            path=change.path,
                            message="new or changed in-workspace symlinks require explicit review",
                        )
                    )

            if (
                change.kind is ChangeKind.ADD
                and after
                and after.kind is EntryKind.FILE
                and (
                    after.mode & 0o111
                    or Path(change.path).suffix.lower() in self.executable_suffixes
                )
            ):
                destructive = True
                findings.append(
                    Finding(
                        code="executable_file_added",
                        severity="warning",
                        path=change.path,
                        message="new executable or script content requires explicit review",
                    )
                )

            name = Path(change.path).name.lower()
            if (
                name in sensitive_names
                or name.startswith(".env.")
                or name.endswith((".pem", ".key", ".p12", ".pfx"))
            ):
                destructive = True
                findings.append(
                    Finding(
                        code="sensitive_path_change",
                        severity="warning",
                        path=change.path,
                        message="a credential- or secret-like path changed and requires review",
                    )
                )

        delete_count = counts[ChangeKind.DELETE.value]
        baseline_count = len(baseline.entries)
        delete_fraction_ppm = (
            int((delete_count / baseline_count) * 1_000_000) if baseline_count else 0
        )
        is_mass_delete = (
            baseline_count >= self.mass_delete_min_baseline_entries
            and delete_count > 0
            and (
                delete_count >= self.hard_delete_entries
                or delete_count / baseline_count >= self.hard_delete_fraction
            )
        )
        if is_mass_delete and not self.allow_mass_delete:
            hard_deny = True
            findings.append(
                Finding(
                    code="mass_deletion_denied",
                    severity="error",
                    message=(
                        f"plan deletes {delete_count} of {baseline_count} tracked entries; "
                        "a separate break-glass policy is required"
                    ),
                )
            )

        if len(changes) > self.max_total_changes:
            hard_deny = True
            findings.append(
                Finding(
                    code="change_budget_exceeded",
                    severity="error",
                    message=(
                        f"plan contains {len(changes):,} changes, above the "
                        f"{self.max_total_changes:,} hard limit"
                    ),
                )
            )

        add_only = bool(changes) and all(change.kind is ChangeKind.ADD for change in changes)
        if add_only and (
            len(changes) > self.auto_add_max_entries or added_bytes > self.auto_add_max_bytes
        ):
            destructive = True
            findings.append(
                Finding(
                    code="automatic_add_budget_exceeded",
                    severity="warning",
                    message="large add-only plans require review before commit",
                )
            )

        if hard_deny:
            decision = Decision.DENY
        elif destructive:
            decision = Decision.REQUIRE_APPROVAL
        else:
            decision = Decision.ALLOW

        summary = {
            "total_changes": len(changes),
            "added": counts[ChangeKind.ADD.value],
            "modified": counts[ChangeKind.MODIFY.value],
            "deleted": counts[ChangeKind.DELETE.value],
            "type_changed": counts[ChangeKind.TYPE_CHANGE.value],
            "added_bytes": added_bytes,
            "replacement_bytes": replacement_bytes,
            "removed_bytes": removed_bytes,
            "baseline_entries": baseline_count,
            "staged_entries": len(staged.entries),
            "delete_fraction_ppm": delete_fraction_ppm,
        }
        return decision, findings, summary


def _unsafe_symlink_reason(
    link_path: str,
    target: str | None,
    *,
    protected_top_level: tuple[str, ...],
) -> str | None:
    """Return a denial reason for symlinks that escape the transaction namespace."""
    if not target or "\x00" in target:
        return "empty or malformed symlink targets are not commit-capable"

    windows_target = PureWindowsPath(target)
    if target.startswith(("/", "\\")) or windows_target.is_absolute() or windows_target.drive:
        return "absolute, drive-qualified, and UNC symlink targets are denied"

    # Treat backslashes as separators too. This is conservative on POSIX and
    # prevents a plan from becoming unsafe when moved to a Windows backend.
    normalized_target = target.replace("\\", "/")
    components = list(PurePosixPath(link_path).parent.parts)
    for component in PurePosixPath(normalized_target).parts:
        if component in ("", "."):
            continue
        if component == "..":
            if not components:
                return "symlink target escapes above the workspace root"
            components.pop()
            continue
        components.append(component)

    if components and components[0].casefold() in {
        item.casefold() for item in protected_top_level
    }:
        return "symlink target enters protected broker or VCS metadata"
    return None
