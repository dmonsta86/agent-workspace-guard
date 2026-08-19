# References

Access snapshot: **August 18, 2026 in America/Chihuahua** (August 19 UTC where applicable). Links are provided for design context; this repository remains an independent proposal.

## OpenAI Codex public repository

- Contribution guidance: https://github.com/openai/codex/blob/main/docs/contributing.md
- Security policy: https://github.com/openai/codex/blob/main/SECURITY.md
- Dangerous-command classifier: https://github.com/openai/codex/blob/main/codex-rs/shell-command/src/command_safety/is_dangerous_command.rs
- Execution-policy integration: https://github.com/openai/codex/blob/main/codex-rs/core/src/exec_policy.rs
- Execpolicy overview: https://github.com/openai/codex/blob/main/codex-rs/execpolicy/README.md

## Linux primitives

- Landlock userspace API: https://docs.kernel.org/userspace-api/landlock.html
- OverlayFS documentation: https://docs.kernel.org/filesystems/overlayfs.html
- `openat2(2)`: https://man7.org/linux/man-pages/man2/openat2.2.html
- `rename(2)` / `renameat2`: https://man7.org/linux/man-pages/man2/rename.2.html
- `open(2)` / `O_NOFOLLOW`: https://man7.org/linux/man-pages/man2/open.2.html

## Windows filesystem security

- File security and access rights: https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
- File access rights constants: https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants
- Reparse points: https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points
- Naming files, paths, and namespaces: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
- `CreateFile` semantics and flags: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
- `MoveFileEx`: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw

## Shell/platform behavior represented in replays

- PowerShell environment variables: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables
- PowerShell automatic variables: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables
- PowerShell `Remove-Item`: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item
- PowerShell redirection: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_redirection
- POSIX shell command language: https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html

## Version control

- Git worktree documentation: https://git-scm.com/docs/git-worktree
