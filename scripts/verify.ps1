$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Push-Location $Root
try {
    $env:PYTHONPATH = Join-Path $Root 'src'
    python scripts/verify_manifest.py
    python -m compileall -q src tests scripts
    python -m unittest discover -s tests -v
    python scripts/run_replay.py
    python -m agent_workspace_guard --help | Out-Null
    Write-Host "`nVerification complete."
}
finally {
    Pop-Location
}
