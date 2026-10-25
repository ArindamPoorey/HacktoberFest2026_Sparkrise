<#
.SYNOPSIS
    Permission Fence agent-friendly PowerShell wrapper (PRD Section 11).
.DESCRIPTION
    Routes a proposed PowerShell command and user intent through Permission Fence (`python -m app.main`).
    By default runs in safe check mode unless -Execute is specified.
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Command,

    [Parameter(Mandatory=$false)]
    [string]$Intent = "",

    [Parameter(Mandatory=$false)]
    [string]$WorkingDirectory = (Get-Location).Path,

    [Parameter(Mandatory=$false)]
    [string]$AgentName = "powershell-hook",

    [Parameter(Mandatory=$false)]
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
$SubCommand = if ($Execute) { "run" } else { "check" }

$ArgsList = @(
    "-m", "app.main",
    $SubCommand,
    "--shell", "powershell",
    "--command", $Command,
    "--cwd", $WorkingDirectory,
    "--source", "agent-hook",
    "--agent", $AgentName
)

if ($Intent -ne "") {
    $ArgsList += @("--intent", $Intent)
}

& python @ArgsList
exit $LASTEXITCODE
