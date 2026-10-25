<#
.SYNOPSIS
    One-command GitHub push helper for Permission Fence.
.DESCRIPTION
    Configures your GitHub remote URL and pushes all structured feature commits to main.
    Never stores your GitHub Personal Access Token (PAT) in repository files.
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$RepoUrl,

    [Parameter(Mandatory=$false)]
    [string]$Branch = "main"
)

$ErrorActionPreference = "Stop"

if (git remote | Select-String -Pattern "^origin$") {
    git remote set-url origin $RepoUrl
} else {
    git remote add origin $RepoUrl
}

git branch -M $Branch
Write-Host "Pushing Permission Fence commits to $RepoUrl ($Branch)..." -ForegroundColor Cyan
git push -u origin $Branch
Write-Host "Successfully pushed to GitHub!" -ForegroundColor Green
