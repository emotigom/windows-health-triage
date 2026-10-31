#requires -Version 5.1
<#
.SYNOPSIS
    Upload the initial reviewed project to an existing, empty GitHub repository.
.DESCRIPTION
    This helper never force-pushes, never overwrites a nonempty remote, and
    verifies the currently authenticated GitHub user matches the owner.
    Prefer GitHub PRs after initial bootstrap.
#>
[CmdletBinding()]
param([string]$Repository = 'emotigom/windows-health-triage')
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'Git is required.' }
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'GitHub CLI is required.' }
& gh auth status 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Run gh auth login first.' }
$activeLogin=[string](& gh api user --jq .login)
if ($LASTEXITCODE -ne 0 -or $activeLogin.Trim() -ne ($Repository.Split('/')[0])) {
    throw 'The active GitHub CLI identity does not match the destination owner.'
}
& gh repo view $Repository --json nameWithOwner --jq .nameWithOwner | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'The remote repository does not exist. Create it before uploading.' }
$remoteHeads=@(& git ls-remote --heads "https://github.com/$Repository.git")
if ($LASTEXITCODE -ne 0) { throw 'Unable to check existing remote branches.' }
if ($remoteHeads.Count -gt 0) {
    throw 'Remote already has commits. STOP: use git clone + a reviewed PR. Never overwrite a nonempty main.'
}
Push-Location $PSScriptRoot
try {
    if (-not (Test-Path -LiteralPath .git)) {
        & git init -b main
        if ($LASTEXITCODE -ne 0) { throw 'git init failed' }
    }
    & git add -- .
    if ($LASTEXITCODE -ne 0) { throw 'git add failed' }
    & git diff --cached --quiet
    if ($LASTEXITCODE -ne 0) {
        & git commit -m 'Bootstrap Windows Health Triage (experimental)'
        if ($LASTEXITCODE -ne 0) { throw 'git commit failed; check git user.name and user.email' }
    }
    $remotes=@(& git remote)
    if ($remotes -contains 'origin') {
        $url=[string](& git remote get-url origin)
        if ($url -notin @("https://github.com/$Repository.git", "git@github.com:$Repository.git")) {
            throw "Unexpected origin URL: $url"
        }
    } else {
        & git remote add origin "https://github.com/$Repository.git"
        if ($LASTEXITCODE -ne 0) { throw 'git remote add failed' }
    }
    & git push -u origin main
    if ($LASTEXITCODE -ne 0) { throw 'Push failed. No force push attempted.' }
    Write-Host "Uploaded: https://github.com/$Repository"
} finally { Pop-Location }
