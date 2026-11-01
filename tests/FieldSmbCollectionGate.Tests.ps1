#requires -Version 5.1
# ADR-065: invented SMB states and a deliberately invalid path; no real share enumeration.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'tools\WinTriage.FieldSmbPreflight.psm1') -Force
function Assert-GateFixture([bool]$Condition,[string]$Label) {
    if (-not $Condition) { throw ('Synthetic SMB field guard regression: '+$Label) }
}
$fixed='SMB field collection guard blocked or inconclusive; review storage privately.'
foreach ($state in @('BROAD_ACCESS_REVIEW','SHARED_REVIEW','UNKNOWN','NOT_CHECKED')) {
    $blocked=$false
    try {
        Assert-WtFieldSmbCollectionGate -PathState 'REVIEW_REQUIRED' -SmbExposure $state
    } catch {
        $blocked=($_.Exception.Message -eq $fixed)
    }
    Assert-GateFixture $blocked ('unsafe SMB state must block: '+$state)
}
foreach ($pathState in @('REJECTED','UNKNOWN')) {
    $blocked=$false
    try {
        Assert-WtFieldSmbCollectionGate -PathState $pathState -SmbExposure 'NO_NON_SPECIAL_SHARE_OBSERVED'
    } catch { $blocked=($_.Exception.Message -eq $fixed) }
    Assert-GateFixture $blocked ('bad path cannot be cleared by empty ordinary share set: '+$pathState)
}
# Invented providers, including an unavailable SMB service and administrative share.
$fictionalPath='C:\FICTIVE_COLLECTION\REPORTS'
$empty=Get-WtFieldSmbExposure -Directory $fictionalPath -PathState 'REVIEW_REQUIRED' -ShareProvider { @() } -AccessProvider { throw 'MUST_NOT_ENUMERATE_ACCESS' }
Assert-GateFixture ($empty -eq 'NO_NON_SPECIAL_SHARE_OBSERVED') 'empty ordinary share inventory is a narrow observation'
Assert-GateFixture ($null -eq (Assert-WtFieldSmbCollectionGate -PathState 'REVIEW_REQUIRED' -SmbExposure $empty)) 'narrow no-extra-SMB-block result is silent, not approval'
$unavailable=Get-WtFieldSmbExposure -Directory $fictionalPath -PathState 'REVIEW_REQUIRED' -ShareProvider { throw 'FICTIVE_UNAVAILABLE_PROVIDER_PRIVATE_CANARY' } -AccessProvider { throw 'MUST_NOT_ACCESS' }
Assert-GateFixture ($unavailable -eq 'UNKNOWN') 'service absent or access denied is unknown'
$blocked=$false
try { Assert-WtFieldSmbCollectionGate -PathState 'REVIEW_REQUIRED' -SmbExposure $unavailable } catch { $blocked=($_.Exception.Message -eq $fixed) }
Assert-GateFixture $blocked 'unavailable provider must block'
$special=Get-WtFieldSmbExposure -Directory $fictionalPath -PathState 'REVIEW_REQUIRED' -ShareProvider {
    [pscustomobject]@{Path='C:\';Name='FICTIVE_ADMIN$';Special=$true}
} -AccessProvider {
    param($share)
    [pscustomobject]@{AccountName='S-1-5-32-544';AccessControlType='Allow';AccessRight='Full'}
}
Assert-GateFixture ($special -eq 'SHARED_REVIEW') 'if special share leaks through provider it cannot be cleared'
# The opt-in command must refuse an invented relative path before any collection.
# No SMB provider is called for a rejected path; no output directory is created.
$exe=if ($PSVersionTable.PSEdition -eq 'Desktop') { Join-Path $PSHOME 'powershell.exe' } else { Join-Path $PSHOME 'pwsh.exe' }
$PSNativeCommandUseErrorActionPreference=$false
$previousPreference=$ErrorActionPreference
try {
    # A failing child emits PowerShell error-stream objects on Windows PS 5.1;
    # capture them without allowing the parent test's Stop policy to terminate.
    $ErrorActionPreference='Continue'
    $lines=@(& $exe -NoProfile -NonInteractive -File (Join-Path $root 'Invoke-WtFieldValidation.ps1') -OutputDir 'relative\FICTIONAL_PRIVATE_CANARY' -RequireSmbPreflight 2>&1 | Out-String)
    $code=$LASTEXITCODE
} finally {
    $ErrorActionPreference=$previousPreference
}
Assert-GateFixture ($code -eq 2) 'invalid opt-in collection must return fixed exit 2'
$output=($lines -join [Environment]::NewLine)
Assert-GateFixture ($output.Trim() -eq 'SmbCollectionGate: BLOCKED_OR_UNKNOWN') 'early rejection emits exactly one fixed line and no environment banner'
Assert-GateFixture (-not $output.Contains($fixed)) 'internal exception message must not escape top-level guard'
Assert-GateFixture (-not $output.Contains('relative\FICTIONAL_PRIVATE_CANARY')) 'caller path must not be echoed'
Assert-GateFixture (-not $output.Contains('.psm1:')) 'PowerShell module path and stack must not appear'
Assert-GateFixture (-not $output.Contains('At ')) 'unhandled exception source line must not appear'
# Test a missing optional SMB module from a disposable SYNTHETIC clone.
# Copy only script/module sources, never reports, logs, SMB state or system ACL.
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('WtGuardSynthetic_'+[guid]::NewGuid().ToString('N'))
try {
    [void][IO.Directory]::CreateDirectory((Join-Path $fixture 'tools'))
    Copy-Item -LiteralPath (Join-Path $root 'Invoke-WtFieldValidation.ps1') -Destination $fixture
    # No src/test collectors are copied: the missing optional guard must be
    # detected BEFORE generic collector imports can even run.
    Copy-Item -LiteralPath (Join-Path $root 'tools\WinTriage.FieldPreflight.psm1') -Destination (Join-Path $fixture 'tools')
    # Intentionally do NOT copy WinTriage.FieldSmbPreflight.psm1.
    $previousPreference=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $loaderLines=@(& $exe -NoProfile -NonInteractive -File (Join-Path $fixture 'Invoke-WtFieldValidation.ps1') -OutputDir 'relative\FICTIONAL_IMPORT_CANARY' -RequireSmbPreflight 2>&1 | Out-String)
        $loaderExit=$LASTEXITCODE
    } finally {
        $ErrorActionPreference=$previousPreference
    }
    Assert-GateFixture ($loaderExit -eq 2) 'missing optional module exits 2'
    Assert-GateFixture ((($loaderLines -join [Environment]::NewLine).Trim()) -eq 'SmbCollectionGate: BLOCKED_OR_UNKNOWN') 'missing optional module has no PowerShell loader path or exception text'
} finally {
    # Only the disposable, test-created synthetic checkout is removed.
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
# Test-owned mocked checkout only: these modules are fabricated, not live SMB.
# The real module's state policy is already covered by the earlier fixtures.
function Invoke-SyntheticGuardStage {
    param([bool]$ProvideCollectorModules,[bool]$LateBroad,[string]$FaultCase='')
    $synthetic=Join-Path ([IO.Path]::GetTempPath()) ('WtSmbRaceSynthetic_'+[guid]::NewGuid().ToString('N'))
    try {
        [void][IO.Directory]::CreateDirectory((Join-Path $synthetic 'tools'))
        Copy-Item -LiteralPath (Join-Path $root 'Invoke-WtFieldValidation.ps1') -Destination $synthetic
        $fakePath=@'
function Get-WtFieldPreflightPathState {
    [CmdletBinding()]
    param([string]$Directory)
    __PATH_RESPONSE__
}
Export-ModuleMember -Function Get-WtFieldPreflightPathState
'@
        $pathResponse=switch ($FaultCase) {
            'PathCase' { "return 'review_required'" }
            'PathCoerced' { "$"+'obj=[pscustomobject]@{Fictional=1}; $obj | Add-Member -MemberType ScriptMethod -Name ToString -Value { return '+ "'REVIEW_REQUIRED'"+' } -Force; return $obj' }
            'PathError' { "Write-Error 'FICTIONAL_PRIVATE_PATH_ERROR' -ErrorAction Continue; return 'REVIEW_REQUIRED'" }
            'PathExtra' { "Write-Output 'REVIEW_REQUIRED'; return 'REVIEW_REQUIRED'" }
            default { "return 'REVIEW_REQUIRED'" }
        }
        $fakePath=$fakePath.Replace('__PATH_RESPONSE__',$pathResponse)
        Set-Content -LiteralPath (Join-Path $synthetic 'tools\WinTriage.FieldPreflight.psm1') -Value $fakePath -Encoding UTF8
        $fakeSmb=@'
$script:ProbeCount=0
function Get-WtFieldSmbExposure {
    [CmdletBinding()]
    param([string]$Directory,[string]$PathState)
    $script:ProbeCount++
    __RISK_CONDITION__
    __SMB_RESPONSE__
}
function Assert-WtFieldSmbCollectionGate {
    [CmdletBinding()]
    param([string]$PathState,[string]$SmbExposure)
    if ($PathState -ne 'REVIEW_REQUIRED' -or $SmbExposure -ne 'NO_NON_SPECIAL_SHARE_OBSERVED') {
        throw 'FICTIONAL_PRIVATE_RISK_CANARY'
    }
    __POLICY_RESPONSE__
}
Export-ModuleMember -Function Get-WtFieldSmbExposure,Assert-WtFieldSmbCollectionGate
'@
        $condition=if ($LateBroad) {
            "if ("+'$script:ProbeCount'+" -ge 3) { return 'SHARED_REVIEW' }"
        } else { '# all synthetic samples are narrow' }
        $fakeSmb=$fakeSmb.Replace('__RISK_CONDITION__',$condition)
        $smbResponse=switch ($FaultCase) {
            'SmbCase' { "return 'no_non_special_share_observed'" }
            'SmbCoerced' { "$"+'obj=[pscustomobject]@{Fictional=2}; $obj | Add-Member -MemberType ScriptMethod -Name ToString -Value { return '+ "'NO_NON_SPECIAL_SHARE_OBSERVED'"+' } -Force; return $obj' }
            'SmbError' { "Write-Error 'FICTIONAL_PRIVATE_SMB_ERROR' -ErrorAction Continue; return 'NO_NON_SPECIAL_SHARE_OBSERVED'" }
            'SmbExtra' { "Write-Output 'NO_NON_SPECIAL_SHARE_OBSERVED'; return 'NO_NON_SPECIAL_SHARE_OBSERVED'" }
            default { "return 'NO_NON_SPECIAL_SHARE_OBSERVED'" }
        }
        $policyResponse=switch ($FaultCase) {
            'PolicyError' { "Write-Error 'FICTIONAL_PRIVATE_POLICY_ERROR' -ErrorAction Continue" }
            'PolicyOutput' { "return 'FICTIONAL_POLICY_OUTPUT_CANARY'" }
            default { '# empty policy result required' }
        }
        $fakeSmb=$fakeSmb.Replace('__SMB_RESPONSE__',$smbResponse).Replace('__POLICY_RESPONSE__',$policyResponse)
        Set-Content -LiteralPath (Join-Path $synthetic 'tools\WinTriage.FieldSmbPreflight.psm1') -Value $fakeSmb -Encoding UTF8
        if ($ProvideCollectorModules) {
            [void][IO.Directory]::CreateDirectory((Join-Path $synthetic 'src'))
            [void][IO.Directory]::CreateDirectory((Join-Path $synthetic 'tests'))
            foreach ($module in @('WinTriage.ReportSecurity.psm1','WinTriage.FieldValidation.psm1')) {
                Set-Content -LiteralPath (Join-Path $synthetic ('src\'+$module)) -Value '# Synthetic stub: no real collection' -Encoding UTF8
            }
            Set-Content -LiteralPath (Join-Path $synthetic 'src\WinTriage.IntegrityCollector.psm1') -Value @'
function Test-WtAdministrator { return $false }
Export-ModuleMember -Function Test-WtAdministrator
'@ -Encoding UTF8
            Set-Content -LiteralPath (Join-Path $synthetic 'tests\ReportContract.psm1') -Value '# Synthetic contract stub' -Encoding UTF8
            # If called, an unexpected collector execution MUST be detected.
            Set-Content -LiteralPath (Join-Path $synthetic 'WinTriage.ps1') -Value "throw 'FICTIONAL_COLLECTOR_MUST_NOT_RUN'" -Encoding UTF8
        }
        $prior=$ErrorActionPreference
        try {
            $ErrorActionPreference='Continue'
            $resultLines=@(& $exe -NoProfile -NonInteractive -File (Join-Path $synthetic 'Invoke-WtFieldValidation.ps1') -OutputDir 'relative\FICTIONAL_SMB_RACE_CANARY' -RequireSmbPreflight 2>&1 | Out-String)
            $resultExit=$LASTEXITCODE
        } finally { $ErrorActionPreference=$prior }
        Assert-GateFixture ($resultExit -eq 2) ('fake collection-stage failure exits 2: '+$FaultCase)
        Assert-GateFixture ((($resultLines -join [Environment]::NewLine).Trim()) -eq 'SmbCollectionGate: BLOCKED_OR_UNKNOWN') 'stage failure must emit only fixed one-line denial'
    } finally {
        # Only the synthetic, test-created disposable checkout is removed.
        if (Test-Path -LiteralPath $synthetic) { Remove-Item -LiteralPath $synthetic -Recurse -Force }
    }
}
Invoke-SyntheticGuardStage -ProvideCollectorModules:$false -LateBroad:$false
Invoke-SyntheticGuardStage -ProvideCollectorModules:$true -LateBroad:$true
# The mock collector throws if reached; every unexpected provider/policy
# stream, object coercion or noncanonical enum must fail before collection.
foreach ($fault in @('PathCase','PathCoerced','PathError','PathExtra',
                      'SmbCase','SmbCoerced','SmbError','SmbExtra',
                      'PolicyError','PolicyOutput')) {
    Invoke-SyntheticGuardStage -ProvideCollectorModules:$true -LateBroad:$false -FaultCase $fault
}
$global:LASTEXITCODE=0
Write-Host 'PASS: fictional strict SMB provider and policy contract, no-error/no-output fail-closed'

