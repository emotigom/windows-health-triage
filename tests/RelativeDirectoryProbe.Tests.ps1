#requires -Version 5.1
# ADR-023 research ONLY: synthetic directories under a random test-owned temp root.
# Never run against an existing user report; no scanner, repair or upload.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows required for native directory probe.' }
Add-Type -Path (Join-Path $PSScriptRoot 'RelativeDirectoryProbe.cs') -ErrorAction Stop

function Assert-Probe {
    param([bool]$Condition,[string]$Label)
    if (-not $Condition) { throw ('Relative directory probe failed: '+$Label) }
}
function Expect-InvalidLeaf {
    param([Microsoft.Win32.SafeHandles.SafeFileHandle]$Parent,[string]$Leaf)
    $rejected=$false
    try { [void][WinTriageTests.RelativeDirectoryProbe]::IdentifyChildRelative($Parent,$Leaf) }
    catch [System.ArgumentException] { $rejected=$true }
    Assert-Probe $rejected 'invalid synthetic child name was accepted'
}

$fixture=Join-Path ([System.IO.Path]::GetTempPath()) ('wt-relative-probe-' + [guid]::NewGuid().ToString('N'))
$parent=Join-Path $fixture 'parent'
$child=Join-Path $parent 'child'
$movedParent=Join-Path $fixture 'parent-moved'
$handle=$null
$wasMoved=$false
$decoyCreated=$false
try {
    [void][System.IO.Directory]::CreateDirectory($child)
    $original=[WinTriageTests.RelativeDirectoryProbe]::IdentifyTestDirectory($child)
    $handle=[WinTriageTests.RelativeDirectoryProbe]::PinTestParent($parent)
    foreach ($bad in @('..','.', '..\child','C:\unsafe','child:stream','child ','child.')) {
        Expect-InvalidLeaf -Parent $handle -Leaf $bad
    }

    $relativeSupported=$false
    try {
        $before=[WinTriageTests.RelativeDirectoryProbe]::IdentifyChildRelative($handle,'child')
        Assert-Probe ($before -eq $original) 'parent-relative identity differs before a swap'
        $relativeSupported=$true
    } catch [System.IO.IOException] {
        Write-Host 'SKIP: exact directory NtCreateFile options not accepted by this Windows runner'
    }

    try { [System.IO.Directory]::Move($parent,$movedParent);$wasMoved=$true }
    catch [System.IO.IOException] {
        Write-Host 'SKIP: Windows runner refused to rename the test-owned pinned parent'
    }
    if ($wasMoved) {
        # Replace only a test-owned name with a different test-owned child.
        [void][System.IO.Directory]::CreateDirectory($child)
        $decoyCreated=$true
        $decoy=[WinTriageTests.RelativeDirectoryProbe]::IdentifyTestDirectory($child)
        Assert-Probe ($decoy -ne $original) 'decoy identity did not change'
        if ($relativeSupported) {
            $opened=$false
            try {
                $result=[WinTriageTests.RelativeDirectoryProbe]::IdentifyChildRelative($handle,'child')
                $opened=$true
                Assert-Probe ($result -eq $original) 'native relative lookup resolved to the decoy'
            } catch [System.IO.IOException] {
                Write-Host 'INFO: native relative lookup refused after synthetic rename'
            }
            if ($opened) { Write-Host 'INFO: native relative lookup kept original synthetic child identity' }
        }
    }

    Write-Host 'PASS: synthetic parent-handle directory probe; no production API or filesystem behavior changed'
} finally {
    if ($null -ne $handle) { $handle.Dispose() }
    if ($decoyCreated) {
        # Non-recursive: the decoy contains only an empty child created by this test.
        [System.IO.Directory]::Delete($child)
        [System.IO.Directory]::Delete($parent)
    }
    if ($wasMoved) { [System.IO.Directory]::Move($movedParent,$parent) }
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
