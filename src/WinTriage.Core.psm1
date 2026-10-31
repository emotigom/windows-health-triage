#requires -Version 5.1
# Pure, read-only classification and aggregation. No operating system side effects.
function Get-WtEventFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Provider,
        [Parameter(Mandatory=$true)][int]$EventId
    )
    $p = $Provider.ToLowerInvariant().Trim()
    $category = 'general'
    $severity = 'review'
    $explanation = '이벤트 메시지, 시각, 재현 여부와 주변 기록을 함께 검토하세요.'

    if ($p -match '(^|[.\-])whea-logger$') {
        $category = 'hardware-signal'
        $severity = if ($EventId -in @(18,19,20,46,47)) { 'high' } else { 'review' }
        $explanation = 'WHEA 하드웨어 관련 이벤트입니다. CPU, RAM, PCIe, 펌웨어, 드라이버를 함께 검토하며 한 부품의 고장으로 단정하지 마세요.'
    } elseif ($p -match '(^|[.\-])(disk|ntfs|storahci|stornvme|iastor|iastora|iastorac)$') {
        $category = 'storage-signal'
        $severity = 'high'
        $explanation = '디스크, 저장장치 컨트롤러 또는 파일시스템 신호입니다. 중요한 데이터 백업 후 저장장치 상태 및 드라이버를 확인하세요.'
    } elseif ($p -match 'kernel-power$' -and $EventId -eq 41) {
        $category = 'unexpected-shutdown'
        $explanation = 'Windows가 정상 종료되지 않았다는 기록입니다. 전원장치 고장을 의미하지는 않습니다.'
    } elseif ($p -eq 'eventlog' -and $EventId -eq 6008) {
        $category = 'unexpected-shutdown'
        $explanation = '이전 종료가 예기치 않게 발생했습니다. 원인은 충돌 기록과 사용 당시 상황에서 찾아야 합니다.'
    } elseif ($p -match 'resource-exhaustion-detector$' -and $EventId -eq 2004) {
        $category = 'memory-pressure'
        $severity = 'high'
        $explanation = '시스템 자원 부족 기록입니다. 이벤트의 프로세스 정보, 커밋 사용량, 가상 메모리 상태를 확인하세요.'
    } elseif ($p -eq 'application error' -and $EventId -eq 1000) {
        $category = 'application-crash'
        $explanation = '응용프로그램 충돌입니다. 충돌한 앱과 모듈, 업데이트 및 반복 여부를 확인하세요.'
    } elseif ($p -eq 'application hang' -and $EventId -eq 1002) {
        $category = 'application-hang'
        $explanation = '응용프로그램 응답 중단입니다. CPU, I/O, 메모리, 외부 장치를 함께 확인하세요.'
    } elseif ($p -eq 'service control manager' -and $EventId -in @(7031,7034)) {
        $category = 'service-crash'
        $explanation = 'Windows 서비스가 예기치 않게 종료되었습니다. 서비스명, 종료 횟수 및 관련 앱을 확인하세요.'
    } elseif ($p -match 'kernel-eventtracing$' -and $EventId -eq 2) {
        $category = 'tracing-session'
        $severity = 'info'
        $explanation = 'ETW 세션 시작 실패입니다. 0xC0000035 여부를 이벤트 원문에서 확인하세요. 단독으로 하드웨어 결함을 뜻하지 않습니다.'
    } elseif ($p -match 'deviceassociationservice$' -and $EventId -eq 3509) {
        $category = 'device-pairing'
        $severity = 'info'
        $explanation = '장치 연결/페어링 실패 기록입니다. 실제 사용 중인 장치에 문제가 있는지 확인하세요.'
    } elseif ($p -eq 'display' -and $EventId -eq 4101) {
        $category = 'graphics-reset'
        $explanation = '그래픽 드라이버 응답 중단/복구 가능성입니다. GPU 드라이버, 부하, 온도, 하드웨어를 함께 점검하세요.'
    } elseif ($p -match 'windows-wereporting$' -and $EventId -eq 1001) {
        $category = 'windows-error-report'
        $explanation = 'Windows 오류 보고 이벤트입니다. 원문에서 오류 유형과 중지코드를 확인해야 합니다.'
    } elseif ($p -match 'windows defender$') {
        switch ($EventId) {
            1116 { $category='malware-detected'; $severity='high'; $explanation='Defender가 위협을 감지했습니다. 보호 기록의 처리 상태와 오탐 여부를 확인하세요.' }
            1117 { $category='malware-action'; $severity='review'; $explanation='Defender가 탐지 항목에 조치를 시도/수행한 기록입니다. 실제 처리 성공 여부를 보호 기록에서 확인하세요.' }
            1118 { $category='malware-action-failed'; $severity='high'; $explanation='Defender의 위협 처리 작업 실패 기록입니다. 보호 기록을 검토하세요.' }
            1119 { $category='malware-action'; $severity='review'; $explanation='Defender 처리 관련 기록입니다. 메시지와 보호 기록을 함께 확인하세요.' }
        }
    }
    [pscustomobject]@{
        Category=$category; Severity=$severity; Explanation=$explanation
    }
}

function Get-WtProcessGrowth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Samples,
        [AllowNull()][hashtable]$QualityInfo=$null
    )
    # A fixed, non-identifying count of rejected groups is optional; the
    # historical public return type remains growth rows only.
    if ($null -ne $QualityInfo) { $QualityInfo['RejectedGrowthGroups']=0 }
    # Fail closed per process identity: never join PID reuse, unreliable starts,
    # duplicate timestamps or a clock moving backwards into a growth estimate.
    # Only UTC ISO8601 timestamps emitted by Get-WtProcesses are accepted.
    $utcPattern='^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$'
    $eligible=@($Samples | Where-Object {
        $null -ne $_ -and
        -not [string]::IsNullOrWhiteSpace([string]$_.InstanceKey)
    })
    $results = foreach ($g in @($eligible | Group-Object InstanceKey)) {
        $rows=@($g.Group)
        if ($rows.Count -lt 2) { continue }
        $trusted=$true
        $previousUtcTicks=[long]::MinValue
        foreach ($row in $rows) {
            $sampleText=[string]$row.SampleTimeUtc
            $startText=[string]$row.StartedUtc
            $pidText=[string]$row.Pid
            $identityProperty=$row.PSObject.Properties['IdentityReliable']
            if ($null -eq $identityProperty -or
                $identityProperty.Value -isnot [bool] -or
                $identityProperty.Value -ne $true -or
                [string]::IsNullOrWhiteSpace($pidText) -or
                $startText -cnotmatch $utcPattern -or
                $sampleText -cnotmatch $utcPattern -or
                [string]$row.InstanceKey -cne ('{0}|{1}' -f $pidText,$startText)) {
                $trusted=$false
                break
            }
            $sampleTime=[datetimeoffset]::MinValue
            $startTime=[datetimeoffset]::MinValue
            if (-not [datetimeoffset]::TryParse($sampleText,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::None,[ref]$sampleTime) -or
                -not [datetimeoffset]::TryParse($startText,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::None,[ref]$startTime)) {
                $trusted=$false
                break
            }
            $ticks=$sampleTime.UtcDateTime.Ticks
            if ($ticks -le $previousUtcTicks -or
                $startTime.UtcDateTime.Ticks -gt $ticks) {
                $trusted=$false
                break
            }
            $previousUtcTicks=$ticks
        }
        if (-not $trusted) {
            if ($null -ne $QualityInfo) { $QualityInfo['RejectedGrowthGroups']++ }
            continue
        }
        # Preserve actual capture order; sorting untrusted timestamps would
        # conceal a backward clock jump and invent a growth interval.
        $first=$rows[0]; $last=$rows[$rows.Count - 1]
        [pscustomobject]@{
            Name=$last.Name; Pid=$last.Pid; Samples=$rows.Count
            FirstUtc=$first.SampleTimeUtc; LastUtc=$last.SampleTimeUtc
            FirstPrivateMiB=[math]::Round([double]$first.PrivateMiB,1)
            LastPrivateMiB=[math]::Round([double]$last.PrivateMiB,1)
            PrivateGrowthMiB=[math]::Round(([double]$last.PrivateMiB - [double]$first.PrivateMiB),1)
            FirstWorkingSetMiB=[math]::Round([double]$first.WorkingSetMiB,1)
            LastWorkingSetMiB=[math]::Round([double]$last.WorkingSetMiB,1)
            WorkingSetGrowthMiB=[math]::Round(([double]$last.WorkingSetMiB - [double]$first.WorkingSetMiB),1)
        }
    }
    @($results | Sort-Object PrivateGrowthMiB -Descending)
}

function Get-WtEventSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Events)
    $result = foreach ($group in @($Events | Group-Object Provider, EventId)) {
        $ordered = @($group.Group | Sort-Object TimeUtc)
        if ($ordered.Count -eq 0) { continue }
        $first=$ordered[0]; $last=$ordered[$ordered.Count-1]
        [pscustomobject]@{
            Provider=$last.Provider; EventId=$last.EventId
            Category=$last.Category; Severity=$last.Severity
            Count=$ordered.Count; FirstUtc=$first.TimeUtc; LastUtc=$last.TimeUtc
            Interpretation=$last.Interpretation
        }
    }
    @($result | Sort-Object Count -Descending)
}

function Get-WtTriageAdvice {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Events)
    $adviceByCategory=@{
        'storage-signal'='중요 데이터부터 백업하고 드라이브 제조사 진단 도구, 케이블/컨트롤러, SMART 상세 값을 확인하세요. 재시도·재부팅만 반복하지 마세요.'
        'hardware-signal'='WHEA 이벤트 시간·ID와 장치 경로를 비교하세요. 오버클럭/온도/펌웨어/PCIe/RAM 등을 교차 검사하며 부품 고장으로 바로 확정하지 마세요.'
        'memory-pressure'='동일 시각 상위 프로세스와 전체 커밋 사용량을 비교하세요. 가상 메모리 설정과 앱 부하, 누수 가능성을 조사하세요.'
        'application-crash'='반복 충돌한 앱/모듈을 먼저 확인하고 업데이트·재설치 여부를 검토하세요. 운영체제 손상 가능성은 필요할 때 sfc /verifyonly로 별도 확인하세요.'
        'application-hang'='멈춤이 반복되는 앱을 식별하고 디스크 I/O, 네트워크, 메모리 압박 및 외부 장치와의 상관관계를 확인하세요.'
        'service-crash'='종료된 서비스명과 같은 시각의 Application 오류를 확인하세요. 관련 앱/서비스 업데이트 후 재발 여부를 추적하세요.'
        'unexpected-shutdown'='종료 직전의 WHEA, BugCheck, 저장장치 이벤트와 실제 전원 차단 여부를 확인하세요. 이 이벤트만으로 PSU 불량이라 판단하지 마세요.'
        'malware-detected'='Windows 보안 > 보호 기록에서 탐지 경로·조치 결과·오탐 여부를 확인하세요. 의심 파일을 직접 열지 마세요.'
        'malware-action-failed'='Defender 보호 기록에서 실패 이유를 확인하고 보안 업데이트·재검사를 검토하세요.'
        'graphics-reset'='그래픽 드라이버, 고부하, 발열, 전원 관련 로그를 비교하고 재현 상황을 기록하세요.'
        'tracing-session'='실제 프로그램 장애가 없고 단독 ETW 중복 이름 오류라면 우선 기록만 추적하세요. 0xC0000035는 상세 메시지에서 확인하세요.'
        'device-pairing'='문제가 있는 실제 장치가 있는지 먼저 확인하고 필요 시 장치 관리자에서 해당 장치 연결·드라이버 상태를 검토하세요.'
    }
    $advice=foreach ($g in @($Events | Group-Object Category)) {
        if (-not $adviceByCategory.ContainsKey($g.Name)) { continue }
        $priority=if (@($g.Group | Where-Object { $_.Severity -eq 'high' }).Count -gt 0) { 'high' } else { 'review' }
        [pscustomobject]@{
            Category=$g.Name; Priority=$priority; EventCount=$g.Count
            Action=$adviceByCategory[$g.Name]
            Confidence='hypothesis-only'
        }
    }
    @($advice | Sort-Object @{Expression={if ($_.Priority -eq 'high') { 0 } else { 1 }}}, @{Expression='EventCount';Descending=$true})
}


# Read-only storage signals; unknown data is explicitly inconclusive.
function Get-WtStorageAssessment {
    [CmdletBinding()]
    param(
        [string]$HealthStatus,
        [string]$OperationalStatus,
        [AllowNull()][object]$Counters,
        [bool]$CountersAvailable = $false
    )
    $evidence=New-Object 'System.Collections.Generic.List[string]'
    $state='inconclusive'
    $health=[string]$HealthStatus
    $operational=[string]$OperationalStatus
    if ($health -match '^(Warning|Unhealthy)$') {
        $state='attention'; $evidence.Add("storage provider HealthStatus=$health")
    } elseif ($health -eq 'Healthy') {
        $evidence.Add('Storage provider reports Healthy (limited provider signal, not a full SMART test)')
    } else {
        $evidence.Add('Storage provider health is missing/unknown')
    }
    $operationalStates=@($operational -split ',\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    # Provider status 'Unknown' is missing evidence, NOT a warning and NOT healthy.
    $uninformativeStates=@('Unknown','Not Available','Unspecified','')
    $safeStates=@('OK','In Service','Online')
    $unexpectedStates=@($operationalStates | Where-Object {
        $_ -notin $safeStates -and $_ -notin $uninformativeStates
    })
    if ($unexpectedStates.Count -gt 0) {
        $state='attention'; $evidence.Add("Storage provider OperationalStatus=$operational")
    } elseif (@($operationalStates | Where-Object { $_ -in $uninformativeStates }).Count -gt 0 -or
              $operationalStates.Count -eq 0) {
        $evidence.Add('Storage provider operational status is missing/unknown')
    }
    if (-not $CountersAvailable -or $null -eq $Counters) {
        $evidence.Add('Reliability counters unavailable; no inference of health')
    } else {
        foreach ($name in @('ReadErrorsUncorrected','WriteErrorsUncorrected')) {
            $property=$Counters.PSObject.Properties[$name]
            if ($null -eq $property -or $null -eq $property.Value -or [string]$property.Value -eq '') { continue }
            $value=0L
            if ([long]::TryParse([string]$property.Value,[ref]$value) -and $value -gt 0) {
                $state='attention'; $evidence.Add("$name=$value (verify raw vendor data, back up important files)")
            }
        }
    }
    [pscustomobject]@{ Assessment=$state; Evidence=@($evidence.ToArray()) }
}

Export-ModuleMember -Function Get-WtEventFinding,Get-WtProcessGrowth,Get-WtEventSummary,Get-WtTriageAdvice,Get-WtStorageAssessment
