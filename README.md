# Windows Health Triage (윈도우 진단 도구)

**관리자가 필요할 때 PowerShell에서 실행하는 로컬 진단 도구의 개선 버전 (v0.3.0, Windows 현장 검증 전).**
바이러스/악성코드 징후, 메모리 사용량 증가, Windows 이벤트 로그, 하드웨어 오류 단서를 **모으고 분류**합니다.

> ⚠️ 이 도구는 전문 백신, 메모리 프로파일러 또는 하드웨어 검사기를 대체하지 않습니다. 기본 모드는 읽기 전용입니다. `-RunDefenderQuickScan`을 명시적으로 사용하면 Microsoft Defender가 자체 정책에 따라 악성 항목을 격리/처리할 수 있습니다. ClamAV 연동은 **탐지 전용**이며 삭제나 격리를 실행하지 않습니다.

## 준비 환경

- Windows 10/11, Windows PowerShell 5.1 또는 PowerShell 7
- 기본 진단: 내장 `Get-Process`, `Get-WinEvent`, CIM, Windows Defender cmdlet(설치 시) 사용
- 선택적 오픈소스 악성코드 검사: [ClamAV 공식 Windows 빌드](https://docs.clamav.net/manual/Installing.html) (GPLv2, 별도 설치)
- 원칙: **이 저장소의 코드는 MIT 라이선스**. Windows 시스템 API와 Defender는 Windows에 내장된 도구로, 오픈소스라고 주장하지 않습니다.

## GitHub 저장소 만들기 (1회)

연결된 GitHub 계정은 `emotigom`입니다. **이 배포 파일만으로 원격 저장소가 자동 생성되는 것은 아닙니다.** ZIP을 압축 해제한 폴더에서 `git`/`gh`를 설치하고, GitHub CLI로 인증한 다음 **본인이 직접** 실행합니다. 기본값은 비공개 저장소입니다. `gh`에 여러 계정이 연결되어 있으면 **현재 활성 계정이 emotigom인지 검사하고**, 다르면 업로드를 중단합니다.

```powershell
# ZIP 압축 해제한 프로젝트 폴더에서 실행
gh auth login
.\Publish-GitHub.ps1
# 공개 프로젝트로 시작하려는 경우에만: .\Publish-GitHub.ps1 -Public
```

새 저장소가 만들어지고 현재 코드가 `main`으로 push됩니다. 저장소가 이미 존재하면 자동으로 덮어쓰지 않고 오류를 냅니다.

## 빠른 시작

PowerShell을 열어 아래 명령을 실행합니다. 처음에는 **관리자 권한 없이** 시작해도 됩니다. 일부 이벤트/디스크/Defender 조회는 권한에 따라 생략되며 경고로 남습니다.

```powershell
# GitHub에 저장소를 생성하고 업로드한 뒤:
git clone https://github.com/emotigom/windows-health-triage.git
cd windows-health-triage

# 기본: 최근 48시간의 주요 오류, 프로세스, 시스템/보안/하드웨어 단서
.\WinTriage.ps1 -Mode Quick

# 메모리 사용량 증가 추적: 10초 간격 x 12회(총 110초)
.\WinTriage.ps1 -Mode Monitor -Samples 12 -IntervalSeconds 10

# 이벤트 로그만 상세 수집 (최근 72시간)
.\WinTriage.ps1 -Mode Events -EventHours 72

# 보안 상태 및 최근 위협 기록 확인 (스캔은 실행 안 함)
.\WinTriage.ps1 -Mode Security

# 하드웨어 + 저장장치 제공 상태/신뢰성 카운터 단서 수집
.\WinTriage.ps1 -Mode Hardware

# Windows 파일/구성요소 무결성 검사 가능 여부 확인 (기본은 외부 검사 실행 없음)
.\WinTriage.ps1 -Mode Integrity

# 관리자 PowerShell에서만 명시적으로 실행 (오래 걸릴 수 있음, 복구하지 않음)
.\WinTriage.ps1 -Mode Integrity -RunSfcVerifyOnly
.\WinTriage.ps1 -Mode Integrity -RunDismScanHealth

# 두 검사를 모두 실행하려면
.\WinTriage.ps1 -Mode Integrity -RunSfcVerifyOnly -RunDismScanHealth

# Windows Defender 빠른 검사 실행 - 명시적 선택, 보호 정책에 따른 격리 가능
.\WinTriage.ps1 -Mode Security -RunDefenderQuickScan

# ClamAV 설치+서명 업데이트를 완료한 경우, 특정 폴더만 탐지 검사
.\WinTriage.ps1 -Mode Security -RunClamAV -ScanPath "$env:USERPROFILE\Downloads"

# 공식 ZIP 형태 ClamAV와 같이 쓰는 경우: 실행 파일 경로 명시
.\WinTriage.ps1 -Mode Security -RunClamAV -ScanPath "$env:USERPROFILE\Downloads" -ClamAVExe 'C:\ClamAV\clamscan.exe'

# 전체 정보 수집(백신 검사 실행은 포함되지 않음)
.\WinTriage.ps1 -Mode Full
```

### Windows 10/11 실기기 검증 (사용자가 명시적으로 실행)

Windows PowerShell 또는 PowerShell 7에서 아래 명령을 실행하면 기본 읽기 전용 5개 모드를 가벼운 설정으로 검사합니다. 결과는 로컬의 별도 제한된 폴더에 남으며 **자동 삭제·스캔·업로드는 없습니다.** 콘솔에는 컴퓨터 이름이나 원본 이벤트 대신 고정 상태값만 표시하지만 Windows 빌드·PowerShell 버전·관리자 여부는 공개되므로 공유 전에 검토하세요. 구조 검사 PASS는 PC 정상 판정이 아닙니다.

```powershell
.\Invoke-WtFieldValidation.ps1
```

일반 권한과 관리자 권한에서 각각 수동 실행해 비교하세요. 회사 관리 PC에서는 먼저 보안 정책을 확인하세요. 세부 절차: [실기기 검증 프로토콜](docs/FIELD-VALIDATION.md).

새 보고서 작성 중에는 Windows 디렉터리 핸들과 파일 식별자를 유지해 쓰기 시점마다 경로 변경 여부를 확인합니다. 다만 Windows에서 열린 폴더도 이름 변경이 가능해, 검사 직후 파일을 열기 전의 경쟁 조건까지 막지는 못합니다. 권한 또는 경로 식별이 불확실한 경우 데이터 수집을 중단하며, 특권 프로세스에 대한 완전한 방어·암호화는 보장하지 않습니다. 자세한 제약은 [개인정보 보호 정책](docs/PRIVACY.md)에 설명되어 있습니다.

핵심 진단 출력(JSON·CSV·SUMMARY·manifest)은 이제 **검증한 보고서 폴더의 열린 핸들을 기준으로 새 파일만 생성**합니다. 기존 파일의 덮어쓰기를 거부하며 임의 경로나 파일명은 허용하지 않습니다. 선택적 ClamAV·SFC·DISM 명령의 텍스트 로그도 이제 명시적 실행 시 열린 보고서 핸들 기준으로 스트리밍 저장합니다. 안전한 로그 파일을 생성하지 못하면 해당 네이티브 명령은 시작하지 않습니다. 다만 초기 핸들 획득·외부 도구 자체 로그·사후 변조는 보호 범위 밖입니다.

### 로컬 보고서 보존 상태 조회 (명시적 실행, 삭제 없음)

진단 보고서가 쌓였는지 **파일 내용을 읽지 않고** 확인할 수 있습니다. 새 도구는 기존 로컬 폴더의 실행 횟수, 30일 경과 폴더 수, 검증된 보호 폴더의 직접 포함 파일 용량만 집계합니다. 경로·파일명·이벤트 메시지를 출력하지 않습니다. 결과에 `Incomplete=True`가 있으면 일부 자료를 접근 권한 문제나 집계 상한 등으로 확인하지 못한 것입니다.

```powershell
# 기본 진단 보고서 위치(로컬, 읽기 전용)
.\Get-WtReportRetention.ps1

# 실기기 검증에서 남긴 별도 보고서 위치
.\Get-WtReportRetention.ps1 -ReportRoot "$env:LOCALAPPDATA\WinTriage\field-validation" -OlderThanDays 14
```

어떤 파일도 **삭제·이동·수정·업로드하지 않습니다.** 오래된 폴더는 삭제 대상이 아니라 검토 대상일 뿐이며, 사용자가 별도로 판단해야 합니다. 폴더 생성 시각은 원래 진단 실행 날짜와 다를 수 있습니다. 세부 정책: [개인정보·보존](docs/PRIVACY.md).

### 메타설계 및 검증 상태

- [`docs/META-DESIGN.md`](docs/META-DESIGN.md): 신뢰 경계, 오류 허용, 정확도, 변경 절차 및 완료 기준
- [`docs/VALIDATION.md`](docs/VALIDATION.md): 테스트 매트릭스와 Windows 확인 방법
- [`CHANGELOG.md`](CHANGELOG.md): 버전별 변경 이력
- **중요:** Linux 파일 환경에서는 Windows 수집 API를 실행할 수 없으므로 Windows PowerShell 5.1/7 실제 검증이 남아 있습니다. 자동 검사·복구 기능이 정상 완료되었다고 주장하지 않습니다.

### 실행 정책 오류가 발생한다면

신뢰할 수 있는 코드를 **직접 확인**한 후에만 현재 PowerShell 프로세스 범위로 허용하세요. 시스템 전체 실행 정책을 바꾸지 않습니다.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\WinTriage.ps1 -Mode Quick
```

## 수집 항목과 한계

| 모드 | 결과 | 해석 시 주의 |
| --- | --- | --- |
| `Quick` | 현재 프로세스 메모리, 오류/경고 이벤트, Defender 상태, 하드웨어 정보 | 순간 사진일 뿐 누수 확진 불가 |
| `Processes` | 현재 프로세스별 Private/Working Set, CPU 누적 시간 | Working Set은 공유 페이지 등 영향 |
| `Monitor` | 프로세스별 시간대별 CSV 및 Private Memory 변화량 | 작업 부하 증가, 캐시, GC 때문에 정상 증가도 가능. PID+시작 시각으로 구분하며, 시작 시각을 확인할 수 없는 프로세스는 누수 증가량 집계에서 제외 |
| `Events` | System/Application/Defender Operational의 경고·오류 | 최근 N시간, **로그당 최대 N건**을 역순으로 수집하므로 전체 기록 아님 |
| `Security` | Defender 상태, 위협 탐지 이력, 선택적 Defender/ClamAV 검사 | ClamAV는 실시간 보호용 엔드포인트 제품이 아님 |
| `Hardware` | 디스크 공급자 상태, 가능한 경우 신뢰성 카운터 및 메모리 진단 기록 | `Healthy`, 누락된 SMART 값은 정상 판정 근거가 아님 |
| `Integrity` | 관리자 권한과 검사 요청 상태 기록; 플래그 지정 시 SFC/DISM 읽기 전용 검사 | **기본적으로 검사 미실행**. 파일 무결성 결과는 원본 로그를 보고 판단 |
| `Full` | 위 항목 모두(모니터링은 단회 샘플) | 명시적 선택 없이 백신 또는 SFC/DISM 검사를 시작하지 않음 |

**알려진 이벤트 분류:** `WHEA-Logger`, 디스크/파일시스템, Kernel-Power 41, EventLog 6008, Resource-Exhaustion-Detector 2004, Application Error 1000, Application Hang 1002, Kernel-EventTracing 2, DeviceAssociationService 3509, Service Control Manager 7031/7034, Display 4101, Windows Defender 1116/1117/1118/1119. **단일 로그로 고장 원인을 확정하지 않습니다.**

## 보고서

각 실행 결과는 기본적으로 `"$env:LOCALAPPDATA\WinTriage\reports\<UTC날짜>_<임의값>"` 아래에 저장됩니다.

- `SUMMARY.md`: 요약 및 경고
- `manifest.json`: 실행 조건과 생성 파일
- `system.json`, `processes.json`, `events.json`, `security.json`, `hardware.json`: 모드에 따라 생성
- `memory-samples.csv`, `memory-growth.csv`: `Monitor` 모드 (데이터가 없으면 헤더만 기록)
- `triage-advice.json`: 이벤트 유형별 검사 제안 (원인 확정 아님)
- `event-summary.json`: 이벤트 공급자/ID별 횟수와 첫·마지막 시각 (`Quick`, `Events`, `Full`)
- `clamav-output.txt`: ClamAV를 실제 실행했을 때
- `hardware.json`의 `ReliabilityCounters`, `StorageAssessments`: Windows 저장장치 공급자가 지원하는 범위에서만 제공 (미지원 시 판단 불가)
- `integrity.json`: `Integrity`/`Full` 모드에서 검사 요청 및 관리자 권한 상태
- `sfc-verifyonly.txt`, `dism-scanhealth.txt`: 사용자가 명시적으로 실행한 무결성 검사 원본 출력

새 보고서 폴더는 Windows ACL을 **폴더 생성 시점부터** 현재 사용자, SYSTEM, Administrators로 제한한 뒤 데이터를 수집합니다. ACL 또는 폴더 **소유자 SID** 검증에 실패하면 수집을 시작하지 않으며, 기존 보고서의 권한이나 데이터는 바꾸지 않습니다. 회사의 보안 정책이 다른 소유자를 강제할 경우 해당 환경에서 실패할 수 있으며 임의로 허용 범위를 넓히지 않습니다. 네트워크 공유(UNC/매핑 드라이브)는 출력 경로로 사용할 수 없습니다. OneDrive 등 동기화 폴더는 로컬 ACL과 별도로 외부 전송이 발생할 수 있으므로 피하세요. 보고서는 자동 삭제되지 않습니다.

로그에는 프로그램 이름, 프로세스 ID, 이벤트 메시지, 장치 이름, 감지된 파일 경로 등 **민감한 환경 정보가 포함될 수 있습니다.** 보고서를 공개 이슈나 저장소에 업로드하지 마세요. 별도 전송, 클라우드 업로드, 원격 명령은 없습니다.

## 악성코드 처리 정책

1. `Security`는 기본적으로 **상태 확인만** 수행합니다.
2. `-RunClamAV -ScanPath ...`는 서명 파일이 준비된 ClamAV에 맡겨 **탐지**만 합니다. `--remove`/`--move`를 사용하지 않습니다. ClamAV 종료 코드 0=탐지 없음, 1=탐지 있음, 2=실패.
3. `-RunDefenderQuickScan`은 사용자가 의도적으로 고른 경우에만 Windows Defender에 검사를 요청합니다. Defender는 자체 보호 정책대로 자동 격리하거나 차단할 수 있습니다. 검색 완료는 `Start-MpScan` 명령 반환 상태로만 표시하며 위협 치료 성공을 의미하지 않습니다.
4. 탐지가 발생하면 증거를 보존하고 **Windows Security 보호 기록**을 확인한 다음, 격리/복원/오탐 검토를 진행하세요. 시스템 중요 파일을 독단적으로 삭제하지 마세요.
5. ClamAV는 정식 Windows 엔드포인트 보호 소프트웨어 대신 쓰지 마세요. 반드시 [공식 문서](https://docs.clamav.net/manual/Installing.html)에 따라 설치 및 `freshclam` 서명 업데이트를 완료하세요(이 저장소는 외부 실행 파일이나 업데이트를 자동 다운로드하지 않습니다).

## Windows 무결성 확인 (명시적 선택만 실행)

`-Mode Integrity` 기본 명령은 **관리자 권한 및 실행 가능 여부만 기록**합니다. SFC 또는 DISM은 실행하지 않습니다. 명시적으로 `-RunSfcVerifyOnly`/`-RunDismScanHealth`를 선택한 경우에만 Windows 기본 제공 검사기를 실행하고 출력 파일과 종료 코드를 기록합니다. 관리자 권한이 없으면 실행을 건너뛰고 경고를 남깁니다.

```powershell
# 관리자 PowerShell, 외부 검사 실행 전 시간/디스크 부하 고려
.\WinTriage.ps1 -Mode Integrity -RunSfcVerifyOnly
.\WinTriage.ps1 -Mode Integrity -RunDismScanHealth
```

`SFC /verifyonly`는 **복구 없이 보호된 시스템 파일을 확인**합니다. `DISM /Online /Cleanup-Image /ScanHealth`는 Windows 구성요소 저장소 손상을 **검사**합니다. <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sfc> · <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image>

검사 성공 종료 코드만으로 파일 손상 없음이 확정되는 것은 아닙니다. 원본 로그를 확인하고, 오류가 확인되더라도 도구는 `sfc /scannow` 또는 `DISM /RestoreHealth` 같은 **복구 명령을 자동 실행하지 않습니다.** Windows 자체 진단 로그 및 검사 I/O는 발생할 수 있습니다.

### 디스크 해석 주의

`Get-PhysicalDisk` 상태와 `Get-StorageReliabilityCounter`의 온도, 마모도, 읽기/쓰기 오류 등은 **하드웨어와 저장장치 공급자가 노출할 때만** 기록됩니다. USB 인클로저, RAID, 가상 디스크 등은 정보를 제공하지 않을 수 있습니다. 일부 카운터는 단위와 의미가 벤더마다 달라 임의의 임곗값으로 정상/고장을 확정하지 않습니다. `StorageAssessments.Assessment` 값은 `attention`(추가 확인 필요) 또는 `inconclusive`(판단 불가)이며, **완전한 건강 판정을 출력하지 않습니다.** 정정 불가능 오류가 관측되면 백업 후 벤더 진단 도구로 재확인하세요. 원시 디스크 식별자 매칭을 임의로 추측하지 않습니다.

공식 명령 참조: <https://learn.microsoft.com/en-us/powershell/module/storage/get-physicaldisk> · <https://learn.microsoft.com/en-us/powershell/module/storage/get-storagereliabilitycounter>


### 명시적 개인정보 최소화 내보내기 (시험 기능)

원본 진단 보고서는 컴퓨터 이름, 사용자/파일 경로, 이벤트 메시지, 장치 ID 등 민감한 정보가 있을 수 있습니다. **GitHub 이슈에 원본 보고서를 올리지 마세요.** 필요한 경우에만 새 로컬 JSON 요약을 생성합니다. 기본 실행으로는 내보내거나 업로드하지 않습니다.

```powershell
.\Export-WtShareSummary.ps1 -RunDirectory "$env:LOCALAPPDATA\WinTriage\reports\YOUR_RUN_ID" -OutputPath "$env:TEMP\triage-minimal.json"
```

해당 명령은 이벤트 *범주별 집계* 및 저장장치 *평가 개수* 등 허용된 값만 포함합니다. 원본 경로, 계정, 시각, 공급자/이벤트 ID와 설명은 복사하지 않습니다. 생성한 파일도 공유 전 직접 검토하세요. 출력 파일이 이미 있으면 덮어쓰지 않습니다. 자세한 내용은 [개인정보 모델](docs/PRIVACY.md)을 참조하세요.

## 개발 및 검증

```powershell
# 정적 파서 검사(Windows PowerShell 5.1 또는 PowerShell 7)
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\WinTriage.ps1),[ref]$null,[ref]$errors) | Out-Null
$errors

# 권장: Windows에서 문법·분류·수집기 모의 테스트·개인정보 테스트·읽기 전용 통합 테스트 한 번에 실행
.\Validate-Windows.ps1

# 필요하면 실제 OS 수집을 생략하고 단위·모의 테스트만
.\Validate-Windows.ps1 -SmokeOnly

# 개발자: 플랫폼 중립 사전 점검(Python 3, PowerShell 구문 파서 대체 아님)
python .\tools\check_static.py
```

GitHub Actions는 PR, main 푸시 및 수동 실행에서 Windows PowerShell 5.1 / PowerShell 7의 구문·분류·주입형 프로세스/CIM 실패 테스트·합성 개인정보 테스트와 읽기 전용 통합 검사를 수행합니다. CI에서 Defender·ClamAV·SFC·DISM 실검사는 실행하지 않습니다. 실제 일반 사용자 PC에서의 검증은 별도로 필요합니다.

## 로드맵

[`docs/ROADMAP.md`](docs/ROADMAP.md), [`SECURITY.md`](SECURITY.md)를 참조하세요. 사용자가 실행하기 전까지 앱이 상주하거나 자동 백그라운드 모니터링하지 않습니다.

## 라이선스

MIT (이 저장소 코드만). ClamAV는 별도 GPLv2 라이선스입니다. 타사 바이너리를 저장소에 포함하지 않습니다.


### 이벤트 로그 샘플링 한계

`-MaxEventsPerLog`는 **System, Application, Defender 각각의 최종 수집 개수 상한**입니다. Defender 로그에서는 오류·경고와 탐지 이벤트를 별도로 조회하되 중복된 기록을 합친 뒤 최신순으로 해당 상한을 적용합니다. `manifest.json`의 `EventSampling`에는 로그별 `Retained`, `ObservedDistinct`, `Incomplete`, `AnyQueryReachedLimit`, `QueryFailures`가 기록됩니다. 조회 제한에 도달하거나 로그 접근이 실패한 경우 전체 이벤트 수로 오해해서는 안 됩니다.

### 하드웨어 수집기의 실패 격리

`src/WinTriage.HardwareCollector.psm1`은 CIM 디스크 목록, 물리 디스크와 신뢰성 카운터, PnP 장치, 메모리 진단 이벤트를 독립적으로 수집합니다. 어느 한 장치의 카운터에 접근하지 못해도 나머지 장치의 상태는 가능한 범위에서 보존됩니다. 불완전하거나 알 수 없는 저장장치 정보는 `inconclusive`로 보고하며, 하드웨어 정상임을 보증하지 않습니다. 테스트에서는 실제 개인 장치 정보를 사용하지 않습니다.


### Before any real Windows 10/11 field-validation run (ADR-062)

For an authorized, private workstation review, `Test-WtFieldPreflight.ps1 -OutputDir 'C:\ApprovedPrivateTriage'` is an **optional, read-only planning step**. It does not collect logs, make directories or run `Invoke-WtFieldValidation.ps1`. It outputs only fixed environment/path risk labels and **always exits 2 / NO_GO**, even on an apparently supported machine. A candidate environment or local NTFS path is never proof of permission to collect private data, authenticated initial root, ACL confidentiality or absence of backup/cloud sync. Obtain separate explicit authorization and independent private storage/security review *before* running any physical five-mode tests. See `docs/FIELD-VALIDATION.md` and `docs/FIELD-REVIEW-HANDOFF.md`; issues #2/#3 remain OPEN.


### 공개 버그 신고와 실제 현장 자료 (ADR-063)

실제 Windows 진단 결과는 **공개 GitHub 이슈에 붙여 넣거나 첨부하지 마세요.** `SUMMARY.md` 경고 원문, 이벤트, 전체 콘솔 출력, 경로, 사용자·호스트·장치 식별자, 정확한 빌드 번호 및 스크린샷은 일부만 가려도 식별 가능할 수 있습니다. 독립 공개 검토 후 [공개 신고 안내](docs/PUBLIC-ISSUE-GUIDE.md)와 [합성 자료 전용 버그 템플릿](.github/ISSUE_TEMPLATE/bug_report.md)을 이용해 **완전히 창작된 재현**만 게시합니다. 보안 취약점은 `SECURITY.md`의 비공개 채널을 이용하세요. 실제 Windows 10/11 검증 및 독립 승인 전까지 NO-GO, 이슈 #2·#3 OPEN입니다.


### SMB parent-share visibility in manual preflight (ADR-064)

The optional `Test-WtFieldPreflight.ps1 -OutputDir 'C:\ApprovedPrivateTriage'` now includes a bounded `SmbExposure` line. `BROAD_ACCESS_REVIEW` or `SHARED_REVIEW` means a recognized ordinary SMB share covers the output directory, requiring a separate **private** access/privacy review; `UNKNOWN` means the share inventory or ACL cannot be conclusively inspected. `NO_NON_SPECIAL_SHARE_OBSERVED` does **not** prove the path is private or exclude administrative shares, backup/OneDrive/DLP, NTFS permission issues or external access. Share names, user accounts, paths and OS exceptions are never printed. This optional check never changes shares, writes reports, runs collectors or authorizes release; exit 2 and NO_GO remain unconditional. See `docs/FIELD-VALIDATION.md`.

### 선택형 SMB 수집 차단 (ADR-065)

독립 검토를 받은 비공개 로컬 경로에서 현장 5모드 수집을 수동으로 진행할 때 `Invoke-WtFieldValidation.ps1 -OutputDir 'C:\ApprovedPrivateTriage' -RequireSmbPreflight`를 명시하면, 매 모드 수집 전에 일반 SMB 상위 공유를 읽기 전용으로 검사합니다. 공유가 관측되거나 SMB 조회가 불가능/불확실하면 해당 모드의 새 보고서 수집을 차단합니다. 기존 자료, 공유 및 ACL을 변경하지 않습니다. 기본 호출과 `WinTriage.ps1` 직접 호출은 바뀌지 않습니다. 공유가 관측되지 않아 진행하더라도 관리 공유·실제 원격 접근·백업·동기화·경로 경합을 배제하거나 개인정보/출시를 승인하는 것은 아닙니다. 자세한 내용은 [현장 검증](docs/FIELD-VALIDATION.md) 및 ADR-065를 참조하세요.

### SMB 차단 첫 단계의 최소 출력 (ADR-067)

`-RequireSmbPreflight` 사용 시 첫 번째 수집 전 SMB/경로 검사 또는 선택형 모듈 로딩에 실패하면, Windows 빌드 번호를 출력하기 전에 `SmbCollectionGate: BLOCKED_OR_UNKNOWN` 한 줄만 출력하고 종료 코드 2로 중단합니다. 이미 앞선 진단 모드가 실행됐다면 이후 차단 이전에 환경·모드 상태가 출력되었을 수 있으므로 전체 콘솔 로그를 공개해도 된다는 의미는 아닙니다. 직접 수집기와 기본 실행은 변경되지 않으며 출시 NO-GO입니다.

### SMB 보호 실행 전 재확인 (ADR-068)

선택형 `-RequireSmbPreflight` 사용 시 일반 수집 모듈 로딩 전, 매 모드의 기존 폴더 목록 확인 전, 실제 수집기 호출 직전에 SMB 공유·경로 상태를 다시 검사합니다. 도중 공유가 관측되거나 조회/모듈 로딩/기존 폴더 메타데이터 확인에 실패하면 고정 코드로 차단하며 기존 보고서와 ACL을 변경하지 않습니다. 체크 이후의 TOCTOU까지 막는 것은 아니며, 보호된 저장소 또는 출시 승인 판정을 내리지 않습니다. 기본 진단 실행은 그대로입니다.

### SMB 보호 응답의 엄격 검증 (ADR-069)

명시적으로 `-RequireSmbPreflight`를 사용한 경우, 경로·SMB 조회 또는 정책 확인이 비종료 오류를 내면서 정상 상태를 반환하거나, 문자열로 변환 가능한 객체·대소문자 변형·복수 값·예상 밖 정책 출력을 내면 모두 **차단**합니다. 정상 판정의 유일한 의미는 해당 순간의 일반 SMB 추가 차단 조건이 관찰되지 않았다는 뜻이며 저장소 기밀성이나 출시를 승인하지 않습니다. 기본 진단 동작과 기존 자료는 변경되지 않습니다.

### SMB 목록 불완전성 보호 (ADR-070)

선택형 SMB 보호를 사용하면 SMB 공유 목록이나 접근권한 조회 중 경고·비종료 오류가 발생했을 때, 정상처럼 보이는 빈 목록 또는 부분 목록이 함께 반환되더라도 **`UNKNOWN`으로 차단**합니다. 중복 공유 이름·누락된 필수 속성·불완전한 공유 ACL도 차단합니다. 오류 없이 반환된 빈 목록 자체의 완전성은 검증할 수 없으므로 개인정보·접근권한 승인으로 해석해서는 안 됩니다. 기본 진단 실행은 바뀌지 않습니다.

### 검증 증거와 출시 승인 경계표 (ADR-071 / PR #76)

[현장 검증 증거 경계표](docs/FIELD-ASSURANCE-BOUNDARIES.md) 및 [고정 상태 목록](docs/field-assurance-boundaries.json)은 합성 테스트·GitHub Windows CI가 확인하는 범위와 실제 Windows 10/11 실기기 및 독립 보안·개인정보·출시 승인이 **여전히 필요한 범위**를 구분합니다. 이 공개 문서에는 실기기 결과나 개인 PC 자료가 포함되지 않으며, 8개 실기기 조합은 모두 `NOT_AUTHENTICATED`로 남깁니다. 워크플로 검증 성공과 `NO_NON_SPECIAL_SHARE_OBSERVED`는 승인 증거가 아닙니다. 이슈 #2·#3은 OPEN, 출시 판단은 NO-GO입니다.

### 현장 실행 중단·독립 인계 기준 (ADR-072 / PR #77)

[현장 담당자 중단 규칙](docs/FIELD-OPERATOR-STOP-RULES.md)은 사용 승인·독립 루트/저장소 검토, 수집 중 SMB 차단 및 ACL·스키마 오류, 수집 후 비공개 검토와 출시 권한을 구분합니다. **추가 수동 실행을 중단하라는 운영 지침**이며, 기존 수집을 자동 취소하거나 보고서를 삭제·업로드하는 기능은 아닙니다. 모든 원본 증거는 비공개로 보존하고 독립 승인 전 출시 NO-GO, 이슈 #2·#3 OPEN입니다.
