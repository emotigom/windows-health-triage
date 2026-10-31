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

# 권장: Windows에서 문법·단위·읽기 전용 통합 테스트 한 번에 실행
.\Validate-Windows.ps1

# 필요하면 단위 테스트만
.\Validate-Windows.ps1 -SmokeOnly

# 개발자: 플랫폼 중립 사전 점검(Python 3, PowerShell 구문 파서 대체 아님)
python .\tools\check_static.py
```

GitHub Actions는 PR, main 푸시 및 수동 실행에서 Windows PowerShell 5.1 / PowerShell 7의 구문·분류·합성 개인정보 테스트와 읽기 전용 통합 검사를 수행합니다. CI에서 Defender·ClamAV·SFC·DISM 실검사는 실행하지 않습니다. 실제 일반 사용자 PC에서의 검증은 별도로 필요합니다.

## 로드맵

[`docs/ROADMAP.md`](docs/ROADMAP.md), [`SECURITY.md`](SECURITY.md)를 참조하세요. 사용자가 실행하기 전까지 앱이 상주하거나 자동 백그라운드 모니터링하지 않습니다.

## 라이선스

MIT (이 저장소 코드만). ClamAV는 별도 GPLv2 라이선스입니다. 타사 바이너리를 저장소에 포함하지 않습니다.
