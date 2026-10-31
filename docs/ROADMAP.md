# Roadmap and engineering decisions

현재 개발 버전: v0.3.0 (Windows 현장 검증 미완료)

## v0.1: 준비됨 (Windows 현장 검증 전)
- [x] 수동 PowerShell 실행 진단 CLI
- [x] 주요 이벤트 유형의 설명·분류(특히 ETW Session ID 2, 장치 연결 3509)
- [x] 샘플 기반 Private Memory 변화량과 CSV 기록
- [x] Windows Defender 상태 조회 및 **명시적** 빠른 검사 요청
- [x] 오픈소스 ClamAV의 탐지 전용 CLI 연동
- [x] 로컬 JSON/CSV/Markdown 저장, .gitignore, 간단 테스트
- [ ] Windows 10/11 PowerShell 5.1/7 실제 구동 테스트 및 권한 검증

## v0.2: 규칙 정확성 (코드 완료, Windows 검증 대기)
- [x] 수집기 장애 발생 시 OS 스냅샷을 부분 데이터와 경고로 보존
- [x] 시작 시각 불확실한 PID의 메모리 성장률 분석 제외
- [x] 반복 Event ID 그룹과 발생 시각 요약
- [x] 원인 확정 없이 다음 검사 단계만 제시하는 분류별 triage 조언
- [x] Defender 1116~1119 정보 수준 이벤트 별도 조회
- [x] SCM 7031/7034, Display 4101 분류
- [x] 테스트 코드 추가, Windows PowerShell 5.1 및 7 수동 CI 워크플로 준비
- [ ] **Windows 실기기/CI 검증 후 오류 수정 및 안정화**
- [ ] WHEA 이벤트 문맥(장치/버스/코어) 구조적 추출
- [ ] ETW 오류(0xC0000035) 주변 이벤트·세션 이름 상관관계
- [ ] Windows 서비스 종료/충돌(7031/7034 등) 상관관계
- [ ] Resource-Exhaustion-Detector 2004 XML 사용자/프로세스 정보 분석
- [ ] Defender 위협 탐지 1116/1117 계열 이벤트와 보호 기록 정합성
- [ ] 벤더 공식 문서 출처/권장 조치 가이드 링크
- [ ] 이벤트 빈도 기준 중복제거 및 타임라인

## v0.3: 하드웨어 및 리소스 추적 (일부 구현, Windows 검증 대기)
- [x] Windows Storage 공급자 상태 및 지원되는 신뢰성 카운터 수집(부재 시 판단 불가)
- [x] 디스크 정정 불가 오류 / 경고 신호를 보수적으로 분류
- [x] `Integrity` 기본 수동 모드와 별도 플래그 방식 SFC/DISM 검사(복구 없음)
- [x] 관련 분류 단위 테스트 및 읽기 전용 통합 테스트 추가
- [ ] Windows PowerShell 5.1/7 실제 CI 녹색 및 PC에서 검증
- [ ] Performance Counter: Committed Bytes, Hard Faults/sec, Disk latency 측정
- [ ] 동일 프로세스 다중 샘플 안정적 식별(시작 시각 접근 불가 시 방안)
- [ ] 드라이버 버전/서명 검사, 과부하 시 진단 최소화
- [ ] 오픈소스 smartmontools 연동(사전 설치한 경우만, 읽기 전용)
- [ ] MemTest86+ 안내 및 Windows Memory Diagnostic 결과 상관관계

## v0.4: 검토 기반 수리 플레이북
- [x] `sfc /verifyonly`, DISM `/ScanHealth` 등 명시적 진단 전용 플로우 (Windows 검증 대기)
- [ ] 수리 전 Restore Point/백업/BitLocker 확인 체크리스트
- [ ] *개별 승인 시* `sfc /scannow`, `DISM /RestoreHealth` 등 제안 (원클릭 자동수정 금지)
- [ ] ClamAV 결과 오탐 검토 절차, 파일 해시 보존 및 안전한 격리 디자인

## 설계 원칙
- 기본값 읽기 전용, 디스크 삭제/레지스트리 수정/프로세스 종료 자동 금지
- 네트워크 전송 없음, 원격 측정/자동 업데이트 없음
- 이벤트 로그는 증거이지 진단의 확정적 결론이 아님
- 실시간 악성코드 차단은 기존 엔드포인트 백신 유지
- 관리자 권한은 필요한 작업에만 사용


## Privacy and maintainability tracker
- [x] #3: explicit minimal, local-only allowlisted report export and synthetic privacy tests (pending CI confirmation)
- [ ] #3: user review of summary before disclosure, review permissions for published release
- [ ] #4: split OS collectors by subsystem with dependency-injected failure fixtures and independent error handling
- [x] #4 groundwork: independent, pure privacy transformation module with Windows CI unit tests

- [x] #4 stage 1: process + OS collectors extracted with injected test doubles and independent failure warnings
- [ ] #4 stage 2: event logs per-log caps, Defender sampling and injectable log provider
- [ ] #4 stage 3: storage/PnP collectors with injectable provider and failure isolation
