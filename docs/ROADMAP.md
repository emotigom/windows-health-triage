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

- [x] #4 stage 2: event collector with injected provider, per-log combined sampling cap and Defender dedup
- [ ] #4 stage 3: physical disk, PnP and MemoryDiagnostics collectors with injectable failures

- [x] #4 stage 3: hardware module with injected providers and per-device counter failure isolation (pending CI)
- [ ] #4 follow-up: bounded provider sampling, report schema contracts and production hardware test matrix

## Private report lifecycle (2026-10-31)
- [x] Create restricted per-run local raw report directories; prevent reparse-point redirection (PR #17/#19).
- [x] Provide explicit metadata-only retention inventory, capped enumeration and no-delete/no-upload invariant.
- [ ] Validate retention metadata on actual unmanaged/managed Windows 10/11 installations, OneDrive/redirected profiles and unusual ACL policies (issues #2/#3).
- [ ] Evaluate atomic Windows security-descriptor creation and policy-oriented guidance before a public stable release; no default automatic cleanup.

## Concurrent report creation safety — 2026-10-31
- [x] Reject same-name concurrent report creation at the Windows CreateDirectoryW call using native ERROR_ALREADY_EXISTS; create with protected ACL and verify ownership (ADR-018).
- [x] Synthetic two-process collision test in Windows PowerShell 5.1 and 7 CI, with no live report deletion.
- [ ] Handle-relative directory/path verification for parent-swapping attackers (requires dedicated Windows security review). Parent reparse-point checks alone do not guarantee race freedom.
- [ ] Real Windows 10/11 end-user and managed-policy compatibility testing before a stable security claim.

## Report path identity lease — 2026-10-31
- [x] Maintain drive-root-to-run directory handles with delete sharing omitted while reporting (ADR-019); **tests show this does not reliably block directory renames**.
- [x] Detect renamed/vanished directory paths via file-ID checkpoints, reject reparse points while acquiring handles and dispose on errors.
- [ ] Eliminate the check-to-write race with genuine handle-relative file creation rather than path-based `Out-File` / `Export-Csv`. Do not claim the current lease prevents all redirection.
- [ ] Stronger handle-relative writes and external native scanner output paths still require dedicated security design review. A handle lease is not an atomic sandbox or defense against same-user/admin file tampering.
- [ ] Physical Windows 10/11, corporate profiles and non-NTFS filesystem testing.

## Handle-relative core reports — 2026-10-31
- [x] Bind standard JSON, CSV, SUMMARY and manifest creation to the held report directory handle (ADR-020) with exclusive create-new and allowlisted leaf names.
- [x] Add synthetic PS 5.1/7 privacy, ACL, UTF-8 and no-overwrite tests; preserve report schema v1.
- [ ] Migrate or isolate optional native scanner log file writes; these remain path-based and require separate review.
- [ ] Verify native user-mode NtCreateFile flag/parent-rights compatibility on physical Windows 10/11 and enterprise-managed endpoints.

## Optional native log output — 2026-10-31 (ADR-021)
- [x] Create allowlisted ClamAV/SFC/DISM text logs relative to pinned report directory handle and stream output to disposable file writer without path-based `Out-File`.
- [x] Fail before starting optional native command if secure sink creation fails; synthetic PS 5.1/7 tests.
- [ ] Physical Windows 10/11, managed endpoint, stdout/stderr and native exit-code validation before production claims.


## Report path acquisition checkpoints — 2026-10-31 (ADR-022)
- [x] Check the pinned root-to-run identity prefix immediately after each directory handle is opened; fail before traversing further on sustained path substitutions.
- [x] Exercise deterministic parent move/decoy injection during acquisition with synthetic, test-owned folders on both PowerShell editions.
- [ ] Design and separately review truly handle-relative *parent-to-child traversal and initial private directory creation* before making stronger guarantees; no atomic provenance claim today.
- [ ] Physical Windows 10/11 and managed filesystem validation; keep issues #2/#3 open.


## Relative parent-child relationship research — 2026-10-31 (ADR-023)
- [x] Audit documented `NtCreateFile` / `RootDirectory` / directory and reparse flag semantics, explicitly record missing guarantees.
- [x] Add a **research-only**, read-only pinned-parent native probe and synthetic pinned-parent or unpinned-ancestor move/decoy identity comparison (both Windows PowerShell editions).
- [ ] Review supported options, root grant/access rights and direct handle-derived ACL/owner attestation with Windows expertise before touching production acquisition.
- [ ] Prove provenance across create-to-open, junction conversion and transient swaps; validate on physical Windows 10/11, managed policies and filesystem variants.
- [ ] Leave #2 and #3 open; do not claim complete race-free paths.


## Security research continuation (ADR-024, 2026-10-31)
- [x] Add test-only READ_CONTROL and pinned-handle ACL/owner query plus synthetic path-decoy comparison; production remains unchanged.
- [ ] Validate handle-derived security descriptors, access errors, rename/reparse/managed policy behavior on actual Windows 10/11, including non-NTFS and redirected locations (#2).
- [ ] Design and separately review fully handle-relative private directory creation and complete trust-chain binding before considering production adoption.


## Directory creation handle lineage (ADR-025)
- [x] Synthetic-only test for parent-relative private directory exclusive creation returning its own handle; no production change.
- [ ] Review initial trusted root-to-parent chain, no-reparse contract, Windows 10/11 and enterprise-policy compatibility before production migration.


## Rooted directory chain research (ADR-026)
- [x] Synthetic-only pinned-anchor multi-hop handle-relative opens and test-only private run creation with owner/DACL checks; unchanged production.
- [ ] Establish trusted initial root/anchor provenance, reparse-in-call safety, documented NT options and physical Windows 10/11 and enterprise filesystem validation before considering production migration.


## Anchor provenance research (ADR-027)
- [x] Synthetic-only known-file-ID anchor substitution refusal and deterministic pre-open junction substitution negative cases; unchanged production path handling.
- [ ] Establish how the initial directory identity becomes **independently trusted**, reject in-call reparse/redirection, and validate field Windows 10/11, enterprise policy and non-NTFS filesystems before any production adoption.


## Rooted handle chain and lexical fail-closed policy (ADR-028)
- [x] Research-only strict path spelling classification and least-privilege fixed NTFS volume root to disposable fixture traversal with optional junction rejection.
- [ ] Independently authenticate the first volume root, establish operational path compatibility, prove or reject in-call reparse redirect behavior, and validate physical Windows 10/11 and managed volumes before considering any production implementation.


## Volume/file identity trust (ADR-029)
- [x] Test-only full 128-bit native file ID + volume serial and optional handle-derived GUID alias observation; same-volume synthetic decoy rejection.
- [ ] Independently authenticate initial drive/volume identity across process lifetime and real-world Windows 10/11/managed/remapped volumes before any production adoption.


## Session-scoped root provenance research (ADR-030)
- [x] Research-only held-reference lease, synthetic alias substitution, self-attestation negative control, revoked/wrong-epoch/closed-handle rejection; no production code changes.
- [ ] Establish an independently authoritative initial root source and handle lifetime, Windows 10/11 and enterprise-field behavior before adopting any code in src/.


## Physical field evidence gate (ADR-031 / PR #36)
- [x] Offline, no-go-only bounded metadata evidence checker, strict eight-cell Windows 10/11 × shell × privilege matrix, exceptional provider status and manual security/privacy review, with invented-fixture regression tests on both Windows jobs.
- [ ] Collect genuine approved physical Windows 10/11 field evidence, authenticate the initial root, perform reparse/mount and managed-storage review, independently authorize privacy/security release. Never treat hosted CI or a self-asserted JSON as GO.

## Manual field-status transcription (ADR-032 / PR #37)
- [x] Standalone offline, enum-only, create-new status recorder; cannot overwrite a reviewed cell, infer GO, parse raw reports or publish evidence.
- [x] Synthetic privacy and consistency regression tests in both hosted Windows jobs.
- [ ] Perform approved physical Windows 10/11 tests with authorized privilege contexts, review real ACLs/sync and root trust, and obtain independent security/privacy signoff. Keep #2/#3 OPEN and release NO-GO.

## Strict privacy-bounded field metadata reads (ADR-033 / PR #38)
- [x] Shared, bounded strict JSON parser with duplicate/nonfinite refusal and descriptor metadata checks for the two offline field helpers.
- [x] Synthetic ambiguous-input, non-regular/linked file, no-echo CLI and downstream recorder regressions in both hosted Windows jobs.
- [ ] Validate real Windows 10/11 devices and managed storage/ACL/sync/reparse policies; obtain independent trusted-root and release approval. Issues #2/#3 remain OPEN; NO-GO.

## Windows field-status snapshot permission research (ADR-034 / PR #39)
- [x] Separate, opt-in, read-only fixed-label Windows file owner/DACL/path observation with permanent NO-GO and unknown cloud-sync state.
- [x] Both Windows CI shells exercise test-owned protected-parent and synthetic weak ACL/reparse scenarios, no user report reads.
- [ ] Physical Windows 10/11 ACL, redirected/synced profiles, backup/enterprise policies, initial root authenticity and independently authorized release review. Issue #2/#3 OPEN.
