# KNDbgX

[English](README.md) · 한국어

KNDbgX는 x64 WinDbg에 시각적인 분석 작업 화면을 제공한다. 프로세스 목록 교차 조회, VM 접근 핸들 조사, 커널 스냅샷 저장·비교, 드라이버 파일 분석 결과를 탭으로 보관한다. 결과 옆이나 별도 창에서 메모리·디스어셈블리·레지스터를 확인한다. 확장 자체는 커널 드라이버를 설치하지 않는다.

아래 이미지는 **0.2.0-preview.7**을 WinDbg에 로드하고 실제 Windows 11 x64 VMware 게스트에서 촬영한 화면이다. 커널 수집기와 Data Model 연동은 실험적 기능이다. [지원 환경과 제약](docs/SUPPORT.md)을 참고한다.

## KNDbgX 수집기로 조사하기

지원되는 커널 대상을 중단하고 **Library / Ctrl+K**에서 `!hiddenproc`를 찾아 실행한다. 원격 KD에서는 활성 프로세스 목록과 대상의 CID 테이블을 비교한다. 양쪽에서 관측한 식별 정보와 비교 결과를 한 표에서 확인하고, **Row details**로 원본 필드를 열거나 **Export**로 비교 결과를 저장한다.

![두 목록의 프로세스 식별 정보를 나란히 비교한 결과](docs/screenshots/process-cross-view.jpg)

- **프로세스 핸들 접근 권한:** `!handles /owner-pid 4`로 System 프로세스의 VM 접근 핸들을 조사하거나, 현재 대상에서 확인한 PID로 목적지를 좁힌다. 소유자·목적지·접근 마스크·다른 프로세스 여부를 함께 확인한다. [핸들 조사 절차](docs/UX.md#inspect-process-handle-access)
- **스냅샷 비교:** 서로 다른 새 디렉터리에 `!snapshot`을 저장한 뒤 `!diff` 결과를 연다. Added·Removed·Changed·Unknown을 해석하기 전에 수집 범위와 식별 정보부터 확인한다. [저장과 비교](docs/UX.md#save-and-compare-kernel-snapshots)
- **드라이버 파일 분석:** `driver-audit`로 지정한 호스트 PE 파일의 식별 정보·완화 설정·섹션·임포트·내장 서명 정책 결과를 행 단위로 확인한다. [드라이버 분석 절차](docs/UX.md#audit-a-driver-file)
- **등록 함수와 디스패치:** 미니필터의 Pre/Post 콜백과 드라이버 디스패치 함수의 소유 모듈을 확인하고, 로드된 이미지의 PE 정보와 함께 조사한다. [미니필터](docs/UX.md#follow-minifilter-registrations) · [드라이버 디스패치](docs/UX.md#inspect-driver-dispatch-and-loaded-image-metadata)
- **메모리 권한:** VAD 보호 속성과 페이지 표본을 비교하고, 지정 범위의 주소 변환과 big-pool의 W+X 관측 결과를 확인한다. 표본·누락·미검사 페이지를 구분한다. [VAD 표본](docs/UX.md#compare-vad-protection-with-page-samples) · [페이지 권한](docs/UX.md#inspect-page-permissions-for-a-chosen-range) · [Big pool](docs/UX.md#inspect-big-pool-allocations-and-wx-samples)
- **커널 상태와 진단:** CPU별 IDT·제어 상태, ETW 로거 메타데이터를 보관하고, 정해진 진단 체크리스트를 실행해 단계별 원본 출력을 확인한다. [CPU 상태](docs/UX.md#review-per-cpu-idt-and-control-state) · [ETW](docs/UX.md#inspect-etw-logger-metadata) · [진단 레시피](docs/UX.md#run-a-diagnostic-checklist)
- **수집 범위 확인:** **Capture info**와 **View output**에 읽지 못한 범위, 없는 레이아웃 등의 제약이 남는다. Partial인 결과의 0행은 객체 부재를 뜻하지 않는다. [수집 한계 예시](docs/UX.md#read-a-collectors-coverage-limits)

목록 간 차이나 핸들의 접근 권한만으로 은닉·인젝션을 판정하지 않는다. [프로세스 교차 조회와 해석 범위](docs/UX.md#compare-two-process-inventories)

## 작업 화면 열기

![실행 중인 VMware 커널 대상에 연결된 KNDbgX 작업 화면](docs/screenshots/workspace.jpg)

x64 WinDbg, Microsoft VC++ x64 런타임, WebView2 Evergreen Runtime이 필요하다. 배포 ZIP 전체를 풀고 `runtime\dia\msdia140.dll`을 확장 기준의 같은 상대 경로에 유지한다. WinDbg를 대상에 연결하고 메모리를 조사하기 전에 대상을 중단한다.

처음에 확장을 로드하고 창을 연다.

```text
.load C:\path\to\kndbgx.dll
!kndbgx
```

이후에는 **KNDbgX 창**에서 작업한다. **Library**는 명령을 찾는 곳, **Results**는 수집 결과, **Inspect**는 네 가지 검사 뷰다. **Windows**에서 배치와 분리된 창을 관리한다. 창을 닫아도 로드된 확장에 작업 화면이 남으며 `!kndbgx`로 다시 연다.

## 할 일을 찾고 실행하기

**Library**를 열거나 **Ctrl+K**를 누른다. `callback`처럼 목적에 맞는 단어를 검색하고 항목을 선택한 뒤 Enter로 초안을 넣는다. 필요한 인자를 채우고 **Run**을 누른다. **Tab**은 문법과 로드된 심볼을 완성한다. 선택이나 자동 완성만으로 명령이 실행되지는 않는다.

![명령 팔레트에서 콜백 관련 작업 검색](docs/screenshots/command-palette.jpg)

**Pin left**로 Library를 Results 옆에 고정한다. 즐겨찾기·필터·그룹 접기로 자주 쓰는 명령을 정리하고, **Investigation starting points > Kernel investigation**을 펼쳐 크래시·I/O·드라이버 분석의 시작점을 선택한다. [명령 찾기](docs/UX.md#find-and-run-commands)

## 프로세스에서 조사 시작하기

**Inspect > Processes**에서 프로세스를 선택하고 **Open details**, **Threads**, **Memory (VADs)** 또는 **Token**을 누른다. 프로세스 목록을 유지하면서 별도 결과 탭이 열린다. 결과 탭을 더블클릭하면 알아보기 쉬운 이름을 붙일 수 있다.

![선택한 프로세스의 스레드를 Results에서 확인](docs/screenshots/processes.jpg)

행 선택만으로 디버거의 주소 공간이 바뀌지는 않는다. **Attach address space**는 별도로 검증을 거치는 동작이며, 레지스터의 스레드·CPU 컨텍스트도 구분된다. [프로세스 검사](docs/UX.md#processes-tab)

## 주소를 따라 메모리와 코드 확인하기

결과의 인식 가능한 주소를 오른쪽 클릭해 **Open Memory** 또는 **Open Disassembly**를 선택한다. 콜백 행에서는 Routine·Pre·Post를 구분해서 선택한다. 읽기 전에 원본 결과와 프로세스 컨텍스트를 확인한다.

![콜백 결과 옆에서 해당 주소의 바이트와 ASCII 확인](docs/screenshots/memory.jpg)

**Memory**는 byte·word·dword·qword 표시, ASCII와 저장된 **Read details**를 제공한다. **Disassembly**는 Current IP·Next instructions·Follow IP·중단점 표시를 제공한다. **Registers**에서는 고정한 값, 변경된 값과 벡터 바이트를 확인한다. 각 뷰의 **Float**로 별도 창을 열거나 **Float group**으로 Inspect 탭 묶음을 분리한다. [검사 뷰와 별도 창](docs/UX.md#floating-inspection-windows)

## 결과 보관·실행 제어·작업 복구

- **결과:** 다시 실행하지 않고 탭을 전환하며 열 선택·정렬·값 복사·**Row details**를 사용한다. **Capture info**에서 상태와 수집 범위를 확인하고, **Export**로 화면 밖의 행까지 포함한 전체 보관 결과를 저장한다. [결과와 내보내기](docs/UX.md#export-and-recovery)
- **실행:** 지원되는 라이브 대상에서 **Continue / Break**, F5와 Disassembly의 F10/F11을 사용한다. **Breakpoints**에서 설정을 관리하며, 추가·삭제와 등록된 메모리 쓰기는 미리보기 승인을 거친다. [실행과 변경](docs/UX.md#execution-and-changes)
- **컨텍스트와 심볼:** **Context details > Symbols**에서 선택한 모듈의 PDB 일치 여부와 타입 정보를 확인한다. [심볼 검사](docs/UX.md#context-symbols-and-waits)
- **오래 걸리는 작업:** **Operations**에서 단계와 보관된 처리 결과를 확인한다. **Cancel operation**은 취소 요청이며, 진행 중인 네이티브 심볼·메모리 호출이 끝날 때까지 기다릴 수 있다. Refresh outcomes는 기존 작업의 결과만 조회한다. [작업 상태와 수집 범위](docs/UX.md#context-symbols-and-waits)

[화면별 사용 안내](docs/UX.md)에서 각 조작, 단축키와 스냅샷 비교를 이어서 확인한다. 정확한 문법은 컴파일된 레지스트리에서 생성하는 [명령 명세](docs/COMMANDS.md)를 따른다. UI를 시작하지 못한 경우에도 CLI 명령은 사용할 수 있다.

## 소스 빌드

Visual Studio 2022 C++ 도구(v143)와 Windows 10/11 SDK를 설치하고 저장소 루트의 PowerShell에서 실행한다.

```powershell
.\tools\build.ps1 -Configuration Release -RunTests
```

스크립트가 `vswhere`로 Visual Studio를 찾아 `x64\Release`에 확장을 생성한다. `-RunTests`의 프런트엔드 검사에는 Node.js가 필요하며 빌드만 하려면 이 옵션을 생략한다. 배포 도구에는 Python 3.11 이상, `samples/snapshot-demo`에는 별도로 WDK가 필요하다. [빌드 검증과 배포 패키징](docs/VALIDATION.md)을 참고한다.

## 결과 해석과 명령 전달

심볼·페이지 누락이나 수집 한도는 **Partial** 또는 **Unavailable**로 표시한다. 행이 없다는 사실만으로 객체 부재를 단정하지 않는다. 결과는 수집 당시 컨텍스트를 유지하며, 과거 결과로 현재 대상을 변경할 수 없다. 중요한 결과는 보관 한도 도달이나 DLL 언로드 전에 내보낸다.

UI에서 직접 입력한 미등록 명령은 WinDbg로 전달되며 대상이나 호스트를 변경할 수 있다. 등록된 이름에는 KNDbgX의 검증과 승인 규칙이 적용된다. CLI와 작업에서 미등록 명령을 실행하려면 `raw --ack-effects <명령>`이 필요하다. 덤프와 로컬 KD는 대상 쓰기와 실행 제어를 지원하지 않는다. [지원 범위와 제약](docs/SUPPORT.md)

## 라이선스

KNDbgX는 [MIT 라이선스](LICENSE)로 배포한다. Copyright (c) 2026 kernullist.
서드파티 구성요소에는 각각의 라이선스가 적용된다. [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)를 참고한다.
