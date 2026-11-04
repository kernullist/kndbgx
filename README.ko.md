# KNDbgX

[English](README.md) · 한국어

KNDbgX는 디버거 탐색과 Windows 보안 분석을 위한 x64 WinDbg 확장이다. CLI, WebView2 작업 화면, 선택적 Data Model이 결과·디버거 컨텍스트·수집 범위를 공유한다. 확장 자체는 커널 드라이버를 설치하지 않는다.

**Context details**는 현재 디버거 컨텍스트와 선택한 모듈의 심볼 상태를 설명한다. **Operations**는 작업 단계·대기·보존된 결과를 보여준다. **Memory > Read details**는 대상을 다시 읽지 않고 저장된 읽기 범위·바이트 수·네이티브 오류를 표시한다. [컨텍스트 진단](docs/CONTEXT_DIAGNOSTICS.md)과 [작업 화면](docs/UX.md)을 참고한다.

커널 수집기와 Data Model은 **Experimental**이다. 자료구조 미확인·페이지 누락·수집 한도를 명시하며, 불완전한 목록으로 객체 부재나 시스템 무결성을 단정하지 않는다. 지원 범위는 [지원 환경](docs/SUPPORT.md)을 따른다.

## 빌드와 실행

본체 빌드에는 Visual Studio 2022 C++ 도구(v143)와 Windows 10/11 SDK가 필요하다. 스크립트는 `vswhere`로 Visual Studio를 찾는다. 프런트엔드 테스트에는 Node.js, 배포 도구에는 Python 3.11 이상을 사용한다. WDK는 별도 snapshot 드라이버 샘플에만 필요하다. UI에는 WebView2 Evergreen Runtime, 바이너리 실행에는 Microsoft VC++ x64 런타임이 필요하다. UI 초기화에 실패해도 CLI는 사용할 수 있다.

```powershell
.\tools\build.ps1 -Configuration Release -RunTests
.\tools\run-engine-test.ps1 -Configuration Release -EvidenceDirectory artifacts\engine-check
```

엔진 테스트는 설치된 WinDbg 런타임에서 테스트용 사용자 모드 프로세스와 덤프를 직접 만든다. 빌드를 복사할 때 `runtime/dia/msdia140.dll`도 `kndbgx.dll` 옆의 같은 상대 경로로 복사한다.

배포 ZIP에는 PDB와 원본 증거 자료를 넣지 않는다. 전체 빌드 결과, 덤프, 내보낸 결과는 로컬에 보관하고 외부 공유 전 [공개 범위와 검사](docs/VALIDATION.md#publication-boundary)를 확인한다.

x64 WinDbg에서 로드한다.

```text
.load C:\path\to\kndbgx.dll
!kndbgx version
!kndbgx status
!kndbgx help
!kndbgx
```

마지막 명령이 작업 화면을 연다. WinDbg에서는 `!kndbgx <명령>`, KNDbgX에서는 `<명령>`을 사용한다. `help ui`는 화면 도움말, `help <명령 또는 별칭>`은 문법과 세션 조건을 보여준다. [명령 명세](docs/COMMANDS.md)는 컴파일된 레지스트리에서 생성한다.

## 디버거 사용

- **Find a command / Ctrl+K**는 수정 가능한 초안을 넣는다. Tab은 등록된 문법과 로드된 심볼을 완성하며 명령을 실행하지 않는다. 위·아래 방향키로 명령 이력을 탐색하고 최신 항목 다음으로 돌아오면 미완성 입력을 복원한다.
- **Inspect / Ctrl+M**은 Results 옆에 Processes·Memory·Disassembly·Registers를 연다. 각 뷰의 **Float**로 네 뷰를 각각 별도 창에 띄워 동시에 볼 수 있다. **Dock** 또는 개별 창의 닫기 버튼으로 해당 뷰를 복귀시키고, **Dock all**로 모두 되돌린다. 기본 제목 표시줄을 작업 화면이나 그룹의 도킹 가이드로 드래그해 복귀시킬 수도 있다. 입력값·조회 결과·선택·스크롤 위치를 유지한다. **Float group**은 개별 창을 유지하면서 탭 묶음을 분리한다. **Row details**는 선택한 결과 행의 상세 패널로, 표시 여부와 폭을 따로 조절한다.
- **Inspect > Registers**는 표시 중인 상태에서 새 정지 컨텍스트를 감지하면 갱신하고, 변경된 값과 벡터의 원시 바이트를 표시한다. 이름 필터와 값 복사를 지원한다. 실행 중이거나 읽기 실패·조회 불가 상태이면 이전 값과 안내를 유지한다. 디버거의 현재 스레드/CPU 컨텍스트를 사용하며, 프로세스 선택만으로 레지스터 컨텍스트를 바꾸지는 않는다. `registers` / `r` 명령은 별도의 결과 스냅샷을 생성한다.
- **Windows**는 적응형 레이아웃 복원, Compact/Comfortable 밀도 변경과 분리 창 위치 복구를 제공한다. **Operations**는 Output Off에서도 보존된 작업 기록과 결과를 확인하고 열 수 있으며, UI 재생성 후 명령을 재실행하지 않고 완료 상태를 복구한다.
- 결과의 주소를 우클릭하면 Memory 또는 Disassembly로 연다. 콜백은 Routine·Pre·Post를 선택한다. 원본 컨텍스트와 주소 공간을 검증하며, 과거 결과나 다른 소유 프로세스의 주소는 대상 읽기를 거부한다.
- 상단 **Continue / Break**로 라이브 대상을 실행·중단한다. F5는 계속 실행하고 Disassembly가 활성화된 상태의 F10/F11은 단계 실행한다. **Follow IP**는 새 중단 위치를 따라가며 수동 코드 탐색은 추적을 멈춘다. 작업 취소용 **Cancel operation**은 Break와 별개다.
- 결과 탭마다 이름·순서·열·정렬·선택을 유지한다. 일반 창 닫기는 작업 화면을 보존하고 `!kndbgx`로 다시 연다. `!kndbgx shutdown`, 확장 언로드 또는 UI 문서 재생성은 이 상태를 해제한다.

대상 읽기에는 유효한 정지 상태가 필요하다. Busy나 컨텍스트 변경 중에도 기존 자료를 표시하지만 과거 주소에 대한 동작은 비활성화한다. 상세 사용법과 복구는 [작업 화면 안내](docs/UX.md)에 정리했다.

## 변경·수집·저장

등록된 메모리 변경은 전체 미리보기와 일회용 승인을 요구한다. 전역 쓰기 스위치는 없으며 기존 `policy` / `gate`는 제거 안내만 한다. UI의 브레이크포인트 Add/Delete는 미리보기 승인을 사용하고, Enable/Disable과 실행 제어는 클릭 시 컨텍스트에 연결된 작업을 적용한다. 덤프와 로컬 커널 세션에서는 이런 변경을 허용하지 않는다.

**UI에 직접 입력한 미등록 명령**은 WinDbg로 전달되며 WinDbg 자체 의미에 따라 대상이나 호스트를 변경할 수 있다. 등록된 이름은 KNDbgX 검증을 유지한다. CLI와 백그라운드 작업의 불투명한 엔진 실행에는 `raw --ack-effects <명령>`이 필요하다.

```text
!kndbgx plan eb <address> 41 42
!kndbgx approve <plan-id> <approval-token>
!kndbgx !snapshot "C:\captures\before"
!kndbgx !snapshot "C:\captures\after"
!kndbgx !diff "C:\captures\before" "C:\captures\after"
!kndbgx results
!kndbgx result-export <result-id> "C:\captures\result.json"
```

자리표시자를 실제 값으로 바꾸고 snapshot마다 완료를 기다린다. `jobs`, `job <id>`, `cancel <id>`로 비동기 작업을 확인·취소한다. 취소 요청 접수가 엔진 호출의 종료를 뜻하지는 않는다. Snapshot은 새 디렉터리를 요구하며, 서로 다른 세션의 비교에는 `/cross-session`이 필요하다. 불완전한 입력은 Partial로 유지한다.

**Export**는 화면 밖 행을 포함한 보존 결과 전체를 저장한다. 실패하면 경로와 Win32 오류를 표시하며, 남아 있는 결과를 다른 쓰기 가능한 경로로 저장할 수 있다. **Operations > Refresh outcomes**는 명령이나 저장을 반복하지 않고 보존된 작업 기록을 조회한다. **Open result**는 보존된 결과를 열고, **Copy saved path**는 확인된 내보내기 경로를 복사한다. 작업 기록은 만료되거나 정리될 수 있으며 DLL 언로드 후에는 남지 않는다. 결과 본문은 별도의 보존 한도를 적용하며, 탭으로 보호되지 않는 최근 결과 최대 16개와 UI 탭으로 보호된 결과 최대 128개가 64 MiB를 공유한다. 정리·언로드 전에 필요한 자료를 저장한다.

## 문서 안내

- [작업 화면](docs/UX.md): 명령 입력, 검사, 실행 제어, 결과 탭과 복구.
- [명령 명세](docs/COMMANDS.md): 문법·별칭·효과·기본 대상·세션 조건.
- [커널·드라이버 분석](docs/KERNEL_ANALYSIS.md), [심볼 지원](docs/SYMBOL_SUPPORT.md): 수집기·진단·프로필·해석 한계.
- [지원 환경](docs/SUPPORT.md): 대상 조건, 미지원 기능과 자원 한도.
- [검증 절차](docs/VALIDATION.md): 빌드 검사, 테스트 실행과 공개 전 확인 사항.
- [설계](DESIGN.md), [외부 구성요소](THIRD_PARTY_NOTICES.md).

저장소의 별도 `samples/snapshot-demo` 실습은 해당 폴더의 README.ko.md에서 빌드·서명·게스트 테스트 요구 사항을 설명한다. 확장 배포 패키지에는 포함하지 않는다. 배포 검증과 패키징 명령은 [배포 검증 절차](docs/VALIDATION.md#release-validation)를 참고한다.
