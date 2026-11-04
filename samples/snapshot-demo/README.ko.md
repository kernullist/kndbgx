# KNDbgX snapshot/diff 데모

Windows x64 VMware 게스트에서 콜백과 모듈의 전후 변화를 보여주는 WDM 드라이버와 제어 프로그램이다. `ObRegisterCallbacks`로 샘플 자신의 프로세스·스레드 객체 Pre/Post 콜백을 추가·교체·제거한다. 콜백은 핸들 생성·복제 이벤트 개수만 세며 접근 권한이나 작업 결과를 수정하지 않는다.

SSDT/IDT/MSR, 타 드라이버의 포인터, 프로세스·모듈 연결 목록을 직접 변경하지 않는다. 실제 은닉이나 흔적 삭제는 구현하지 않았다. 포인터 변조와 모듈 관찰 누락의 비교 화면은 별도의 **합성 snapshot**으로 재현한다. 합성 자료에는 `synthetic: true`와 `Synthetic:SnapshotDemo` 출처가 있으며, 실제 드라이버에서 얻은 증거와 섞지 않는다.

## 구성

- `driver/Driver.cpp`: 관리자/SYSTEM 전용 제어 장치, A/B 콜백 집합, 실패 시 등록 취소, 파일 객체 cleanup.
- `controller/Controller.cpp`: 서비스 파일 식별 확인, 실행·제어·정리, 오프라인 자체 검사와 게스트용 IOCTL 경계 검사.
- `controller/DeviceClient.h`: 응답의 phase·등록 비트 일관성과 요청 결과 검사. 정상 요청 양성 대조군과 오류 코드별 경계 검사.
- `Protocol.h`: METHOD_BUFFERED IOCTL과 고정 크기 ABI. 주소·오프셋·메모리 읽기/쓰기 요청은 받지 않는다.
- `fixtures/Fixtures.cpp`: 실제 제품의 snapshot 저장·읽기·비교 코드를 사용하는 합성 자료 생성기.
- `build.ps1`: 독립 프로젝트 빌드와 오프라인 검사. KNDbgX 본체 솔루션에는 추가하지 않았다.
- `sign.ps1`: 사용자가 명시한 기존 인증서로 SYS를 서명하고 정책 검증 결과를 별도로 기록한다.
- `Artifacts.ps1`, `test-scripts.ps1`: 빌드·서명 배타 잠금, 원자적 manifest 저장, 부분 실패·복구의 모의 검사.

## 빌드

Visual Studio 2022 C++ 도구, 같은 VS 설치에 연결된 WDK 확장, Python 3이 필요하다. 기본 SDK/WDK는 `10.0.26100.0`, 대상은 x64, 출력은 저장소의 `artifacts/snapshot-demo/Release`다. SDK/WDK가 다른 경우 `-SdkVersion`으로 지정한다.

```powershell
.\samples\snapshot-demo\build.ps1 -Configuration Release -Analyze
```

`KnSnapshotDemo.sys`, 대응 PDB/MAP, `KnSnapshotDemoCtl.exe`, `KnSnapshotDemoFixtures.exe`, `build-manifest.json`을 만든다. SYS와 두 EXE의 PDB GUID/Age, x64·ASLR·NX, SYS의 FORCE_INTEGRITY, 실행/쓰기 겸용 섹션 부재와 A/B Pre/Post 네 함수의 서로 다른 주소를 검사해 `artifact-verification.json`에 남긴다. 기본 빌드는 **미서명**이다. 빌드 스크립트는 서비스를 생성하거나 드라이버를 로드하지 않는다. 자체 검사는 SCM이나 디바이스를 열지 않으며, 합성 snapshot 검사는 사용자 모드 파일만 만든다.

manifest v2의 `state`는 `Building`, `Signing`, `Ready`, `Failed`를 구분한다. 사용 가능한 묶음은 `Ready`이며 여섯 바이너리/PDB의 크기와 SHA-256도 일치해야 한다. 빌드가 중간에 실패하면 이전 성공 manifest를 유지하지 않고 `Failed`로 표시한다. 중단되어 `Building`/`Signing`에 남은 디렉터리는 다시 빌드한다. 스크립트끼리는 같은 출력 디렉터리의 잠금을 사용하며, VS에서 프로젝트만 직접 빌드한 결과는 성공 묶음으로 취급하지 않는다.

서명할 때는 Code Signing EKU와 개인 키가 있는 기존 CurrentUser/My 인증서를 명시한다.

```powershell
.\samples\snapshot-demo\sign.ps1 -CertificateThumbprint <40자리-thumbprint>
```

이 스크립트는 인증서를 생성하거나 신뢰 저장소를 수정하지 않는다. 서명 적용, 호스트 Authenticode 검증, 호스트 커널 정책 검증을 구분한다. 테스트 인증서에서는 호스트의 `/kp` 검증이 실패할 수 있으며, 서명 적용에 성공했더라도 이 경우 별도 실패를 보고한다. 게스트의 신뢰 및 테스트 서명 정책은 별도로 준비해야 한다. Secure Boot·HVCI·서명 정책을 자동으로 변경하거나 우회하지 않는다.

서명 전에 `Ready`와 원본 해시를 확인하고 별도 SYS 복사본을 서명한다. 서명 도구가 파일 일부를 변경한 뒤 실패해도 원래 SYS를 보존한다. 선택한 인증서의 서명인지 확인한 뒤 결과를 교체하며, 적용에 성공했지만 정책 검증에 실패하면 실제 적용 바이트와 두 검증 종료 코드를 manifest에 남기고 실패를 보고한다. SYS 교체 후 manifest 저장이 실패하거나 파일 교체가 부분 실패하면 원본 복구를 시도한다. 복구가 불확실하거나 다른 입력이 바뀌었다면 `Ready`로 되돌리지 않으며, 복구용 백업이 남았다면 삭제하지 않는다.

드라이버는 `/INTEGRITYCHECK`로 링크한다. 객체 콜백은 서명 조건이나 altitude 충돌 때문에 거부될 수 있다. 거부 상태는 `registration=0x...`와 등록 비트에서 확인한다. 등록은 하나의 `ObRegisterCallbacks` 요청으로 수행하며 실패하면 Off 상태를 유지한다. A→B에서 B 등록이 실패하면 A는 이미 해제된 상태이고 오류와 Off 상태를 보고한다. altitude 값은 격리된 데모용이며 배포용 할당을 주장하지 않는다.

## 실제 VMware 데모

전체 PDB/MAP, 테스트 로그와 snapshot은 로컬 분석 자료다. 빌드 디렉터리를 그대로 ZIP으로 묶어 외부에 배포하지 않는다. SYS/EXE에는 PDB 파일명만 기록하고, 산출물 검증은 빌드 경로나 개인 경로가 남아 있으면 실패한다. 전체 PDB는 경로가 남을 수 있으므로 별도로 보관한다. 저장소의 [공개 범위와 검사](../../docs/VALIDATION.md#publication-boundary)도 참고한다.

SYS와 EXE는 **게스트**, KNDbgX와 snapshot 저장 경로는 **WinDbg 호스트**에 둔다. 게스트 복원 지점을 먼저 만들고, 기존 원격 KD 연결과 게스트의 드라이버 서명 조건을 준비한다. SYS를 다시 빌드했다면 대응 PDB도 교체한다.

호스트의 심볼 경로에 대응 PDB 디렉터리를 추가하면 `Callbacks<0>::Pre/Post`와 `Callbacks<1>::Pre/Post`를 구분하기 쉽다. 드라이버 로드 후 native WinDbg에서 다음과 같이 심볼을 갱신한다. 아래 경로는 호스트에 PDB를 복사한 디렉터리다.

```text
.sympath+ C:\lab\snapshot-demo-symbols
.reload /f KnSnapshotDemo.sys
```

호스트 WinDbg에서 처음에 게스트를 중단하고 baseline을 저장한다. 각 snapshot 작업이 끝났는지 `jobs`와 `job <id>`로 확인한 뒤 다음 단계로 진행한다. 기존 출력 디렉터리는 덮어쓰지 않는다.

```text
!kndbgx !snapshot "C:\evidence\demo-00-baseline"
```

게스트를 실행 상태로 돌린 뒤, 게스트의 관리자 콘솔에서 실행한다. 기본 경로는 제어 EXE 옆의 SYS다. 다른 경로는 두 번째 인자로 명시한다.

```powershell
.\KnSnapshotDemoCtl.exe run
```

처음에는 `phase=0 mask=0x00`이다. 모듈과 제어 장치만 로드된 상태다. 이후 순서는 다음과 같다.

1. 게스트에서 `A`를 누른다. `phase=1`, `mask=0x03`과 `operation=0x00000000`을 확인한다. 프로세스·스레드 각각에 Pre/Post 루틴이 생긴다.
2. 호스트에서 게스트를 중단하고 `demo-01-a` snapshot을 저장한다.
3. 게스트를 재개한 뒤 `B`를 누른다. A 콜백을 정상 해제하고 다른 주소의 B 콜백을 등록한다.
4. 다시 중단하고 `demo-02-b` snapshot을 저장한다.
5. 재개한 뒤 `O`를 누른다. `mask=0`과 성공 상태를 확인한다. 중단하고 `demo-03-off`를 저장한다.
6. 재개한 뒤 `Q`로 종료한다. 이번 실행이 시작한 서비스는 정지하고, 이번 실행이 만든 서비스만 삭제한다. 중단하고 `demo-04-unloaded`를 저장한다.

호스트 명령 예시는 다음과 같다. snapshot마다 완료 후 게스트 재개/다음 입력/중단 순서를 지킨다.

```text
!kndbgx !snapshot "C:\evidence\demo-01-a"
!kndbgx !snapshot "C:\evidence\demo-02-b"
!kndbgx !snapshot "C:\evidence\demo-03-off"
!kndbgx !snapshot "C:\evidence\demo-04-unloaded"
!kndbgx !diff "C:\evidence\demo-00-baseline" "C:\evidence\demo-01-a"
!kndbgx !diff "C:\evidence\demo-01-a" "C:\evidence\demo-02-b"
!kndbgx !diff "C:\evidence\demo-02-b" "C:\evidence\demo-03-off"
!kndbgx !diff "C:\evidence\demo-00-baseline" "C:\evidence\demo-04-unloaded"
```

예상 차이는 baseline→A의 모듈·콜백 추가, A→B의 루틴 주소 변경 또는 등록 삭제/추가, B→Off의 콜백 삭제다. 등록 객체가 재할당될 수 있어 A→B의 모든 행이 `Changed`가 되는 것은 아니다. 마지막 비교에도 다른 프로세스나 드라이버의 변화가 남을 수 있다.

콜백 목록이 불완전하거나 guest NT/PDB의 private layout을 지원하지 않으면 `Unknown`/`Partial`/`Unavailable`이 정상적인 제한 보고다. `!callbacks`는 모든 Windows 빌드를 지원하지 않는다. 해당 상황을 드라이버 실패나 은닉 성공으로 해석하지 않는다. 활성 phase의 필수 등록 비트는 드라이버가 정상 API 등록에 성공했음을 뜻하며 KNDbgX의 수집 성공과 별도로 확인한다.

snapshot에 자동 포함되는 대상은 현재 프로세스·모듈·콜백·SSDT·IDT·제어 레지스터·HAL이다. 샘플 제어 장치와 디스패치를 따로 보고 싶으면 `!kndbgx !drvobj \Driver\KnSnapshotDemo`를 실행한다. 이 결과는 snapshot에 자동 추가되지 않는다. 이 드라이버는 SSDT·IDT·제어 레지스터·HAL을 변경하지 않는다.

## 수명과 정리

장치는 배타적으로 열리며 같은 파일 객체의 중복 핸들은 마지막 핸들이 닫힐 때 cleanup한다. 콜백은 세션 메모리를 참조하지 않고 resident 정적 코드와 interlocked 카운터만 사용한다. 전환·해제는 PASSIVE_LEVEL의 mutex 아래에서 직렬화하며 콜백 자체는 이 mutex를 잡지 않는다.

`Ctrl+C`/`Ctrl+Break`는 서비스 준비·시작 단계부터 취소를 요청할 수 있다. 시작 중 취소해도 이번 실행이 만든 항목과 시작한 서비스만 정리한다. 네이티브 서비스 호출 내부를 강제로 중단하지는 않으며, 호출이 반환된 뒤 취소를 처리한다. 강제 종료나 콘솔 강제 닫기에서도 장치 핸들이 닫히면 드라이버의 `IRP_MJ_CLEANUP`이 콜백을 해제한다. 강제 종료에서는 사용자 모드의 서비스 정리는 보장되지 않는다. 등록 핸들은 한 번만 `ObUnRegisterCallbacks`로 해제하고, Off·cleanup·unload에서 같은 정리 함수를 사용한다. unload 함수는 DriverEntry에서 고정 등록하며 실행 중 교체하지 않는다.

열린 제어 장치가 있는 동안 서비스 언로드는 완료되지 않을 수 있다. 정상 흐름은 `O` 또는 `Q`다. 남은 서비스의 명시적 정리는 다음 명령을 사용한다. 설정된 서비스가 지정한 SYS와 같은 파일인지 확인하고, 다른 바이너리이거나 식별할 수 없으면 중지·삭제하지 않는다.

```powershell
.\KnSnapshotDemoCtl.exe remove "C:\lab\KnSnapshotDemo.sys"
```

기존 서비스가 실행 중이었다면 일반 `run` 종료에서 그 서비스를 중지하거나 삭제하지 않는다. 기존 정지 서비스만 시작했다면 종료 시 정지하고 서비스 항목은 유지한다. 새로 만든 서비스는 정지 후 삭제하며, 실패하면 남은 상태를 보고한다.

소유권 확인은 서비스 종류·설정 경로·볼륨/파일 ID를 확인하고 파일을 읽기 전용으로 고정한다. 파일 ID가 같은 다른 NTFS 스트림을 동일한 바이너리로 오인하지 않도록 대체 데이터 스트림 경로는 거부한다. UNC·상대 서비스 경로·추가 인자와 파일 ID 확인 실패도 거부한다. 다른 관리자가 동시에 서비스를 정지·재시작하거나 설정을 바꾸는 상황에 대한 실서비스 경쟁 검증은 수행하지 않았다.

## 합성 변조·관찰 누락 화면

빌드 중 생성된 `fixtures-*` 디렉터리 또는 다음 명령의 출력 디렉터리를 사용한다. 부모 디렉터리는 존재해야 하고 마지막 디렉터리는 새 경로여야 한다.

```powershell
.\KnSnapshotDemoFixtures.exe "C:\evidence\synthetic-demo"
```

합성 before/after는 콜백·서비스 테이블·IDT·CR4 값 변화와 모듈 기록 누락을 담는다. 모듈 기록 누락은 `Removed`가 어떻게 표시되는지 보여주는 입력일 뿐, 실제 은닉의 증거가 아니다. incomplete 입력은 같은 모듈 누락에 불완전한 수집 범위를 부여해 `Unknown`이 유지되는지 보여준다.

```text
!kndbgx !diff "C:\evidence\synthetic-demo\synthetic-before" "C:\evidence\synthetic-demo\synthetic-after"
!kndbgx !diff "C:\evidence\synthetic-demo\synthetic-before" "C:\evidence\synthetic-demo\synthetic-incomplete"
```

`checksum-negative-control`은 체크섬 거절 검사 후 의도적으로 불일치하는 별도 입력이다. 정상 데모에는 사용하지 않는다. 생성기는 제품의 저장·읽기·비교 코드를 직접 호출하고, 출력 보존·완료 해시·확인된 변경과 미확인 누락의 구분을 검사한다. 합성 주소는 실제 대상의 주소로 탐색하지 않는다.

## 검증 범위

빌드 검사는 산출물의 PDB 참조·GUID/Age·이미지 속성·콜백 주소와 제어 프로그램·합성 snapshot 동작을 확인한다. 사용한 도구 버전과 결과는 해당 실행의 로그 및 `build-manifest.json`으로 확인한다. 이 절차는 드라이버를 자동으로 서명하거나 로드하지 않는다.

빌드와 사용자 모드 검사만으로 VMware 로드, 실제 콜백 실행·해제, 서명 정책, 서비스 경쟁, Driver Verifier 통과를 주장하지 않는다. 게스트의 `T` 검사는 먼저 현재 phase에 대한 정상 요청이 성공하는지 확인한다. 이후 잘못된 IOCTL 길이·버전·예약 필드·phase·명령과 Query 입력을 보내 각각의 Win32 오류 코드, 반환 바이트, 제어 상태/generation 불변을 확인한다. 쓰기가 전부 거부되는 장치는 양성 대조군을 통과할 수 없다. 이 게스트 검사는 기본 빌드 검사에 포함되지 않는다.

`test-scripts.ps1`은 합성 파일과 모의 서명 함수를 사용한다. 실제 인증서 저장소나 서명 도구를 호출하지 않으며, 실패 복구 경고를 의도적으로 주입하는 검사가 있다. 이 결과는 실제 PKI·Secure Boot·HVCI·게스트 로드를 검증한 증거가 아니다.

지원 목표는 Windows 10/11 x64 WDM 실험 환경이다. 실제 검증한 컴파일러·WDK·검사 수와 미수행 항목은 작업 결과와 `build-manifest.json`으로 확인한다. VAD/PTE 은닉, 작은 풀, 전체 커널 무결성, 악성코드 탐지율은 이 샘플의 검증 범위가 아니다.

공식 계약: [객체 콜백 등록](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks), [객체 콜백 해제](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obunregistercallbacks), [장치 ACL](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/sddl-for-device-objects).
