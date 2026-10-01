# ShareHub — C++ Windows ↔ iPhone 파일 공유

같은 Wi-Fi에서 Windows 공유 폴더와 iPhone Safari 사이에 파일을 주고받습니다. Windows 앱을 직접 실행한 동안만 서버가 켜지며, 전송 내역이 실행 창에 표시됩니다. 기본 공유 폴더는 앱 옆의 `Shared`입니다.

| 항목 | 보안 모드 (기본값) | 비보안 모드 |
| --- | --- | --- |
| 실행 | `start-secure.bat` | `start-basic.bat` |
| 명령 | `sharehub.exe --mode secure` | `sharehub.exe --mode basic` |
| 전송 | HTTPS / Windows Schannel TLS 1.2 | HTTP / 암호화 없음 |
| 최초 설정 | Windows 인증서 생성, iPhone 인증서 신뢰 설정 | 인증서 설정 불필요 |
| 연결 코드 · 로그인 | 실행마다 새 코드, 30분 세션 | 동일. 코드와 파일은 평문 전송 |
| 폴더 제한 · 기존 파일 보호 | 적용 | 적용 |

모드는 실행할 때 선택합니다. 실행 창과 브라우저 모두 현재 모드를 표시합니다. 보안 모드에서 인증서가 없거나 만료되면 서버가 시작되지 않으며 비보안 모드로 자동 전환하지 않습니다. 비보안 모드는 신뢰하는 개인 Wi-Fi에서만 사용하세요.

## 바로 실행하기

`sharehub.exe`가 있으면 원하는 모드의 `.bat`을 실행합니다. 새로 빌드하려면 `build-and-run.bat`을 실행하고 모드를 선택하세요. 실행 창의 주소를 같은 Wi-Fi의 iPhone Safari에서 열고 `Pairing code`에 표시된 코드를 로그인 화면에 입력합니다. 파일을 선택해 업로드하거나, 목록의 파일을 눌러 다운로드합니다. 종료는 Windows 실행 창에서 `Ctrl+C`를 누릅니다.

연결 코드는 URL과 파일에 저장하지 않습니다. 연결된 iPhone에서는 `연결 종료` 버튼으로 세션을 해제할 수 있습니다. 업로드 대상에 같은 이름의 파일이 있으면 거절하므로, 새 이름으로 업로드하세요.

## 보안 모드 최초 설정

Windows PowerShell에서 앱 폴더로 이동한 뒤 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup-https.ps1
```

특정 PC 주소를 지정하려면 `-IpAddress 192.168.0.10`을 추가합니다. 스크립트는 사설 IPv4 주소를 인증서에 포함하며, Windows 현재 사용자 인증서 저장소에 로컬 CA와 서버 인증서를 만듭니다. RSA 3072 / SHA-256을 사용하고 개인 키는 내보내기 불가로 생성합니다. 서버 인증서는 90일, CA는 1년간 유효합니다. 방화벽이나 신뢰 저장소 설정을 자동으로 바꾸지 않습니다.

생성되는 `root-cert.cer`는 공개 CA 인증서이고, `tls-cert.txt`는 서버 인증서의 저장소 식별자입니다. 공개 인증서를 신뢰하는 경로로 iPhone에 옮기고, Windows 창에 표시된 SHA-256 지문을 확인해 설치하세요. iPhone에서는 설치 후 **설정 → 일반 → 정보 → 인증서 신뢰 설정**에서 해당 CA의 전체 신뢰를 켜야 합니다. [Apple 공식 인증서 신뢰 안내](https://support.apple.com/en-ie/102390).

그다음 `start-secure.bat`을 실행해 `https://PC주소:8765/`로 접속합니다. 인증서 경고가 있으면 IP 주소, 만료일, 신뢰 설정을 확인하세요. 경고를 무시하고 연결 코드를 입력하지 마세요. PC 주소가 바뀌거나 인증서가 만료되면 스크립트를 다시 실행하고 새 CA 인증서를 iPhone에 설치해야 합니다. 반복 실행으로 만든 이전 인증서는 Windows 인증서 관리자에서 확인 후 제거할 수 있습니다.

## 옵션과 빌드

공유 폴더, 포트, 사용할 네트워크 주소를 지정할 수 있습니다.

```bat
sharehub.exe --mode secure --folder "C:\공유 폴더" --port 8765
sharehub.exe --mode basic --folder "C:\공유 폴더" --bind 192.168.0.10
sharehub.exe --mode secure --read-only
```

`--read-only`는 업로드를 차단합니다. `--cert-thumbprint`로 다른 서버 인증서를 지정할 수 있습니다. 기본 설정에서는 `tls-cert.txt`의 식별자를 사용합니다. `--local-http`는 개발용으로 HTTP를 `127.0.0.1`에만 바인딩합니다. 기본값은 IPv4 사설 인터페이스의 HTTPS이고 공인 IP 클라이언트는 거절합니다.

Visual Studio Developer Command Prompt:

```bat
cl /std:c++17 /utf-8 /EHsc /O2 /MT sharehub.cpp ws2_32.lib bcrypt.lib secur32.lib crypt32.lib shell32.lib /Fe:sharehub.exe
```

MinGW-w64:

```bat
g++ -std=c++17 -O2 -Wall -Wextra sharehub.cpp -lws2_32 -lbcrypt -lsecur32 -lcrypt32 -lshell32 -o sharehub.exe
```

서버 실행에 Python이나 OpenSSL은 필요하지 않습니다. MinGW 빌드는 해당 배포판의 C++ 런타임 DLL이 필요하므로 컴파일러의 `bin` 폴더가 PATH에 있어야 합니다. Windows 방화벽이 묻는 경우 사설 네트워크 접근을 허용해야 합니다. 게스트 Wi-Fi의 기기 간 격리 설정은 연결을 막을 수 있습니다.

## 공통 보호 기능과 범위

- Windows CNG 보안 난수로 생성한 연결 코드, 세션 ID, 요청 토큰.
- 로그인 실패를 IP마다 1분당 5회로 제한하고 활성 세션은 최대 16개로 제한.
- HttpOnly / SameSite=Strict 세션 쿠키. HTTPS 모드는 Secure / `__Host-` 쿠키 사용.
- Host, Origin, CSRF 토큰 검사 및 콘텐츠 보안 정책으로 다른 사이트의 업로드 요청 차단.
- `..`, 절대 경로, Windows 장치 이름, 대체 데이터 스트림, 정션, 심볼릭 링크, 하드링크 접근 차단. 실제 파일 핸들의 최종 위치도 검증.
- 업로드를 임시 파일에 스트리밍한 후 열린 핸들로 이름을 변경. 완료 전에는 대상 파일을 노출하지 않고 기존 파일을 덮어쓰지 않음.
- 최대 8개 작업 스레드와 8개 대기 연결, 헤더/접속/전송 시간 제한으로 자원 사용 제한.

파일당 업로드는 최대 2 GiB이고, 단일 전송은 최대 30분입니다. 목록은 폴더당 최대 5,000개를 표시합니다. 강제 종료나 전원 차단 시 숨겨진 `.sharehub-upload-*.part`가 남을 수 있으나, 서버가 실행 중이 아닐 때 삭제할 수 있습니다. 공유 폴더는 로컬 디스크의 일반 폴더여야 하며, 정션이나 클라우드 자리 표시자 경로는 사용할 수 없습니다. 앱을 실행하는 Windows 사용자의 파일 권한을 사용하며 다른 로컬 프로그램이나 관리자와 파일 시스템을 격리하는 샌드박스는 아닙니다. 이 버전은 Wi-Fi 공유를 지원하고 Bluetooth는 지원하지 않습니다.

256 KiB 청크 스트리밍과 재사용 TLS 버퍼로 파일을 메모리에 통째로 올리지 않습니다. 실제 속도는 Wi-Fi와 저장 장치에 따라 달라집니다. Windows 로컬 루프백 검증에서 8 MiB 업로드·다운로드의 합산 처리량은 HTTP 약 307 MiB/s, HTTPS 약 222 MiB/s였습니다. 이 수치는 iPhone/Wi-Fi 성능 측정이 아닙니다.

## 검증

빌드 후 `python -X utf8 tools/verify_security.py`로 실제 서버를 사용한 11개 통합 검증을 실행할 수 있습니다. 로그인, 쿠키, CSRF, 경로/정션/하드링크 차단, 덮어쓰기 방지, 중단 전송 정리, HTTP 프레이밍, 동시 전송, 읽기 전용 공유, 인증서 신뢰 확인, 인증서 없이 HTTPS 시작 거절을 검사합니다. 검증은 임시 CA와 서버 인증서를 현재 사용자 저장소에 만들고 종료 시 개인 키와 함께 제거하며, 시스템 신뢰나 방화벽 설정은 변경하지 않습니다.

구현 참고: [Windows 보안 난수](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom), [Windows 파일 이름 제한](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file), [OWASP CSRF 방어](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
