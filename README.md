# ShareHub (C++)

Windows 폴더와 iPhone 사이에서 파일을 주고받는 로컬 Wi-Fi 공유 앱입니다. 아이폰에서는 Safari를 사용합니다.

Visual Studio Developer Command Prompt에서 빌드:

```bat
cl /std:c++17 /EHsc /O2 sharehub.cpp ws2_32.lib /Fe:sharehub.exe
sharehub.exe
```

또는 MinGW-w64에서 `g++ -std=c++17 -O2 sharehub.cpp -lws2_32 -o sharehub.exe`로 빌드합니다. `build-and-run.bat`은 설치된 컴파일러를 찾아 빌드하고 실행합니다.

기본 공유 폴더는 실행 위치의 `Shared`입니다. 다른 폴더와 포트는 `sharehub.exe "C:\경로\폴더" 8765`처럼 지정할 수 있습니다. 콘솔 주소를 같은 Wi-Fi의 iPhone Safari에서 여세요. 파일은 메모리에 통째로 적재하지 않고 256 KiB 청크로 스트리밍하며, 여러 접속을 동시에 처리합니다. 네트워크 버퍼도 4 MiB로 설정합니다.

서버는 직접 실행한 동안만 켜지고 실행마다 임의 접속 토큰을 생성합니다. HTTP를 사용하므로 신뢰하는 개인 Wi-Fi에서 실행하고, Windows 방화벽은 사설 네트워크에서만 허용하세요. 업로드 한도는 파일당 2 GiB입니다. Bluetooth 전송은 지원하지 않습니다.
