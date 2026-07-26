# LocalGate: Zero-Trust Python Package Isolation & In-Memory Execution OS

[English](#english) | [한국어](#한국어)

---

# English

LocalGate is an enterprise-grade, zero-trust security framework that controls the Python 가상 머신 (VM) module search and loading mechanisms. It blocks vulnerable or tampered public storage (`site-packages`), compiles validated dependencies into a secure encrypted vault (`.vault/`), and loads modules directly in-memory (RAM) on-demand.

## Key Features & Core VM Hijacking Technologies

1. **`sys.meta_path` Hijacking Guard**
   Installs `LocalGateFinder` as the absolute number 1 finder in `sys.meta_path` to preemptively block imports from `site-packages`, defending against supply chain attacks.
2. **Virtual File System I/O Interceptor**
   Globally wraps Python's built-in `builtins.open` function. If a loaded module requests package resources (e.g. `certifi` loading `cacert.pem`) via standard I/O relative paths, LocalGate intercepts and streams the data directly from the encrypted memory ZIP.
3. **In-Memory Bytecode Cache**
   Stores compiled Code Objects in RAM (`LocalGateFinder._code_cache`). Prevents redundant decryption and compilation cycles, achieving faster-than-disk module load times.
4. **Cryptographic Key Separation**
   Eliminates hardcoded credentials. It derives a secure signature token by hashing the `LICENSE.md` file integrity and an execution-bound seed. If the license is tampered with or removed, the vault will fail to decrypt.

---

## Installation

```bash
pip install -e .
```

## Quick Start

### 1. Initialize local vault
```bash
localgate init
```
This creates a `.vault/` directory in your current workspace.

### 2. Trace & Pack Dependencies
```bash
localgate pack requests colorama
```
Automatically resolves the dependency trees (e.g. `urllib3`, `certifi`, etc.) and compiles them into a single encrypted archive `.vault/packages.bin`.

### 3. Run Securely
```bash
localgate run your_script.py
```
Launches your script under the zero-trust shield. Any unauthorized imports from `site-packages` will raise a security exception.

---

## License & Commercial Restrictions
Copyright (c) 2026 SANGHA1986. All rights reserved.
Licensed under the Business Source License 1.1 (BUSL-1.1 Custom).

* **Free Use**: Individuals and non-profit organizations with annual revenues under **KRW 300,000,000 (approx. USD 250,000)** can use this for non-commercial or testing purposes.
* **Commercial Restrictions**: Any enterprise or entity exceeding **KRW 300,000,000 (USD 250,000)** in annual revenue is strictly prohibited from copying, deploying, or utilizing this software without signing a separate Commercial License Agreement with **SANGHA1986**. Unauthorized commercial use is subject to civil liabilities and criminal prosecution.

---

# 한국어

LocalGate는 파이썬 가상 머신(VM)의 모듈 검색 및 로딩 메커니즘을 전적으로 통제하는 엔터프라이즈급 제로-트러스트 보안 프레임워크입니다. 해킹 우려가 있는 공용 창고(`site-packages`)를 차단하고, 검증된 패키지들을 프로젝트 내부의 암호화 비밀 금고(`.vault/`)로 밀봉하여 메모리(RAM) 상에서 실시간으로 복호화 실행합니다.

## 핵심 기능 및 3대 원천 VM 제어 기술

1. **`sys.meta_path` 하이재킹 가드**
   `LocalGateFinder`를 파이썬 모듈 주소록(`sys.meta_path`)의 0순위에 삽입하여, 인가되지 않은 외부 패키지의 임포트 시도를 탐지하고 차단합니다.
2. **가상 파일 시스템 I/O 인터셉터**
   내장 `builtins.open` 함수를 글로벌하게 랩핑하여 가상화합니다. 암호화된 모듈이 내부 리소스 파일(예: `certifi` 패키지의 `cacert.pem`)을 조회할 때, 파일 입출력을 가로채어 메모리 ZIP 가상 파일 스트림으로 자동 반환합니다.
3. **인메모리 바이트코드 캐시**
   최초 1회 복호화되어 컴파일된 코드 객체(Code Object)를 RAM 상에 영구 유지(`LocalGateFinder._code_cache`)하여, 중복 참조 시 컴파일 오버헤드를 제로화하고 디스크 속도를 압도하는 성능을 제공합니다.
4. **암호학적 키 분리 구조**
   코드 내에 암호화 키를 하드코딩하지 않습니다. `LICENSE.md` 파일의 무결성 해시값과 내부 서명 시드를 결합하여 런타임에 동적으로 유도합니다. 라이선스 파일이 변조되거나 삭제되면 금고 해독이 원천 차단됩니다.

---

## 설치 방법

```bash
pip install -e .
```

## 사용법

### 1. 보안 금고 초기화
```bash
localgate init
```
현재 작업 폴더에 `.vault/` 디렉토리를 생성합니다.

### 2. 패키지 및 종속성 역추적 밀봉
```bash
localgate pack requests colorama
```
지정한 패키지의 종속 라이브러리(예: `urllib3`, `certifi` 등)까지 자동으로 역추적하여 암호화 밀봉 파일 `.vault/packages.bin`을 구축합니다.

### 3. 제로-트러스트 격리 실행
```bash
localgate run your_script.py
```
보안 쉴드가 장착된 상태에서 스크립트를 구동합니다. 금고 외부의 비인가 모듈 임포트 시도 시 보안 예외가 즉각 발생합니다.

---

## 라이선스 및 사용 제한
Copyright (c) 2026 SANGHA1986. All rights reserved.
Licensed under the Business Source License 1.1 (BUSL-1.1 Custom).

* **무상 사용 범위**: 연 매출 **3억 원(USD 250,000 상당)** 이하의 개인 개발자 및 비영리 단체는 비상업적 학습 목적으로 무상 사용이 가능합니다.
* **상업적 도용 제한**: 연 매출 **3억 원(USD 250,000 상당)**을 초과하는 대기업 및 영리 기업은 저작권자 **SANGHA1986**과의 별도 상용 계약 체결 없이 본 소프트웨어를 무단 도용, 임베딩, 혹은 납품할 수 없습니다. 위반 시 강력한 형사 처벌 및 손해배상 소송의 대상이 됩니다.
