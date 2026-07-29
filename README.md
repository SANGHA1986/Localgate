# LocalGate

LocalGate prevents untrusted Python packages from entering runtime.  
Most Python apps trust `site-packages` by default. LocalGate trusts only your vault.  
If it is not packed and encrypted, it does not execute.

**Positioning:** Zero-Trust Package Execution OS for Python

---

## 🇺🇸 English

### Problem
Python supply-chain attacks usually enter through dependency resolution paths.
Once malicious code is imported, your process is already compromised.

### Solution
LocalGate enforces a vault-first execution model.

- Blocks unauthorized imports from global package storage
- Loads approved modules from encrypted `.vault/packages.bin` in memory
- Verifies integrity at runtime before execution

### 3-Second Flow

```text
[ Script Starts ]
      |
      v
[ Import Request ]
      |
      v
[ In Vault? ] -- no --> [ Block Import ]
      |
     yes
      v
[ Decrypt in RAM -> Execute ]
```

### Core Components
1. **LocalGateFinder**: zero-trust import control on `sys.meta_path`
2. **LocalGatePacker**: dependency trace and encrypted vault build
3. **LocalGateCrypto**: authenticated encryption/decryption for vault integrity

### Installation
```bash
pip install -e .
```

### Quick Start
```bash
localgate init
localgate pack requests colorama
localgate run your_script.py
```

### Evidence (Demo)
This is a reproducible local demo result (not a customer case study).

```text
$ LocalGateCrypto.encrypt/decrypt
roundtrip True
cipher_len 84
tamper_blocked yes
```

### License
BUSL-1.1 Custom. See `LICENSE.md` for commercial restrictions.

---

## 🇰🇷 한국어

### 문제
파이썬 공급망 공격은 대부분 의존성 임포트 경로에서 시작됩니다.
악성 코드가 한 번 로딩되면 이미 런타임은 오염된 상태가 됩니다.

### 해결
LocalGate는 금고(vault) 기반 실행 정책을 강제합니다.

- 전역 패키지 저장소(`site-packages`)의 비인가 임포트 차단
- 승인된 모듈만 암호화 금고에서 메모리 로드
- 실행 전 무결성 검증 실패 시 즉시 차단

### 3초 이해 흐름도

```text
[ 스크립트 시작 ]
      |
      v
[ 임포트 요청 ]
      |
      v
[ 금고에 존재? ] -- 아니오 --> [ 임포트 차단 ]
      |
     예
      v
[ RAM 복호화 -> 실행 ]
```

### 핵심 구성 요소
1. **LocalGateFinder**: `sys.meta_path` 기반 제로트러스트 임포트 제어
2. **LocalGatePacker**: 의존성 추적 및 암호화 금고 생성
3. **LocalGateCrypto**: 무결성 검증 포함 암복호화 엔진

### 설치 방법
```bash
pip install -e .
```

### 빠른 시작
```bash
localgate init
localgate pack requests colorama
localgate run your_script.py
```

### Evidence (데모)
아래는 실제 고객 사례가 아니라, 로컬에서 재현 가능한 데모 결과입니다.

```text
$ LocalGateCrypto.encrypt/decrypt
roundtrip True
cipher_len 84
tamper_blocked yes
```

### 라이선스
BUSL-1.1 Custom. 상업적 이용 조건은 `LICENSE.md`를 확인하세요.
