# OTA System Setup & Execution Guide

이 문서는 국민대학교 자동차융합대학 차량보안동아리 KUSE 2025-2 'Secure OTA' 프로젝트 구현 내용에 대한 설명입니다.

------------------------------------------------------------------------

## OEM Server(chunking_watchdog.py)
업데이트 할 컨테이너 이미지 압축 파일을 확인하여, FastCDC를 활용한 chunk 분할 및 manifest를 생성합니다.

- `OTA_Dircector_Server/src_add/stage`: 업데이트 이미지 업로드 디렉토리

### 수행절차
1. 컨테이너 이미지 FastCDC 기반 Chunk 분할 및 저장 -> 중복 제거
2. Global Target metadata 생성 및 OTA 서버로 배포(Image, Director)
3. Image Repository의 chunk_storage 및 manifest 업데이트

## Image Repository(Image_Repository_ver2.py)
Chunk 저장소와 Manifest를 제공하는 역할로, 전체 이미지에 대한 메타데이터 관리

- `OTA_Dircector_Server/Image_Repo/chunk_storage`: Chunk 저장소
- `OTA_Dircector_Server/Image_Repo/meta`: metadata 및 manifest 관리

### 수행절차
1. Target 메타데이터가 수정되면, Snapshot, Timestamp 메타데이터를 순차적으로 갱신
2. Flask 서버를 통해 `chunk_storage`와 `meta` 서비스
3. Vehicle로부터 메타데이터 요청을 수신하면 Timestamp 및 base Url 전달(MQTT)
4. 나머지 메타데이터 및 chunk 관련 정보는 모두 HTTPS를 통해 서비스

## Director Repository(main.py)
Vehicle의 상태 정보를 바탕으로 업데이트 정보 판단 및 생성하는 역할

- `Director/meta`: metadata 및 manifest 관리

### 수행절차
1. Vehicle이 publish 한 VVM 정보를 수신
2. Global Target metadata와 VVM 비교를 통해 업데이트 할 Target 메타데이터 생성(`target_per_vehicle.json`)
3. 생성된 Target 메타데이터를 기반으로, Snapshot, Timestamp 메타데이터 생성
4. 모든 메타데이터를 MQTT를 통해 publish

## Primary ECU(Primary_ECU.py)
VVM 정보를 기반으로 생성된 업데이트 정보 검증 및 다운로드

- `Primary_ECU/downloads`: Image Repository로부터 다운로드 한 모든 데이터 관리

### 수행절차
1. VVM 정보를 publish
2. 수신한 Director Repository의 모든 메타데이터 서명 검증
3. 수신한 Image Repository의 메타데이터 순차적 서명 검증
4. Director와 Image의 target 이미지에 대한 교차 검증
5. Manifest 및 chunk 다운로드



# 프로젝트 사용 방법
## 📌 1. MQTT 및 HTTP 인증서 제작 및 설정

MQTT 브로커와 Flask 서버 통신을 위해 필요한 인증서를 제작하고 아래
경로에 배치합니다.

-   `OTA_Director_Server/src/utils/certs`
-   `Primary_ECU/utils/certs`

인증서 제작 방법 참고:\
🔗 https://www.notion.so/Linux-2484ccbeeb28809ca4dcd98faaedbfdd?pvs=21

------------------------------------------------------------------------

## 📌 2. MQTT 브로커 및 Flask 서버 IP 설정

다음 파일에서 MQTT 및 HTTP 서버 IP 주소를 환경에 맞게 수정합니다.

-   `OTA_Director_Server/src/Image_Repository.py`
-   `Primary_ECU/Prime_ECU.py`

------------------------------------------------------------------------

## 📌 3. Chunking Watchdog 실행

이미지 chunking 상태를 모니터링하기 위해 watchdog을 실행합니다.

``` bash
python3 OTA_Director_Server/src/chunking_watchdog.py
```

------------------------------------------------------------------------

## 📌 4. Image Repository 실행

컨테이너 이미지 chunk 생성 및 OTA 파일 배포 기능을 수행하는 Image
Repository를 실행합니다.

``` bash
python3 OTA_Director_Server/src/Image_Repository.py
```

------------------------------------------------------------------------

## 📌 5. 컨테이너 이미지 준비 및 배포 파일 배치

OTA 업데이트에 사용할 `ivi_0.0.0.tar.xz` 파일을 아래 디렉터리에
배치합니다.(`ecu_버전.tar.xz` 이름 형식 주의)

-   `OTA_Director_Server/src_add/stage`
- Image Repository가 파일 변화 시점을 감지해야 하므로, Image Repository가 실행되고 있어야 함

이미지는 Docker Hub에서 가져와 oci-archive 형식으로 변환해 사용합니다.

``` bash
podman pull hanbin6157/seame_hu_app:1.0.0
podman save --format oci-archive -o ivi_2.0.0.tar.xz seame_hu_app:1.0.0
```

------------------------------------------------------------------------

## 📌 6. Director Repository 실행

VVM 정보를 수신하고, 업데이트 정보를 생성하는 Director Repository 실행

``` bash
python3 Director/main.py
```

------------------------------------------------------------------------

## 📌 6. Prime ECU 실행

ECU 측에서 업데이트 요청 및 수신을 담당하는 Prime ECU 프로그램을
실행합니다.

``` bash
python3 Primary_ECU/Prime_ECU.py
```

------------------------------------------------------------------------

## 📌 7. 컨테이너 이미지 빌드 및 자동 실행

Prime ECU 실행과 동시에 다운로드가 진행되며, Prime ECU에서 전송된 이미지로 컨테이너를 자동 빌드 및
실행 됨

------------------------------------------------------------------------

## ⚠️ 키 및 인증서 확인
    1. 최상위 디렉터리에 `root_keys`디렉터리를 생성하고, 아래의 키가 존재해야 함
    - root1_pub.pem
    - root1.pem
    - root2_pub.pem
    - root2.pem
    - root3_pub.pem
    - root3.pem
    - snapshot_pub.pem
    - snapshot.pem
    - targets_pub.pem
    - targets.pem
    - timestamp_pub.pem
    - timestamp.pem

    2. root.py 실행하면 Image, Director Repository에 root 메타데이터 생성
    3. 각 영역에 snapshot, targets, timestamp 키 쌍 존재해야 함
    - OTA_Director_Server/keys
    - Director/keys

    4. OTA_Director_Server/keys 에 업데이트할 이미지에 대한 키 쌍 임의 생성
      ex) ivi.pem, ivi_pub.pem

    5. Primary_ECU/make_vvm.py 실행으로 root_vvm 및 vvm 생성 가능

    6. 그 외 MQTT, HTTPS 관련 인증서 확인

------------------------------------------------------------------------

