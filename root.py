#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Uptane/TUF root 메타데이터 생성 + 서명 스크립트 (업데이트 버전)
- root: RSA 3키, threshold=2
- snapshot/targets/timestamp: Ed25519 공개키 사용 (PEM → RAW 32B → hex 로 keyval.public 저장)
- expires: 현재 한국 시간(Asia/Seoul) 기준 + 1년(업계 관행) 후, UTC 'Z' 포맷
- 출력: 1.root.json (필드 순서는 예시와 동일)
"""

import json
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from pathlib import Path

try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:
    from backports.zoneinfo import ZoneInfo  # backports 패키지 필요
    
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ====== 설정(필요 시 수정) =====================================================

# 공개키(PEM)
ROOT_PUBS = ["root1_pub.pem", "root2_pub.pem", "root3_pub.pem"]   # RSA 공개키 3개
SNAPSHOT_PUB = Path("./root_keys/snapshot_pub.pem")                                  # Ed25519 공개키
TARGETS_PUB  = Path("./root_keys/targets_pub.pem")                                 # Ed25519 공개키
TIMESTAMP_PUB= Path("./root_keys/timestamp_pub.pem")                              # Ed25519 공개키

# 서명에 사용할 RSA 개인키(PEM) 2개 — threshold=2 충족
SIGNING_PRIVS = ["root1.pem", "root2.pem"]

# 스펙/버전
SPEC_VERSION = "1.0.0"
VERSION = 1
CONSISTENT_SNAPSHOT = False

# 만료: 한국시간 '지금' 기준 + 1년 → UTC 'Z'
def make_expires_iso8601_kst_plus_year() -> str:
    now_kst = datetime.now(ZoneInfo("Asia/Seoul"))
    exp_kst = now_kst + timedelta(days=365)  # 업계에서 root는 보통 장기(1년~수년); 여기선 1년 적용
    return exp_kst.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# =============================================================================
# 유틸

def read_text(path: str) -> str:
    """텍스트 파일(PEM 등)을 읽어 문자열로 반환합니다."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()

def read_private_key(path: str, password: Optional[bytes] = None):
    """PEM 형식의 개인키를 로드하여 cryptography 객체로 반환합니다."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password, backend=default_backend())

def canonical_json(obj) -> bytes:
    """
    서명용 canonical form: 키 정렬 + 공백 최소화.
    (출력용 json.dump는 dict 삽입 순서를 유지하여 가독성/예시 순서를 따릅니다.)
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def tuf_keyid(keyobj: dict) -> str:
    """
    TUF keyid 계산: key 객체를 canonical JSON으로 직렬화 후 SHA-256 해시(hex).
    (keytype/scheme/keyid_hash_algorithms/keyval.public 이 동일해야 동일 keyid가 생성됩니다.)
    """
    return hashlib.sha256(canonical_json(keyobj)).hexdigest()

# =============================================================================
# 키 엔트리 생성기

def make_rsa_keyentry(pem_public: str) -> dict:
    """
    RSA 공개키(PEM 문자열)를 TUF keys 항목으로 래핑합니다.
    """
    return {
        "keytype": "rsa",
        "scheme": "rsassa-pss-sha256",
        "keyid_hash_algorithms": ["sha256", "sha512"],
        "keyval": {"public": pem_public},
    }

def ed25519_pem_to_raw_hex(pem_public: str) -> str:
    """
    Ed25519 공개키 PEM → raw 32바이트 → hex 문자열(소문자).
    """
    pub = serialization.load_pem_public_key(pem_public.encode("utf-8"), backend=default_backend())
    if not isinstance(pub, ed25519.Ed25519PublicKey):
        raise ValueError("제공된 PEM이 Ed25519 공개키가 아닙니다.")
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)  # 32 bytes
    return raw.hex()

def make_ed25519_keyentry_hex(hex_public: str) -> dict:
    """
    Ed25519 공개키(32B raw hex 문자열)를 TUF keys 항목으로 래핑합니다.
    """
    return {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyid_hash_algorithms": ["sha256", "sha512"],
        "keyval": {"public": hex_public},
    }

# =============================================================================
# 서명

def rsa_pss_sha256_sign(privkey, data: bytes) -> bytes:
    """
    RSA-PSS(SHA-256) 서명.
    """
    return privkey.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

# =============================================================================
# 메인

def main():
    # === RSA(root) 공개키 로딩 ===
    root_keyobjs = [make_rsa_keyentry(read_text(Path(f"./root_keys/{p}"))) for p in ROOT_PUBS]

    # === Ed25519(snapshot/targets/timestamp) 공개키 로딩 + RAW hex 변환 ===
    snapshot_hex = ed25519_pem_to_raw_hex(read_text(SNAPSHOT_PUB))
    targets_hex  = ed25519_pem_to_raw_hex(read_text(TARGETS_PUB))
    timestamp_hex= ed25519_pem_to_raw_hex(read_text(TIMESTAMP_PUB))

    snapshot_keyobj  = make_ed25519_keyentry_hex(snapshot_hex)
    targets_keyobj   = make_ed25519_keyentry_hex(targets_hex)
    timestamp_keyobj = make_ed25519_keyentry_hex(timestamp_hex)

    # === keys dict + keyids ===
    keys: dict[str, dict] = {}
    root_keyids: list[str] = []
    for keyobj in root_keyobjs:
        kid = tuf_keyid(keyobj)
        keys[kid] = keyobj
        root_keyids.append(kid)

    snapshot_kid  = tuf_keyid(snapshot_keyobj)
    targets_kid   = tuf_keyid(targets_keyobj)
    timestamp_kid = tuf_keyid(timestamp_keyobj)
    keys[snapshot_kid]  = snapshot_keyobj
    keys[targets_kid]   = targets_keyobj
    keys[timestamp_kid] = timestamp_keyobj

    # === roles 선언 (threshold는 일반적으로 1) ===
    roles = {
        "root":      {"keyids": root_keyids,         "threshold": 2},
        "snapshot":  {"keyids": [snapshot_kid],      "threshold": 1},
        "targets":   {"keyids": [targets_kid],       "threshold": 1},
        "timestamp": {"keyids": [timestamp_kid],     "threshold": 1},
    }

    # === expires ===
    EXPIRES = make_expires_iso8601_kst_plus_year()

    # === root signed payload (필드 순서: 예시와 동일) ===
    root_signed = {
        "_type": "root",
        "consistent_snapshot": CONSISTENT_SNAPSHOT,
        "expires": EXPIRES,
        "keys": keys,
        "roles": roles,
        "spec_version": SPEC_VERSION,
        "version": VERSION,
    }

    # === canonicalize for signing ===
    to_be_signed = canonical_json(root_signed)

    # === threshold(=2)개 서명 생성 (RSA-PSS-SHA256) ===
    signatures = []
    for priv_path in SIGNING_PRIVS:
        priv = read_private_key(Path(f"./root_keys/{priv_path}"), password=None)
        # 대응 공개키 PEM 추출 → RSA keyobj → keyid 계산 (roles에 선언된 것과 동일해야 함)
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8").strip()
        signer_keyobj = make_rsa_keyentry(pub_pem)
        signer_kid = tuf_keyid(signer_keyobj)

        sig_bytes = rsa_pss_sha256_sign(priv, to_be_signed)
        signatures.append({"keyid": signer_kid, "sig": sig_bytes.hex()})

    # === 최종 문서 (출력 순서 유지) ===
    root_doc = {"signatures": signatures, "signed": root_signed}

    dir_ver_path = f"./Director/meta/{VERSION}.root.json"
    dir_cur_path = "./Director/meta/root.json"
    img_ver_path = f"./Image/meta/{VERSION}.root.json"
    img_cur_path = "./OTA_Director_Server/Image_Repo/meta/root.json"

    # with open(dir_ver_path, "w", encoding="utf-8") as f:
    #     json.dump(root_doc, f, indent=2, ensure_ascii=False)
    #     f.write("\n")
    with open(dir_cur_path, "w", encoding="utf-8") as f:
        json.dump(root_doc, f, indent=2, ensure_ascii=False)
        f.write("\n")

    # with open(img_ver_path, "w", encoding="utf-8") as f:
    #     json.dump(root_doc, f, indent=2, ensure_ascii=False)
    #     f.write("\n")
    with open(img_cur_path, "w", encoding="utf-8") as f:
        json.dump(root_doc, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"[ok] wrote root for Director")
    print(f"[ok] wrote root for Image")
if __name__ == "__main__":
    main()