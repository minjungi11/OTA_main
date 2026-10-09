import os, re, json, binascii, hashlib
from typing import Any, Dict, Optional, Tuple
from datetime import datetime, timedelta, timezone
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:
    from backports.zoneinfo import ZoneInfo  # backports 패키지 필요
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ===== 설정(고정) =====
from config import (
    DIRECTOR_METADATA_DIR,
    DIRECTOR_KEYS_DIR,
    TIMESTAMP_EXPIRES_DAYS,
)

SPEC_VERSION            = "1.0.0"
ROOT_JSON_PATH          = DIRECTOR_METADATA_DIR / "root.json"
SNAPSHOT_JSON_PATH      = DIRECTOR_METADATA_DIR / "snapshot.json"

TIMESTAMP_PRIV_PEM      = DIRECTOR_KEYS_DIR / "timestamp.pem"
TIMESTAMP_PUB_PEM       = DIRECTOR_KEYS_DIR / "timestamp_pub.pem"

# ===== 유틸 =====
def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def load_private_key_pem(path: str) -> Ed25519PrivateKey:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Private key not found: {path}")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def ed25519_sign_hex(sk: Ed25519PrivateKey, data: bytes) -> str:
    return binascii.hexlify(sk.sign(data)).decode("ascii")

def ed25519_pub_pem_to_raw_hex(pub_pem_path: str) -> str:
    if not os.path.exists(pub_pem_path):
        raise FileNotFoundError(f"Public key not found: {pub_pem_path}")
    with open(pub_pem_path, "r", encoding="utf-8") as f:
        pem = f.read().strip()
    pub = serialization.load_pem_public_key(pem.encode("utf-8"), backend=default_backend())
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)  # 32 bytes
    return raw.hex()

def make_expires_iso8601_kst_plus_hours(hours: int) -> str:
    """현재 KST 기준 +hours → UTC 'Z' ISO8601."""
    now_kst = datetime.now(ZoneInfo("Asia/Seoul"))
    exp_kst = now_kst + timedelta(hours=hours)
    return exp_kst.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ===== keyid 해석(공개키 HEX 기반, snapshot 방식과 동일) =====
def resolve_timestamp_keyid_from_root_by_pubhex(root_path: str, my_pub_hex: str) -> str:
    with open(root_path, "r", encoding="utf-8") as f:
        root_doc = json.load(f)

    signed = root_doc["signed"]
    keys = signed["keys"]                                  # { keyid: keyobj }
    role_kids = signed["roles"]["timestamp"]["keyids"]     # [ keyid, ... ]
    for kid in role_kids:
        keyobj = keys[kid]
        if keyobj.get("keytype") == "ed25519" and keyobj.get("keyval", {}).get("public") == my_pub_hex:
            return kid

    raise RuntimeError("[!] root.json의 'timestamp' role에 공개키가 등록되어 있지 않습니다.")

def read_current_timestamp_version() -> int:
    try:
        with open("./timestamp.json", "r", encoding="utf-8") as f:
            doc = json.load(f)
        return int(doc.get("signed", {}).get("version", 0))
    except FileNotFoundError:
        return 0
    except Exception:
        return 0

# ===== snapshot 메타 항목 구성 =====
def build_snapshot_meta_entry(snapshot_path: Optional[str]) -> Dict[str, Any]:
    entry: Dict[str, Any] = {}
    if snapshot_path and os.path.exists(snapshot_path):
        with open(snapshot_path, "rb") as f:
            blob = f.read()
        sha = hashlib.sha256(blob).hexdigest()
        length = len(blob)
        try:
            snap = json.loads(blob)
            ver = int(snap.get("signed", {}).get("version", 1))
        except Exception:
            ver = 1
        entry["snapshot.json"] = {"hashes": {"sha256": sha}, "length": length, "version": ver}
    else:
        entry["snapshot.json"] = {"version": 1}
    return entry

def write_timestamp_json(doc: Dict[str, Any]) -> Path:
    out = DIRECTOR_METADATA_DIR / "timestamp.json"
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return out

# ===== 메인 =====
def generate_timestamp() -> None:
    # 1) 최신 root & 공개키 hex → keyid 해석
    my_pub_hex = ed25519_pub_pem_to_raw_hex(TIMESTAMP_PUB_PEM)
    timestamp_kid = resolve_timestamp_keyid_from_root_by_pubhex(ROOT_JSON_PATH, my_pub_hex)

    prev_ver = read_current_timestamp_version()
    new_ver = 1 if prev_ver <= 0 else prev_ver + 1

    # 2) signed(timestamp) 구성 (spec의 version 필드는 유지)
    expires = make_expires_iso8601_kst_plus_hours(TIMESTAMP_EXPIRES_DAYS)
    signed_obj: Dict[str, Any] = {
        "_type": "timestamp",
        "expires": expires,
        "meta": build_snapshot_meta_entry(SNAPSHOT_JSON_PATH),
        "spec_version": SPEC_VERSION,
        "version": new_ver
    }

    # 3) 서명(PEM 개인키; keyid 해석은 공개키로만)
    payload = canonical_json_bytes(signed_obj)
    sk = load_private_key_pem(TIMESTAMP_PRIV_PEM)
    sig_hex = ed25519_sign_hex(sk, payload)

    # 4) 파일 저장 후 경로 반환
    result: Dict[str, Any] = {"signatures": [{"keyid": timestamp_kid, "sig": sig_hex}], "signed": signed_obj}
    return write_timestamp_json(result)
