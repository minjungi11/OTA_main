# Director/src/vvm_verify.py
from __future__ import annotations
import json, base64, binascii
from pathlib import Path
from typing import Any, Dict, List

from config import DIRECTOR_METADATA_DIR, DIRECTOR_KEYS_DIR
from src.targets_per_vehicle import canonical_json_bytes

def _find_root_vvm_path() -> Path:
    p_meta = (DIRECTOR_METADATA_DIR / "root_vvm.json").resolve()
    if p_meta.exists():
        return p_meta
    # 폴백: keys에도 있을 수 있음
    return (DIRECTOR_KEYS_DIR / "root_vvm.json").resolve()

def _load_root_vvm(path: Path | None = None) -> Dict[str, Any]:
    if path is None:
        path = _find_root_vvm_path()
    return json.loads(path.read_text(encoding="utf-8"))

def _get_vvm_pubkeys(root_doc: Dict[str, Any]) -> Dict[str, bytes]:
    signed = root_doc.get("signed", {})
    roles = signed.get("roles", {}) or {}
    vvm_role = roles.get("vvm", {}) or {}
    keyids: List[str] = vvm_role.get("keyids", []) or []
    keys = signed.get("keys", {}) or {}

    out: Dict[str, bytes] = {}
    for kid in keyids:
        k = keys.get(kid) or {}
        if (k.get("keytype") == "ed25519"
            and isinstance(k.get("keyval", {}), dict)
            and isinstance(k.get("keyval", {}).get("public"), str)):
            try:
                out[kid] = bytes.fromhex(k["keyval"]["public"])
            except (ValueError, binascii.Error):
                continue
    return out

def verify_vvm_signature(vvm_doc: Dict[str, Any], root_doc: Dict[str, Any] | None = None) -> bool:
    """
    root_vvm.json(Director/meta) 기반:
      - roles.vvm.keyids 에 등록된 ed25519 공개키로 VVM 서명 검증
      - 메시지 = canonical_json_bytes(vvm_doc["signed"])
      - threshold=1
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception:
        return False

    sigs = vvm_doc.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        return False

    signed_body = vvm_doc.get("signed")
    if not isinstance(signed_body, dict):
        return False

    if root_doc is None:
        try:
            root_doc = _load_root_vvm()
        except Exception:
            return False

    pubkeys_map = _get_vvm_pubkeys(root_doc)
    if not pubkeys_map:
        return False

    message = canonical_json_bytes(signed_body)

    for s in sigs:
        keyid = s.get("keyid")
        sig_b64 = s.get("sig")
        if not keyid or not sig_b64:
            continue
        pub = pubkeys_map.get(keyid)
        if not pub:
            continue
        try:
            sig = base64.b64decode(sig_b64)
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
            return True
        except Exception:
            continue
    return False