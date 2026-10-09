import os, json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ed25519, rsa
from cryptography.exceptions import InvalidSignature
import binascii


def read_root(metadata: str) -> dict:
    """
    root.json에서 role 별로 키 정보 추출
    """
    raw = metadata

    signed = raw["signed"]
    keys_section = signed["keys"]
    roles_section = signed["roles"]

    # 1) keyid → key 정보
    keys_db: dict[str, dict] = {}
    for keyid, keyinfo in keys_section.items():
        keys_db[keyid] = {
            "keytype": keyinfo.get("keytype"),
            "scheme":  keyinfo.get("scheme"),
            "public":  keyinfo["keyval"]["public"],
        }

    # 2) role → threshold / keyids
    roles_db: dict[str, dict] = {}
    for role_name, role_info in roles_section.items():
        roles_db[role_name] = {
            "threshold": role_info["threshold"],
            "keyids":    list(role_info["keyids"]),
        }

    keydb = {
        "keys":  keys_db,
        "roles": roles_db,
    }

    return keydb

def _load_public_key_from_entry(entry: dict):
    """
    keyid 통해 keytype과 공개키 회득
    """
    keytype = entry.get("keytype")
    public  = entry.get("public")

    if keytype == "rsa":
        # root.json 안 RSA 키는 PEM 그대로 들어 있음
        pem_bytes = public.encode("utf-8")
        pub = serialization.load_pem_public_key(pem_bytes)
        return pub, "rsa"

    if keytype == "ed25519":
        # ed25519 키는 raw 32바이트를 hex로 저장한 형태
        pub_bytes = bytes.fromhex(public)
        pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        return pub, "ed25519"

    raise ValueError(f"unsupported keytype: {keytype}")

def verify_multi_signature(metadata: dict, keydb: dict) -> None:
    """
    메타데이터 검증
    """
    raw = metadata
    signed = raw["signed"]
    signatures = raw.get("signatures", [])

    role = signed.get("_type")
    roles_db = keydb.get("roles", {})

    # print(f"Roles in key DB:        {roles_db}")
    if role not in roles_db:
        raise ValueError(f"role '{role}' not found in keydb")

    role_cfg = roles_db[role]
    threshold = role_cfg["threshold"]
    allowed_keyids = set(role_cfg["keyids"])

    # print(f"\n\n [{role}]   threshold:  {threshold}")
    # print(f"\n\n [{role}]   allowed_key:  {allowed_keyids}")
    # canonical JSON 직렬화
    signed_bytes = json.dumps(
        signed,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    ok_count = 0

    for sig_info in signatures:
        keyid = sig_info.get("keyid")
        sig_hex = sig_info.get("sig")

        # print(f"{role} can verify with:     {keyid}")

        # 이 role에서 허용한 key가 아니면 스킵
        if keyid not in allowed_keyids:
            continue

        key_entry = keydb["keys"].get(keyid)
        if not key_entry:
            # root에는 있는데 keydb에 없으면 설정 오류
            continue

        # print(f"\n{role} has a key entry:     {key_entry}")
        pub, keytype = _load_public_key_from_entry(key_entry)

        try:
            sig_bytes = bytes.fromhex(sig_hex)
        except ValueError:
            raise ValueError(f"signature for keyid={keyid} is not valid hex")

        try:
            if keytype == "rsa":
                pub.verify(
                    sig_bytes,
                    signed_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            elif keytype == "ed25519":
                pub.verify(sig_bytes, signed_bytes)
            else:
                raise ValueError(f"unsupported keytype: {keytype}")

            ok_count += 1
            if ok_count >= threshold:
                break

        except InvalidSignature as e:
            # 이 keyid 서명은 실패 → 다른 keyid 계속 시도
            print(f"[verify_multi_signature] signature FAIL for {keyid}: {e}")
            continue

    if ok_count < threshold:
        raise RuntimeError(
            f"multi-signature verification failed for role '{role}': "
            f"need {threshold}, got {ok_count}"
        )