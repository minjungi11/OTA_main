import json
import base64
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes


# ===== 설정 =====
EXPIRES_DAYS = 365

# VVM 서명용 Ed25519 키
ED25519_PRIVATE_KEY_PATH = Path("ed25519_private_key.pem")

# ROOT 서명용 RSA 키 (없으면 새로 생성)
ROOT_RSA_PRIVATE_KEY_PATH = Path("root_rsa_private_key.pem")

VVM_JSON_PATH = Path("vvm.json")
ROOT_JSON_PATH = Path("root_vvm.json")


# ===== fileinfo 계산 =====
def calc_fileinfo(path: Path) -> Dict[str, Any]:
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    length = 0

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            length += len(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    return {
        "hashes": {
            "sha256": sha256.hexdigest(),
            "sha512": sha512.hexdigest(),
        },
        "length": length,
    }


# ===== Ed25519 키 관리 =====
def generate_ed25519_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def save_ed25519_private_key_pem(private_key: Ed25519PrivateKey, path: Path):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)


def load_or_create_ed25519_private_key(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        data = path.read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("Not an Ed25519 private key")
        return key

    key = generate_ed25519_private_key()
    save_ed25519_private_key_pem(key, path)
    return key


# ===== RSA 키 관리 (root 서명용) =====
def generate_rsa_private_key() -> RSAPrivateKey:
    # 2048-bit RSA, public exponent 65537 (일반적인 설정)
    return generate_private_key(public_exponent=65537, key_size=2048)


def save_rsa_private_key_pem(private_key: RSAPrivateKey, path: Path):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)


def load_or_create_rsa_private_key(path: Path) -> RSAPrivateKey:
    if path.exists():
        data = path.read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, RSAPrivateKey):
            raise TypeError("Not an RSA private key")
        return key

    key = generate_rsa_private_key()
    save_rsa_private_key_pem(key, path)
    return key


# ===== keyid / 공개키 =====
def calc_ed25519_keyid_from_public_key(private_key: Ed25519PrivateKey) -> str:
    pub = private_key.public_key()
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(pub_raw).hexdigest()


def get_ed25519_public_hex(private_key: Ed25519PrivateKey) -> str:
    pub = private_key.public_key()
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return pub_raw.hex()


def calc_rsa_keyid_from_public_key(private_key: RSAPrivateKey) -> str:
    """
    RSA keyid 정의:
    - SubjectPublicKeyInfo (DER) 바이트에 sha256 적용
    """
    pub = private_key.public_key()
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def get_rsa_public_pem(private_key: RSAPrivateKey) -> str:
    pub = private_key.public_key()
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


# ===== 공통: 캐논컬 JSON 바이트 =====
def canonical_json_bytes(d: Dict[str, Any]) -> bytes:
    return json.dumps(
        d,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


# ===== Ed25519 서명 =====
def sign_block_ed25519(private_key: Ed25519PrivateKey, signed_dict: Dict[str, Any]) -> str:
    canonical = canonical_json_bytes(signed_dict)
    sig = private_key.sign(canonical)
    return base64.b64encode(sig).decode("ascii")


# ===== RSA 서명 (RSASSA-PSS-SHA256) =====
def sign_block_rsa_pss_sha256(private_key: RSAPrivateKey, signed_dict: Dict[str, Any]) -> str:
    canonical = canonical_json_bytes(signed_dict)
    sig = private_key.sign(
        canonical,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode("ascii")


# ===== vvm.signed 구성 =====
def build_vvm_signed_block(
    vin: str,
    primary_ecu_serial: str,
    ecu_images: List[Dict[str, str]],
) -> Dict[str, Any]:

    now = datetime.now(timezone.utc)
    expires_str = (
        now + timedelta(days=EXPIRES_DAYS)
    ).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

    ecu_items = []

    for item in ecu_images:
        ecu_serial = item["ecu_serial"]
        image_path = Path(item["image_path"]).resolve()

        ecu_items.append(
            {
                "ecu_serial": ecu_serial,
                "target_image": {
                    "filename": image_path.name,
                    "fileinfo": calc_fileinfo(image_path),
                },
            }
        )

    signed = {
        "vin": vin,
        "primary_ecu_serial": primary_ecu_serial,
        "expires": expires_str,
        "ecu_version": ecu_items,
    }

    return signed


# ===== root.signed 구성 (요청하신 구조) =====
def build_root_signed_block(
    root_keyid: str,
    root_pub_pem: str,
    vvm_keyid: str,
    vvm_pub_hex: str,
) -> Dict[str, Any]:
    """
    구조 예:
    {
      "_type": "root",
      "expires": "...",
      "keys": {
        "<root_keyid>": { ...rsa... },
        "<vvm_keyid>":  { ...ed25519... }
      },
      "roles": {
        "root": { "keyids": ["<root_keyid>"], "threshold": 1 },
        "vvm":  { "keyids": ["<vvm_keyid>"],  "threshold": 1 }
      }
    }
    """
    now = datetime.now(timezone.utc)
    expires_str = (
        now + timedelta(days=EXPIRES_DAYS)
    ).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

    root_signed = {
        "_type": "root",
        "expires": expires_str,
        "keys": {
            root_keyid: {
                "keytype": "rsa",
                "scheme": "rsassa-pss-sha256",
                "keyval": {
                    "public": root_pub_pem,
                },
            },
            vvm_keyid: {
                "keytype": "ed25519",
                "scheme": "ed25519",
                "keyid_hash_algorithms": ["sha256"],
                "keyval": {
                    "public": vvm_pub_hex,
                },
            },
        },
        "roles": {
            "root": {
                "keyids": [root_keyid],
                "threshold": 1,
            },
            "vvm": {
                "keyids": [vvm_keyid],
                "threshold": 1,
            },
        },
    }

    return root_signed


# ===== vvm.json 생성 =====
def build_vvm_json(
    ed_private_key: Ed25519PrivateKey,
    vin: str,
    primary_ecu_serial: str,
    ecu_images: List[Dict[str, str]],
) -> Dict[str, Any]:
    vvm_keyid = calc_ed25519_keyid_from_public_key(ed_private_key)
    signed = build_vvm_signed_block(vin, primary_ecu_serial, ecu_images)

    # 사용한 서명키의 keyid를 signed에 기록
    signed["keyid"] = vvm_keyid

    sig = sign_block_ed25519(ed_private_key, signed)

    vvm_obj = {
        "signatures": [
            {
                "keyid": vvm_keyid,
                "sig": sig,
            }
        ],
        "signed": signed,
    }

    return vvm_obj, vvm_keyid


# ===== root.json 생성 (RSA로 서명) =====
def build_root_json(
    rsa_private_key: RSAPrivateKey,
    root_keyid: str,
    root_pub_pem: str,
    vvm_keyid: str,
    vvm_pub_hex: str,
) -> Dict[str, Any]:
    root_signed = build_root_signed_block(
        root_keyid,
        root_pub_pem,
        vvm_keyid,
        vvm_pub_hex,
    )

    sig = sign_block_rsa_pss_sha256(rsa_private_key, root_signed)

    root_obj = {
        "signatures": [
            {
                "keyid": root_keyid,
                "sig": sig,
            }
        ],
        "signed": root_signed,
    }

    return root_obj


# ===== 키 정보 출력 (옵션) =====
def print_vvm_key_info(ed_private_key: Ed25519PrivateKey, vvm_keyid: str):
    print("\n===== VVM SIGN / VERIFY KEY INFO =====")

    raw_private = ed_private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    print("VVM Private Key (RAW, hex):")
    print(raw_private.hex())

    private_pem = ed_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    print("\nVVM Private Key (PEM):")
    print(private_pem.decode())

    public_key = ed_private_key.public_key()
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print("VVM Public Key (RAW, hex):")
    print(raw_public.hex())

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    print("\nVVM Public Key (PEM):")
    print(public_pem.decode())

    print("VVM Key ID (sha256(pubkey raw)):")
    print(vvm_keyid)
    print("=================================\n")


def print_root_key_info(rsa_private_key: RSAPrivateKey, root_keyid: str):
    print("===== ROOT SIGN KEY INFO =====")
    private_pem = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    print("ROOT RSA Private Key (PEM):")
    print(private_pem.decode())

    pub_pem = get_rsa_public_pem(rsa_private_key)
    print("ROOT RSA Public Key (PEM):")
    print(pub_pem)

    print("ROOT Key ID (sha256(SubjectPublicKeyInfo DER)):")
    print(root_keyid)
    print("=================================\n")


# ===== main =====
def main():
    vin = "VIN-TEST-0001"
    primary_ecu_serial = "primary0"

    # 현재 ECU별 이미지 정보
    ecu_images = [
        {"ecu_serial": "ivi", "image_path": "./meta/ivi_0.0.0.bin"},
        {"ecu_serial": "cluster", "image_path": "./meta/cluster_1.0.0.bin"},
    ]

    # 1) Ed25519 (vvm 서명용) 키 로드 / 생성
    ed_private_key = load_or_create_ed25519_private_key(ED25519_PRIVATE_KEY_PATH)

    # 2) RSA root 개인키 로드 / 생성
    rsa_private_key = load_or_create_rsa_private_key(ROOT_RSA_PRIVATE_KEY_PATH)

    # 3) vvm.json 생성
    vvm_obj, vvm_keyid = build_vvm_json(
        ed_private_key,
        vin,
        primary_ecu_serial,
        ecu_images,
    )
    VVM_JSON_PATH.write_text(
        json.dumps(vvm_obj, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"vvm.json 생성 완료: {VVM_JSON_PATH}")

    # 4) root.json 생성 (root/vvm 키 둘 다 keys에 넣고, RSA로 root 서명)
    vvm_pub_hex = get_ed25519_public_hex(ed_private_key)
    root_keyid = calc_rsa_keyid_from_public_key(rsa_private_key)
    root_pub_pem = get_rsa_public_pem(rsa_private_key)

    root_obj = build_root_json(
        rsa_private_key,
        root_keyid,
        root_pub_pem,
        vvm_keyid,
        vvm_pub_hex,
    )
    ROOT_JSON_PATH.write_text(
        json.dumps(root_obj, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"root.json 생성 완료: {ROOT_JSON_PATH}")

    # 5) 키 정보 출력 (디버깅용)
    print_vvm_key_info(ed_private_key, vvm_keyid)
    print_root_key_info(rsa_private_key, root_keyid)


if __name__ == "__main__":
    main()
