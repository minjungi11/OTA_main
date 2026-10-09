from __future__ import annotations

import os
import re
import time
import json
import shutil
import binascii
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.backends import default_backend

from utils.fastcdc_chunking import ensure_dirs, split_all, CHUNKS_DIR

#==========================================================================================================================
#==========================================================================================================================
# 로컬(Director 서버) 쪽 기본 경로
ROOT_DIR   = '../src_add'
WATCH_DIR  = os.path.join(ROOT_DIR, 'stage')  # 업데이트 이미지 업로드 위치

# Image, Director 쪽 기본 경로
IMAGE_REPO_DEFAULT    = '../Image_Repo'
DIRECTOR_REPO_DEFAULT = '../../Director'

# 키 경로(Root metadata)
KEY_ROOT = '../keys'
ECU_KEY_CONFIG: Dict[str, Dict[str, str]] = {
    "ivi": {
        "pub": os.path.join(KEY_ROOT, "ivi_pub.pem"),
        "priv": os.path.join(KEY_ROOT, "ivi.pem"),
    },
    # "cluster": { "pub": "...", "priv": "..." },  이런 식으로 추가 가능
    "cluster": {
        "pub": os.path.join(KEY_ROOT, "cluster_pub.pem"),
        "priv": os.path.join(KEY_ROOT, "cluster.pem")
    },
}

TARGETS_PUB_PATH  = os.path.join(KEY_ROOT, "targets_pub.pem")
TARGETS_PRIV_PATH = os.path.join(KEY_ROOT, "targets.pem")

#==========================================================================================================================
#==========================================================================================================================

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def default_expires(days: int = 365) -> str:
    now = datetime.now(timezone.utc)
    exp = (now + timedelta(days=days)).replace(microsecond=0)
    return exp.isoformat().replace("+00:00", "Z")


def hashlib_sha256_hex(b: bytes) -> str:
    import hashlib
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def parse_image_name_version(path: str):
    """
    {ecu}_{X.Y.Z}.tar 형식의 파일명에서
      ecu, version, stem(ecu_version)을 추출.
    예) ivi_1.0.0.tar -> ("ivi", "1.0.0", "ivi_1.0.0")
    """
    fname = os.path.basename(path)
    if not fname.endswith(".tar"):
        raise ValueError(f"지원하지 않는 이미지 파일명: {fname}")

    stem = fname[:-4]  # .tar 제거
    m = re.match(r"^(?P<ecu>.+?)_(?P<ver>\d+(?:\.\d+)*)$", stem)
    if not m:
        raise ValueError(f"이름/버전 파싱 실패: {stem}")

    ecu = m.group("ecu")
    ver = m.group("ver")
    image_stem = f"{ecu}_{ver}"
    return ecu, ver, image_stem


def load_json_if_exists(path: str) -> Optional[dict]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_ecu_pub_key_entry(ecu: str) -> tuple[str, Dict[str, Any]]:
    """
    ECU 이름(ivi 등)을 받아서:
      - PEM 공개키를 읽고
      - TUF key object와 keyid를 계산해서 반환.
    공개키는 hex 문자열로 저장.
    """
    cfg = ECU_KEY_CONFIG.get(ecu)
    if not cfg or "pub" not in cfg:
        raise ValueError(f"ECU '{ecu}'에 대한 공개키 설정이 없습니다 (ECU_KEY_CONFIG).")

    pub_path = cfg["pub"]
    if not os.path.exists(pub_path):
        raise FileNotFoundError(f"ECU '{ecu}' 공개키 파일을 찾을 수 없습니다: {pub_path}")

    with open(pub_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read(), backend=default_backend())

    # Ed25519 전제로 Raw 32바이트 사용 → hex로 저장
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = binascii.hexlify(raw).decode("ascii")

    key_obj = {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyid_hash_algorithms": ["sha256"],
        "keyval": {
            "public": pub_hex,
        },
    }
    keyid = hashlib_sha256_hex(canonical_json_bytes(key_obj))
    return keyid, key_obj


def load_targets_pub_key_entry() -> tuple[str, Dict[str, Any]]:
    """
    상위 targets를 서명하는 targets 키 (targets_pub.pem)를 읽어서
    key object와 keyid 반환. 공개키도 hex로 저장.
    """
    if not os.path.exists(TARGETS_PUB_PATH):
        raise FileNotFoundError(f"targets 공개키 파일을 찾을 수 없습니다: {TARGETS_PUB_PATH}")

    with open(TARGETS_PUB_PATH, "rb") as f:
        pub = serialization.load_pem_public_key(f.read(), backend=default_backend())

    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = binascii.hexlify(raw).decode("ascii")

    key_obj = {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyid_hash_algorithms": ["sha256", "sha512"],
        "keyval": {
            "public": pub_hex,
        },
    }
    keyid = hashlib_sha256_hex(canonical_json_bytes(key_obj))
    return keyid, key_obj


def ensure_ecu_delegation(parent_targets_path: str, ecu: str) -> str:
    """
    meta/targets.json 의 delegations에 ECU 단위 역할을 보장.

    - delegations.keys[<keyid>] 에 ECU 공개키 등록
    - delegations.roles 에 name == ecu 인 역할 등록 (paths: ["ecu/*"])
    """
    obj = load_json_if_exists(parent_targets_path)
    if obj is None:
        obj = {
            "signatures": [],
            "signed": {
                "_type": "targets",
                "spec_version": "1.0.0",
                "version": 1,
                "expires": default_expires(),
                "targets": {},
                "delegations": {
                    "keys": {},
                    "roles": [],
                },
            },
        }

    signed = obj.setdefault("signed", {})
    deleg = signed.setdefault("delegations", {})
    keys  = deleg.setdefault("keys", {})
    roles = deleg.setdefault("roles", [])

    ecu_keyid, ecu_key_obj = load_ecu_pub_key_entry(ecu)
    keys[ecu_keyid] = ecu_key_obj

    role_name = ecu  # role 이름은 ECU 이름 기준
    found = False
    for r in roles:
        if r.get("name") == role_name:
            r["keyids"] = [ecu_keyid]
            r["paths"] = [f"{ecu}/*"]
            r["terminating"] = False
            r["threshold"] = 1
            found = True
            break

    if not found:
        roles.append({
            "name": role_name,
            "keyids": [ecu_keyid],
            "paths": [f"{ecu}/*"],
            "terminating": False,
            "threshold": 1,
        })

    os.makedirs(os.path.dirname(parent_targets_path), exist_ok=True)
    with open(parent_targets_path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

    return ecu_keyid


def sign_image_metadata_for_ecu(ecu: str, signed: Dict[str, Any]) -> Dict[str, Any]:
    """
    ECU 이름(ivi 등)과 signed 객체를 받아서
    - ECU 공개키 기반 keyid 계산
    - ECU 개인키로 Ed25519 서명
    을 수행해 signatures를 채운 메타데이터를 반환.
    서명도 hex 문자열로 저장.
    """
    cfg = ECU_KEY_CONFIG.get(ecu)
    if not cfg or "priv" not in cfg:
        raise ValueError(f"ECU '{ecu}'에 대한 개인키 설정이 없습니다 (ECU_KEY_CONFIG).")

    priv_path = cfg["priv"]
    if not os.path.exists(priv_path):
        raise FileNotFoundError(f"ECU '{ecu}' 개인키 파일을 찾을 수 없습니다: {priv_path}")

    ecu_keyid, _ = load_ecu_pub_key_entry(ecu)

    with open(priv_path, "rb") as f:
        priv = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend(),
        )
    if not isinstance(priv, Ed25519PrivateKey):
        raise TypeError("현재 구현은 Ed25519 개인키만 지원합니다.")

    signed_bytes = canonical_json_bytes(signed)
    sig_bytes = priv.sign(signed_bytes)
    sig_hex = binascii.hexlify(sig_bytes).decode("ascii")

    meta = {
        "signatures": [
            {
                "keyid": ecu_keyid,
                "sig": sig_hex,
            }
        ],
        "signed": signed,
    }
    return meta

def _parse_target_name_ver(stem: str) -> tuple[Optional[str], Optional[str]]:
    """
    ivi_1.0.0 같은 target 이름에서
      name="ivi", ver="1.0.0" 으로 분리
    실패하면 (None, None) 리턴
    """
    m = re.match(r"^(?P<name>.+?)_(?P<ver>\d+(?:\.\d+)*)$", stem)
    if not m:
        return None, None
    return m.group("name"), m.group("ver")


def _split_ver(ver: str) -> list[int]:
    return [int(x) for x in ver.split(".")]


def _version_gt(a: str, b: str) -> bool:
    """
    a > b 이면 True (버전 비교)
    예: "2.0.0" > "1.0.0" → True
    """
    pa = _split_ver(a)
    pb = _split_ver(b)
    L = max(len(pa), len(pb))
    pa += [0] * (L - len(pa))
    pb += [0] * (L - len(pb))
    for xa, xb in zip(pa, pb):
        if xa > xb:
            return True
        if xa < xb:
            return False
    return False

def update_parent_targets(parent_targets_path: str,
                          target_name: str,
                          image_path: str,
                          sha256_hex: str,
                          sha512_hex: str) -> None:
    """
    meta/targets.json 의 signed.targets[target_name] 갱신.
    같은 이미지 이름(ivi, cluster 등)에 대해서는
    항상 가장 최신 버전만 남도록 이전 버전 entry를 정리함.
    """
    obj = load_json_if_exists(parent_targets_path)
    if obj is None:
        obj = {
            "signatures": [],
            "signed": {
                "_type": "targets",
                "spec_version": "1.0.0",
                "version": 1,
                "expires": default_expires(),
                "targets": {},
                "delegations": {
                    "keys": {},
                    "roles": [],
                },
            },
        }

    signed = obj.setdefault("signed", {})
    targets = signed.setdefault("targets", {})

    # 새로 들어온 target_name 을 name/ver로 분리 (예: ivi_2.0.0 → name=ivi, ver=2.0.0)
    new_name, new_ver = _parse_target_name_ver(target_name)

    if new_name and new_ver:
        # 이미 들어있는 targets 중, 같은 name(ivi)이면 버전 비교해서 정리
        for existing in list(targets.keys()):
            old_name, old_ver = _parse_target_name_ver(existing)
            if old_name != new_name or not old_ver:
                continue

            # 기존이 더 최신이면, 새 버전을 굳이 넣지 않음
            if _version_gt(old_ver, new_ver):
                # 그래도 상위 targets의 version/expires는 갱신할 수 있으니
                # 밑에서 version/expired만 올리고 반환
                length = os.path.getsize(image_path)
                # 기존 entry는 그대로 두고, 해시는 굳이 덮지 않아도 됨
                try:
                    cur_ver = int(signed.get("version", 0))
                except Exception:
                    cur_ver = 0
                signed["version"] = cur_ver + 1
                signed["expires"] = default_expires()
                os.makedirs(os.path.dirname(parent_targets_path), exist_ok=True)
                with open(parent_targets_path, "w", encoding="utf-8") as f:
                    json.dump(obj, f, indent=2, ensure_ascii=False)
                return

            # 새 버전이 더 최신이면, 기존 entry 삭제
            if _version_gt(new_ver, old_ver):
                del targets[existing]

    # 여기까지 왔으면 새 버전을 넣으면 됨 (기존 구버전은 위에서 삭제됨)
    length = os.path.getsize(image_path)
    targets[target_name] = {
        "hashes": {
            "sha256": sha256_hex,
            "sha512": sha512_hex,
        },
        "length": length,
    }

    # version 증가 + expires 갱신
    try:
        cur_ver = int(signed.get("version", 0))
    except Exception:
        cur_ver = 0
    signed["version"] = cur_ver + 1
    signed["expires"] = default_expires()

    os.makedirs(os.path.dirname(parent_targets_path), exist_ok=True)
    with open(parent_targets_path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def sign_parent_targets(parent_targets_path: str) -> None:
    """
    상위 targets(meta/targets.json)의 signed 부분을
    targets.pem / targets_pub.pem으로 Ed25519 서명하여 signatures에 채운다.
    서명 값은 hex 문자열.
    """
    obj = load_json_if_exists(parent_targets_path)
    if obj is None:
        return

    signed = obj.get("signed")
    if not isinstance(signed, dict):
        return

    if not os.path.exists(TARGETS_PRIV_PATH):
        print(f"[watchdog] 경고: targets 개인키 없음: {TARGETS_PRIV_PATH}")
        return

    try:
        targets_keyid, _ = load_targets_pub_key_entry()
    except Exception as e:
        print(f"[watchdog] targets 공개키 로드 실패: {e}")
        return

    with open(TARGETS_PRIV_PATH, "rb") as f:
        priv = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend(),
        )
    if not isinstance(priv, Ed25519PrivateKey):
        print("[watchdog] 경고: targets.pem이 Ed25519 키가 아님")
        return

    signed_bytes = canonical_json_bytes(signed)
    sig_bytes = priv.sign(signed_bytes)
    sig_hex = binascii.hexlify(sig_bytes).decode("ascii")

    obj["signatures"] = [
        {
            "keyid": targets_keyid,
            "sig": sig_hex,
        }
    ]

    with open(parent_targets_path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, watch_dir: str, image_repo_root: str) -> None:
        super().__init__()
        self.watch_dir = watch_dir
        self.image_repo_root = image_repo_root
        self.director_repo_root = DIRECTOR_REPO_DEFAULT

        # Image_Repo 내 경로들
        self.chunks_dir_remote = os.path.join(self.image_repo_root, "chunks_storage")
        self.meta_root = os.path.join(self.image_repo_root, "meta")
        self.targets_base = os.path.join(self.meta_root, "targets")
        self.parent_targets_json = os.path.join(self.meta_root, "targets.json")

        # Director_Repo 내 경로들
        self.director_meta_root = os.path.join(self.director_repo_root, "meta")
        self.director_targets_base = os.path.join(self.director_meta_root, "targets")
        self.director_parent_targets_json = os.path.join(self.director_meta_root, "targets.json")

    def on_created(self, event):
        if event.is_directory:
            return

        image_path = event.src_path
        # 0) tar 형식의 파일 업로드 확인하여 대상 ECU 및 버전 확인
        if not image_path.endswith(".tar"):
            print(f"[watchdog] 무시 (tar 아님): {image_path}")
            return

        try:
            ecu, image_ver, image_stem = parse_image_name_version(image_path)
        except ValueError as e:
            print(f"[watchdog] 파일명 파싱 실패: {e}")
            return

        target_name = image_stem  # 상위 targets에서의 이름 (예: ivi_1.0.0)

        print(f"[watchdog] 새 이미지 감지: {image_path}")
        print(f"[watchdog] ECU={ecu}, version={image_ver}")

        ensure_dirs(CHUNKS_DIR, self.chunks_dir_remote, self.targets_base, self.director_targets_base)

        # 1) FastCDC 분할 + signed.chunks 생성
        metrics, elapsed, signed = split_all(image_path)
        print(
            f"[watchdog] FastCDC 분할 완료 "
            f"(time={elapsed:.2f}s, total_chunks={metrics['total_chunks']}, "
            f"new_chunks={metrics['created_chunks']})"
        )

        sha256_hex = metrics.get("sha256")
        sha512_hex = metrics.get("sha512")
        new_chunk_ids = metrics.get("new_chunk_ids", [])

        # 2) 상위 targets의 delegations에 ECU 역할/키 보장 (Image / Director 둘 다)
        try:
            ecu_keyid_img = ensure_ecu_delegation(self.parent_targets_json, ecu)
            ecu_keyid_dir = ensure_ecu_delegation(self.director_parent_targets_json, ecu)
            print(f"[watchdog] delegations에 ECU={ecu} 반영 완료 "
                  f"(image_repo keyid={ecu_keyid_img}, director keyid={ecu_keyid_dir})")
        except Exception as e:
            print(f"[watchdog] delegations 갱신 중 오류: {e}")

        # 3) per-image 메타데이터 서명 후 Image_Repo, Director 에 저장
        try:
            meta = sign_image_metadata_for_ecu(ecu, signed)
        except Exception as e:
            print(f"[watchdog] 이미지 메타데이터 서명 실패 (dummy 서명 사용): {e}")
            meta = {
                "signatures": [
                    {"keyid": "dummy_keyid", "sig": "00"}
                ],
                "signed": signed,
            }

        # Image_Repo: meta/targets/{ecu}/{ecu}_image/{stem}.json
        ecu_role_dir_img = os.path.join(self.targets_base, ecu, f"{ecu}_image")
        ensure_dirs(ecu_role_dir_img)
        image_json_path_img = os.path.join(ecu_role_dir_img, f"{image_stem}.json")
        with open(image_json_path_img, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        print(f"[watchdog] 이미지 메타데이터 저장(Image_Repo): {image_json_path_img}")

        # Director: ../../Director/meta/targets/{ecu}/{ecu}_image/{stem}.json
        ecu_role_dir_dir = os.path.join(self.director_targets_base, ecu, f"{ecu}_image")
        ensure_dirs(ecu_role_dir_dir)
        image_json_path_dir = os.path.join(ecu_role_dir_dir, f"{image_stem}.json")
        with open(image_json_path_dir, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        print(f"[watchdog] 이미지 메타데이터 저장(Director): {image_json_path_dir}")

        # 4) 새 청크를 Image_Repo/chunks_storage 로 복사 (중복 제거)
        copied = 0
        for h in new_chunk_ids:
            src = os.path.join(CHUNKS_DIR, h)
            dst = os.path.join(self.chunks_dir_remote, h)
            if not os.path.exists(src):
                continue
            if os.path.exists(dst):
                continue
            shutil.copy2(src, dst)
            copied += 1
        print(f"[watchdog] 새 청크 복사(Image_Repo): {copied}/{len(new_chunk_ids)}개")

        # 5) 상위 targets.json 의 targets 갱신 (Image_Repo + Director)
        if sha256_hex and sha512_hex:
            try:
                update_parent_targets(
                    self.parent_targets_json,
                    target_name,
                    image_path,
                    sha256_hex,
                    sha512_hex,
                )
                update_parent_targets(
                    self.director_parent_targets_json,
                    target_name,
                    image_path,
                    sha256_hex,
                    sha512_hex,
                )
                print(f"[watchdog] 상위 targets 갱신 완료: "
                      f"{self.parent_targets_json}, {self.director_parent_targets_json}")

                # 6) 갱신된 상위 targets에 대해 targets.pem으로 서명
                sign_parent_targets(self.parent_targets_json)
                sign_parent_targets(self.director_parent_targets_json)
                print("[watchdog] 상위 targets 서명 완료 (targets.pem)")
            except Exception as e:
                print(f"[watchdog] 상위 targets 갱신/서명 중 오류: {e}")
        else:
            print("[watchdog] 경고: sha256/sha512 없음 (상위 targets 갱신 생략)")


class FileHandler:
    def __init__(self, watch_dir: str, image_repo_root: str) -> None:
        self.watch_dir = watch_dir
        self.image_repo_root = image_repo_root

        self.observer = Observer()
        self.event_handler = FileChangeHandler(self.watch_dir, self.image_repo_root)
        self.observer.schedule(self.event_handler, self.watch_dir, recursive=False)

    def start_watching(self) -> None:
        print(f"[watchdog] 감시 시작: {self.watch_dir}")
        self.observer.start()

    def stop_watching(self) -> None:
        print("[watchdog] 감시 중지 요청")
        self.observer.stop()


if __name__ == "__main__":
    IMAGE_DIR = IMAGE_REPO_DEFAULT

    ensure_dirs(WATCH_DIR)
    file_handler = FileHandler(WATCH_DIR, IMAGE_DIR)
    file_handler.start_watching()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        file_handler.stop_watching()
        file_handler.observer.join()
