# Director/src/targets_per_vehicle.py
from __future__ import annotations

import json, os, re, binascii
from typing import Any, Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from config import DIRECTOR_KEYS_DIR, DIRECTOR_METADATA_DIR, TARGETS_EXPIRES_DAYS

ROOT_JSON_PATH = DIRECTOR_METADATA_DIR / "root.json"

# ---------------------------------------------------------------------------
# 버전 / 이미지 ID 파싱 유틸
# ---------------------------------------------------------------------------

_RX_IMAGE_ID = re.compile(
    r"^(?P<name>.+?)_(?P<ver>\d+(?:\.\d+)*)(?:\.[^.]+)?$"
)

def split_image_id(image_id: str) -> Optional[Tuple[str, str]]:
    m = _RX_IMAGE_ID.match(image_id)
    if not m:
        return None
    return m.group("name"), m.group("ver")

def _split_ver(ver: str) -> List[int]:
    return [int(x) for x in ver.split(".")]

def version_gt(a: str, b: str) -> bool:
    """a > b ? (버전 비교)"""
    return _split_ver(a) > _split_ver(b)

# ---------------------------------------------------------------------------
# 서명 유틸
# ---------------------------------------------------------------------------

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _sign_ed25519_pem(message: bytes, pem_path: str) -> str:
    key_data = Path(pem_path).read_bytes()
    sk = serialization.load_pem_private_key(key_data, password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise TypeError("Expected Ed25519 private key")
    sig = sk.sign(message)
    return binascii.hexlify(sig).decode("ascii")

def _load_targets_keyid_from_root(root_path: Path = ROOT_JSON_PATH) -> str:
    """
    root.json 에서 Director targets 키의 keyid 하나 가져오기
    (roles.targets.keyids[0] 기준)
    """
    if not root_path.exists():
        raise FileNotFoundError(f"root.json not found: {root_path}")
    root_raw = json.loads(root_path.read_text(encoding="utf-8"))
    body = root_raw.get("signed", root_raw)
    roles = body.get("roles") or {}
    t_role = roles.get("targets") or {}
    keyids = t_role.get("keyids") or []
    if not keyids:
        raise ValueError("No targets keyids found in root.json (roles.targets.keyids)")
    return keyids[0]

def _write_targets_json(doc: Dict[str, Any]) -> Path:
    out = Path(DIRECTOR_METADATA_DIR / "targets_per_vehicle.json")
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return out

# ---------------------------------------------------------------------------
# 1) VVM 파싱: 설치된 이미지 리스트 추출
#    반환: [{ecu, image_id, name, version, image_info}, ...]
# ---------------------------------------------------------------------------

def extract_installed_list_from_vvm(vvm_raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    vvm.json 예시 구조에 맞춰 ECU별 현재 이미지 정보 추출.
    - ecu_serial
    - installed_image / target_image
      - image / iamge / filename 등에서 image_id 추출
      - hashes, length 도 image_info 로 함께 가져옴
    """
    out: List[Dict[str, Any]] = []
    body = vvm_raw.get("signed", vvm_raw)
    evs = body.get("ecu_version", []) or []

    for ev in evs:
        if not isinstance(ev, dict):
            continue
        ecu_id = ev.get("ecu_serial") or ev.get("ecu") or ""
        if not ecu_id:
            continue

        img_obj = (
            ev.get("installed_image")
            or ev.get("target_image")
            or {}
        )
        if not isinstance(img_obj, dict):
            continue

        # 다양한 키 케이스 대응: image / iamge / filename
        image_id = (
            img_obj.get("image")
            or img_obj.get("iamge")
            or img_obj.get("filename")
        )
        if not image_id:
            continue

        sv = split_image_id(image_id)
        if not sv:
            continue
        name, ver = sv

        # image_info는 hashes + length 정도만 추려서 사용
        fileinfo = img_obj.get("fileinfo") or {}
        hashes = (
            img_obj.get("hashes")
            or fileinfo.get("hashes")
            or {}
        )
        length = (
            img_obj.get("length")
            or fileinfo.get("length")
        )

        image_info = {}
        if hashes:
            image_info["hashes"] = hashes
        if length is not None:
            image_info["length"] = length

        out.append({
            "ecu": ecu_id,
            "image_id": image_id,
            "name": name,
            "version": ver,
            "image_info": image_info,
        })

    return out

# ---------------------------------------------------------------------------
# 2) 글로벌 targets_delegation 에서 이미지별 최신 버전 찾기
#    global_targets["signed"]["targets"] 가
#    {"ivi_2.0.0": {...}, "cluster_1.0.0": {...}} 형태라고 가정
#    반환: {name: (best_image_id, best_version, image_info)}
# ---------------------------------------------------------------------------

def build_latest_map_from_global(global_targets: Dict[str, Any]) -> Dict[str, Tuple[str, str, Dict[str, Any]]]:
    """
    name 별(예: 'ivi', 'cluster')로 가장 높은 버전의 이미지를 뽑는다.
    """
    out: Dict[str, Tuple[str, str, Dict[str, Any]]] = {}
    signed = global_targets.get("signed") or {}
    targets_obj = signed.get("targets") or {}

    if not isinstance(targets_obj, dict):
        return out

    for image_id, info in targets_obj.items():
        if not isinstance(info, dict):
            continue
        sv = split_image_id(image_id)
        if not sv:
            continue
        name, ver = sv

        prev = out.get(name)
        if not prev:
            out[name] = (image_id, ver, info)
        else:
            _, prev_ver, _ = prev
            if version_gt(ver, prev_ver):
                out[name] = (image_id, ver, info)

    return out

# ---------------------------------------------------------------------------
# 3) 청크 manifest 로딩 / required_chunks 계산
#    manifest 경로 가정:
#      DIRECTOR_METADATA_DIR / "targets" / {ecu} / {image_name}_image / {image_id}.json
#    예: meta/targets/ivi/ivi_image/ivi_1.0.0.json
# ---------------------------------------------------------------------------

def _manifest_path_for_image(ecu: str, image_name: str, image_id: str) -> Path:
    image_dir = f"{image_name}_image"
    return DIRECTOR_METADATA_DIR / "targets" / ecu / image_dir / f"{image_id}.json"

def _collect_chunks_from_manifest(man_path: Path) -> Set[str]:
    """
    ivi_1.0.0.json 같은 delegated targets(청크 manifest)에서
    signed.chunks.* 에 들어있는 청크 해시들을 모두 set 로 모은다.
    """
    if not man_path.exists():
        raise FileNotFoundError(str(man_path))

    raw = json.loads(man_path.read_text(encoding="utf-8"))
    body = raw.get("signed", raw)
    chunks_obj = body.get("chunks") or {}

    chunk_set: Set[str] = set()

    if isinstance(chunks_obj, dict):
        for _, chunk_list in chunks_obj.items():
            if not isinstance(chunk_list, list):
                continue
            for ch in chunk_list:
                if isinstance(ch, str):
                    h = ch
                elif isinstance(ch, dict):
                    h = ch.get("hash") or ch.get("sha256")
                else:
                    continue
                if h:
                    chunk_set.add(h)

    return chunk_set

def compute_required_chunks(ecu: str, image_name: str, old_image_id: str, new_image_id: str) -> List[str]:
    """
    이전 버전과 최신 버전 manifest 를 비교해서
    new_chunks - old_chunks 로 required_chunks 리스트 생성.
    manifest 가 없으면(초기 설치 등) 최신 버전 전체 청크를 반환.
    """
    new_path = _manifest_path_for_image(ecu, image_name, new_image_id)
    old_path = _manifest_path_for_image(ecu, image_name, old_image_id)

    new_set = _collect_chunks_from_manifest(new_path)

    try:
        old_set = _collect_chunks_from_manifest(old_path)
    except FileNotFoundError:
        old_set = set()

    required = sorted(new_set - old_set)
    return required

# ---------------------------------------------------------------------------
# 4) 메인: VVM + 글로벌 targets_delegation 비교 → per-vehicle targets 생성/서명
# ---------------------------------------------------------------------------

def make_targets_for_car(vvm_raw: Dict[str, Any], global_targets: Dict[str, Any]) -> Path:
    """
    - vvm: prime ECU 가 보낸 vehicle_version_manifest
    - global_targets: Image repo 가 발행한 최상위 targets_delegation.json

    동작:
      1) VVM에서 ECU별 현재 이미지 (name, version) 추출
      2) global_targets 에서 같은 name 에 대한 최신 버전 찾기
      3) 최신 버전 > 현재 버전이면 업데이트 대상
         - required_chunks = 최신 vs 현재 manifest 청크 차집합
      4) 결과를 targets_per_vehicle.json 포맷으로 출력/서명
    """
    installed_list = extract_installed_list_from_vvm(vvm_raw)
    latest_map = build_latest_map_from_global(global_targets)

    per_ecu_entries: List[Dict[str, Any]] = []
    any_update = False

    for installed in installed_list:
        ecu_id     = installed["ecu"]
        cur_img_id = installed["image_id"]
        img_name   = installed["name"]
        cur_ver    = installed["version"]
        # cur_info = installed["image_info"]  # 필요하면 사용

        latest = latest_map.get(img_name)
        if not latest:
            # 이 ECU의 이미지 name 에 대해 global targets 에 정보가 없으면 스킵
            continue

        best_img_id, best_ver, best_info = latest

        # 버전 비교만 사용 (해시 비교는 요구사항대로 제외)
        try:
            need_update = version_gt(best_ver, cur_ver)
        except Exception:
            # 버전 파싱 실패하면 그냥 스킵하는 쪽으로
            continue

        if not need_update:
            continue

        any_update = True

        # required_chunks 계산
        try:
            required_chunks = compute_required_chunks(
                ecu=ecu_id,
                image_name=img_name,
                old_image_id=cur_img_id,
                new_image_id=best_img_id,
            )
        except FileNotFoundError:
            # manifest 가 없으면 일단 빈 리스트 반환 (필요하면 나중에 로직 보강)
            required_chunks = []

        per_ecu_entries.append({
            "ecu": ecu_id,
            "images": {
                "image_name": best_img_id,
                "image_info": best_info,
                "required_chunks": required_chunks,
            }
        })

    # 만료 시간 / 버전은 간단하게 고정 전략 사용
    now = datetime.now(timezone.utc)
    expires_str = (now + timedelta(days=TARGETS_EXPIRES_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    version = 1  # 필요하면 파일 탐색해서 증가시키는 로직 추가 가능
    
    final_signed = {
        "_type": "targets",
        "version": version,
        "expires": expires_str,
        "targets": per_ecu_entries,
        "update": bool(any_update),
    }

    # 서명
    sign_key_path = DIRECTOR_KEYS_DIR / "targets.pem"
    if not sign_key_path.exists():
        raise FileNotFoundError(f"Director signing key not found: {sign_key_path}")

    msg = canonical_json_bytes(final_signed)
    sig_hex = _sign_ed25519_pem(msg, str(sign_key_path))
    targets_keyid = _load_targets_keyid_from_root()

    final_doc = {
        "signatures": [{"keyid": targets_keyid, "sig": sig_hex}],
        "signed": final_signed,
    }
    return _write_targets_json(final_doc)
