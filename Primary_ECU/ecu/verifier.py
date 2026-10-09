from dataclasses import dataclass
from typing import Optional, Union, Dict, Any, List, Tuple
from pathlib import Path
import hashlib, json, os, binascii

from manage_meta import read_root, verify_multi_signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from datetime import datetime, timedelta, timezone

JsonMeta = Dict[str, Any]

@dataclass
class VerifyResult:
    ok: bool
    reason: Optional[str] = None

class Verifier:
    def __init__(self, director_root_path: str = "./root.json"):
        if not os.path.exists(director_root_path):
            raise FileNotFoundError(f"director root not found: {director_root_path}")

        with open(director_root_path, "r", encoding="utf-8") as f:
            root_meta = json.load(f)

        self.keydb = read_root(root_meta)  # 역할별 keyid / threshold 정보 포함

    # Image에서 받을 때 쓰는 거인듯. 지금은 필요 없음.
    # def quick_hash_check(self, file_path: str, expected_sha256: str):
    #     h = hashlib.sha256()
    #     with open(file_path, "rb") as f:
    #         for chunk in iter(lambda: f.read(1024 * 1024), b""):
    #             h.update(chunk)
    #     got = h.hexdigest()
    #     if got.lower() != expected_sha256.lower():
    #         raise ValueError(f"sha256 mismatch: expected={expected_sha256} got={got}")

    def canonical_json_bytes(self, obj: Any) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def parse_timestamp_datetime(self, dt_str: str) -> datetime:
        """
        TUF 스타일의 expires 문자열(예: '2025-11-27T12:34:56Z')을
        timezone-aware datetime(UTC)로 변환.
        """
        # 뒤에 'Z'가 붙어 있으면 +00:00 으로 바꿔서 fromisoformat에 먹인다.
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1] + "+00:00"
        return datetime.fromisoformat(dt_str)
    
    def load_root_key_by_keyid(self, root_path: str, keyid: str) -> Dict[str, Any]:
        """
        root.json에서 keyid로 key 객체를 찾아 반환.
        """
        with open(root_path, "r", encoding="utf-8") as f:
            root_doc = json.load(f)

        signed = root_doc["signed"]
        keys = signed["keys"]  # { keyid: keyobj }

        if keyid not in keys:
            raise KeyError(f"[!] root.json에 keyid={keyid} 가 존재하지 않습니다.")

        return keys[keyid]
    
    def ed25519_verify_hex(self, pub_hex: str, data: bytes, sig_hex: str) -> None:
        """
        pub_hex(32바이트 Ed25519 공개키 hex)와 sig_hex(서명 hex)를 이용해 검증.
        검증 실패 시 InvalidSignature 예외 발생.
        """
        pub_bytes = binascii.unhexlify(pub_hex)
        sig_bytes = binascii.unhexlify(sig_hex)

        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, data)  # 예외 없으면 검증 성공

    def verity_timestamp(self, signed_obj):
        # 만료 시간(expires) 검증
        expires_str = signed_obj.get("expires")
        if not expires_str:
            raise RuntimeError("[!] timestamp.signed.expires 필드가 없습니다.")

        expires_dt = self.parse_timestamp_datetime(expires_str)

        # 보통 TUF 메타데이터는 UTC 기준이므로 UTC now 사용
        now = datetime.now(timezone.utc)

        if now >= expires_dt:
            print(
                f"[!] timestamp 메타데이터 만료됨: "
                f"expires={expires_dt.isoformat()}, now={now.isoformat()}"
            )
            return False

        print("[*] timestamp 서명 및 만료 시간 검증 성공 (유효 기간 내)")
        return True

    
    def verify_metadata(self, meta: dict,
                        s_hash: Optional[str] = None, 
                        target_ver: Optional[int] = None,
                        snapshot_raw: Optional[bytes] = None) -> Tuple[bool, Optional[Any]]:
        # Verify a signature
        signatures = meta.get("signatures", [])
        if not signatures:
            raise RuntimeError("[!] timestamp.json에 signatures가 없습니다.")
        
        sig_entry = signatures[0]
        keyid = sig_entry["keyid"]
        sig_hex = sig_entry["sig"]

        keyobj = self.load_root_key_by_keyid("./meta/root.json", keyid)

        if keyobj.get("keytype") != "ed25519":
            raise RuntimeError(
                f"[!] keyid={keyid} 의 keytype이 ed25519가 아닙니다: {keyobj.get('keytype')}"
            )
        
        pub_hex = keyobj.get("keyval", {}).get("public")
        if not pub_hex:
            raise RuntimeError(f"[!] keyid={keyid} 의 keyval.public 이 비어 있습니다.")
        
        signed_obj = meta["signed"]
        payload = self.canonical_json_bytes(signed_obj)

        try:
            self.ed25519_verify_hex(pub_hex, payload, sig_hex)

        except Exception as e:
            print(f"[!] timestamp 서명 검증 실패: {e}")
            return False, None
        
        meta_type = signed_obj.get("_type")

        # 메타데이터 타입별 검증
        if meta_type == "timestamp":
            if not self.verity_timestamp(signed_obj):
                print("[FAIL] Timestamp is not correct")
                return False, None

            signed_meta = signed_obj.get("meta", {})

            try:
                s_hash_val = signed_meta["snapshot.json"]["hashes"]["sha256"]
            except KeyError:
                print("[FAIL] timestamp.meta에 snapshot.json 해시가 없습니다.")
                return False, None

            return True, s_hash_val
        
        elif meta_type == "snapshot":
            if s_hash is None:
                print("[FAIL] snapshot 검증에 필요한 s_hash가 없습니다.")
                return False, None

            sha = hashlib.sha256(snapshot_raw).hexdigest()

            if sha != s_hash:
                print("[FAIL] Snapshot hash mismatch")
                print(f"expected: {s_hash}")
                print(f"actual  : {sha}")
                return False, None

            signed_meta = signed_obj.get("meta", {})
            try:
                target_ver_val = signed_meta["targets.json"]["version"]
            except KeyError:
                print("[FAIL] snapshot.meta에 targets.json version이 없습니다.")
                return False, None

            return True, target_ver_val

        elif meta_type == "targets":
            # target_ver를 가지고 버전 일관성 체크를 하고 싶으면 여기서 추가
            targets_val = signed_obj.get("targets")
            return True, targets_val

        # 그 외 타입은 단순히 서명만 성공한 것으로 처리
        return True, None
    
    
    # Image 및 Director Target 메타데이터 교차 검증
    def hash_check(self, update_path: str, image_target: JsonMeta) -> List:
        with open(update_path, "r", encoding="utf-8") as f:
            update_meta = json.load(f)

        update_data = update_meta.get("signed")
        update_targets = update_data["targets"]

        h_check = False
        update_image = []

        for target in update_targets:
            h_check = False

            update_name = target["images"]["image_name"]
            sha_256 = target["images"]["image_info"]["hashes"]["sha256"]
            sha_512 = target["images"]["image_info"]["hashes"]["sha512"]

            if sha_256 == image_target[update_name]["hashes"]["sha256"]:
                h_check = True
            else:
                h_check = False

            if sha_512 == image_target[update_name]["hashes"]["sha512"]:
                h_check = True
            else:
                h_check = False

        if h_check:
            print("[Primary ECU] Update target hash is correct with Image target")
            return update_targets
        else:
            print("[FAIL] Update target hash is different with Image target")
            return update_image

    
    def verify_director_chain(self, timestamp: JsonMeta, snapshot: JsonMeta, targets: JsonMeta) -> VerifyResult:
        """
        Director의 메타데이터 순차 검증
        """
        try:
            # 역할/타입 정합성
            if timestamp["signed"].get("_type") != "timestamp":
                raise ValueError("Timestamp metadata _type mismatch")
            if snapshot["signed"].get("_type") != "snapshot":
                raise ValueError("Snapshot metadata _type mismatch")
            if targets["signed"].get("_type") != "targets":
                raise ValueError("Targets metadata _type mismatch")

            # 1) timestamp / snapshot / targets 서명 검증
            self._verify_signature(timestamp)
            self._verify_signature(snapshot)
            self._verify_signature(targets)

            # 2) 버전 연결 규칙 체크
            # timestamp → snapshot
            snap_ver_ref = next(iter(timestamp["signed"]["meta"].values()))["version"]
            if snap_ver_ref != snapshot["signed"]["version"]:
                raise ValueError(f"timestamp->snapshot version mismatch: {snap_ver_ref} != {snapshot['signed']['version']}")

            # snapshot → targets
            tgt_ver_ref = next(iter(snapshot["signed"]["meta"].values()))["version"]
            if tgt_ver_ref != targets["signed"]["version"]:
                raise ValueError(f"snapshot->targets version mismatch: {tgt_ver_ref} != {targets['signed']['version']}")

            out = Path("./meta/update_target.json")
            out.write_text(json.dumps(targets, ensure_ascii=False, indent=2), encoding="utf-8")
            
            return VerifyResult(ok=True)

        except Exception as e:
            return VerifyResult(ok=False, reason=str(e))
        
    def _verify_signature(self, meta: JsonMeta):
        verify_multi_signature(meta, self.keydb)

    # def verify_with_meta(self, meta_in: Union[JsonLike, PathLike], image_path: str) -> VerifyResult:
    #     """
    #     meta_in: dict 또는 파일 경로 어느 쪽도 허용.
    #     - root 메타면 read_root()로 공개키를 파일로 내리고 verify_multi_signature() 수행
    #     - 비-루트 메타도 signature(s) 필드만 있으면 verify_multi_signature() 호출 가능
    #     이미지 해시는 Updater 단계에서 expected_sha256로 이미 빠른 검증을 함.
    #     """
    #     try:
    #         meta = _as_dict(meta_in)
    #         meta = _normalize_signatures(meta)

    #         mtype = meta.get("signed", {}).get("_type")
    #         if mtype == "root":
    #             key_info = read_root(meta)          # manage_meta는 dict 기대
    #             verify_multi_signature(meta, key_info)
    #         else:
    #             # 필요 시 비-루트에 대한 key_info 설계/확장 가능
    #             verify_multi_signature(meta, {})

    #         return VerifyResult(ok=True)
    #     except Exception as e:
    #         return VerifyResult(ok=False, reason=str(e))