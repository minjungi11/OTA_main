from dataclasses import dataclass
from typing import Optional, Union, Dict, Any, List
from urllib.parse import urljoin
from pathlib import Path
import os, shutil, json, subprocess
import requests
from utils.fastcdc_chunking import join_all_by_manifest
from utils.fastcdc_chunking import run_container

from .storage import Storage

@dataclass
class InstallResult:
    ok: bool
    reason: Optional[str] = None

class Installer:
    def __init__(self, storage: Storage):
        self.storage = storage

    def build_image_manifest_url(self, base_url, ecu, image_name):
        filename = f"{image_name}.json"
        return f"{base_url}/meta/targets/{ecu}/{ecu}_image/{filename}"
    
    def build_image_chunk_url(self, base_url, chunk_name):
        return f"{base_url}/chunks/{chunk_name}"


    # OCI-DIR → OCI-TAR 변환 함수
    def convert_oci_dir_to_tar(self, oci_dir: str, out_tar: str):
        
        # 먼저 import (oci-dir → temp image)
        temp_tag = "local/tmp_ivi:latest"
        subprocess.run(
            ["podman", "image", "import", oci_dir, "--tag", temp_tag],
            check=True
        )

        # temp image → oci archive (.tar)
        subprocess.run(
            ["podman", "image", "save", "--format", "oci-archive", "-o", out_tar, temp_tag],
            check=True
        )

    # SBOM Static Verification 실행 함수
    def run_static_verification(self, archive_path: str):
        
        env = os.environ.copy()
        env["ARCHIVE"] = archive_path   # shell pipeline에서 사용할 환경 변수

        # static/run_all.sh 경로 자동 설정
        static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
        runall = os.path.join(static_dir, "run_all.sh")

        print(f"[Primary ECU] Static Verification Start  ->  {archive_path}")
        
        result = subprocess.run(
            [runall],
            env=env,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr)
            raise RuntimeError("Static verification FAILED for: " + archive_path)

        print("[Primary ECU] Static Verification PASSED")

    # Chunk 다운로드 및 재조립
    def download_chunk(self, update_images: List, base_url: str):
        
        for t in update_images:
            chunk_list = t["images"]["required_chunks"]

            for c in chunk_list:
                url = self.build_image_chunk_url(base_url, c)
                out_path = f"./downloads/chunk_storage/{c}"
                print(f"[Primary ECU] GET:  {url}")

                try:
                    with requests.get(url, stream=True, verify=False) as response:
                        response.raise_for_status()
                        with open(out_path, "wb") as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                    print(f"[OK] saved chunk -> {out_path}")
                except Exception as e:
                    print(f"[FAIL] failed to download chunk {c} from {url}: {e}")

            # 재조립
            image_name = t["images"]["image_name"]
            manifest_path = f"./downloads/{image_name}.json"
            oci_dir = f"./downloads/{image_name}"

            metrics, tt = join_all_by_manifest(
                manifest_path, 
                oci_dir, 
                "./downloads/chunk_storage"
            )
            print(f"[Primary ECU] Reassembled (OCI-DIR): {oci_dir}")

            # OCI DIR → OCI TAR 변환
            archive_path = f"./downloads/{image_name}.tar"
            self.convert_oci_dir_to_tar(oci_dir, archive_path)
            print(f"[Primary ECU] Normalized OCI-Archive: {archive_path}")

            # Static Verification
            self.run_static_verification(archive_path)

            # static PASS → 실제 컨테이너 load + run
            subprocess.run(["podman", "load", "-i", archive_path], check=True)
            run_container()

    # Manifest 다운로드 -> 컨테이너 재조립을 위한 chunk 목록
    def download_manifest(self, update_images:List, base_url:str):
        
        for t in update_images:
            ecu = t["ecu"]
            image_name = t["images"]["image_name"]

            url = self.build_image_manifest_url(base_url, ecu, image_name)
            print(f"[Primary ECU] GET:  {url}")

            resp = requests.get(url, verify=False)
            if resp.status_code != 200:
                # 상황에 따라 raise / continue 등 정책 선택
                raise RuntimeError(f"Failed to fetch {url}: {resp.status_code}")

            image_meta = resp.json()
            save_path = Path(f"./downloads/{image_name}.json")
            save_path.write_text(json.dumps(image_meta, indent=2, ensure_ascii=False), encoding="utf-8")




    def install(self, image_path: str, version: str) -> InstallResult:
        try:
            staging = self.storage.staging_dir(version)
            os.makedirs(staging, exist_ok=True)
            shutil.copy2(image_path, os.path.join(staging, os.path.basename(image_path)))

            active = self.storage.active_symlink()
            if os.path.islink(active): os.unlink(active)
            os.symlink(staging, active)

            self.storage.write_version(version)
            return InstallResult(ok=True)
        except Exception as e:
            return InstallResult(ok=False, reason=str(e))

    def rollback(self):
        prev = self.storage.last_good_version()
        if not prev:
            raise RuntimeError("no previous version to rollback")
        active = self.storage.active_symlink()
        if os.path.islink(active): os.unlink(active)
        os.symlink(self.storage.staging_dir(prev), active)
