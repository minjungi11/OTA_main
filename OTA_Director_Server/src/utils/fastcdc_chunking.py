import os, json, mmap, re, fastcdc, time, hashlib, tarfile, shutil
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple, List, Any

# 기본 경로 (필요하면 프로젝트에 맞게 수정해서 쓰시면 됩니다)
ROOT_DIR      = '../src_add'
CHUNKS_DIR    = os.path.join(ROOT_DIR, 'chunks_storage')

# FastCDC 파라미터
AVG = 64 * 1024
MIN = AVG // 2
MAX = AVG * 2


def ensure_dirs(*dirs: str) -> None:
    """필요한 디렉터리를 생성만 하는 헬퍼."""
    for d in dirs:
        if d:
            os.makedirs(d, exist_ok=True)


def clean_path(name: str) -> str:
    """tar 내부 경로를 깔끔한 상대경로로 정리."""
    name = name.replace('\\', '/')
    name = re.sub(r'^\\./', '', name).lstrip('/')
    parts = [p for p in name.split('/') if p not in ('', '.', '..')]
    return '/'.join(parts)


def hashlib_sha256(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def file_hashes(path: str) -> Tuple[str, str]:
    """전체 tar 파일에 대한 sha256 / sha512 해시 계산."""
    h256 = hashlib.sha256()
    h512 = hashlib.sha512()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            if not chunk:
                break
            h256.update(chunk)
            h512.update(chunk)
    return h256.hexdigest(), h512.hexdigest()


def default_expires(days: int = 365) -> str:
    """만료 시간 ISO8601 문자열 생성."""
    now = datetime.now(timezone.utc)
    exp = (now + timedelta(days=days)).replace(microsecond=0)
    # Uptane 스타일로 Z 접미사
    return exp.isoformat().replace('+00:00', 'Z')


def write_chunk_if_absent(h: str, data: bytes, metrics: Dict[str, Any]) -> bool:
    """
    청크 파일이 없으면 새로 저장하고 metrics 갱신.
    반환값: 새로 생성되었으면 True, 이미 있었으면 False.
    """
    ensure_dirs(CHUNKS_DIR)
    p = os.path.join(CHUNKS_DIR, h)
    if not os.path.exists(p):
        with open(p, 'wb') as w:
            w.write(data)
        metrics['created_chunks'] += 1
        metrics['created_bytes'] += len(data)
        metrics['new_chunk_ids'].append(h)
        return True
    return False


def chunk_file_fastcdc(path: str,
                       base_dir: str,
                       metrics: Dict[str, Any],
                       chunks_map: Dict[str, List[str]]) -> None:
    """
    단일 파일을 FastCDC로 분할하여 CHUNKS_DIR에 청크 저장 후
    파일 경로별 청크 해시 리스트를 chunks_map[rel_path]에 기록.
    """
    rel = os.path.relpath(path, base_dir)
    rel = clean_path(rel)

    hashes: List[str] = []
    size = os.path.getsize(path)
    metrics['split_input_bytes'] += size

    with open(path, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        if size < MIN:
            data = mm[:]
            h = hashlib_sha256(data)
            hashes.append(h)
            write_chunk_if_absent(h, data, metrics)
            metrics['chunk_sizes'].append(len(data))
            metrics['total_chunks'] += 1
        else:
            for c in fastcdc.fastcdc(mm, min_size=MIN, avg_size=AVG, max_size=MAX):
                # 가장 안전하고 호환성 있는 offset/length 추출 방식
                off = getattr(c, "offset", None)
                ln  = getattr(c, "length", None)

                if off is None or ln is None:
                    if isinstance(c, dict):
                        off = c.get("offset") or c.get("start") or 0
                        ln  = c.get("length") or c.get("size") or 0
                    else:
                        # fallback: tuple or list
                        off, ln = c[0], c[1]

                if ln <= 0:
                    continue

                data = mm[off:off+ln]
                h = hashlib_sha256(data)
                hashes.append(h)
                write_chunk_if_absent(h, data, metrics)
                metrics['chunk_sizes'].append(len(data))
                metrics['total_chunks'] += 1

    chunks_map[rel] = hashes


def split_all(source_path: str) -> Tuple[Dict[str, Any], float, Dict[str, Any]]:
    """
    watchdog에서 호출하는 엔트리 포인트.

    입력:
      - source_path: tar 파일 경로(권장) 또는 OCI 디렉터리 경로

    반환:
      - metrics: {
          'total_chunks', 'created_chunks', 'created_bytes',
          'split_input_bytes', 'chunk_sizes', 'new_chunk_ids',
          'sha256', 'sha512'
        }
      - elapsed: 분할에 걸린 시간 (초)
      - signed: ivi_1.0.0.json의 signed 구조와 동일한 dict
    """
    ensure_dirs(CHUNKS_DIR)

    metrics: Dict[str, Any] = {
        'total_chunks': 0,
        'created_chunks': 0,
        'created_bytes': 0,
        'split_input_bytes': 0,
        'chunk_sizes': [],
        'new_chunk_ids': [],
        'sha256': None,
        'sha512': None,
    }

    # tar인지 디렉터리인지 구분
    temp_dir = None
    if os.path.isdir(source_path):
        source_dir = source_path
    elif os.path.isfile(source_path):
        sha256_hex, sha512_hex = file_hashes(source_path)
        metrics['sha256'] = sha256_hex
        metrics['sha512'] = sha512_hex

        # tar를 임시 디렉터리에 풀기
        parent_dir = os.path.dirname(os.path.abspath(source_path))
        temp_dir = os.path.join(parent_dir, '.chunking_tmp')
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir, exist_ok=True)

        with tarfile.open(source_path, 'r:*') as tf:
            tf.extractall(temp_dir)

        # OCI 레이아웃이 temp_dir 바로 아래에 있다고 가정
        source_dir = temp_dir
    else:
        raise ValueError(f"split_all: '{source_path}' is neither file nor directory")

    chunks_map: Dict[str, List[str]] = {}

    t0 = time.perf_counter()
    for root, _, files in os.walk(source_dir):
        for n in files:
            fpath = os.path.join(root, n)
            chunk_file_fastcdc(fpath, source_dir, metrics, chunks_map)
    t1 = time.perf_counter()
    elapsed = t1 - t0

    # 임시 디렉터리 정리
    if temp_dir and os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)

    signed = {
        "_type": "targets",
        "expires": default_expires(),
        "algo": {
            "type": "fastcdc",
            "min": MIN,
            "avg": AVG,
            "max": MAX,
            "hash": "sha256",
        },
        "chunks": chunks_map,
    }

    return metrics, elapsed, signed
