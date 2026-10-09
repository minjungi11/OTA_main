#!/usr/bin/env python3
# OCI → FastCDC chunk → Reassemble → Merge Layers(whiteout) → Import(podman)
# 단계 배너 + 성능 지표 출력

import os, sys, json, shutil, tarfile, mmap, subprocess, re, fastcdc, time, statistics, hashlib
from pathlib import Path

# --- 경로/설정 ---
SOURCE_OCI_DIR    = 'HU_ver1'
ROOT_DIR          = '../src_add'
CHUNKS_DIR        = os.path.join(ROOT_DIR, 'chunks_storage')
MANIFESTS_DIR     = os.path.join(ROOT_DIR, 'manifests')
REASSEMBLED_DIR   = os.path.join(ROOT_DIR, 'reassembled_oci')
MERGED_ROOTFS_DIR = os.path.join(REASSEMBLED_DIR, '_merged_rootfs')
# IMAGE_NAME        = 'ubuntu-reassembled-final:latest'
IMAGE_NAME        = 'seame_hu_app'

AVG = 64 * 1024
MIN = AVG // 2
MAX = AVG * 2

# ------------------------- 유틸 -------------------------
def ensure_dirs(chunks_dir=CHUNKS_DIR,
                manifests_dir=MANIFESTS_DIR,
                reassembled_dir=REASSEMBLED_DIR,
                merged_rootfs_dir=MERGED_ROOTFS_DIR):
    
    for d in [manifests_dir, reassembled_dir, merged_rootfs_dir]:
        if os.path.exists(d): shutil.rmtree(d)
    for d in [chunks_dir, manifests_dir, reassembled_dir, merged_rootfs_dir]:
        os.makedirs(d, exist_ok=True)

def clean_path(name: str) -> str:
    name = name.replace('\\','/')
    name = re.sub(r'^\./','', name).lstrip('/')
    parts = [p for p in name.split('/') if p not in ('', '.', '..')]
    return '/'.join(parts)

def hashlib_sha256(b: bytes) -> str:
    import hashlib
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

def write_chunk_if_absent(h: str, data: bytes, metrics):
    p = os.path.join(CHUNKS_DIR, h)
    created = False
    if not os.path.exists(p):
        with open(p, 'wb') as w: w.write(data)
        metrics['created_chunks'] += 1
        metrics['created_bytes']  += len(data)
        created = True
    return created

def fmt_bytes(n):
    return f"{n/1024/1024:.2f} MB"

def fmt_thr(bytes_, secs):
    if secs <= 0: return "∞ MB/s"
    return f"{(bytes_/1024/1024)/secs:.2f} MB/s"

# ------------------------- 1) FastCDC 분할 -------------------------
def file_hashes(path: str):
    """파일 전체 sha256 / sha512 해시 계산"""
    h256 = hashlib.sha256()
    h512 = hashlib.sha512()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h256.update(chunk)
            h512.update(chunk)
    return h256.hexdigest(), h512.hexdigest()

def chunk_file_fastcdc(path: str, base_dir: str, metrics):
    rel = os.path.relpath(path, base_dir)
    mf_path = os.path.join(MANIFESTS_DIR, rel)
    os.makedirs(os.path.dirname(mf_path), exist_ok=True)

    hashes = []
    size = os.path.getsize(path)
    metrics['split_input_bytes'] += size

    with open(path, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        if size < MIN:
            data = mm[:]
            h = hashlib_sha256(data); hashes.append(h)
            #metrics['chunks'].append(h)

            created = write_chunk_if_absent(h, data, metrics)
            if created:
                metrics['chunks'].append(h)

            metrics['chunk_sizes'].append(len(data))
            metrics['total_chunks'] += 1
            metrics['total_bytes']  += len(data)
        else:
            for c in fastcdc.fastcdc(mm, min_size=MIN, avg_size=AVG, max_size=MAX):
                off = getattr(c, 'offset', None); ln = getattr(c, 'length', None)
                if off is None or ln is None:
                    if isinstance(c, dict):
                        off = c.get('offset') or c.get('start') or 0
                        ln  = c.get('length') or c.get('size') or 0
                    else:
                        off, ln = c[0], c[1]
                if ln <= 0: continue
                data = mm[off:off+ln]
                h = hashlib_sha256(data); hashes.append(h)
                metrics['chunks'].append(h)

                created = write_chunk_if_absent(h, data, metrics)
                if created:
                    metrics['chunks'].append(h)

                metrics['chunk_sizes'].append(len(data))
                metrics['total_chunks'] += 1
                metrics['total_bytes']  += len(data)

    with open(mf_path, 'w') as mf:
        json.dump(hashes, mf, indent=0)

def split_all(source_path=SOURCE_OCI_DIR):
    print('--- [1/6] FastCDC 분할 ---')
    metrics = {
        'ecu': None, 'version': None,
        'total_chunks':0, 'created_chunks':0,
        'total_bytes':0,  'created_bytes':0,
        'split_input_bytes':0,
        'chunk_sizes':[],
        'chunks': [],
        'sha256': None,
        'sha512': None
    }
    if os.path.isdir(source_path):
        source_dir = source_path

    elif os.path.isfile(source_path):
        sha256_hex, sha512_hex = file_hashes(source_path)
        metrics['sha256'] = sha256_hex
        metrics['sha512'] = sha512_hex

        parent_dir = os.path.dirname(source_path)
        basename   = os.path.basename(source_path)          # HU_ver1.tar.xz
        name_no_compress, _ = os.path.splitext(basename)    # HU_ver1.tar, .xz

        if name_no_compress.endswith('.tar'):
            base_name = name_no_compress[:-4]               # HU_ver1
        else:
            base_name = name_no_compress

        tmp_root = os.path.normpath(os.path.join(parent_dir, '..', 'tmp'))

        if os.path.exists(tmp_root):
            shutil.rmtree(tmp_root)
        os.makedirs(tmp_root, exist_ok=True)

        with tarfile.open(source_path, 'r:*') as tf:
            tf.extractall(tmp_root)

        source_dir = os.path.join(tmp_root, base_name)

    else:
        raise ValueError(f"split_all: '{source_path}' is neither file nor directory")
    
    new_basename = os.path.basename(source_dir)

    if '_' in new_basename:
        ecu_part = new_basename.split('_')[0]      # 'HU'
        version_part = new_basename.split('_')[-1] # 'ver1'
    else:
        ecu_part = new_basename
        version_part = new_basename
    metrics['ecu'] = ecu_part
    
    if len(version_part) > 0:
        metrics['version'] = version_part[-1]
    else:
        metrics['version'] = None

    t0 = time.perf_counter()
    for root, _, files in os.walk(source_dir):
        for n in files:
            chunk_file_fastcdc(os.path.join(root, n), source_dir, metrics)
    t1 = time.perf_counter()

    manifests_archive = os.path.join(ROOT_DIR, 'manifests.tar.gz')
    if os.path.exists(manifests_archive):
        os.remove(manifests_archive)
    with tarfile.open(manifests_archive, 'w:gz') as tar:
        tar.add(MANIFESTS_DIR, arcname=os.path.basename(MANIFESTS_DIR))
    print(f"  매니페스트 압축 생성: {manifests_archive}")

    # 통계
    count = metrics['total_chunks']
    avg_sz = (sum(metrics['chunk_sizes'])/count) if count else 0
    p95    = int(statistics.quantiles(metrics['chunk_sizes'], n=20)[18]) if count >= 20 else (max(metrics['chunk_sizes']) if count else 0)

    print(f"  총 청크: {count:,} (고유 생성 {metrics['created_chunks']:,})")
    print(f"  평균 청크 크기: {avg_sz:.1f} B, P95: {p95} B, 최소:{min(metrics['chunk_sizes']) if count else 0} B, 최대:{max(metrics['chunk_sizes']) if count else 0} B")
    print(f"  입력 바이트: {fmt_bytes(metrics['split_input_bytes'])}")
    print(f"  생성 바이트(신규 청크): {fmt_bytes(metrics['created_bytes'])}")
    dur = t1 - t0
    print(f"  분할 시간: {dur:.3f} s, 처리량: {fmt_thr(metrics['split_input_bytes'], dur)}")
    return metrics, dur

# ------------------------- 2) 재조립 -------------------------
def reassemble_file(manifest_path: str, reassembled_dir: str, chunks_dir:str, base_dir: str, metrics):
    rel = os.path.relpath(manifest_path, base_dir)
    outp = os.path.join(reassembled_dir, rel)
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    with open(manifest_path, 'r') as mf:
        hashes = json.load(mf)
    with open(outp, 'wb') as w:
        for h in hashes:
            p = os.path.join(chunks_dir, h)
            with open(p, 'rb') as r:
                shutil.copyfileobj(r, w)
                metrics['reassembled_bytes'] += os.path.getsize(p)
                metrics['reassembled_files'] += 1

def join_all(manifests_dir=MANIFESTS_DIR, reassembled_dir=REASSEMBLED_DIR, chunks_dir=CHUNKS_DIR):
    print('--- [2/6] 파일 재조립 ---')
    metrics = {'reassembled_bytes':0, 'reassembled_files':0}
    t0 = time.perf_counter()
    for root, _, files in os.walk(manifests_dir):
        for n in files:
            reassemble_file(os.path.join(root, n), reassembled_dir, chunks_dir, manifests_dir, metrics)
    t1 = time.perf_counter()
    dur = t1 - t0
    print(f"  재조립 파일 수: {metrics['reassembled_files']:,}")
    print(f"  재조립 바이트: {fmt_bytes(metrics['reassembled_bytes'])}")
    print(f"  재조립 시간: {dur:.3f} s, 처리량: {fmt_thr(metrics['reassembled_bytes'], dur)}")
    return metrics, dur

def join_all_by_manifest(manifests=MANIFESTS_DIR, reassembled_dir=REASSEMBLED_DIR, chunks_dir=CHUNKS_DIR):
    print('--- [2/6] 파일 재조립 ---')
    metrics = {'reassembled_bytes':0, 'reassembled_files':0}
    t0 = time.perf_counter()
    with open(manifests, "r") as f:
        m = json.load(f)

    chunks_info = m["signed"]["chunks"]

    for rel_path, chunk_ids in chunks_info.items():
        out_path = Path(f"{reassembled_dir}/{rel_path}")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        print(f"[JOIN] {rel_path}  <- {len(chunk_ids)} chunks")

        # 파일을 새로 만들고, chunk들을 순서대로 append
        with out_path.open("wb") as out_f:
            for chunk_id in chunk_ids:
                chunk_path = Path(f"{chunks_dir}/{chunk_id}")

                if not chunk_path.is_file():
                    raise FileNotFoundError(
                        f"Chunk file not found: {chunk_path}"
                    )

                # chunk 내용을 그대로 이어 붙임
                with chunk_path.open("rb") as c_f:
                    shutil.copyfileobj(c_f, out_f, length=1024 * 1024)

    t1 = time.perf_counter()
    dur = t1 - t0
    # print(f"  재조립 파일 수: {metrics['reassembled_files']:,}")
    # print(f"  재조립 바이트: {fmt_bytes(metrics['reassembled_bytes'])}")
    print(f"  재조립 시간: {dur:.3f} s, 처리량: {fmt_thr(metrics['reassembled_bytes'], dur)}")
    return metrics, dur

# ------------------------- 3) 매니페스트 로드(첫 항목 고정) -------------------------
def get_layers_first_manifest():
    print('--- [3/6] 매니페스트 로드(첫 항목) ---')
    idx = os.path.join(REASSEMBLED_DIR, 'index.json')
    mans = json.load(open(idx))['manifests']
    man_dig = mans[0]['digest'].split(':')[1]
    man_path = os.path.join(REASSEMBLED_DIR, 'blobs', 'sha256', man_dig)
    manifest = json.load(open(man_path))
    layers = [l['digest'].split(':')[1] for l in manifest['layers']]
    print(f"  레이어 수: {len(layers)}")
    return layers

# ------------------------- 4) 레이어 병합(화이트아웃) -------------------------
def apply_whiteout(base_dir: str, member_dir: str, base_name: str):
    tgt = os.path.join(base_dir, member_dir, base_name[4:])
    if os.path.isdir(tgt): shutil.rmtree(tgt, ignore_errors=True)
    else:
        try: os.remove(tgt)
        except FileNotFoundError: pass

def apply_opq(base_dir: str, member_dir: str):
    tdir = os.path.join(base_dir, member_dir)
    if os.path.isdir(tdir):
        for e in os.listdir(tdir):
            p = os.path.join(tdir, e)
            shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else (os.remove(p) if os.path.exists(p) else None)

def extract_member(tar: tarfile.TarFile, m: tarfile.TarInfo, dest_root: str):
    name = clean_path(m.name)
    if not name: return
    tar.extract(m, path=dest_root)  # 신뢰 입력 가정

def apply_layer(layer_tar_path: str, dest_root: str):
    with tarfile.open(layer_tar_path, 'r:*') as t:
        mem = t.getmembers()
        for m in mem:
            if os.path.basename(m.name) == '.wh..wh..opq':
                apply_opq(dest_root, clean_path(os.path.dirname(m.name)))
        for m in mem:
            name = clean_path(m.name)
            base = os.path.basename(name)
            if base.startswith('.wh.'):
                apply_whiteout(dest_root, os.path.dirname(name), base); continue
            if base == '.wh..wh..opq': continue
            extract_member(t, m, dest_root)

def merge_layers(layers):
    print('--- [4/6] 레이어 병합(화이트아웃 반영) ---')
    if os.path.exists(MERGED_ROOTFS_DIR): shutil.rmtree(MERGED_ROOTFS_DIR)
    os.makedirs(MERGED_ROOTFS_DIR, exist_ok=True)
    t0 = time.perf_counter()
    applied = 0
    for dg in layers:
        lp = os.path.join(REASSEMBLED_DIR, 'blobs', 'sha256', dg)
        apply_layer(lp, MERGED_ROOTFS_DIR)
        applied += 1
    t1 = time.perf_counter()
    dur = t1 - t0
    print(f"  적용 레이어: {applied}")
    print(f"  병합 시간: {dur:.3f} s")
    return dur

# ------------------------- 5) Import -------------------------
def import_image(reassembled_dir=REASSEMBLED_DIR):
    print('--- [5/6] tar 스트림 → podman import ---')
    t0 = time.perf_counter()
    MERGED_ROOTFS_DIR = os.path.join(REASSEMBLED_DIR, '_merged_rootfs')
    merged_rootfs_dir = os.path.join(reassembled_dir, '_merged_rootfs')
    tar_p = subprocess.Popen(['tar','-C', MERGED_ROOTFS_DIR, '-cf','-','.'], stdout=subprocess.PIPE)
    try:
        subprocess.run(
            [
                'podman','import',
                '--change','ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                # '--change','CMD ["/bin/sh","-lc","echo OK"]',
                '-', IMAGE_NAME
            ],
            check=True, stdin=tar_p.stdout
        )
    finally:
        if tar_p.stdout: tar_p.stdout.close()
        tar_p.wait()
    t1 = time.perf_counter()
    dur = t1 - t0
    print(f"  import 시간: {dur:.3f} s")
    return dur

def load_image_from_oci(reassembled_dir=REASSEMBLED_DIR):
    print('--- [5/6] OCI 이미지 → podman load ---')
    t0 = time.perf_counter()
    oci_tar = os.path.join(reassembled_dir, 'image-oci.tar')
    subprocess.run(['tar', '-C', reassembled_dir, '-cf', oci_tar, '.'], check=True)
    subprocess.run(['podman','load','--input', oci_tar], check=True)
    t1 = time.perf_counter()
    dur = t1 - t0
    print(f"  load 시간: {dur:.3f} s")
    return dur

# ------------------------- 6) 스모크 테스트 -------------------------
def run_container():
    print('--- [6/6] 컨테이너 실행 ---')
    cmd = [
        'podman', 'run', '--rm',
        # 원래 스크립트의 -it
        '-it',
        '--name', 'hu_qt5_run',
        '--network', 'host',
        '--ipc=host',
        '--cap-add=NET_RAW',
        '-e', f'DISPLAY={os.environ.get("DISPLAY", "")}',
        '-v', '/tmp/.X11-unix:/tmp/.X11-unix:rw',
        '--device', '/dev/dri',
        IMAGE_NAME,
    ]
    print(f"> 실행: podman run --rm {IMAGE_NAME}")
    subprocess.run(cmd, check=True)

# ------------------------- 메인 -------------------------
def main():
    if not os.path.isdir(SOURCE_OCI_DIR):
        print(f"오류: '{SOURCE_OCI_DIR}' 없음", file=sys.stderr); sys.exit(1)
    print('=== FastCDC 기반 OCI 재조립 파이프라인 시작 ===')
    ensure_dirs()
    split_metrics, split_time = split_all()
    join_metrics,  join_time  = join_all()
    layers = get_layers_first_manifest()
    # merge_time = merge_layers(layers)
    # import_time = import_image()
    load_image_from_oci()
    run_container()

    print('=== 성능 요약 ===')
    total_input = split_metrics['split_input_bytes']
    print(f"  입력 파일 총 크기: {fmt_bytes(total_input)}")   # ← 추가
    print(f"  분할: {split_time:.3f}s, 처리량 {fmt_thr(total_input, split_time)}")
    print(f"  재조립: {join_time:.3f}s, 처리량 {fmt_thr(join_metrics['reassembled_bytes'], join_time)}")
    # print(f"  병합: {merge_time:.3f}s, import: {import_time:.3f}s")
    reused = max(split_metrics['total_chunks'] - split_metrics['created_chunks'], 0)
    reuse_ratio = (reused / split_metrics['total_chunks']*100.0) if split_metrics['total_chunks'] else 0.0
    print(f"  고유 청크: {split_metrics['created_chunks']:,} / 총 {split_metrics['total_chunks']:,} (재사용률 {reuse_ratio:.1f}%)")
    print('=== 완료 ===')

if __name__ == '__main__':
    main()
