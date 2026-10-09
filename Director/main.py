# Director/main.py
import json, time, logging
from pathlib import Path

from config import ( DIRECTOR_METADATA_DIR, TOPIC_DIRECTOR_TARGETS,
                    TOPIC_DIRECTOR_SNAPSHOT, TOPIC_DIRECTOR_TIMESTAMP )
from mqtt_handler import MQTTBus

from src.targets_per_vehicle import make_targets_for_car
from src.snapshot import generate_snapshot
from src.timestamp import generate_timestamp
from src.vvm_verify import verify_vvm_signature   # <-- 추가

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("director-main")

def _load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def _load_global_targets_fixed() -> dict:
    # 글로벌 카탈로그 파일을 한 곳으로 고정 (둘 중 하나를 선택해서 운영)
    p = DIRECTOR_METADATA_DIR / "targets.json"
    return _load_json(p) if p.exists() else {}

def main():
    # MQTT 버스 형식
    bus = MQTTBus()
    bus.connect_and_loop()
    log.info("Director service started. Waiting for VVM...")

    while True:
        vvm = bus.vvm_queue.get()
        vin = (vvm.get("signed") or vvm).get("vin", "unknown")

        # (0) VVM 서명 검증
        if not verify_vvm_signature(vvm):
            log.error(f"VVM signature invalid → drop (vin={vin})")
            continue
        log.info(f"VVM verified (vin={vin})")

        # (1) 글로벌 targets 로드(리스트 스키마)
        global_targets = _load_global_targets_fixed()

        # (2) per-vehicle targets 생성(리스트 스키마) → 파일 Path
        t_path = make_targets_for_car(vvm, global_targets)
        targets = _load_json(t_path)

        # (3) snapshot / (4) timestamp 생성
        s_path  = generate_snapshot()
        ts_path = generate_timestamp()
        snapshot  = _load_json(s_path)
        timestamp = _load_json(ts_path)

        # (5) Publish 순서: timestamp → snapshot → targets
        bus.publish_meta(TOPIC_DIRECTOR_TIMESTAMP, "timestamp", timestamp)
        bus.publish_meta(TOPIC_DIRECTOR_SNAPSHOT, "snapshot",  snapshot)
        bus.publish_meta(TOPIC_DIRECTOR_TARGETS, "targets",   targets)

        log.info(f"Published meta for vin={vin} (targets={t_path.name})")
        
        report = bus.report_queue.get()

        status = report.get("status")
        reason = report.get("reason") or {}

        if status == "director_meta_verify_ok":
            log.info(f"[OK] Prime ECU verified metadata for {vin}")
        else:
            log.error(f"[FAIL] Prime ECU rejected metadata for {vin}: {reason}")

if __name__ == "__main__":
    main()