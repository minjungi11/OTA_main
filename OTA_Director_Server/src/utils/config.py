# Director/config.py
from pathlib import Path

# === 기준 경로: 이 파일이 들어있는 Director 폴더 ===
ROOT = Path(__file__).resolve().parent

# --- 디렉터리 ---
DIRECTOR_METADATA_DIR = (ROOT / "../../Image_Repo/meta").resolve()
DIRECTOR_KEYS_DIR     = (ROOT / "../../keys").resolve()

# --- MQTT (mTLS) ---
MQTT_BROKER = "192.168.182.9"
MQTT_PORT   = 8883

# cert/key는 프로젝트 구조: Director/src/utils/certs/...
MQTT_CA   = "./src/utils/certs/ca.crt"
MQTT_CERT = "./src/utils/certs/director.crt"
MQTT_KEY  = "./src/utils/certs/director.key"

# --- Topics ---
TOPIC_VVM    = "primary/version"
TOPIC_REPORT = "primary/report"
TOPIC_UPDATE = "director/updateMeta"
TOPIC_DIRECTOR_TIMESTAMP  = "director/timestamp"
TOPIC_DIRECTOR_SNAPSHOT   = "director/snapshot"
TOPIC_DIRECTOR_TARGETS    = "director/targets"

# --- 만료일 ---
TARGETS_EXPIRES_DAYS   = 14
SNAPSHOT_EXPIRES_DAYS  = 7
TIMESTAMP_EXPIRES_DAYS = 2

# (옵션) 메타/키 폴더 보장
DIRECTOR_METADATA_DIR.mkdir(parents=True, exist_ok=True)
DIRECTOR_KEYS_DIR.mkdir(parents=True, exist_ok=True)