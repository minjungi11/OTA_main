import os
import tarfile
import time
import json
import base64
import hashlib
import ssl
import threading
import requests
from datetime import datetime, timezone

from flask import Flask, request, jsonify, send_from_directory
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import paho.mqtt.client as mqtt
from ecdsa import SigningKey

# from utils.json_handler import JsonHandler
from utils.signature.pub_signature import make_payload_with_signatures
from utils.signature.sub_signature import verify_multi_signature
from utils.snapshot import generate_snapshot
from utils.timestamp import generate_timestamp

BASE_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WATCH_DIR  = os.path.join(BASE_DIR, "Image_Repo/meta")          # new_chunks.tar.gz, manifests.tar.gz 위치
CHUNKS_DIR = os.path.join(WATCH_DIR, "../chunks_storage")  # 항상 서비스할 청크 디렉터리
MANIFESTS_TAR = os.path.join(WATCH_DIR, "manifests.tar.gz")
NEW_CHUNKS_TAR = os.path.join(WATCH_DIR, "new_chunks.tar.gz")

os.makedirs(CHUNKS_DIR, exist_ok=True)

class FlaskServer:
    def __init__(self, host="10.30.101.15", port=8443,
                 cert="./utils/certs/https_server.crt",
                 key="./utils/certs/https_server.key"):
        self.app = Flask(__name__)
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self._register_routes()

    def _register_routes(self):
        # 청크 서비스
        @self.app.route("/chunks/<path:chunk_name>", methods=["GET"])
        def get_chunk(chunk_name):
            """
            예: GET /chunks/abcd1234sha256
              → WATCH_DIR/chunks_storage/abcd1234sha256
            """
            full_path = os.path.join(CHUNKS_DIR, chunk_name)
            if not os.path.exists(full_path):
                return jsonify({"error": "chunk not found"}), 404
            return send_from_directory(CHUNKS_DIR, chunk_name, as_attachment=True)

        # Metadata 서비스
        @self.app.route("/meta/<path:meta_type>", methods=["GET"])
        def get_manifests(meta_type):
            """
            예: GET /meta/targets.json
              → WATCH_DIR/meta/targets.json
            """
            full_path = os.path.join(WATCH_DIR, meta_type)
            if not os.path.exists(full_path):
                return jsonify({"error": "manifests not ready"}), 404
            
            return send_from_directory(
                WATCH_DIR,
                meta_type,
                as_attachment=True
            )

    def run(self):
        threading.Thread(
            target=self.app.run,
            kwargs={
                "host": self.host,
                "port": self.port,
                "ssl_context": (self.cert, self.key),
                "threaded": True,
            },
            daemon=True,
        ).start()


class FileHandler:
    def __init__(self, mqtt_broker, mqtt_port, watch_dir, files_path):
        self.MQTT_BROKER = mqtt_broker
        self.MQTT_PORT = mqtt_port
        self.WATCH_DIR = watch_dir
        self.files_path = files_path

        self.MQTT_REQUEST_TOPIC = "primary/request"
        self.MQTT_META_TOPIC = "image/metaData"

        self.ca_cert = "./utils/certs/ca.crt"
        self.client_cert = "./utils/certs/mqtt_client.crt"
        self.client_key = "./utils/certs/mqtt_client.key"

        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        configure_tls(self.client, self.ca_cert, self.client_cert, self.client_key)

        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

        self.observer = Observer()
        self.event_handler = FileChangeHandler(self.client, self.WATCH_DIR, self.files_path)
        self.observer.schedule(self.event_handler, self.WATCH_DIR, recursive=False)

    def connect_mqtt(self):
        try:
            self.client.connect(self.MQTT_BROKER, self.MQTT_PORT, 60)
        except Exception as e:
            print(f"[Error] MQTT connection failed: {e}")

    def start_watching(self):
        print(f"[Watcher] Watching directory: {self.WATCH_DIR}")
        self.observer.start()

    def stop_watching(self):
        self.observer.stop()

    def loop_mqtt(self):
        self.client.loop_start()

    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"[MQTT] Connected: {rc}")
        client.subscribe(self.MQTT_REQUEST_TOPIC)

    def on_message(self, client, userdata, msg):
        # Vehicle 업데이트 요청 수신
        if msg.topic == self.MQTT_REQUEST_TOPIC:
            print("[MQTT] Meta Data request received from Primary ECU")

            # Send the timestamp metadata
            with open("../Image_Repo/meta/timestamp.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            
            upload_url = f"https://{self.MQTT_BROKER}:8443"
            data["url"] = upload_url
            
            # Timestamp + URL Json 데이터 전송
            self.client.publish(self.MQTT_META_TOPIC, json.dumps(data, ensure_ascii=False).encode("utf-8"), qos=2)
            print(f"[MQTT] 📡 Meta Data published metadata")


class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, client, watch_dir, files_path):
        self.client = client
        self.watch_dir = watch_dir
        self.files_path = files_path
        # self.json_handler = JsonHandler()
        self.signing_key_path = "./utils/signature/image_private.pem"

    # targets.json 변경 감지
    def on_modified(self, event):
        fname = os.path.basename(event.src_path)
        
        # 변경된 target 메타데이터에 대한 snapshot, timestamp 메타데이터 갱신
        if fname == "targets.json":
            s_path = generate_snapshot()
            print(f"[Image] Update a new snapshot metadata: {s_path}\n")
            ts_path = generate_timestamp()
            print(f"[Image] Update a new timestamp metadata: {ts_path}\n")
    
    # targets.json 생성 감지(처음 생성할 경우) -> 현재 사용 X
    def on_created(self, event):
        if event.is_directory:
            TARGET_PATH = "../data/target_new.json"
            # 추후 target_new.json / target_image.json 경로 및 이름을 통일
            
            if not os.path.exists(TARGET_PATH):
                print("[Error] target_new.json not found")
                return

            with open(TARGET_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)

            targets = {}
            sk = SigningKey.from_pem(open(self.signing_key_path).read())

            for folder_name, files in data.items():
                if folder_name == "version":
                    continue
                folder_path = os.path.join(self.watch_dir, folder_name)

                for file_name, file_info in files.items():
                    rel_path = file_info.get("path")
                    full_path = os.path.join(folder_path, rel_path)
                    if not os.path.exists(full_path):
                        print(f"[Watcher] File not found: {full_path}")
                        continue

                    with open(full_path, "rb") as f:
                        content = f.read()
                    sha256_digest = hashlib.sha256(content).digest()
                    file_info["sha256"] = base64.b64encode(sha256_digest).decode('utf-8')
                    file_info["signature"] = base64.b64encode(sk.sign(sha256_digest)).decode('utf-8')

                    targets[file_name] = {
                        "hashes": {"sha256": hashlib.sha256(content).hexdigest()},
                        "length": len(content)
                    }

            output = {
                "signed": {
                    "_type": "targets",
                    "spec_version": "1.0.0",
                    "version": 1,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "expires": "2030-01-01T00:00:00Z",
                    "targets": targets
                },
                "signatures": []
            }

            os.makedirs("./data", exist_ok=True)
            target_json_path = "./data/target_image.json"
            with open(target_json_path, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=4, ensure_ascii=False)
            print(f"[Watcher] ✅ target_image.json created with timestamp")

            output_tar_path = "./data/update_image.tar.xz"
            # self.json_handler.create_new_update_tarball(target_json_path, self.watch_dir, output_tar_path)
            print(f"[Watcher] 🗜️ Tarball created: {output_tar_path}")


def configure_tls(client, ca_cert, client_cert, client_key):
    client.tls_set(
        ca_certs=ca_cert,
        certfile=client_cert,
        keyfile=client_key,
        tls_version=ssl.PROTOCOL_TLSv1_2
    )
    client.tls_insecure_set(False)

# def process_new_chunks_periodically(interval_sec=5):
#     """
#     WATCH_DIR 안의 new_chunks.tar.gz를 주기적으로 확인.
#     - 있으면 CHUNKS_DIR에 풀고, new_chunks.tar.gz 삭제
#     - manifests.tar.gz는 외부에서 이미 새걸로 덮어쓴다고 가정
#       (우리는 그냥 있는 그대로 /manifests 로 서비스)
#     """
#     while True:
#         try:
#             if os.path.exists(NEW_CHUNKS_TAR):
#                 print(f"[Repo] 🔔 new_chunks.tar.gz detected: {NEW_CHUNKS_TAR}")
#                 with tarfile.open(NEW_CHUNKS_TAR, "r:gz") as tar:
#                     tar.extractall(CHUNKS_DIR)
#                 os.remove(NEW_CHUNKS_TAR)
#                 print(f"[Repo] ✅ new_chunks.tar.gz extracted into chunks_storage and removed")

#                 # manifests.tar.gz는 처음엔 없을 수도 있음
#                 if os.path.exists(MANIFESTS_TAR):
#                     print(f"[Repo] ℹ️ manifests.tar.gz present (will be served by /manifests)")
#                 else:
#                     print(f"[Repo] ⚠️ manifests.tar.gz not found yet")
#         except Exception as e:
#             print(f"[Repo] ❌ Error while processing new_chunks.tar.gz: {e}")
#         time.sleep(interval_sec)



if __name__ == "__main__":
    flask_server = FlaskServer()
    flask_server.run()
    print("[Image] Flask repository server started")

    # threading.Thread(
    #     target=process_new_chunks_periodically,
    #     kwargs={"interval_sec": 5},
    #     daemon=True,
    # ).start()
    print("[Main] new_chunks watcher started")

    MQTT_BROKER = "10.30.101.15"
    MQTT_PORT = 8883
    WATCH_DIR = "../Image_Repo/meta"
    files_path = "./data/update_image.tar.xz"
    # update_image.tar.xz 경로도 통일 필요

    file_handler = FileHandler(MQTT_BROKER, MQTT_PORT, WATCH_DIR, files_path)
    file_handler.connect_mqtt()
    file_handler.start_watching()
    file_handler.loop_mqtt()

    try:
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("[Watcher] Shutting down...")
        
        file_handler.stop_watching()
        file_handler.client.loop_stop()
        file_handler.observer.join()