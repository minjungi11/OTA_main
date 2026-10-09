import os
import time
import json
import base64
import hashlib
import ssl
import threading
import requests
from datetime import datetime, timezone

from flask import Flask, request, send_from_directory
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import paho.mqtt.client as mqtt
from ecdsa import SigningKey

from utils.json_handler import JsonHandler
from src.utils.signature.pub_signature import make_payload_with_signatures
from utils.signature.sub_signature import verify_multi_signature


class FlaskServer:
    def __init__(self, host="10.222.88.12", port=8443,
                 cert="./utils/certs/https_server.crt",
                 key="./utils/certs/https_server.key",
                 upload_folder="./uploads"):
        os.makedirs(upload_folder, exist_ok=True)
        self.app = Flask(__name__)
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.upload_folder = upload_folder
        self._register_routes()

    def _register_routes(self):
        @self.app.route('/upload', methods=['POST'])
        def upload_file():
            try:
                file = request.files['file']
                filepath = os.path.join(self.upload_folder, file.filename)
                file.save(filepath)
                print(f"[Flask] ✅ File saved at: {filepath} ({os.path.getsize(filepath)} bytes)")
                
                return {"url": f"https://{self.host}:{self.port}/download/{file.filename}"}, 200
            
            except Exception as e:
                print(f"[Error] Upload failed: {e}")
                
                return {"error": "upload failed"}, 500

        @self.app.route('/download/<filename>', methods=['GET'])
        def download_file(filename):
            return send_from_directory(self.upload_folder, filename, as_attachment=True)

    def run(self):
        threading.Thread(
            target=self.app.run,
            kwargs={"host": self.host, "port": self.port,
                    "ssl_context": (self.cert, self.key), "threaded": True},
            daemon=True
        ).start()


class FileHandler:
    def __init__(self, mqtt_broker, mqtt_port, watch_dir, files_path):
        self.MQTT_BROKER = mqtt_broker
        self.MQTT_PORT = mqtt_port
        self.WATCH_DIR = watch_dir
        self.files_path = files_path

        self.MQTT_REQUEST_TOPIC = "primary/requestMeta"
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

        self.json_handler = JsonHandler()

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
        try:
            payload_data = json.loads(msg.payload.decode('utf-8'))
            temp_json_path = "./receive_signature.json"
            with open(temp_json_path, "w", encoding="utf-8") as f:
                json.dump(payload_data, f, indent=2)

            if verify_multi_signature(temp_json_path):
                print("[MQTT] ✅ Multi-signature verification passed")

                if msg.topic == self.MQTT_REQUEST_TOPIC:
                    print("[MQTT] Meta Data request received from Primary ECU")

                    target_path = "./data/target_image.json"
                    # 추후 동일한 경로/파일명으로 맞춰야 함
                    
                    if not os.path.exists(target_path):
                        print("[Error] target_image.json not found")
                        return

                    with open(target_path, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    upload_url = f"https://{self.MQTT_BROKER}:8443/upload"
                    with open(self.files_path, 'rb') as f:
                        files = {'file': ('update_image.tar.xz', f)}
                        res = requests.post(upload_url, files=files, verify="./utils/certs/https_server.crt")
                    
                    if res.status_code != 200:
                        print(f"[Error] File upload failed (HTTP {res.status_code})")
                        return

                    download_url = res.json().get('url')
                    if not download_url:
                        print("[Error] No URL in server response")
                        return

                    data["url"] = download_url
                    meta_payload = make_payload_with_signatures(data)
                    client.publish(self.MQTT_META_TOPIC, meta_payload, qos=2)
                    print(f"[MQTT] 📡 Upload complete, download URL: {download_url}")

            else:
                print("[MQTT] ❌ Multi-signature verification failed")

        except Exception as e:
            print(f"[Error] Exception in on_message: {e}")


class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, client, watch_dir, files_path):
        self.client = client
        self.watch_dir = watch_dir
        self.files_path = files_path
        self.json_handler = JsonHandler()
        self.signing_key_path = "./utils/signature/image_private.pem"

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
            self.json_handler.create_new_update_tarball(target_json_path, self.watch_dir, output_tar_path)
            print(f"[Watcher] 🗜️ Tarball created: {output_tar_path}")


def configure_tls(client, ca_cert, client_cert, client_key):
    client.tls_set(
        ca_certs=ca_cert,
        certfile=client_cert,
        keyfile=client_key,
        tls_version=ssl.PROTOCOL_TLSv1_2
    )
    client.tls_insecure_set(False)


if __name__ == "__main__":
    flask_server = FlaskServer()
    flask_server.run()

    MQTT_BROKER = "10.222.88.12"
    MQTT_PORT = 8883
    WATCH_DIR = "../Image_Repo"
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