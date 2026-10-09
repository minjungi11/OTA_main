# Director/mqtt_handler.py
import json, ssl, queue, logging
from pathlib import Path
import paho.mqtt.client as mqtt

from config import (
    MQTT_BROKER, MQTT_PORT,
    MQTT_CA, MQTT_CERT, MQTT_KEY,
    TOPIC_VVM, TOPIC_REPORT
)

log = logging.getLogger("mqtt_handler")

class MQTTBus:
    def __init__(self):
        self.client = mqtt.Client(client_id="director-001")
        self.vvm_queue = queue.Queue()
        self.report_queue = queue.Queue()
        self._mtls = False

    def _configure_tls(self):
        ca_p   = MQTT_CA
        cert_p = MQTT_CERT
        key_p  = MQTT_KEY

        self.client.tls_set(
            ca_certs=ca_p,
            certfile=cert_p,
            keyfile=key_p,
            tls_version=ssl.PROTOCOL_TLSv1_2,
        )
        self.client.tls_insecure_set(True)  # 검증 ON

    def _on_connect(self, client, userdata, flags, rc):
        log.info(f"MQTT connected rc={rc}")
        client.subscribe(TOPIC_VVM, qos=1)
        client.subscribe(TOPIC_REPORT, qos=1)

    def _on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception:
            log.exception(f"Invalid message on {msg.topic}")
            return

        if msg.topic == TOPIC_VVM:
            self.vvm_queue.put(payload)
            log.info(f"VVM received on {msg.topic}")

        elif msg.topic == TOPIC_REPORT:
            self.report_queue.put(payload)
            log.info(f"Prime ECU report received: {payload}")

    def connect_and_loop(self):
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

        # mTLS 강제
        self._configure_tls()

        log.info(
            f"MQTT connecting to {MQTT_BROKER}:{MQTT_PORT} "
            f"(TLS={'yes' if self._mtls else 'no'}, mTLS={'yes' if self._mtls else 'no'})"
        )

        # paho 연결 + 백그라운드 루프
        self.client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
        self.client.loop_start()

    def publish_meta(self, topic: str, role: str, data: dict):
        payload = json.dumps(data, separators=(",", ":"))
        self.client.publish(topic, payload, qos=1, retain=False)
        log.info(f"Published {role} to {topic}")