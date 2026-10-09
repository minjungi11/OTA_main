import json
import paho.mqtt.client as mqtt
from typing import Optional, Dict

class Reporter:
    def __init__(self, client: mqtt.Client, topic: str):
        self.client = client
        self.topic = topic

    # def report(self, status: str, reason: dict | None = None, qos: int = 1, retain: bool = False):
    def report(self, status: str, reason: Optional[dict] = None, qos: int = 1, retain: bool = False):
        msg = {"status": status}
        if reason:
            msg["reason"] = reason
        
        payload = json.dumps(msg, ensure_ascii=False, separators=(",", ":"))
        self.client.publish(self.topic, payload, qos=qos, retain=retain)
        self.client.publish("primary/request", json.dumps({}, ensure_ascii=False).encode("utf-8"), qos=0)
        print("[Prime ECU] Success to report")