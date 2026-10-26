import os
import sys
import json
import asyncio
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
import paho.mqtt.client as mqtt

# Ensure root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from gateway.schemas import TelemetryMessage, OSLogMessage, AlertMessage
from gateway.detector import AnomalyDetector
from storage.database import UnifiedDatabase
from storage.storage_manager import StorageManager

db = UnifiedDatabase()
detector = AnomalyDetector()
storage = StorageManager(db=db)

# MQTT Client for Gateway
mqtt_client: Optional[mqtt.Client] = None
loop: Optional[asyncio.AbstractEventLoop] = None


def on_mqtt_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("[Gateway] Connected to MQTT broker. Subscribing to 'fabrica/#'...")
        client.subscribe("fabrica/#", qos=1)
    else:
        print(f"[Gateway] MQTT connection failed with code {rc}")


def on_mqtt_message(client, userdata, message):
    topic = message.topic
    try:
        payload_str = message.payload.decode("utf-8")
        data = json.loads(payload_str)

        if loop and not loop.is_closed():
            asyncio.run_coroutine_threadsafe(handle_incoming_message(topic, data), loop)
    except Exception as e:
        print(f"[Gateway] Error parsing MQTT message on {topic}: {e}")


async def handle_incoming_message(topic: str, data: Dict[str, Any]):
    try:
        if topic.endswith("/telemetrie"):
            msg = TelemetryMessage(**data)
            alerts = detector.process_telemetry(msg)
            await storage.enqueue("telemetry", msg)
            for alert in alerts:
                print(f"[ALERT TRIGGERED] [{alert.severity}] Device: {alert.device_name} - {alert.rule}")
                await storage.enqueue("alert", alert)

        elif topic.endswith("/logs"):
            msg = OSLogMessage(**data)
            alerts = detector.process_os_log(msg)
            await storage.enqueue("log", msg)
            for alert in alerts:
                print(f"[ALERT TRIGGERED] [{alert.severity}] Device: {alert.device_name} - {alert.rule}")
                await storage.enqueue("alert", alert)
    except Exception as e:
        print(f"[Gateway] Message processing error on topic {topic}: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global mqtt_client, loop
    loop = asyncio.get_running_loop()

    # Start storage worker task
    worker_task = asyncio.create_task(storage.worker_loop())

    # Try connecting to MQTT broker
    broker_host = os.getenv("MQTT_BROKER", "localhost")
    broker_port = int(os.getenv("MQTT_PORT", 1883))

    try:
        mqtt_client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id="IndustrialGateway-Ingest"
        )
        mqtt_client.on_connect = on_mqtt_connect
        mqtt_client.on_message = on_mqtt_message
        mqtt_client.connect_async(broker_host, broker_port, keepalive=60)
        mqtt_client.loop_start()
        print(f"[Gateway] Initialized MQTT listener on {broker_host}:{broker_port}")
    except Exception as e:
        print(f"[Gateway] MQTT broker connection bypassed ({e}). REST API ingestion active.")

    yield

    if mqtt_client:
        mqtt_client.loop_stop()
        mqtt_client.disconnect()
    storage.stop()
    worker_task.cancel()


app = FastAPI(
    title="Industrial IoT Gateway & Anomaly Detector",
    description="Central ingestion, semantic validation, and threshold alerting service",
    version="1.0.0",
    lifespan=lifespan
)


@app.post("/api/ingest/telemetry")
async def ingest_telemetry(msg: TelemetryMessage):
    alerts = detector.process_telemetry(msg)
    await storage.enqueue("telemetry", msg)
    for alert in alerts:
        await storage.enqueue("alert", alert)
    return {"status": "accepted", "alerts_generated": len(alerts)}


@app.post("/api/ingest/log")
async def ingest_log(msg: OSLogMessage):
    alerts = detector.process_os_log(msg)
    await storage.enqueue("log", msg)
    for alert in alerts:
        await storage.enqueue("alert", alert)
    return {"status": "accepted", "alerts_generated": len(alerts)}


@app.get("/api/telemetry")
def get_telemetry(device_id: Optional[str] = None, limit: int = 100):
    return db.get_telemetry_history(device_id=device_id, limit=limit)


@app.get("/api/logs")
def get_logs(device_id: Optional[str] = None, limit: int = 50):
    return db.get_os_logs(device_id=device_id, limit=limit)


@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    return db.get_alerts(limit=limit)


@app.get("/api/graph")
def get_graph():
    return db.get_graph_topology()


@app.get("/api/attack_path/{target_device}")
def get_attack_path(target_device: str):
    return db.find_attack_path(target_device)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
