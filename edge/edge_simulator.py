import os
import sys
import json
import time
import asyncio
from typing import Dict, Any, List, Optional
import paho.mqtt.client as mqtt

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if sys.stdout.encoding and sys.stdout.encoding.lower().startswith("cp"):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from edge.virtual_clock import VirtualClock
from edge.device_models import get_device_model
from edge.os_log_generator import OSLogGenerator
from gateway.schemas import TelemetryMessage, OSLogMessage


class EdgeSimulator:
    """
    Simulates physical Raspberry Pi nodes (#2 and #3) hosting 7 IoT/IIoT devices.
    Publishes telemetry and OS logs over MQTT to 'fabrica/{device_key}/telemetrie'
    and 'fabrica/{device_key}/logs'.
    """
    def __init__(
        self,
        config_path: str = "config/edge_devices.json",
        scenario_path: str = "config/attack_scenario.json",
        broker_host: str = "localhost",
        broker_port: int = 1883,
        speed_factor: float = 1.0,
        standalone_queue: Optional[Any] = None
    ):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.speed_factor = speed_factor
        self.clock = VirtualClock(speed_factor=speed_factor)
        self.standalone_queue = standalone_queue

        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        if not os.path.isabs(config_path):
            config_path = os.path.join(root_dir, config_path)
        if not os.path.isabs(scenario_path):
            scenario_path = os.path.join(root_dir, scenario_path)

        with open(config_path, "r", encoding="utf-8") as f:
            self.config = json.load(f)

        with open(scenario_path, "r", encoding="utf-8") as f:
            self.scenario = json.load(f)

        self.mqtt_client: Optional[mqtt.Client] = None
        self.mqtt_connected = False
        self._init_mqtt()

        # Build device models and loggers partitioned by virtual Pi node
        self.nodes = self.config.get("nodes", {})
        self.models: Dict[str, Any] = {}
        self.log_generators: Dict[str, OSLogGenerator] = {}
        self.device_node_map: Dict[str, str] = {}
        self.active_overrides: Dict[str, Dict[str, Any]] = {}
        self.executed_actions: set = set()

        for node_id, node_data in self.nodes.items():
            hostname = node_data.get("hostname", node_id)
            ip_addr = node_data.get("ip_address", "192.168.1.1")
            self.log_generators[node_id] = OSLogGenerator(node_id, hostname, ip_addr)

            for dev_key, dev_cfg in node_data.get("devices", {}).items():
                self.models[dev_key] = get_device_model(dev_key, dev_cfg)
                self.device_node_map[dev_key] = node_id

    def _init_mqtt(self):
        try:
            self.mqtt_client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id="EdgeSimulator-Pi2-Pi3"
            )
            self.mqtt_client.on_connect = self._on_connect
            self.mqtt_client.on_disconnect = self._on_disconnect
            self.mqtt_client.connect_async(self.broker_host, self.broker_port, keepalive=60)
            self.mqtt_client.loop_start()
            print(f"[EdgeSimulator] Connecting to MQTT broker {self.broker_host}:{self.broker_port}...")
        except Exception as e:
            print(f"[EdgeSimulator] MQTT broker not available ({e}). Running in standalone/queue mode.")
            self.mqtt_connected = False

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self.mqtt_connected = True
            print(f"[EdgeSimulator] Connected to MQTT broker at {self.broker_host}:{self.broker_port}")
        else:
            print(f"[EdgeSimulator] MQTT connection returned code {rc}")

    def _on_disconnect(self, client, userdata, flags, rc, properties=None):
        self.mqtt_connected = False
        print("[EdgeSimulator] Disconnected from MQTT broker.")

    def publish_payload(self, topic: str, payload_dict: Dict[str, Any]):
        json_str = json.dumps(payload_dict)
        if self.mqtt_connected and self.mqtt_client:
            self.mqtt_client.publish(topic, json_str, qos=1)
        if self.standalone_queue is not None:
            self.standalone_queue.put({"topic": topic, "data": payload_dict})

    def check_scenario_timeline(self, elapsed: float, timestamp_iso: str) -> List[Dict[str, Any]]:
        dispatched_events = []
        for step_idx, step in enumerate(self.scenario.get("timeline", [])):
            trigger_time = step.get("time_seconds", 0)
            if elapsed >= trigger_time and step_idx not in self.executed_actions:
                self.executed_actions.add(step_idx)
                phase = step.get("phase", "UNKNOWN")
                desc = step.get("description", "")
                print(f"\n[!] [SCENARIO TRIGGER @ T+{elapsed:.1f}s] Phase: {phase} - {desc}")

                for action in step.get("actions", []):
                    action_type = action.get("type")
                    tgt_dev = action.get("target_device")

                    if action_type == "telemetry_override":
                        self.active_overrides[tgt_dev] = action.get("modifications", {})
                        print(f"   |-- [OVERRIDE] {tgt_dev}: {action.get('modifications')}")

                    elif action_type == "os_log":
                        node_id = self.device_node_map.get(tgt_dev, "pi_edge_02")
                        node_cfg = self.nodes.get(node_id, {}).get("devices", {}).get(tgt_dev, {})
                        canonical_id = node_cfg.get("id", tgt_dev)
                        log_gen = self.log_generators[node_id]
                        burst = action.get("burst_count", 1)
                        for _ in range(burst):
                            log_msg = log_gen.create_attack_log(canonical_id, action, timestamp_iso)
                            topic = f"fabrica/{tgt_dev}/logs"
                            self.publish_payload(topic, log_msg.model_dump())
                            dispatched_events.append({"topic": topic, "msg": log_msg.model_dump()})
                            print(f"   |-- [ATTACK LOG] [{log_msg.severity}] {log_msg.message}")

        return dispatched_events

    def step(self) -> Dict[str, Any]:
        """
        Executes a single simulation tick: updates sensor states, processes scenario actions,
        and broadcasts telemetry and logs.
        """
        elapsed = self.clock.elapsed_sim_seconds()
        now_iso = self.clock.current_iso_time()

        # 1. Process scenario injections
        attack_logs = self.check_scenario_timeline(elapsed, now_iso)

        emitted_telemetry = []
        # 2. Step each device model
        for dev_key, model in self.models.items():
            node_id = self.device_node_map[dev_key]
            node_cfg = self.nodes[node_id]["devices"][dev_key]
            override = self.active_overrides.get(dev_key)

            metrics = model.step(elapsed, override)
            topic = node_cfg.get("telemetry_topic", f"fabrica/{dev_key}/telemetrie")

            t_msg = TelemetryMessage(
                timestamp=now_iso,
                node_id=node_id,
                device_id=node_cfg.get("id", dev_key),
                device_type=node_cfg.get("type", "unknown"),
                ip_address=node_cfg.get("ip_address", "192.168.1.1"),
                metrics=metrics,
                status="OVERRIDDEN" if override else "OK"
            )
            self.publish_payload(topic, t_msg.model_dump())
            emitted_telemetry.append(t_msg.model_dump())

            # 3. Occasional background OS log
            bg_log = self.log_generators[node_id].generate_background_log(node_cfg["id"], now_iso)
            if bg_log:
                log_topic = node_cfg.get("logs_topic", f"fabrica/{dev_key}/logs")
                self.publish_payload(log_topic, bg_log.model_dump())

        return {
            "elapsed_seconds": elapsed,
            "timestamp": now_iso,
            "telemetry_count": len(emitted_telemetry),
            "attack_logs_count": len(attack_logs)
        }

    def run_loop(self, tick_interval: float = 1.0, max_seconds: Optional[float] = None):
        print(f"[EdgeSimulator] Starting simulation loop (tick={tick_interval}s, speed={self.speed_factor}x)...")
        try:
            while True:
                res = self.step()
                elapsed = res["elapsed_seconds"]
                sys.stdout.write(f"\r[EdgeSimulator] Clock: T+{elapsed:.1f}s | Telemetry sent for 7 devices   ")
                sys.stdout.flush()

                if max_seconds and elapsed >= max_seconds:
                    print(f"\n[EdgeSimulator] Reached maximum runtime of {max_seconds}s. Stopping.")
                    break
                time.sleep(tick_interval / self.speed_factor)
        except KeyboardInterrupt:
            print("\n[EdgeSimulator] Stopped by user.")
        finally:
            if self.mqtt_client:
                self.mqtt_client.loop_stop()
                self.mqtt_client.disconnect()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="IoT Edge Simulator (Pi #2 & #3)")
    parser.add_argument("--broker", default="localhost", help="MQTT Broker hostname")
    parser.add_argument("--port", type=int, default=1883, help="MQTT Broker port")
    parser.add_argument("--speed", type=float, default=1.0, help="Simulation speed multiplier")
    parser.add_argument("--duration", type=float, default=100.0, help="Run duration in sim seconds")
    args = parser.parse_args()

    simulator = EdgeSimulator(
        broker_host=args.broker,
        broker_port=args.port,
        speed_factor=args.speed
    )
    simulator.run_loop(tick_interval=1.0, max_seconds=args.duration)
