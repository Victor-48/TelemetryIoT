import os
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import networkx as nx

from gateway.schemas import TelemetryMessage, OSLogMessage, AlertMessage


class UnifiedDatabase:
    """
    Unified dual-persistence engine:
    1. Time-Series & Log Storage: SQLite database with indexing on timestamps and devices.
    2. Knowledge Graph Engine: NetworkX directed graph modeling Device, Event, IP, Alert nodes.
    Supports thread-safe writes and real-time analytical queries.
    """
    def __init__(self, db_path: str = "storage/telemetry_soc.db"):
        if not os.path.isabs(db_path):
            root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            db_path = os.path.join(root_dir, db_path)
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.lock = threading.Lock()
        self.graph = nx.DiGraph()

        self._init_sqlite()
        self._init_base_topology()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_sqlite(self):
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Telemetry Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    metrics_json TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_dev_time ON telemetry(device_id, timestamp)")

            # OS Logs Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS os_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    log_type TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    target_ip TEXT,
                    user TEXT,
                    message TEXT NOT NULL,
                    severity TEXT NOT NULL
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_dev_time ON os_logs(device_id, timestamp)")

            # Alerts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    device_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    resolved INTEGER DEFAULT 0
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp)")

            conn.commit()
            conn.close()

    def _init_base_topology(self):
        # Base known device topology
        base_devices = [
            ("plc_modbus_line1", "modbus_plc", "192.168.1.10", "PLC Modbus"),
            ("industrial_fridge_01", "refrigeration", "192.168.1.45", "Frigider Industrial"),
            ("hvac_thermostat_zone_a", "hvac_thermostat", "192.168.1.46", "Termostat Zonă"),
            ("access_cargo_door", "access_control", "192.168.1.47", "Poartă Acces Cargo"),
            ("sensor_motion_light_hall", "pir_light", "192.168.1.70", "Senzor Mișcare & Lumină"),
            ("weather_station_outdoor", "weather_station", "192.168.1.71", "Stație Meteo"),
            ("gps_fleet_tracker_agv1", "gps_tracker", "192.168.1.72", "GPS Transportor"),
        ]
        with self.lock:
            for dev_id, dev_type, ip, label in base_devices:
                self.graph.add_node(dev_id, label=label, type="Device", category=dev_type, ip=ip, status="NORMAL")
                self.graph.add_node(ip, label=ip, type="IP", internal=True)
                self.graph.add_edge(ip, dev_id, relationship="ASSIGNED_TO")

    def save_telemetry(self, msg: TelemetryMessage):
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO telemetry (timestamp, node_id, device_id, device_type, ip_address, metrics_json, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    msg.timestamp,
                    msg.node_id,
                    msg.device_id,
                    msg.device_type,
                    msg.ip_address,
                    json.dumps(msg.metrics),
                    msg.status,
                ),
            )
            conn.commit()
            conn.close()

    def save_os_log(self, msg: OSLogMessage):
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO os_logs (timestamp, node_id, device_id, log_type, event_type, source_ip, target_ip, user, message, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    msg.timestamp,
                    msg.node_id,
                    msg.device_id,
                    msg.log_type,
                    msg.event_type,
                    msg.source_ip,
                    msg.target_ip,
                    msg.user,
                    msg.message,
                    msg.severity,
                ),
            )
            conn.commit()
            conn.close()

            # Knowledge Graph correlation for security-relevant events
            if msg.event_type in ["ssh_failed", "ssh_accepted", "network_recon", "modbus_tampering", "privilege_escalation"]:
                evt_id = f"EVT-{msg.event_type}-{int(datetime.now(timezone.utc).timestamp()*1000)}"
                self.graph.add_node(
                    evt_id,
                    label=msg.event_type,
                    type="Event",
                    severity=msg.severity,
                    timestamp=msg.timestamp,
                    message=msg.message
                )

                if msg.source_ip:
                    is_ext = not msg.source_ip.startswith("192.168.")
                    self.graph.add_node(msg.source_ip, label=msg.source_ip, type="IP", internal=not is_ext)
                    self.graph.add_edge(msg.source_ip, evt_id, relationship="ORIGINATES_FROM")

                if msg.device_id and msg.device_id in self.graph:
                    self.graph.add_edge(evt_id, msg.device_id, relationship="TARGETS")

                if msg.target_ip and msg.target_ip in self.graph:
                    self.graph.add_edge(evt_id, msg.target_ip, relationship="COMMUNICATES_WITH")

    def save_alert(self, alert: AlertMessage):
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO alerts (alert_id, timestamp, device_id, device_name, severity, rule, details_json, resolved)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.timestamp,
                    alert.device_id,
                    alert.device_name,
                    alert.severity,
                    alert.rule,
                    json.dumps(alert.details),
                    1 if alert.resolved else 0,
                ),
            )
            conn.commit()
            conn.close()

            # Add Alert node into Knowledge Graph
            self.graph.add_node(
                alert.alert_id,
                label=alert.rule,
                type="Alert",
                severity=alert.severity,
                timestamp=alert.timestamp
            )
            if alert.device_id in self.graph:
                self.graph.add_edge(alert.alert_id, alert.device_id, relationship="IMPACTS")
                self.graph.nodes[alert.device_id]["status"] = "COMPROMISED" if alert.severity == "CRITICAL" else "SUSPICIOUS"

    def get_telemetry_history(self, device_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            if device_id:
                cursor.execute(
                    "SELECT * FROM telemetry WHERE device_id = ? ORDER BY id DESC LIMIT ?",
                    (device_id, limit),
                )
            else:
                cursor.execute("SELECT * FROM telemetry ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            conn.close()

        results = []
        for r in rows:
            d = dict(r)
            d["metrics"] = json.loads(d["metrics_json"])
            del d["metrics_json"]
            results.append(d)
        return list(reversed(results))

    def get_os_logs(self, device_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            if device_id:
                cursor.execute("SELECT * FROM os_logs WHERE device_id = ? ORDER BY id DESC LIMIT ?", (device_id, limit))
            else:
                cursor.execute("SELECT * FROM os_logs ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            conn.close()
        return [dict(r) for r in rows]

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            conn.close()
        res = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d["details_json"])
            del d["details_json"]
            res.append(d)
        return res

    def get_graph_topology(self) -> Dict[str, Any]:
        """Returns node and edge dictionary for visualization and GraphRAG."""
        with self.lock:
            nodes = []
            for n, attrs in self.graph.nodes(data=True):
                node_info = dict(attrs)
                node_info["id"] = n
                nodes.append(node_info)

            edges = []
            for u, v, attrs in self.graph.edges(data=True):
                edge_info = dict(attrs)
                edge_info["source"] = u
                edge_info["target"] = v
                edges.append(edge_info)

        return {"nodes": nodes, "edges": edges}

    def find_attack_path(self, target_device: str) -> Dict[str, Any]:
        """
        Traverses graph from any external IP or compromised node to target_device.
        """
        with self.lock:
            paths = []
            external_ips = [n for n, d in self.graph.nodes(data=True) if d.get("type") == "IP" and not d.get("internal", True)]

            # Convert directed to undirected for multi-hop path traversal
            undirected = self.graph.to_undirected()

            for ext_ip in external_ips:
                if ext_ip in undirected and target_device in undirected:
                    try:
                        all_p = list(nx.all_simple_paths(undirected, source=ext_ip, target=target_device, cutoff=8))
                        for p in all_p:
                            path_details = []
                            for step in p:
                                node_data = dict(self.graph.nodes[step])
                                node_data["id"] = step
                                path_details.append(node_data)
                            paths.append(path_details)
                    except Exception:
                        pass

        return {
            "target": target_device,
            "paths_found": len(paths),
            "paths": paths
        }
