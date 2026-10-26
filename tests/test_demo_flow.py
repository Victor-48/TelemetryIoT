import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from edge.edge_simulator import EdgeSimulator
from gateway.detector import AnomalyDetector
from storage.database import UnifiedDatabase
from mcp.mcp_server import IndustrialForensicTools
from gateway.schemas import TelemetryMessage, OSLogMessage


def test_full_scenario_execution():
    test_db_path = "storage/test_soc.db"
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    db = UnifiedDatabase(test_db_path)
    simulator = EdgeSimulator(
        config_path="config/edge_devices.json",
        scenario_path="config/attack_scenario.json",
        speed_factor=1.0
    )
    detector = AnomalyDetector()

    # Step simulator 30 times, advancing 3 seconds each tick (reaches T+90s)
    for _ in range(30):
        simulator.clock.advance(3.0)
        elapsed = simulator.clock.elapsed_sim_seconds()
        now_iso = simulator.clock.current_iso_time()

        attack_logs = simulator.check_scenario_timeline(elapsed, now_iso)
        for l_item in attack_logs:
            msg = OSLogMessage(**l_item["msg"])
            db.save_os_log(msg)
            alerts = detector.process_os_log(msg)
            for a in alerts:
                db.save_alert(a)

        for dev_key, model in simulator.models.items():
            node_id = simulator.device_node_map[dev_key]
            node_cfg = simulator.nodes[node_id]["devices"][dev_key]
            override = simulator.active_overrides.get(dev_key)

            metrics = model.step(elapsed, override)
            t_msg = TelemetryMessage(
                timestamp=now_iso,
                node_id=node_id,
                device_id=node_cfg["id"],
                device_type=node_cfg["type"],
                ip_address=node_cfg["ip_address"],
                metrics=metrics,
                status="OVERRIDDEN" if override else "OK"
            )
            db.save_telemetry(t_msg)
            t_alerts = detector.process_telemetry(t_msg)
            for a in t_alerts:
                db.save_alert(a)

    alerts = db.get_alerts()
    assert len(alerts) > 0, "Expected alerts to be generated"

    mcp = IndustrialForensicTools(database=db)
    report = mcp.run_forensic_investigation("Investighează anomalia pe Modbus")
    assert report["incident_detected"] is True, "Expected incident to be detected"
    assert len(report["reconstructed_timeline"]) == 4, "Expected 4 stages of lateral attack"

    paths = mcp.find_attack_path("plc_modbus_line1")
    assert paths["paths_found"] > 0, "Expected attack paths to be found"

    # Cleanup
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    print("PASS: test_full_scenario_execution")


if __name__ == "__main__":
    test_full_scenario_execution()
