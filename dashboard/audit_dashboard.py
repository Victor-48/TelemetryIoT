import os
import sys
import time
import json
import threading
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from edge.edge_simulator import EdgeSimulator
from gateway.detector import AnomalyDetector
from gateway.schemas import TelemetryMessage, OSLogMessage
from storage.database import UnifiedDatabase
from mcp.mcp_server import IndustrialForensicTools

st.set_page_config(
    page_title="Industrial IoT SOC Audit & Forensic Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------------------------------------------
# Global Singletons / Session State Initialization
# -------------------------------------------------------------
if "db" not in st.session_state:
    st.session_state.db = UnifiedDatabase()

if "detector" not in st.session_state:
    st.session_state.detector = AnomalyDetector()

if "mcp" not in st.session_state:
    st.session_state.mcp = IndustrialForensicTools(database=st.session_state.db)

if "sim_running" not in st.session_state:
    st.session_state.sim_running = False

if "sim_speed" not in st.session_state:
    st.session_state.sim_speed = 2.0

if "simulator" not in st.session_state:
    # Initialize simulator with speed
    st.session_state.simulator = EdgeSimulator(
        broker_host="localhost",
        broker_port=1883,
        speed_factor=st.session_state.sim_speed
    )

if "chat_history" not in st.session_state:
    st.session_state.chat_history = [
        {
            "role": "assistant",
            "content": (
                "Salut! Sunt asistentul tău SOC de investigație industrială alimentat de GraphRAG și MCP. "
                "Monitorizez cele 7 dispozitive din fabrică (TON_IoT). "
                "Poți rula simularea din bara laterală sau să-mi pui întrebări despre alertele curente."
            )
        }
    ]


def run_single_simulation_step(time_advance: float = 2.0):
    """Executes one simulation tick and dispatches to Gateway/Storage."""
    sim = st.session_state.simulator
    det = st.session_state.detector
    db = st.session_state.db

    # Advance virtual clock
    sim.clock.advance(time_advance)

    # Step simulator
    elapsed = sim.clock.elapsed_sim_seconds()
    now_iso = sim.clock.current_iso_time()

    # Process attack scenario injections
    attack_logs = sim.check_scenario_timeline(elapsed, now_iso)
    for log_item in attack_logs:
        log_msg = OSLogMessage(**log_item["msg"])
        db.save_os_log(log_msg)
        alerts = det.process_os_log(log_msg)
        for a in alerts:
            db.save_alert(a)

    # Step device models
    for dev_key, model in sim.models.items():
        node_id = sim.device_node_map[dev_key]
        node_cfg = sim.nodes[node_id]["devices"][dev_key]
        override = sim.active_overrides.get(dev_key)

        metrics = model.step(elapsed, override)
        t_msg = TelemetryMessage(
            timestamp=now_iso,
            node_id=node_id,
            device_id=node_cfg.get("id", dev_key),
            device_type=node_cfg.get("type", "unknown"),
            ip_address=node_cfg.get("ip_address", "192.168.1.1"),
            metrics=metrics,
            status="OVERRIDDEN" if override else "OK"
        )
        db.save_telemetry(t_msg)

        # Detect telemetry anomalies
        t_alerts = det.process_telemetry(t_msg)
        for a in t_alerts:
            db.save_alert(a)

        # Occasional background log
        bg_log = sim.log_generators[node_id].generate_background_log(node_cfg["id"], now_iso)
        if bg_log:
            db.save_os_log(bg_log)


# -------------------------------------------------------------
# Sidebar: Simulation Controls & Hardware Topology
# -------------------------------------------------------------
with st.sidebar:
    st.title("🎛️ Panou Simulare Edge")
    st.markdown("**Noduri Emulate (Raspberry Pi #2 & #3)**")

    sim_speed = st.slider("Viteză Simulare (x)", min_value=1.0, max_value=10.0, value=2.0, step=1.0)
    st.session_state.simulator.speed_factor = sim_speed
    st.session_state.simulator.clock.speed_factor = sim_speed

    elapsed_s = st.session_state.simulator.clock.elapsed_sim_seconds()
    st.metric("Timp Simulare", f"T+{elapsed_s:.1f} secunde")

    # Determine Active Phase from Scenario
    scenario = st.session_state.simulator.scenario.get("timeline", [])
    active_phase = "BASELINE"
    for step in scenario:
        if elapsed_s >= step.get("time_seconds", 0):
            active_phase = step.get("phase", "UNKNOWN")

    phase_colors = {
        "BASELINE": "🟢 NORMAL",
        "IT_BRUTEFORCE": "🟡 ATAC IT (Brute Force)",
        "IT_COMPROMISE": "🟠 COMPROMITERE IT",
        "LATERAL_SCAN": "🟣 MIȘCARE LATERALĂ",
        "OT_SABOTAGE": "🔴 SABOTAJ OT (Modbus Tampering)",
        "PHYSICAL_BREACH": "🚨 BREȘĂ FIZICĂ"
    }
    st.subheader(f"Stare: {phase_colors.get(active_phase, active_phase)}")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("▶️ +5 Pași Simulare", use_container_width=True):
            for _ in range(5):
                run_single_simulation_step()
            st.rerun()

    with col_btn2:
        if st.button("⏩ +20 Pași", use_container_width=True):
            for _ in range(20):
                run_single_simulation_step()
            st.rerun()

    if st.button("🔄 Resetează Simularea", use_container_width=True):
        st.session_state.simulator = EdgeSimulator(speed_factor=sim_speed)
        st.session_state.db = UnifiedDatabase()
        st.session_state.detector = AnomalyDetector()
        st.session_state.mcp = IndustrialForensicTools(database=st.session_state.db)
        st.rerun()

    st.markdown("---")
    st.markdown("### Dispozitive Active")
    st.markdown("• **Pi #2**: Modbus PLC, Frigider, Termostat, Garaj")
    st.markdown("• **Pi #3**: Senzor Lumină, Stație Meteo, GPS")


# -------------------------------------------------------------
# Main Dashboard Header & Metrics
# -------------------------------------------------------------
st.title("🛡️ Sistem Inteligent de Audit și Corelare Telemetrie IoT/IIoT")
st.caption("Barieră inteligentă de securitate la nivel de aplicație și proces industrial (Dataset: TON_IoT)")

# Fetch current counts
alerts = st.session_state.db.get_alerts(limit=50)
telemetry_data = st.session_state.db.get_telemetry_history(limit=200)
logs_data = st.session_state.db.get_os_logs(limit=50)

crit_alerts = [a for a in alerts if a.get("severity") == "CRITICAL"]
high_alerts = [a for a in alerts if a.get("severity") == "HIGH"]

col_m1, col_m2, col_m3, col_m4 = st.columns(4)
col_m1.metric("Total Măsurători Ingerate", len(telemetry_data))
col_m2.metric("Evenimente Log OS", len(logs_data))
col_m3.metric("Alerte Critice OT", len(crit_alerts), delta=f"+{len(crit_alerts)}" if crit_alerts else None, delta_color="inverse")
col_m4.metric("Alerte Nivel Mediu/Înalt", len(high_alerts))

st.markdown("---")

# -------------------------------------------------------------
# Section 1: Telemetry Live Charts (Modbus & Fridge)
# -------------------------------------------------------------
tab_telemetry, tab_graph, tab_alerts, tab_mcp = st.tabs([
    "📈 Telemetrie Fizică Live",
    "🕸️ Topologie Atac (Knowledge Graph)",
    "⚠️ Jurnal Alerte & Evenimente OS",
    "🤖 Asistent Forenzic Agentic (MCP)"
])

with tab_telemetry:
    col_t1, col_t2 = st.columns(2)

    with col_t1:
        st.subheader("Linia 1: Controller PLC Modbus (Registru 40001)")
        modbus_records = [
            {
                "timestamp": t["timestamp"][-8:],
                "Registru_40001": t["metrics"].get("holding_register_40001", 140),
                "Coil_1": t["metrics"].get("discrete_coil_01", 1)
            }
            for t in telemetry_data if t["device_id"] == "plc_modbus_line1"
        ]
        if modbus_records:
            df_modbus = pd.DataFrame(modbus_records)
            fig_modbus = px.line(
                df_modbus,
                x="timestamp",
                y="Registru_40001",
                title="Valoare Registru Modbus 40001 (Prag Nominal: 100-200)",
                markers=True
            )
            # Add nominal reference threshold
            fig_modbus.add_hline(y=1000, line_dash="dash", line_color="red", annotation_text="Limită Critică Sabotaj")
            fig_modbus.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=20))
            st.plotly_chart(fig_modbus, use_container_width=True)
        else:
            st.info("Apasă '▶️ +5 Pași Simulare' în stânga pentru a genera primele puncte.")

    with col_t2:
        st.subheader("Depozit Frigorific: Temperatură & Compresor")
        fridge_records = [
            {
                "timestamp": t["timestamp"][-8:],
                "Temperatura_C": t["metrics"].get("temperature_celsius", -20.0),
                "Compresor": t["metrics"].get("compressor_relay", 1)
            }
            for t in telemetry_data if t["device_id"] == "industrial_fridge_01"
        ]
        if fridge_records:
            df_fridge = pd.DataFrame(fridge_records)
            fig_fridge = px.line(
                df_fridge,
                x="timestamp",
                y="Temperatura_C",
                title="Temperatură Frigider (°C) vs. Prag Alterare (-18°C)",
                color_discrete_sequence=["#00CC96"]
            )
            fig_fridge.add_hline(y=-18.0, line_dash="dash", line_color="orange", annotation_text="Prag Maxim Siguranță (-18°C)")
            fig_fridge.add_hline(y=0.0, line_dash="dash", line_color="red", annotation_text="Prag Critic Alterare Alimentară (0°C)")
            fig_fridge.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=20))
            st.plotly_chart(fig_fridge, use_container_width=True)
        else:
            st.info("Apasă '▶️ +5 Pași Simulare' în stânga pentru a genera primele puncte.")

    # Status Cards for other 5 devices
    st.subheader("Stare Senzori Secundari")
    c1, c2, c3, c4, c5 = st.columns(5)
    last_t = {t["device_id"]: t["metrics"] for t in telemetry_data}

    with c1:
        t_term = last_t.get("hvac_thermostat_zone_a", {})
        st.metric("Termostat Hală", f"{t_term.get('ambient_temp_celsius', 22.0)} °C")

    with c2:
        t_gar = last_t.get("access_cargo_door", {})
        st.metric("Ușă Cargo", t_gar.get("door_position", "closed").upper())

    with c3:
        t_lum = last_t.get("sensor_motion_light_hall", {})
        st.metric("Lumină / PIR", f"{t_lum.get('ambient_lux', 380)} Lux | {t_lum.get('pir_motion_sensor', 'idle')}")

    with c4:
        t_met = last_t.get("weather_station_outdoor", {})
        st.metric("Stație Meteo", f"{t_met.get('humidity_percent', 52)}% | {t_met.get('atmospheric_pressure_hpa', 1015)} hPa")

    with c5:
        t_gps = last_t.get("gps_fleet_tracker_agv1", {})
        st.metric("GPS AGV", f"{t_gps.get('speed_kmh', 0.5)} km/h")


with tab_graph:
    st.subheader("Topologia Grafului de Securitate (Knowledge Graph)")
    st.markdown("Corelarea entităților afectate, a adreselor IP și a relațiilor de atac.")

    topology = st.session_state.db.get_graph_topology()
    nodes = topology["nodes"]
    edges = topology["edges"]

    # Render a structured visual card view of graph entities
    col_g1, col_g2 = st.columns([1, 1])

    with col_g1:
        st.markdown("#### Entități Dispozitive & Noduri Rețea")
        node_display = []
        for n in nodes:
            status = n.get("status", "NORMAL")
            status_icon = "🟢" if status == "NORMAL" else ("🔴" if status == "COMPROMISED" else "🟠")
            node_display.append({
                "ID": n.get("id"),
                "Tip": n.get("type"),
                "Etichetă": n.get("label"),
                "IP": n.get("ip", n.get("id")),
                "Stare": f"{status_icon} {status}"
            })
        st.dataframe(pd.DataFrame(node_display), use_container_width=True, height=280)

    with col_g2:
        st.markdown("#### Relații Cauzale & Căi de Propagare Atac")
        edge_display = []
        for e in edges:
            edge_display.append({
                "Sursă": e.get("source"),
                "Relație": e.get("relationship"),
                "Destinație": e.get("target")
            })
        if edge_display:
            st.dataframe(pd.DataFrame(edge_display), use_container_width=True, height=280)
        else:
            st.info("Nicio conexiune de atac încă. Rulați simularea până la T+40s.")

    # Lateral movement path finder
    st.markdown("---")
    st.markdown("#### Reconstituire Automată a Traseului de Atac către Modbus PLC")
    path_res = st.session_state.mcp.find_attack_path("plc_modbus_line1")
    if path_res["paths_found"] > 0:
        st.error(f"⚠️ S-au detectat {path_res['paths_found']} căi active de atac de la adrese IP externe către PLC!")
        for idx, p in enumerate(path_res["paths"], 1):
            path_str = " ➔ ".join([f"`{step.get('id')}` ({step.get('type')})" for step in p])
            st.markdown(f"**Calea #{idx}:** {path_str}")
    else:
        st.success("Nu există nicio cale de atac activă identificată către controller-ul Modbus PLC.")


with tab_alerts:
    st.subheader("Alerte Generate de Motorul de Detecție Semantică")
    if alerts:
        alert_rows = []
        for a in alerts:
            sev = a.get("severity")
            icon = "🔴" if sev == "CRITICAL" else ("🟠" if sev == "HIGH" else "🟡")
            alert_rows.append({
                "ID Alertă": a.get("alert_id"),
                "Timestamp": a.get("timestamp"),
                "Dispozitiv": a.get("device_name"),
                "Severitate": f"{icon} {sev}",
                "Regulă Încălcată": a.get("rule"),
                "Detalii": str(a.get("details"))
            })
        st.dataframe(pd.DataFrame(alert_rows), use_container_width=True, height=260)
    else:
        st.info("Nicio alertă activă. Sistemul funcționează în parametri nominali.")

    st.subheader("Jurnale de Sistem Recente (OS Logs - auth.log & syslog)")
    if logs_data:
        log_rows = [
            {
                "Timestamp": l.get("timestamp"),
                "Dispozitiv": l.get("device_id"),
                "Tip": l.get("event_type"),
                "Sursă IP": l.get("source_ip", "-"),
                "Mesaj": l.get("message"),
                "Severitate": l.get("severity")
            }
            for l in logs_data[:20]
        ]
        st.dataframe(pd.DataFrame(log_rows), use_container_width=True, height=260)


with tab_mcp:
    st.subheader("🤖 Asistent Investigator Forenzic (Model Context Protocol & GraphRAG)")
    st.markdown(
        "Agentul folosește uneltele standardizate MCP (`get_telemetry_window`, `query_os_auth_events`, `find_attack_path`) "
        "pentru a corela telemetria fizică cu jurnalele OS și topologia de rețea."
    )

    # Pre-canned Quick Investigation Questions
    c_q1, c_q2, c_q3 = st.columns(3)
    quick_query = None
    with c_q1:
        if st.button("🔍 Investighează linia Modbus", use_container_width=True):
            quick_query = "Investighează anomalia de pe linia Modbus din ultimele 10 minute."
    with c_q2:
        if st.button("🚨 Verifică atacurile de brute force", use_container_width=True):
            quick_query = "Arată tentativele de autentificare eșuate pe echipamentele perimetrale."
    with c_q3:
        if st.button("🌐 Reconstituie traseul mișcării laterale", use_container_width=True):
            quick_query = "Există mișcare laterală între rețeaua IT și controllerele OT?"

    # Display Chat History
    for message in st.session_state.chat_history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Chat Input
    user_query = st.chat_input("Scrie o întrebare de investigație SOC...") or quick_query

    if user_query:
        st.session_state.chat_history.append({"role": "user", "content": user_query})
        with st.chat_message("user"):
            st.markdown(user_query)

        # Run MCP Forensic Tools
        with st.chat_message("assistant"):
            with st.spinner("Se interoghează uneltele MCP și graful relațional..."):
                report = st.session_state.mcp.run_forensic_investigation(user_query)

                response_text = f"### 📋 Concluzie Forenzică Reconstituită\n\n"
                response_text += f"{report['summary']}\n\n"

                if report["reconstructed_timeline"]:
                    response_text += "#### 🕒 Cronologia Atacului Multi-Etapă Identificată:\n"
                    for stage in report["reconstructed_timeline"]:
                        response_text += f"**Etapa {stage['stage']}: {stage['title']}**\n"
                        response_text += f"* Detalii: {stage['details']}\n\n"

                response_text += "#### 🛡️ Măsuri Recomandate de Remediere (SOC Containment):\n"
                for rec in report["recommendations"]:
                    response_text += f"* {rec}\n"

                response_text += f"\n*Nivel Încredere Forenzică: `{int(report['confidence_score']*100)}%` | "
                response_text += f"Alerte Analizate: `{report['evidence']['active_alerts_count']}` | "
                response_text += f"Căi de Rețea Graph: `{report['evidence']['graph_paths_found']}`*"

                st.markdown(response_text)
                st.session_state.chat_history.append({"role": "assistant", "content": response_text})
