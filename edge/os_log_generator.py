import random
from typing import Dict, Any, Optional
from gateway.schemas import OSLogMessage


class OSLogGenerator:
    """
    Simulates Linux OS logging subsystem (auth.log and syslog) for IoT/Edge nodes.
    Supports normal operational background noise and attack action injections.
    """
    def __init__(self, node_id: str, hostname: str, ip_address: str):
        self.node_id = node_id
        self.hostname = hostname
        self.ip_address = ip_address

    def generate_background_log(self, device_id: str, timestamp_iso: str) -> Optional[OSLogMessage]:
        # Generate occasional normal system noise (CRON, systemd, ntp)
        if random.random() > 0.15:
            return None

        events = [
            ("syslog", "systemd", "INFO", f"systemd[1]: Started Daily apt upgrade and clean activities."),
            ("syslog", "systemd-timesyncd", "INFO", f"systemd-timesyncd[412]: Synchronized with time server 193.2.1.117:123 (ntp.pool.org)."),
            ("auth", "CRON", "INFO", f"CRON[8922]: pam_unix(cron:session): session opened for user root by (uid=0)"),
            ("auth", "CRON", "INFO", f"CRON[8922]: pam_unix(cron:session): session closed for user root"),
            ("syslog", "kernel", "INFO", f"kernel: [ 1042.881290] eth0: Link is Up - 1000Mbps/Full - flow control rx/tx")
        ]
        log_type, user, severity, msg = random.choice(events)

        return OSLogMessage(
            timestamp=timestamp_iso,
            node_id=self.node_id,
            device_id=device_id,
            log_type=log_type,
            event_type="system_background",
            user=user,
            message=msg,
            severity=severity
        )

    def create_attack_log(
        self,
        device_id: str,
        action: Dict[str, Any],
        timestamp_iso: str
    ) -> OSLogMessage:
        event_type = action.get("event_type", "attack_action")
        src_ip = action.get("source_ip", "unknown")
        tgt_ip = action.get("target_ip", self.ip_address)
        user = action.get("user", "root")
        msg = action.get("message", "Attack signature detected")

        severity_map = {
            "ssh_failed": "WARNING",
            "ssh_accepted": "CRITICAL",
            "privilege_escalation": "CRITICAL",
            "network_recon": "ALERT",
            "modbus_tampering": "CRITICAL"
        }
        severity = severity_map.get(event_type, "WARNING")

        return OSLogMessage(
            timestamp=timestamp_iso,
            node_id=self.node_id,
            device_id=device_id,
            log_type="auth" if "ssh" in event_type or "privilege" in event_type else "syslog",
            event_type=event_type,
            source_ip=src_ip,
            target_ip=tgt_ip,
            user=user,
            message=msg,
            severity=severity
        )
