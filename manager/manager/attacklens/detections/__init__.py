"""
manager/manager/attacklens/detections — Production-grade detection modules.

Each module exports a single async `analyze(agent_id, section, data, db, hostname)`.
All return list[dict] in AttackLensEngine finding format.
"""
from .lateral_movement     import analyze as analyze_lateral_movement
from .persistence          import analyze as analyze_persistence
from .exfiltration         import analyze as analyze_exfiltration
from .privilege_escalation import analyze as analyze_privilege_escalation
from .defense_evasion      import analyze as analyze_defense_evasion
from .app_vulnerability    import analyze as analyze_app_vulnerability
from .arp_spoofing         import analyze as analyze_arp_spoofing
from .binary_integrity     import analyze as analyze_binary_integrity
from .covert_channel       import analyze as analyze_covert_channel
from .container_security    import analyze as analyze_container_security
from .package_vulnerability import analyze as analyze_package_vulnerability
from .port_listener         import analyze as analyze_port_listener
from .sbom_posture          import analyze as analyze_sbom_posture
from .service_monitor       import analyze as analyze_service_monitor
from .sysctl_monitor        import analyze as analyze_sysctl_monitor
from .scheduled_task        import analyze as analyze_scheduled_task
from .user_account          import analyze as analyze_user_account
from .mount_monitor         import analyze as analyze_mount_monitor
from .developer_security    import analyze as analyze_developer_security
from .battery_health        import analyze as analyze_battery_health
from .sca_compliance        import analyze as analyze_sca_compliance
from .agent_health          import analyze as analyze_agent_health
from .hardware_integrity    import analyze as analyze_hardware_integrity

__all__ = [
    "analyze_mount_monitor",
    "analyze_developer_security",
    "analyze_battery_health",
    "analyze_sca_compliance",
    "analyze_agent_health",
    "analyze_hardware_integrity",
    "analyze_lateral_movement",
    "analyze_persistence",
    "analyze_exfiltration",
    "analyze_privilege_escalation",
    "analyze_defense_evasion",
    "analyze_app_vulnerability",
    "analyze_arp_spoofing",
    "analyze_binary_integrity",
    "analyze_covert_channel",
    "analyze_container_security",
    "analyze_package_vulnerability",
    "analyze_port_listener",
    "analyze_sbom_posture",
    "analyze_service_monitor",
    "analyze_sysctl_monitor",
    "analyze_scheduled_task",
    "analyze_user_account",
]
