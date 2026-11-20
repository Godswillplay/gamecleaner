from gamecleaner.containment.firewall import FirewallManager, FirewallRuleResult, is_running_as_admin
from gamecleaner.containment.process_shield import ProcessShield, ShieldResult
from gamecleaner.containment.sandbox import SandboxGenerator, SandboxConfig, is_sandbox_supported
from gamecleaner.containment.shell_integration import ShellIntegrationManager
from gamecleaner.containment.proton_helper import (
    ProtonHelper,
    ProtonScriptResult,
    is_network_isolation_supported,
    write_posix_script,
)
from gamecleaner.containment.net_monitor import (
    NetworkMonitor,
    ConnectionRecord,
    NetworkAuditReport,
    categorize_endpoint,
    CATEGORY_LOOPBACK,
    CATEGORY_PRIVATE_LAN,
    CATEGORY_PUBLIC_INTERNET,
    CATEGORY_COINMINER_POOL,
    ALL_CATEGORIES,
    COINMINER_PORTS,
)

__all__ = [
    "FirewallManager",
    "FirewallRuleResult",
    "is_running_as_admin",
    "ProcessShield",
    "ShieldResult",
    "SandboxGenerator",
    "SandboxConfig",
    "is_sandbox_supported",
    "ShellIntegrationManager",
    "ProtonHelper",
    "ProtonScriptResult",
    "is_network_isolation_supported",
    "write_posix_script",
    "NetworkMonitor",
    "ConnectionRecord",
    "NetworkAuditReport",
    "categorize_endpoint",
    "CATEGORY_LOOPBACK",
    "CATEGORY_PRIVATE_LAN",
    "CATEGORY_PUBLIC_INTERNET",
    "CATEGORY_COINMINER_POOL",
    "ALL_CATEGORIES",
    "COINMINER_PORTS",
]
