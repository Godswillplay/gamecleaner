"""
GameCleaner Real-Time Network Socket Monitor & Triage.
Inspects active game network connections via psutil, categorizing endpoints into:
- LOOPBACK: Safe local game socket (127.0.0.1, ::1)
- PRIVATE_LAN: RFC 1918 local co-op/multiplayer (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- PUBLIC_INTERNET: Outbound external IP (telemetry, exfiltration, C2)
- COINMINER_POOL: Stratum mining ports (3333, 4444, 5555, 7777, 8888, 14444, 33333) or mining domains
Generates structured net_audit_<game>.json dossiers.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore


# Categorization Constants
CATEGORY_LOOPBACK = "LOOPBACK"
CATEGORY_PRIVATE_LAN = "PRIVATE_LAN"
CATEGORY_PUBLIC_INTERNET = "PUBLIC_INTERNET"
CATEGORY_COINMINER_POOL = "COINMINER_POOL"

ALL_CATEGORIES = (
    CATEGORY_LOOPBACK,
    CATEGORY_PRIVATE_LAN,
    CATEGORY_PUBLIC_INTERNET,
    CATEGORY_COINMINER_POOL,
)

# Known Suspicious Mining Ports & Mining Pool Domain Signatures
COINMINER_PORTS: Set[int] = {3333, 4444, 5555, 7777, 8888, 14444, 33333}

COINMINER_DOMAIN_KEYWORDS: Set[str] = {
    "stratum",
    "nicehash",
    "nanopool",
    "supportxmr",
    "monero",
    "ethermine",
    "miningpool",
    "xmrpool",
    "hashvault",
    "2miners",
    "crypto-pool",
    "f2pool",
    "antpool",
    "poolin",
    "moneroocean",
    "minergate",
    "pool.",
}

# RFC 1918 IPv4 Private Subnets
RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),  # Link-local
)


@dataclass
class ConnectionRecord:
    """Individual observed network socket connection record."""
    pid: int
    process_name: str
    laddr: str
    raddr: str
    status: str
    category: str
    timestamp: str
    protocol: str = "tcp"
    remote_host: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "laddr": self.laddr,
            "raddr": self.raddr,
            "status": self.status,
            "category": self.category,
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "remote_host": self.remote_host,
            "details": self.details,
        }


@dataclass
class NetworkAuditReport:
    """Consolidated audit report of all observed network connections."""
    target_name: str
    timestamp: str
    duration_seconds: float
    total_connections_observed: int
    categories_count: Dict[str, int]
    records: List[ConnectionRecord]
    suspicious_count: int
    is_safe: bool
    summary: str
    coinminer_alerts: List[Dict[str, Any]] = field(default_factory=list)
    public_endpoints: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_name": self.target_name,
            "timestamp": self.timestamp,
            "duration_seconds": round(self.duration_seconds, 2),
            "total_connections_observed": self.total_connections_observed,
            "categories_count": self.categories_count,
            "suspicious_count": self.suspicious_count,
            "is_safe": self.is_safe,
            "summary": self.summary,
            "coinminer_alerts": self.coinminer_alerts,
            "public_endpoints": self.public_endpoints,
            "records": [r.to_dict() for r in self.records],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save_json(self, output_path: Union[str, Path]) -> Path:
        output_file = Path(output_path).resolve()
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(self.to_json(indent=2), encoding="utf-8")
        return output_file


def categorize_endpoint(
    ip_str: str,
    port: int = 0,
    domain_or_host: Optional[str] = None,
) -> str:
    """
    Categorizes an IP/port/domain into LOOPBACK, PRIVATE_LAN, PUBLIC_INTERNET, or COINMINER_POOL.
    """
    # 1. Coinminer port check (Highest priority threat classification)
    if port in COINMINER_PORTS:
        return CATEGORY_COINMINER_POOL

    # 2. Coinminer domain/host signature check
    if domain_or_host:
        host_lower = domain_or_host.lower()
        for kw in COINMINER_DOMAIN_KEYWORDS:
            if kw in host_lower:
                return CATEGORY_COINMINER_POOL

    clean_ip = (ip_str or "").strip()

    # 3. Handle empty / wildcard listening bindings (e.g. 0.0.0.0 or ::)
    if not clean_ip or clean_ip == "0.0.0.0" or clean_ip == "::":
        if port == 0:
            return CATEGORY_LOOPBACK
        # Listening on all interfaces for local LAN co-op
        return CATEGORY_PRIVATE_LAN

    # 4. Standard loopback shortcuts
    if clean_ip in ("127.0.0.1", "::1", "localhost") or clean_ip.startswith("127."):
        return CATEGORY_LOOPBACK

    # 5. IP Address range analysis (IPv4 / IPv6)
    try:
        addr = ipaddress.ip_address(clean_ip)

        # Loopback
        if addr.is_loopback:
            return CATEGORY_LOOPBACK

        # IPv4 Checks
        if addr.version == 4:
            for net in RFC1918_NETWORKS:
                if addr in net:
                    return CATEGORY_PRIVATE_LAN
            if addr.is_private or addr.is_link_local:
                return CATEGORY_PRIVATE_LAN

        # IPv6 Checks
        elif addr.version == 6:
            if addr.is_private or addr.is_link_local:
                return CATEGORY_PRIVATE_LAN

        # If not loopback and not private LAN, it is public internet
        return CATEGORY_PUBLIC_INTERNET

    except ValueError:
        # If ip_str is a domain name string rather than IP
        lower_str = clean_ip.lower()
        for kw in COINMINER_DOMAIN_KEYWORDS:
            if kw in lower_str:
                return CATEGORY_COINMINER_POOL
        return CATEGORY_PUBLIC_INTERNET


class NetworkMonitor:
    """
    Monitors process network connections and categorizes outbound/inbound traffic.
    Capable of monitoring by PID, executable name, or game directory.
    """

    def __init__(
        self,
        target: Optional[Union[int, str, Path]] = None,
        target_dir: Optional[Union[str, Path]] = None,
    ):
        self.target = target
        self.target_dir: Optional[Path] = None

        if target_dir:
            self.target_dir = Path(target_dir).resolve()
        elif isinstance(target, Path):
            if target.is_dir():
                self.target_dir = target.resolve()
            else:
                self.target_dir = target.parent.resolve()
        elif isinstance(target, str) and (os.sep in target or "/" in target):
            p = Path(target).resolve()
            self.target_dir = p if p.is_dir() else p.parent

        # Derive a clean target name for reports
        if isinstance(target, int):
            self.target_name = f"PID_{target}"
        elif isinstance(target, (str, Path)):
            name = Path(target).stem
            self.target_name = re.sub(r"[^a-zA-Z0-9_]", "_", name) or "Game"
        else:
            self.target_name = "GameProcess"

        self.records: List[ConnectionRecord] = []
        self._seen_signatures: Set[str] = set()

    def find_target_pids(self) -> List[int]:
        """
        Discovers all active process IDs matching the configured target.
        """
        if psutil is None:
            return []

        if isinstance(self.target, int):
            return [self.target] if psutil.pid_exists(self.target) else []

        target_name_lower = ""
        if isinstance(self.target, (str, Path)):
            target_name_lower = Path(self.target).name.lower()
            if not target_name_lower.endswith(".exe"):
                target_name_lower += ".exe"

        matching_pids: List[int] = []
        for proc in psutil.process_iter(attrs=["pid", "name"]):
            try:
                proc_name = (proc.info.get("name") or "").lower()
                if target_name_lower and (
                    proc_name == target_name_lower
                    or proc_name == target_name_lower.replace(".exe", "")
                    or target_name_lower.replace(".exe", "") in proc_name
                ):
                    matching_pids.append(proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return matching_pids

    def sample_connections(self) -> List[ConnectionRecord]:
        """
        Samples network connections for the target process(es) at the current moment.
        Inspects sockets via psutil.net_connections() with fallback to Process.net_connections().
        """
        if psutil is None:
            return []

        target_pids = self.find_target_pids()
        # If target was specific but no process found, return empty
        if self.target is not None and not target_pids:
            return []

        target_pids_set = set(target_pids) if target_pids else None
        raw_conns = []

        # Strategy 1: System-wide net_connections()
        try:
            all_conns = psutil.net_connections(kind="inet")
            for c in all_conns:
                if target_pids_set is None or (c.pid is not None and c.pid in target_pids_set):
                    raw_conns.append(c)
        except (psutil.AccessDenied, PermissionError):
            # Strategy 2: Process-level net_connections() fallback
            if target_pids:
                for pid in target_pids:
                    try:
                        p = psutil.Process(pid)
                        p_conns = getattr(p, "net_connections", getattr(p, "connections", None))
                        if callable(p_conns):
                            for c in p_conns(kind="inet"):
                                raw_conns.append(c)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

        new_records: List[ConnectionRecord] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # Cache process names for PID lookups
        proc_names: Dict[int, str] = {}

        for c in raw_conns:
            pid = c.pid or 0
            if pid not in proc_names:
                try:
                    p = psutil.Process(pid)
                    proc_names[pid] = p.name()
                except Exception:
                    proc_names[pid] = f"PID_{pid}"
            pname = proc_names[pid]

            laddr_str = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr_str = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            status_str = c.status if hasattr(c, "status") else "NONE"
            protocol = "tcp" if getattr(c, "type", None) == socket.SOCK_STREAM else "udp"

            # Determine primary endpoint for classification
            if c.raddr and c.raddr.ip:
                target_ip = c.raddr.ip
                target_port = c.raddr.port
            elif c.laddr and c.laddr.ip:
                target_ip = c.laddr.ip
                target_port = c.laddr.port
            else:
                target_ip = ""
                target_port = 0

            cat = categorize_endpoint(target_ip, target_port)

            sig = f"{pid}_{protocol}_{laddr_str}_{raddr_str}_{status_str}_{cat}"
            if sig in self._seen_signatures:
                continue

            self._seen_signatures.add(sig)

            details = None
            if cat == CATEGORY_COINMINER_POOL:
                details = f"Suspicious coinminer pool signature on port {target_port}"
            elif cat == CATEGORY_PUBLIC_INTERNET:
                details = f"Outbound public internet beacon to {target_ip}:{target_port}"

            rec = ConnectionRecord(
                pid=pid,
                process_name=pname,
                laddr=laddr_str,
                raddr=raddr_str,
                status=status_str,
                category=cat,
                timestamp=now_iso,
                protocol=protocol,
                details=details,
            )
            self.records.append(rec)
            new_records.append(rec)

        return new_records

    def monitor(self, duration: float = 2.0, interval: float = 0.5) -> NetworkAuditReport:
        """
        Samples network connections periodically over the specified duration.
        Returns a compiled NetworkAuditReport.
        """
        start_time = time.time()
        elapsed = 0.0

        while elapsed < duration:
            self.sample_connections()
            time.sleep(interval)
            elapsed = time.time() - start_time

        return self.build_report(duration_seconds=elapsed)

    def build_report(self, duration_seconds: float = 0.0) -> NetworkAuditReport:
        """
        Builds a NetworkAuditReport from the collected connection records.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        categories_count: Dict[str, int] = {cat: 0 for cat in ALL_CATEGORIES}

        coinminer_alerts: List[Dict[str, Any]] = []
        public_endpoints_set: Set[str] = set()

        for r in self.records:
            if r.category in categories_count:
                categories_count[r.category] += 1
            else:
                categories_count[r.category] = 1

            if r.category == CATEGORY_COINMINER_POOL:
                coinminer_alerts.append({
                    "pid": r.pid,
                    "process_name": r.process_name,
                    "endpoint": r.raddr or r.laddr,
                    "protocol": r.protocol,
                    "details": r.details,
                    "timestamp": r.timestamp,
                })
            elif r.category == CATEGORY_PUBLIC_INTERNET and r.raddr:
                public_endpoints_set.add(r.raddr)

        suspicious_count = (
            categories_count[CATEGORY_COINMINER_POOL]
            + categories_count[CATEGORY_PUBLIC_INTERNET]
        )

        is_safe = (categories_count[CATEGORY_COINMINER_POOL] == 0) and (
            categories_count[CATEGORY_PUBLIC_INTERNET] == 0
        )

        # Generate summary description
        if categories_count[CATEGORY_COINMINER_POOL] > 0:
            summary = (
                f"CRITICAL ALERT: Detected {categories_count[CATEGORY_COINMINER_POOL]} "
                f"connection(s) to suspicious coinminer pool ports or domains!"
            )
        elif categories_count[CATEGORY_PUBLIC_INTERNET] > 0:
            summary = (
                f"WARNING: Detected {categories_count[CATEGORY_PUBLIC_INTERNET]} "
                f"outbound public internet connection(s). Air-gap isolation recommended."
            )
        elif self.records:
            summary = (
                "CLEAN & ISOLATED: All observed sockets are strictly confined to local loopback "
                "or RFC 1918 LAN co-op endpoints."
            )
        else:
            summary = "NO CONNECTIONS: No active network sockets observed during the observation window."

        return NetworkAuditReport(
            target_name=self.target_name,
            timestamp=now_iso,
            duration_seconds=duration_seconds,
            total_connections_observed=len(self.records),
            categories_count=categories_count,
            records=list(self.records),
            suspicious_count=suspicious_count,
            is_safe=is_safe,
            summary=summary,
            coinminer_alerts=coinminer_alerts,
            public_endpoints=sorted(list(public_endpoints_set)),
        )

    def generate_audit_report(
        self,
        report: Optional[NetworkAuditReport] = None,
        output_dir: Optional[Union[str, Path]] = None,
    ) -> Path:
        """
        Generates and saves 'net_audit_<game>.json' in the target or specified directory.
        """
        audit_rep = report or self.build_report()

        dest_dir = Path(output_dir).resolve() if output_dir else (
            self.target_dir if self.target_dir else Path.cwd()
        )
        dest_dir.mkdir(parents=True, exist_ok=True)

        clean_game = re.sub(r"[^a-zA-Z0-9_]", "_", self.target_name)
        out_file = dest_dir / f"net_audit_{clean_game}.json"
        return audit_rep.save_json(out_file)
