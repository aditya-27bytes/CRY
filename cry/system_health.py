"""System & Host Health Telemetry Engine for CRY.

Collects system-level telemetry across Linux (Ubuntu/Debian) and Windows/macOS:
- Hostname, user, date/time, OS platform
- Uptime and load averages
- CPU utilization & core count
- RAM and disk storage usage
- Process count and network connectivity checks
- Proactive health alert thresholds
- Generation of timestamped health reports
"""

from __future__ import annotations

import ctypes
import getpass
import os
import platform
import shutil
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

if sys.platform == "win32":
    from ctypes import wintypes


@dataclass
class SystemHealthReport:
    """Telemetry report capturing host environment and system health."""

    hostname: str
    logged_user: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    os_platform: str = "Unknown"
    uptime_seconds: int = 0
    uptime_formatted: str = "Unknown"
    load_averages: str = "N/A"
    cpu_cores: int = 1
    cpu_utilization_pct: float | None = None
    ram_used_gb: float = 0.0
    ram_total_gb: float = 0.0
    ram_percent: float = 0.0
    disk_used_gb: float = 0.0
    disk_total_gb: float = 0.0
    disk_free_gb: float = 0.0
    disk_percent: float = 0.0
    process_count: int = 0
    network_connected: bool = False
    network_status_msg: str = "Unchecked"
    alerts: list[str] = field(default_factory=list)
    overall_status: str = "NOMINAL"


def get_system_uptime() -> tuple[int, str]:
    """Retrieve system uptime in seconds and human-readable format."""
    sec = 0
    if sys.platform == "win32":
        try:
            sec = ctypes.windll.kernel32.GetTickCount64() // 1000
        except Exception:
            sec = 0
    elif os.path.exists("/proc/uptime"):
        try:
            with open("/proc/uptime", encoding="utf-8") as f:
                sec = int(float(f.read().split()[0]))
        except Exception:
            sec = 0

    days, rem = divmod(sec, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)

    parts: list[str] = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")

    formatted = " ".join(parts) if parts else "< 1m"
    return sec, formatted


def get_os_display() -> str:
    """Format OS platform with Linux distribution detection."""
    if sys.platform.startswith("linux") and os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", encoding="utf-8") as f:
                lines = f.readlines()
                info = {}
                for line in lines:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        info[k] = v.strip('"')
                pretty = info.get("PRETTY_NAME")
                if pretty:
                    return f"{pretty} ({platform.machine()})"
        except Exception:
            pass
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def get_load_averages() -> str:
    """Get system load averages on Unix/Linux systems."""
    if hasattr(os, "getloadavg"):
        try:
            l1, l5, l15 = os.getloadavg()
            return f"{l1:.2f}, {l5:.2f}, {l15:.2f} (1m, 5m, 15m)"
        except Exception:
            pass
    return "N/A (Non-Unix platform)"


def get_cpu_utilization() -> float | None:
    """Sample CPU utilization percentage without external dependencies."""
    if sys.platform == "win32":
        try:

            class FILETIME(ctypes.Structure):
                _fields_ = [
                    ("dwLowDateTime", wintypes.DWORD),
                    ("dwHighDateTime", wintypes.DWORD),
                ]

            def ft_to_int(ft: FILETIME) -> int:
                high: int = ft.dwHighDateTime
                low: int = ft.dwLowDateTime
                return (high << 32) + low

            i1, k1, u1 = FILETIME(), FILETIME(), FILETIME()
            ctypes.windll.kernel32.GetSystemTimes(
                ctypes.byref(i1), ctypes.byref(k1), ctypes.byref(u1)
            )
            time.sleep(0.04)
            i2, k2, u2 = FILETIME(), FILETIME(), FILETIME()
            ctypes.windll.kernel32.GetSystemTimes(
                ctypes.byref(i2), ctypes.byref(k2), ctypes.byref(u2)
            )

            idle = ft_to_int(i2) - ft_to_int(i1)
            kernel = ft_to_int(k2) - ft_to_int(k1)
            user = ft_to_int(u2) - ft_to_int(u1)
            total = kernel + user
            if total > 0:
                pct = ((total - idle) / total) * 100.0
                return max(0.0, min(100.0, round(pct, 1)))
        except Exception:
            return None

    elif os.path.exists("/proc/stat"):
        try:

            def read_proc_stat() -> tuple[int, int]:
                with open("/proc/stat", encoding="utf-8") as f:
                    fields = [int(x) for x in f.readline().split()[1:]]
                    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
                    total = sum(fields)
                    return idle, total

            i1, t1 = read_proc_stat()
            time.sleep(0.04)
            i2, t2 = read_proc_stat()
            dt = t2 - t1
            di = i2 - i1
            if dt > 0:
                pct = ((dt - di) / dt) * 100.0
                return max(0.0, min(100.0, round(pct, 1)))
        except Exception:
            return None

    return None


def get_memory_stats() -> tuple[float, float, float]:
    """Retrieve used RAM in GB, total RAM in GB, and utilization percentage."""
    if sys.platform == "win32":
        try:

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                total_gb = stat.ullTotalPhys / (1024**3)
                avail_gb = stat.ullAvailPhys / (1024**3)
                used_gb = max(0.0, total_gb - avail_gb)
                pct = float(stat.dwMemoryLoad)
                return round(used_gb, 2), round(total_gb, 2), round(pct, 1)
        except Exception:
            pass

    elif os.path.exists("/proc/meminfo"):
        try:
            mem_info: dict[str, int] = {}
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        k = parts[0].strip()
                        v = int(parts[1].strip().split()[0])
                        mem_info[k] = v
            total_kb = mem_info.get("MemTotal", 0)
            avail_kb = mem_info.get("MemAvailable", mem_info.get("MemFree", 0))
            if total_kb > 0:
                used_kb = max(0, total_kb - avail_kb)
                total_gb = total_kb / (1024**2)
                used_gb = used_kb / (1024**2)
                pct = (used_kb / total_kb) * 100.0
                return round(used_gb, 2), round(total_gb, 2), round(pct, 1)
        except Exception:
            pass

    return 0.0, 0.0, 0.0


def get_disk_stats(path: str = ".") -> tuple[float, float, float, float]:
    """Retrieve used GB, total GB, free GB, and disk usage percentage."""
    try:
        usage = shutil.disk_usage(path)
        total_gb = usage.total / (1024**3)
        used_gb = usage.used / (1024**3)
        free_gb = usage.free / (1024**3)
        pct = (usage.used / usage.total) * 100.0 if usage.total > 0 else 0.0
        return round(used_gb, 1), round(total_gb, 1), round(free_gb, 1), round(pct, 1)
    except Exception:
        return 0.0, 0.0, 0.0, 0.0


def get_active_process_count() -> int:
    """Retrieve current active process count with zero subprocesses."""
    if sys.platform == "win32":
        try:
            arr = (wintypes.DWORD * 4096)()
            cb_needed = wintypes.DWORD()
            if ctypes.windll.kernel32.K32EnumProcesses(
                ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(cb_needed)
            ):
                return cb_needed.value // ctypes.sizeof(wintypes.DWORD)
        except Exception:
            pass
    elif os.path.exists("/proc"):
        try:
            return len([p for p in os.listdir("/proc") if p.isdigit()])
        except Exception:
            pass
    return 0


def probe_network_connectivity(timeout: float = 1.0) -> tuple[bool, str]:
    """Probe network connectivity by attempting quick TCP handshake to DNS resolvers."""
    resolvers = [("8.8.8.8", 53), ("1.1.1.1", 53)]
    for ip, port in resolvers:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            res = sock.connect_ex((ip, port))
            sock.close()
            if res == 0:
                return True, f"Online (DNS resolver {ip} reachable)"
        except Exception:
            continue
    return False, "Offline or local sandbox isolation (DNS unreachable)"


def collect_system_health() -> SystemHealthReport:
    """Collect comprehensive host health metrics across Linux and Windows."""
    hostname = socket.gethostname()
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

    os_display = get_os_display()
    uptime_sec, uptime_str = get_system_uptime()
    load_avg = get_load_averages()
    cores = os.cpu_count() or 1
    cpu_pct = get_cpu_utilization()
    ram_used, ram_total, ram_pct = get_memory_stats()
    disk_used, disk_total, disk_free, disk_pct = get_disk_stats()
    proc_count = get_active_process_count()
    net_ok, net_msg = probe_network_connectivity(timeout=0.8)

    # Health Alert Thresholds
    alerts: list[str] = []
    overall = "NOMINAL"

    if disk_pct >= 90.0:
        alerts.append(f"CRITICAL: Storage capacity critical ({disk_pct:.1f}% used)")
        overall = "CRITICAL"
    elif disk_pct >= 80.0:
        alerts.append(f"WARNING: High storage utilization ({disk_pct:.1f}% used)")
        if overall != "CRITICAL":
            overall = "WARNING"

    if ram_pct >= 90.0:
        alerts.append(f"WARNING: High RAM consumption ({ram_pct:.1f}% used)")
        if overall != "CRITICAL":
            overall = "WARNING"

    if cpu_pct is not None and cpu_pct >= 95.0:
        alerts.append(f"WARNING: Sustained peak CPU load ({cpu_pct:.1f}%)")
        if overall != "CRITICAL":
            overall = "WARNING"

    if not net_ok:
        alerts.append("NOTICE: External network DNS resolution unavailable")

    return SystemHealthReport(
        hostname=hostname,
        logged_user=user,
        timestamp=datetime.now(UTC),
        os_platform=os_display,
        uptime_seconds=uptime_sec,
        uptime_formatted=uptime_str,
        load_averages=load_avg,
        cpu_cores=cores,
        cpu_utilization_pct=cpu_pct,
        ram_used_gb=ram_used,
        ram_total_gb=ram_total,
        ram_percent=ram_pct,
        disk_used_gb=disk_used,
        disk_total_gb=disk_total,
        disk_free_gb=disk_free,
        disk_percent=disk_pct,
        process_count=proc_count,
        network_connected=net_ok,
        network_status_msg=net_msg,
        alerts=alerts,
        overall_status=overall,
    )


def format_health_report_text(report: SystemHealthReport) -> str:
    """Format human-readable plain text health report."""
    timestamp_str = report.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    cpu_str = (
        f"{report.cpu_utilization_pct:.1f}%" if report.cpu_utilization_pct is not None else "N/A"
    )
    alerts_block = (
        "\n".join(f"  - {a}" for a in report.alerts)
        if report.alerts
        else "  - None detected (all monitored thresholds healthy)"
    )

    return f"""================================================================================
🐧 SYSTEM & HOST HEALTH MONITOR REPORT
================================================================================
Generated At:       {timestamp_str}
Overall Status:     {report.overall_status}

[HOST TELEMETRY]
Hostname:           {report.hostname}
Logged-in User:     {report.logged_user}
OS Platform:        {report.os_platform}
System Uptime:      {report.uptime_formatted} ({report.uptime_seconds:,} seconds)
Load Averages:      {report.load_averages}

[RESOURCE UTILIZATION]
CPU Cores:          {report.cpu_cores}
CPU Load:           {cpu_str}
Memory (RAM):       {report.ram_used_gb:.2f} GB / {report.ram_total_gb:.2f} GB ({report.ram_percent:.1f}% used)
Disk Storage:       {report.disk_used_gb:.1f} GB / {report.disk_total_gb:.1f} GB ({report.disk_percent:.1f}% used, {report.disk_free_gb:.1f} GB free)
Active Processes:   {report.process_count}

[NETWORK CONNECTIVITY]
Network Status:     {report.network_status_msg}
Internet Reachable: {"Yes" if report.network_connected else "No / Degraded"}

[HEALTH MONITOR ALERTS]
{alerts_block}
================================================================================
*Generated by CRY Host & System Health Engine*
"""


def save_system_health_report(report: SystemHealthReport, output_dir: Path | None = None) -> Path:
    """Generate and persist timestamped text report to reports directory."""
    target_dir = output_dir or (Path.cwd() / "reports")
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp_slug = report.timestamp.strftime("%Y%m%d_%H%M%S")
    file_path = target_dir / f"system_health_{timestamp_slug}.txt"
    content = format_health_report_text(report)
    file_path.write_text(content, encoding="utf-8")
    return file_path
