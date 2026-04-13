"""
scanner.py — Logique de scan TCP et structures de données
"""
import socket
import time
from dataclasses import dataclass, field

from utils import get_service_name, get_vulnerability, severity_score


DEFAULT_TIMEOUT   = 1.0
DEFAULT_DELAY     = 0.05
MAX_PORTS_WARNING = 10000


@dataclass
class PortResult:
    port:     int
    open:     bool
    service:  str = "inconnu"
    banner:   str = ""
    vuln:     dict = None   # données de vulnérabilité (depuis utils.VULNERABILITIES)


@dataclass
class HostReport:
    """Résultat complet du scan d'un seul hôte."""
    ip:            str
    port_debut:    int
    port_fin:      int
    open_ports:    list = field(default_factory=list)   # liste de PortResult
    duration:      float = 0.0
    total_scanned: int   = 0
    reachable:     bool  = True

    @property
    def vuln_score(self) -> int:
        """Score de vulnérabilité total de cet hôte."""
        return sum(severity_score(r.port) for r in self.open_ports)

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.open_ports
                   if r.vuln and r.vuln.get("severity") == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for r in self.open_ports
                   if r.vuln and r.vuln.get("severity") == "HIGH")


@dataclass
class NetworkReport:
    """Rapport d'un scan de réseau complet (plusieurs hôtes)."""
    cidr:       str
    port_debut: int
    port_fin:   int
    hosts:      list = field(default_factory=list)   # liste de HostReport
    duration:   float = 0.0

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    @property
    def hosts_with_open_ports(self) -> list:
        return [h for h in self.hosts if h.open_ports]

    @property
    def most_vulnerable_hosts(self) -> list:
        return sorted(self.hosts_with_open_ports,
                      key=lambda h: h.vuln_score, reverse=True)

    def all_open_ports_flat(self) -> list:
        """Liste plate de tous les PortResult ouverts de tous les hôtes."""
        results = []
        for h in self.hosts:
            for r in h.open_ports:
                results.append((h.ip, r))
        return results


# ─── Fonctions de scan ────────────────────────────────────────────────────────

def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> PortResult:
    """Tentative de connexion TCP sur un port. Retourne un PortResult."""
    result = PortResult(
        port=port,
        open=False,
        service=get_service_name(port),
        vuln=get_vulnerability(port)
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                result.open = True
                try:
                    sock.settimeout(0.3)
                    raw = sock.recv(1024)
                    result.banner = raw.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
    except socket.error:
        pass
    return result


def scan_host(
    ip:         str,
    port_debut: int,
    port_fin:   int,
    timeout:    float = DEFAULT_TIMEOUT,
    delay:      float = DEFAULT_DELAY,
    callback=None,
) -> HostReport:
    """Scan tous les ports d'un hôte. Retourne un HostReport."""
    total = port_fin - port_debut + 1
    report = HostReport(ip=ip, port_debut=port_debut, port_fin=port_fin, total_scanned=total)
    start = time.time()

    for idx, port in enumerate(range(port_debut, port_fin + 1), 1):
        result = scan_port(ip, port, timeout)
        if result.open:
            report.open_ports.append(result)
        if callback:
            callback(idx, total, ip, result)
        if delay > 0:
            time.sleep(delay)

    report.duration = time.time() - start
    return report


def scan_network(
    cidr:       str,
    port_debut: int,
    port_fin:   int,
    timeout:    float = DEFAULT_TIMEOUT,
    delay:      float = DEFAULT_DELAY,
    host_callback=None,
    port_callback=None,
) -> NetworkReport:
    """
    Scan un réseau CIDR complet.
    host_callback(host_index, total_hosts, ip) — avant chaque hôte
    port_callback(port_index, total_ports, ip, PortResult) — après chaque port
    """
    from utils import get_hosts_from_cidr
    hosts = get_hosts_from_cidr(cidr)
    report = NetworkReport(cidr=cidr, port_debut=port_debut, port_fin=port_fin)
    start = time.time()

    for i, ip in enumerate(hosts, 1):
        if host_callback:
            host_callback(i, len(hosts), ip)
        host_report = scan_host(ip, port_debut, port_fin, timeout, delay, port_callback)
        report.hosts.append(host_report)

    report.duration = time.time() - start
    return report
