import socket
import time
from dataclasses import dataclass, field
from typing import Callable

from utils import get_service_name


# ─── Constantes ──────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT   = 1.0    # secondes
DEFAULT_DELAY     = 0.05   # délai entre chaque scan (simulation)
MAX_PORTS_WARNING = 10000  # avertissement si la plage dépasse ce seuil


# ─── Structures de données ────────────────────────────────────────────────────

@dataclass
class PortResult:
    """Résultat du scan d'un port."""
    port:    int
    open:    bool
    service: str = "inconnu"
    banner:  str = ""


@dataclass
class ScanReport:
    """Rapport complet d'un scan."""
    target:       str
    ip:           str
    port_debut:   int
    port_fin:     int
    results:      list[PortResult] = field(default_factory=list)
    duration:     float = 0.0
    total_scanned: int  = 0

    @property
    def open_ports(self) -> list[PortResult]:
        return [r for r in self.results if r.open]

    @property
    def closed_count(self) -> int:
        return self.total_scanned - len(self.open_ports)


# ─── Fonctions de scan ────────────────────────────────────────────────────────

def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> PortResult:
    """
    Tente une connexion TCP sur le port spécifié.
    Retourne un PortResult avec l'état du port et le service identifié.
    """
    result = PortResult(port=port, open=False, service=get_service_name(port))

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((ip, port))

            if code == 0:
                result.open = True
                # Tentative de récupération de bannière (best-effort)
                try:
                    sock.settimeout(0.3)
                    banner_raw = sock.recv(1024)
                    result.banner = banner_raw.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass

    except socket.error:
        pass

    return result


def run_scan(
    ip:          str,
    target:      str,
    port_debut:  int,
    port_fin:    int,
    timeout:     float = DEFAULT_TIMEOUT,
    delay:       float = DEFAULT_DELAY,
    callback:    Callable[[int, int, PortResult], None] | None = None,
) -> ScanReport:
    """
    Effectue le scan TCP sur la plage de ports [port_debut, port_fin].

    Args:
        ip          : adresse IP cible (résolue)
        target      : hostname ou IP saisi par l'utilisateur
        port_debut  : premier port à scanner
        port_fin    : dernier port à scanner
        timeout     : timeout par connexion (secondes)
        delay       : délai entre chaque scan (secondes)
        callback    : fonction appelée après chaque port (progress, total, result)

    Returns:
        ScanReport avec tous les résultats.
    """
    total = port_fin - port_debut + 1
    report = ScanReport(
        target=target,
        ip=ip,
        port_debut=port_debut,
        port_fin=port_fin,
        total_scanned=total,
    )

    start_time = time.time()

    for index, port in enumerate(range(port_debut, port_fin + 1), start=1):
        result = scan_port(ip, port, timeout)

        if result.open:
            report.results.append(result)

        if callback:
            callback(index, total, result)

        if delay > 0:
            time.sleep(delay)

    report.duration = time.time() - start_time
    return report
