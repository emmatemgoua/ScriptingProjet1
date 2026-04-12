#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║          Port Scanner — Outil de diagnostic réseau       ║
║          Usage réservé aux réseaux autorisés             ║
╚══════════════════════════════════════════════════════════╝

Architecture :
    main.py    → interaction utilisateur, orchestration
    scanner.py → logique de scan TCP
    utils.py   → validation, parsing, helpers

Usage :
    python main.py
    python main.py --host 192.168.1.1 --ports 20-100
    python main.py --host localhost --ports 80 --timeout 2 --delay 0
"""

import argparse
import sys
import time

from scanner import run_scan, ScanReport, DEFAULT_TIMEOUT, DEFAULT_DELAY, MAX_PORTS_WARNING
from utils import validate_ip, resolve_host, parse_port_range, format_duration


# Couleurs ANSI 

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"
    WHITE  = "\033[97m"
    BLUE   = "\033[94m"


def c(color: str, text: str) -> str:
    """Applique une couleur ANSI au texte."""
    return f"{color}{text}{C.RESET}"


# Affichage

def print_banner() -> None:
    print(c(C.CYAN, C.BOLD + """
╔══════════════════════════════════════════════════════════╗
║         PORT SCANNER  —  Diagnostic réseau TCP           ║
║  Usage réservé aux machines locales / réseaux autorisés  ║
╚══════════════════════════════════════════════════════════╝"""))
    print()


def print_scan_header(host: str, ip: str, port_debut: int, port_fin: int) -> None:
    print(c(C.BOLD, "─" * 56))
    print(f"  {c(C.BOLD, 'Cible     :')} {c(C.WHITE, host)}"
          + (f"  ({c(C.GRAY, ip)})" if host != ip else ""))
    print(f"  {c(C.BOLD, 'IP        :')} {c(C.WHITE, ip)}")
    print(f"  {c(C.BOLD, 'Ports     :')} {c(C.WHITE, str(port_debut))} → {c(C.WHITE, str(port_fin))}"
          f"  ({c(C.GRAY, str(port_fin - port_debut + 1) + ' ports')})")
    print(c(C.BOLD, "─" * 56))
    print()


def progress_callback(index: int, total: int, result) -> None:
    """Affiche une barre de progression et les ports ouverts en temps réel."""
    pct    = index / total
    filled = int(30 * pct)
    bar    = "█" * filled + "░" * (30 - filled)

    # Port ouvert → affichage immédiat
    if result.open:
        service_str = f"({result.service})" if result.service != "inconnu" else ""
        banner_str  = f" ← {result.banner[:60]}" if result.banner else ""
        print(f"\r{' ' * 70}\r", end="")  # efface la ligne de progression
        print(
            f"  {c(C.GREEN, '●')} Port {c(C.BOLD + C.GREEN, str(result.port)):<6}"
            f" {c(C.GRAY, service_str):<18}"
            f"{c(C.YELLOW, banner_str)}"
        )

    # Barre de progression
    print(
        f"\r  {c(C.BLUE, bar)} {c(C.GRAY, f'{index}/{total}')} "
        f"{c(C.GRAY, f'({pct*100:.0f}%)')}  Port {result.port}...",
        end="",
        flush=True,
    )


def print_report(report: ScanReport) -> None:
    """Affiche le rapport final du scan."""
    # Efface la barre de progression
    print(f"\r{' ' * 70}\r", end="")

    print()
    print(c(C.BOLD, "═" * 56))
    print(c(C.BOLD, "  RAPPORT DE SCAN"))
    print(c(C.BOLD, "═" * 56))

    if not report.open_ports:
        print(f"\n  {c(C.YELLOW, '⚠')}  Aucun port ouvert détecté.\n")
    else:
        print(
            f"\n  {c(C.GREEN, '●')} "
            f"{c(C.BOLD, str(len(report.open_ports)))} port(s) ouvert(s) "
            f"sur {c(C.GRAY, str(report.total_scanned))} scannés :\n"
        )

        # En-tête tableau
        print(f"  {'PORT':<8} {'ÉTAT':<10} {'SERVICE':<18} {'BANNIÈRE'}")
        print(f"  {'─'*6}  {'─'*8}  {'─'*16}  {'─'*30}")

        for r in report.open_ports:
            banner = r.banner[:40] + "…" if len(r.banner) > 40 else r.banner
            print(
                f"  {c(C.BOLD + C.WHITE, str(r.port)):<15}"
                f" {c(C.GREEN, 'OUVERT'):<18}"
                f" {c(C.CYAN, r.service):<26}"
                f" {c(C.YELLOW, banner)}"
            )

    print()
    print(c(C.BOLD, "─" * 56))
    print(
        f"  Durée totale    : {c(C.WHITE, format_duration(report.duration))}\n"
        f"  Ports scannés   : {c(C.WHITE, str(report.total_scanned))}\n"
        f"  Ports ouverts   : {c(C.GREEN, str(len(report.open_ports)))}\n"
        f"  Ports fermés    : {c(C.GRAY, str(report.closed_count))}"
    )
    print(c(C.BOLD, "─" * 56))
    print()


# Saisie interactive 

def prompt(label: str, default: str = "") -> str:
    """Affiche un prompt coloré et retourne la saisie utilisateur."""
    default_hint = f" [{c(C.GRAY, default)}]" if default else ""
    try:
        val = input(f"  {c(C.CYAN, '▶')} {label}{default_hint} : ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        raise


def get_user_inputs() -> tuple[str, int, int, float, float]:
    """
    Collecte et valide les entrées utilisateur de manière interactive.
    Retourne (host, port_debut, port_fin, timeout, delay).
    """
    print(c(C.BOLD, "  Configuration du scan\n"))

    # ── Hôte cible
    while True:
        try:
            host = prompt("Hôte cible (IP ou hostname)")
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)

        if not host:
            print(c(C.RED, "  ✗ L'adresse ne peut pas être vide.\n"))
            continue

        if not validate_ip(host):
            print(c(C.RED, f"  ✗ Hôte invalide ou inaccessible : '{host}'\n"))
            continue

        try:
            ip = resolve_host(host)
        except ValueError as e:
            print(c(C.RED, f"  ✗ {e}\n"))
            continue

        break

    # ── Plage de ports
    while True:
        try:
            port_input = prompt("Plage de ports", "1-1024")
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)

        try:
            port_debut, port_fin = parse_port_range(port_input)
        except ValueError as e:
            print(c(C.RED, f"  ✗ {e}\n"))
            continue

        total = port_fin - port_debut + 1
        if total > MAX_PORTS_WARNING:
            print(
                c(C.YELLOW,
                  f"  ⚠  Attention : {total} ports à scanner. Cela peut prendre du temps.")
            )
            try:
                confirm = prompt("Continuer quand même ? (o/N)", "N")
            except (EOFError, KeyboardInterrupt):
                sys.exit(0)
            if confirm.lower() not in ("o", "oui", "y", "yes"):
                continue

        break

    # ── Timeout
    while True:
        try:
            timeout_str = prompt("Timeout par port (secondes)", str(DEFAULT_TIMEOUT))
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)

        try:
            timeout = float(timeout_str)
            if timeout <= 0:
                raise ValueError
        except ValueError:
            print(c(C.RED, "  ✗ Le timeout doit être un nombre positif.\n"))
            continue
        break

    # ── Délai de simulation
    while True:
        try:
            delay_str = prompt("Délai entre scans (secondes, 0 = désactivé)", str(DEFAULT_DELAY))
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)

        try:
            delay = float(delay_str)
            if delay < 0:
                raise ValueError
        except ValueError:
            print(c(C.RED, "  ✗ Le délai doit être un nombre positif ou 0.\n"))
            continue
        break

    return host, port_debut, port_fin, timeout, delay


# Parsing CLI (mode non-interactif) 

def parse_args() -> argparse.Namespace | None:
    """
    Parse les arguments de la ligne de commande.
    Retourne None si aucun argument n'est fourni (mode interactif).
    """
    parser = argparse.ArgumentParser(
        description="Port Scanner TCP — outil de diagnostic réseau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  python main.py --host 192.168.1.1 --ports 20-100\n"
            "  python main.py --host localhost --ports 80 --timeout 2 --delay 0\n"
            "  python main.py --host 10.0.0.1 --ports 1-65535 --delay 0"
        ),
    )
    parser.add_argument("--host",    type=str, help="Adresse IP ou hostname cible")
    parser.add_argument("--ports",   type=str, help="Plage de ports (ex: 20-100 ou 80)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Timeout par port en secondes (défaut: {DEFAULT_TIMEOUT})")
    parser.add_argument("--delay",   type=float, default=DEFAULT_DELAY,
                        help=f"Délai entre scans en secondes (défaut: {DEFAULT_DELAY})")

    args = parser.parse_args()

    # Si aucun argument CLI → mode interactif
    if not args.host and not args.ports:
        return None

    return args


#Point d'entrée 

def main() -> None:
    print_banner()

    args = parse_args()

    try:
        if args:
            #  Mode CLI (arguments fournis)
            if not args.host:
                print(c(C.RED, "  ✗ --host requis en mode CLI."))
                sys.exit(1)
            if not args.ports:
                print(c(C.RED, "  ✗ --ports requis en mode CLI."))
                sys.exit(1)

            host = args.host
            if not validate_ip(host):
                print(c(C.RED, f"  ✗ Hôte invalide : '{host}'"))
                sys.exit(1)

            try:
                ip = resolve_host(host)
                port_debut, port_fin = parse_port_range(args.ports)
            except ValueError as e:
                print(c(C.RED, f"  ✗ {e}"))
                sys.exit(1)

            timeout = args.timeout
            delay   = args.delay

        else:
            # Mode interactif
            host, port_debut, port_fin, timeout, delay = get_user_inputs()
            ip = resolve_host(host)

        # Lancement du scan
        print()
        print_scan_header(host, ip, port_debut, port_fin)
        print(c(C.GRAY, f"  Démarrage du scan  (timeout={timeout}s, délai={delay}s)...\n"))

        report = run_scan(
            ip=ip,
            target=host,
            port_debut=port_debut,
            port_fin=port_fin,
            timeout=timeout,
            delay=delay,
            callback=progress_callback,
        )

        print_report(report)

    except KeyboardInterrupt:
        print(f"\n\n  {c(C.YELLOW, '⚠')}  Scan interrompu par l'utilisateur.\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
