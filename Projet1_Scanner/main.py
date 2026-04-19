# NOMS DES MEMBRES: 
# WOUAPI KOUEKAM WILTRESS
# TEMGOUA EMMANUELLE
# RSI_4 LASALLE
# MATIERE: SCRIPTING


"""
╔══════════════════════════════════════════════════════════╗
║     Port Scanner — Analyse réseau avec visualisation     ║
║     Usage réservé aux réseaux autorisés uniquement       ║
╚══════════════════════════════════════════════════════════╝

Usage :
    python main.py                              # mode interactif
    python main.py --cidr 192.168.1.0/24 --ports 1-1024
    python main.py --host 192.168.1.1   --ports 20-100
    python main.py --cidr 10.0.0.0/24  --ports 1-1024 --delay 0 --output ./rapports
"""
import argparse
import os
import sys
import time

from scanner import scan_host, scan_network, HostReport, NetworkReport
from utils   import (validate_ip, validate_cidr, resolve_host,
                     get_hosts_from_cidr, parse_port_range, format_duration,
                     SEVERITY_COLOR)
from grapher import generate_all_graphs


# Définition des couleurs: Couleurs ANSI 
class C:
    RESET  = "\033[0m"; BOLD = "\033[1m"
    GREEN  = "\033[92m"; RED  = "\033[91m"; YELLOW = "\033[93m"
    CYAN   = "\033[96m"; GRAY = "\033[90m"; WHITE  = "\033[97m"
    BLUE   = "\033[94m"; MAG  = "\033[95m"

def c(color, text): return f"{color}{text}{C.RESET}"

DEFAULT_TIMEOUT = 1.0
DEFAULT_DELAY   = 0.05
DEFAULT_OUTPUT  = "./scan_output"


#  Affichage 
def print_banner():
    print(c(C.CYAN, C.BOLD + """
╔══════════════════════════════════════════════════════════════╗
║       PORT SCANNER  +  ANALYSE GRAPHIQUE RÉSEAU              ║
║       Visualisation Matplotlib — Diagnostic & Sécurité       ║
╚══════════════════════════════════════════════════════════════╝"""))
    print()


def port_callback(idx, total, ip, result):
    pct    = idx / total
    filled = int(25 * pct)
    bar    = "█" * filled + "░" * (25 - filled)
    if result.open:
        sev_str = ""
        if result.vuln:
            sev = result.vuln["severity"]
            colors = {"CRITICAL": C.RED, "HIGH": C.YELLOW,
                      "MEDIUM": C.CYAN, "LOW": C.GREEN}
            sev_str = f" [{c(colors.get(sev, C.GRAY), sev)}]"
        svc = f"({result.service})" if result.service != "inconnu" else ""
        print(f"\r{' '*80}\r"
              f"  {c(C.GREEN,'●')} {c(C.WHITE,str(result.port)):<7}"
              f" {c(C.GRAY,svc):<14}{sev_str}")
    print(f"\r  {c(C.BLUE,bar)} {c(C.GRAY,f'{idx}/{total}')} Port {result.port}...",
          end="", flush=True)


def host_callback(idx, total, ip):
    print(f"\r{' '*80}\r")
    print(c(C.BOLD, f"\n  ── Hôte {idx}/{total} : {c(C.WHITE, ip)} ──"))


def print_host_summary(host: HostReport):
    print(f"\r{' '*80}\r", end="")
    if not host.open_ports:
        print(c(C.GRAY, f"  Aucun port ouvert sur {host.ip}"))
        return
    print(c(C.GREEN, f"  {len(host.open_ports)} port(s) ouvert(s) "
            f"| Score vulnérabilité : {host.vuln_score}"))


def print_network_report(report: NetworkReport, graphs: dict, output_dir: str):
    print("\n" + c(C.BOLD, "═" * 64))
    print(c(C.BOLD + C.CYAN, "  RAPPORT D'ANALYSE RÉSEAU"))
    print(c(C.BOLD, "═" * 64))
    print(f"\n  Réseau ciblé  : {c(C.WHITE, report.cidr)}")
    print(f"  Hôtes scannés : {c(C.WHITE, str(len(report.hosts)))}")
    print(f"  Hôtes actifs  : {c(C.GREEN,  str(len(report.hosts_with_open_ports)))}")
    print(f"  Ports ouverts : {c(C.WHITE,  str(report.total_open_ports))}")
    print(f"  Durée totale  : {c(C.WHITE,  format_duration(report.duration))}")

    # Top IPs vulnérables
    top = report.most_vulnerable_hosts[:5]
    if top:
        print(f"\n  {c(C.BOLD,'Top 5 IPs les plus vulnérables :')}")
        for i, h in enumerate(top, 1):
            crit_str = f" [{c(C.RED, str(h.critical_count)+' CRITICAL')}]" if h.critical_count else ""
            print(f"    {i}. {c(C.WHITE, h.ip):<18} score={c(C.YELLOW, str(h.vuln_score))}"
                  f"  {len(h.open_ports)} ports{crit_str}")

    # Graphiques générés
    if graphs:
        print(f"\n  {c(C.BOLD, 'Graphiques générés (' + str(len(graphs)) + ') :')}")
        for name, path in graphs.items():
            print(f"    {c(C.GREEN,'✓')} {os.path.basename(path)}")
        print(f"  {c(C.GRAY, 'Dossier : ' + output_dir)}")

    print("\n" + c(C.BOLD, "─" * 64) + "\n")


def print_host_report(report: HostReport, graphs: dict, output_dir: str):
    """Affichage pour un scan hôte unique."""
    print("\n" + c(C.BOLD, "═" * 64))
    print(c(C.BOLD + C.CYAN, "  RAPPORT D'ANALYSE HÔTE"))
    print(c(C.BOLD, "═" * 64))
    print(f"\n  Hôte cible    : {c(C.WHITE, report.ip)}")
    print(f"  Ports scannés : {c(C.WHITE, str(report.total_scanned))}")
    print(f"  Ports ouverts : {c(C.GREEN,  str(len(report.open_ports)))}")
    print(f"  Score vulnéra : {c(C.YELLOW, str(report.vuln_score))}")
    print(f"  Durée         : {c(C.WHITE, format_duration(report.duration))}")

    if report.open_ports:
        print(f"\n  {'PORT':<8} {'SERVICE':<16} {'SÉVÉRITÉ':<12} {'CVE / DESCRIPTION'}")
        print(f"  {'─'*6}  {'─'*14}  {'─'*10}  {'─'*35}")
        for r in report.open_ports:
            sev = r.vuln["severity"] if r.vuln else "—"
            desc = r.vuln["desc"][:45] if r.vuln else ""
            cves = ",".join(r.vuln["cves"][:1]) if r.vuln and r.vuln["cves"] else ""
            sev_colors = {"CRITICAL": C.RED, "HIGH": C.YELLOW,
                          "MEDIUM": C.CYAN, "LOW": C.GREEN}
            sev_c = c(sev_colors.get(sev, C.GRAY), sev)
            print(f"  {c(C.WHITE,str(r.port)):<15} {c(C.CYAN,r.service):<24} "
                  f"{sev_c:<20} {c(C.GRAY, cves+' '+desc)}")

    if graphs:
        print(f"\n  {c(C.BOLD, 'Graphiques (' + str(len(graphs)) + ') dans : ' + output_dir)}")
        for _, path in graphs.items():
            print(f"    {c(C.GREEN,'✓')} {os.path.basename(path)}")
    print("\n" + c(C.BOLD, "─" * 64) + "\n")


#  Saisie interactive
def prompt(label, default=""):
    hint = f" [{c(C.GRAY, default)}]" if default else ""
    try:
        v = input(f"  {c(C.CYAN,'▶')} {label}{hint} : ").strip()
        return v if v else default
    except (EOFError, KeyboardInterrupt):
        print(); sys.exit(0)


def get_inputs():
    print(c(C.BOLD, "  Configuration du scan\n"))

    #  Mode 
    mode = prompt("Mode : (1) Hôte unique  (2) Réseau CIDR", "2")

    if mode == "1":
        while True:
            host = prompt("Adresse IP ou hostname cible")
            if not host: continue
            if not validate_ip(host):
                print(c(C.RED, f"  ✗ Hôte invalide : '{host}'\n")); continue
            try:
                ip = resolve_host(host); break
            except ValueError as e:
                print(c(C.RED, f"  ✗ {e}\n"))
        cidr_or_ip = ip
        is_network = False
    else:
        while True:
            cidr = prompt("Réseau CIDR cible", "192.168.1.0/24")
            if validate_cidr(cidr):
                hosts = get_hosts_from_cidr(cidr)
                print(c(C.GRAY, f"  → {len(hosts)} hôtes à scanner"))
                cidr_or_ip = cidr; break
            print(c(C.RED, "  ✗ CIDR invalide. Ex: 192.168.1.0/24\n"))
        is_network = True

    # Ports
    while True:
        pi = prompt("Plage de ports", "1-1024")
        try:
            port_debut, port_fin = parse_port_range(pi); break
        except ValueError as e:
            print(c(C.RED, f"  ✗ {e}\n"))

    # Options
    while True:
        ts = prompt("Timeout par port (s)", str(DEFAULT_TIMEOUT))
        try:
            timeout = float(ts)
            if timeout > 0: break
        except ValueError: pass
        print(c(C.RED, "  ✗ Nombre positif requis\n"))

    while True:
        ds = prompt("Délai entre scans (s, 0=rapide)", str(DEFAULT_DELAY))
        try:
            delay = float(ds)
            if delay >= 0: break
        except ValueError: pass
        print(c(C.RED, "  ✗ Nombre ≥ 0 requis\n"))

    output_dir = prompt("Dossier de sortie des graphiques", DEFAULT_OUTPUT)
    return cidr_or_ip, is_network, port_debut, port_fin, timeout, delay, output_dir


# CLI args
def parse_args():
    p = argparse.ArgumentParser(description="Port Scanner + Analyse graphique réseau")
    p.add_argument("--cidr",    type=str, help="Réseau CIDR (ex: 192.168.1.0/24)")
    p.add_argument("--host",    type=str, help="Hôte unique (IP ou hostname)")
    p.add_argument("--ports",   type=str, help="Plage de ports (ex: 1-1024)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--delay",   type=float, default=DEFAULT_DELAY)
    p.add_argument("--output",  type=str, default=DEFAULT_OUTPUT,
                   help="Dossier de sortie des graphiques")
    args = p.parse_args()
    if not args.cidr and not args.host and not args.ports:
        return None
    return args


#  Entrypoint 
def main():
    print_banner()
    args = parse_args()

    try:
        if args:
            # Mode CLI
            if not args.ports:
                print(c(C.RED, "  ✗ --ports requis")); sys.exit(1)
            port_debut, port_fin = parse_port_range(args.ports)
            timeout    = args.timeout
            delay      = args.delay
            output_dir = args.output
            is_network = bool(args.cidr)
            cidr_or_ip = args.cidr or resolve_host(args.host)
        else:
            cidr_or_ip, is_network, port_debut, port_fin, timeout, delay, output_dir = get_inputs()

        os.makedirs(output_dir, exist_ok=True)
        print()

        if is_network:
            #  Scan réseau CIDR 
            hosts_list = get_hosts_from_cidr(cidr_or_ip)
            print(c(C.BOLD, f"  Scan réseau {cidr_or_ip} "
                            f"({len(hosts_list)} hôtes, ports {port_debut}-{port_fin})"))
            print(c(C.GRAY, f"  timeout={timeout}s  délai={delay}s  → {output_dir}\n"))

            report = scan_network(
                cidr=cidr_or_ip,
                port_debut=port_debut, port_fin=port_fin,
                timeout=timeout, delay=delay,
                host_callback=host_callback,
                port_callback=port_callback,
            )
            print(f"\r{' '*80}\r", end="")

            # Graphiques
            print(c(C.BOLD, "\n  Génération des graphiques..."))
            graphs = generate_all_graphs(report, output_dir)
            print_network_report(report, graphs, output_dir)

        else:
            #  Scan hôte unique 
            ip = cidr_or_ip
            print(c(C.BOLD, f"  Scan hôte {ip} — ports {port_debut}-{port_fin}"))
            print(c(C.GRAY, f"  timeout={timeout}s  délai={delay}s\n"))

            # Encapsuler en NetworkReport pour les graphiques
            from scanner import NetworkReport
            host_rep = scan_host(ip, port_debut, port_fin, timeout, delay, port_callback)
            print(f"\r{' '*80}\r", end="")

            net_rep = NetworkReport(cidr=ip, port_debut=port_debut, port_fin=port_fin)
            net_rep.hosts = [host_rep]
            net_rep.duration = host_rep.duration

            print(c(C.BOLD, "\n  Génération des graphiques..."))
            graphs = generate_all_graphs(net_rep, output_dir)
            print_host_report(host_rep, graphs, output_dir)

    except KeyboardInterrupt:
        print(f"\n\n  {c(C.YELLOW,'⚠')} Scan interrompu.\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
