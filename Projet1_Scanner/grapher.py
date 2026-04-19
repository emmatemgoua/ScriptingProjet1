"""
grapher.py — Génération des graphiques Matplotlib pour l'analyse réseau
"""
import os
import matplotlib
matplotlib.use("Agg")   # backend sans interface graphique
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from collections import Counter

from utils import SEVERITY_COLOR, SEVERITY_SCORE


# définition des Style global, qui seront 
#utilisé dans l'ensemble du code
STYLE = {
    "bg":       "#1E1E2E",
    "bg2":      "#2A2A3E",
    "fg":       "#CDD6F4",
    "accent":   "#89B4FA",
    "grid":     "#313244",
    "critical": "#F38BA8",
    "high":     "#FAB387",
    "medium":   "#F9E2AF",
    "low":      "#A6E3A1",
    "none":     "#585B70",
}

SEV_COLORS = {
    "CRITICAL": STYLE["critical"],
    "HIGH":     STYLE["high"],
    "MEDIUM":   STYLE["medium"],
    "LOW":      STYLE["low"],
    "NONE":     STYLE["none"],
}


def _setup_ax(ax, title="", xlabel="", ylabel=""):
    ax.set_facecolor(STYLE["bg2"])
    ax.tick_params(colors=STYLE["fg"], labelsize=9)
    ax.xaxis.label.set_color(STYLE["fg"])
    ax.yaxis.label.set_color(STYLE["fg"])
    for spine in ax.spines.values():
        spine.set_edgecolor(STYLE["grid"])
    ax.grid(color=STYLE["grid"], linestyle="--", linewidth=0.5, alpha=0.7)
    if title:  ax.set_title(title, color=STYLE["fg"], fontsize=11, fontweight="bold", pad=10)
    if xlabel: ax.set_xlabel(xlabel, color=STYLE["fg"], fontsize=9)
    if ylabel: ax.set_ylabel(ylabel, color=STYLE["fg"], fontsize=9)


def _save(fig, path):
    fig.savefig(path, dpi=150, bbox_inches="tight",
                facecolor=STYLE["bg"], edgecolor="none")
    plt.close(fig)
    return path


# 1. Ports ouverts par IP (bar chart horizontal)

def plot_open_ports_per_ip(network_report, output_dir: str) -> str:
    hosts = [h for h in network_report.hosts if h.open_ports]
    if not hosts:
        return None

    ips   = [h.ip for h in hosts]
    counts = [len(h.open_ports) for h in hosts]
    colors = [STYLE["accent"]] * len(ips)

    # Mise en évidence du max
    max_idx = counts.index(max(counts))
    colors[max_idx] = STYLE["critical"]

    fig, ax = plt.subplots(figsize=(10, max(4, len(ips) * 0.45)))
    fig.patch.set_facecolor(STYLE["bg"])
    bars = ax.barh(ips, counts, color=colors, height=0.6, zorder=3)

    # Labels valeurs
    for bar, val in zip(bars, counts):
        ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", ha="left",
                color=STYLE["fg"], fontsize=8)

    _setup_ax(ax,
              title="Nombre de ports ouverts par adresse IP",
              xlabel="Ports ouverts",
              ylabel="Adresse IP")
    ax.set_xlim(0, max(counts) * 1.2)
    ax.invert_yaxis()

    legend = [mpatches.Patch(color=STYLE["critical"], label="IP la plus exposée"),
              mpatches.Patch(color=STYLE["accent"],   label="Autres IPs")]
    ax.legend(handles=legend, facecolor=STYLE["bg2"], labelcolor=STYLE["fg"],
              fontsize=8, loc="lower right")

    path = os.path.join(output_dir, "01_ports_par_ip.png")
    return _save(fig, path)



# 2. Distribution des sévérités (donut chart)
def plot_severity_distribution(network_report, output_dir: str) -> str:
    sev_counter = Counter()
    for ip, result in network_report.all_open_ports_flat():
        if result.vuln:
            sev_counter[result.vuln["severity"]] += 1
        else:
            sev_counter["NONE"] += 1

    if not sev_counter:
        return None

    order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    labels = [s for s in order if sev_counter[s] > 0]
    sizes  = [sev_counter[s] for s in labels]
    colors = [SEV_COLORS[s] for s in labels]

    fig, ax = plt.subplots(figsize=(7, 7))
    fig.patch.set_facecolor(STYLE["bg"])
    ax.set_facecolor(STYLE["bg"])

    wedges, texts, autotexts = ax.pie(
        sizes, labels=None, colors=colors,
        autopct="%1.1f%%", pctdistance=0.78,
        startangle=90, counterclock=False,
        wedgeprops={"width": 0.55, "edgecolor": STYLE["bg"], "linewidth": 2},
    )
    for t in autotexts:
        t.set_color(STYLE["bg"])
        t.set_fontsize(9)
        t.set_fontweight("bold")

    # Centre
    total = sum(sizes)
    ax.text(0, 0.1, str(total), ha="center", va="center",
            fontsize=26, fontweight="bold", color=STYLE["fg"])
    ax.text(0, -0.2, "ports vulnérables", ha="center", va="center",
            fontsize=9, color=STYLE["fg"])

    # Légende
    legend_elements = [mpatches.Patch(color=SEV_COLORS[s], label=f"{s} ({sev_counter[s]})")
                       for s in labels]
    ax.legend(handles=legend_elements, loc="lower center",
              bbox_to_anchor=(0.5, -0.08), ncol=3,
              facecolor=STYLE["bg2"], labelcolor=STYLE["fg"],
              fontsize=9, framealpha=0.8)

    ax.set_title("Distribution des vulnérabilités par sévérité",
                 color=STYLE["fg"], fontsize=11, fontweight="bold", pad=15)

    path = os.path.join(output_dir, "02_severite_distribution.png")
    return _save(fig, path)



# 3. Score de vulnérabilité par IP (bar chart coloré par risque)

def plot_vuln_score_per_ip(network_report, output_dir: str) -> str:
    hosts = sorted(
        [h for h in network_report.hosts if h.open_ports],
        key=lambda h: h.vuln_score, reverse=True
    )
    if not hosts:
        return None

    # Limiter à top 20 pour la lisibilité
    hosts = hosts[:20]
    ips    = [h.ip for h in hosts]
    scores = [h.vuln_score for h in hosts]

    # Couleur selon score
    def score_color(s):
        if s >= 10: return STYLE["critical"]
        if s >= 6:  return STYLE["high"]
        if s >= 3:  return STYLE["medium"]
        return STYLE["low"]

    colors = [score_color(s) for s in scores]

    fig, ax = plt.subplots(figsize=(10, max(4, len(ips) * 0.5)))
    fig.patch.set_facecolor(STYLE["bg"])
    bars = ax.barh(ips, scores, color=colors, height=0.65, zorder=3)

    for bar, val in zip(bars, scores):
        ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", ha="left", color=STYLE["fg"], fontsize=8)

    _setup_ax(ax,
              title="Score de vulnérabilité par IP (top 20)",
              xlabel="Score de risque cumulé",
              ylabel="Adresse IP")
    ax.set_xlim(0, max(scores) * 1.25 if scores else 10)
    ax.invert_yaxis()

    legend = [
        mpatches.Patch(color=STYLE["critical"], label="Critique  (≥10)"),
        mpatches.Patch(color=STYLE["high"],     label="Élevé     (6–9)"),
        mpatches.Patch(color=STYLE["medium"],   label="Moyen     (3–5)"),
        mpatches.Patch(color=STYLE["low"],      label="Faible    (<3)"),
    ]
    ax.legend(handles=legend, facecolor=STYLE["bg2"], labelcolor=STYLE["fg"],
              fontsize=8, loc="lower right")

    path = os.path.join(output_dir, "03_score_vuln_par_ip.png")
    return _save(fig, path)


# 
# 4. Top 15 ports les plus ouverts sur le réseau (bar chart vertical)
# 
def plot_top_open_ports(network_report, output_dir: str) -> str:
    import socket as _sock
    from utils import get_vulnerability

    port_counter = Counter()
    for ip, result in network_report.all_open_ports_flat():
        port_counter[result.port] += 1

    if not port_counter:
        return None

    top15 = port_counter.most_common(15)

    def get_svc(p):
        try: return _sock.getservbyport(p, "tcp")
        except: return "?"

    ports_labeled = [f":{p}\n{get_svc(p)}" for p, _ in top15]
    counts        = [cnt for _, cnt in top15]

    def port_color(p):
        v = get_vulnerability(p)
        if not v: return STYLE["none"]
        return SEV_COLORS.get(v["severity"], STYLE["none"])

    bar_colors = [port_color(p) for p, _ in top15]

    fig, ax = plt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor(STYLE["bg"])
    bars = ax.bar(range(len(top15)), counts, color=bar_colors, zorder=3)

    ax.set_xticks(range(len(top15)))
    ax.set_xticklabels(ports_labeled, fontsize=8, color=STYLE["fg"])

    for bar, val in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                str(val), ha="center", va="bottom", color=STYLE["fg"], fontsize=8)

    _setup_ax(ax,
              title="Top 15 des ports ouverts sur le réseau",
              xlabel="Port / Service",
              ylabel="Nombre d'hôtes concernés")

    legend = [mpatches.Patch(color=SEV_COLORS[s], label=s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]]
    ax.legend(handles=legend, facecolor=STYLE["bg2"], labelcolor=STYLE["fg"],
              fontsize=8, loc="upper right")

    path = os.path.join(output_dir, "04_top_ports.png")
    return _save(fig, path)


def plot_heatmap(network_report, output_dir: str) -> str:
    hosts_with = [h for h in network_report.hosts if h.open_ports]
    if not hosts_with:
        return None

    # Collecter tous les ports ouverts uniques
    all_ports = sorted(set(
        r.port for h in hosts_with for r in h.open_ports
    ))
    # Limiter à 30 ports max pour la lisibilité
    if len(all_ports) > 30:
        from collections import Counter
        port_freq = Counter(r.port for h in hosts_with for r in h.open_ports)
        all_ports = [p for p, _ in port_freq.most_common(30)]
        all_ports.sort()

    # Limiter à 25 IPs
    hosts_disp = hosts_with[:25]
    ips = [h.ip for h in hosts_disp]

    matrix = np.zeros((len(ips), len(all_ports)))
    for i, host in enumerate(hosts_disp):
        open_set = {r.port for r in host.open_ports}
        for j, port in enumerate(all_ports):
            if port in open_set:
                matrix[i][j] = 1

    fig, ax = plt.subplots(figsize=(max(8, len(all_ports) * 0.45),
                                    max(5, len(ips) * 0.4)))
    fig.patch.set_facecolor(STYLE["bg"])
    ax.set_facecolor(STYLE["bg"])

    im = ax.imshow(matrix, aspect="auto", cmap="Blues",
                   vmin=0, vmax=1, interpolation="nearest")

    ax.set_xticks(range(len(all_ports)))
    ax.set_xticklabels([str(p) for p in all_ports],
                       rotation=45, ha="right", fontsize=7, color=STYLE["fg"])
    ax.set_yticks(range(len(ips)))
    ax.set_yticklabels(ips, fontsize=7, color=STYLE["fg"])

    for spine in ax.spines.values():
        spine.set_edgecolor(STYLE["grid"])

    ax.set_title("Heatmap de présence des ports ouverts par IP",
                 color=STYLE["fg"], fontsize=11, fontweight="bold", pad=10)
    ax.set_xlabel("Port", color=STYLE["fg"], fontsize=9)
    ax.set_ylabel("Adresse IP", color=STYLE["fg"], fontsize=9)

    cbar = fig.colorbar(im, ax=ax, fraction=0.02, pad=0.02)
    cbar.set_ticks([0, 1])
    cbar.set_ticklabels(["Fermé", "Ouvert"])
    cbar.ax.yaxis.set_tick_params(color=STYLE["fg"])
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color=STYLE["fg"], fontsize=8)
    cbar.outline.set_edgecolor(STYLE["grid"])

    path = os.path.join(output_dir, "05_heatmap.png")
    return _save(fig, path)


# 6. Synthèse globale (tableau de bord récapitulatif)

def plot_dashboard(network_report, output_dir: str) -> str:
    from utils import SEVERITY_SCORE, get_vulnerability
    from collections import Counter

    fig = plt.figure(figsize=(14, 8))
    fig.patch.set_facecolor(STYLE["bg"])
    fig.suptitle(f"Tableau de bord — Réseau {network_report.cidr}",
                 color=STYLE["fg"], fontsize=14, fontweight="bold", y=0.98)

    gs = fig.add_gridspec(2, 3, hspace=0.45, wspace=0.35,
                          left=0.07, right=0.97, top=0.92, bottom=0.08)

    # Métriques clés (texte)
    ax0 = fig.add_subplot(gs[0, 0])
    ax0.set_facecolor(STYLE["bg2"])
    for spine in ax0.spines.values():
        spine.set_edgecolor(STYLE["grid"])
    ax0.axis("off")

    total_hosts   = len(network_report.hosts)
    active_hosts  = len(network_report.hosts_with_open_ports)
    total_ports   = network_report.total_open_ports
    critical_ips  = sum(1 for h in network_report.hosts if h.critical_count > 0)

    metrics = [
        ("Hôtes scannés",    str(total_hosts),  STYLE["fg"]),
        ("Hôtes actifs",     str(active_hosts), STYLE["accent"]),
        ("Ports ouverts",    str(total_ports),  STYLE["accent"]),
        ("IPs critiques",    str(critical_ips), STYLE["critical"]),
        ("Durée totale",     f"{network_report.duration:.1f}s", STYLE["fg"]),
    ]
    ax0.set_title("Métriques globales", color=STYLE["fg"], fontsize=10,
                  fontweight="bold", pad=6)
    for i, (label, val, color) in enumerate(metrics):
        y = 0.88 - i * 0.18
        ax0.text(0.05, y, label, transform=ax0.transAxes,
                 color=STYLE["fg"], fontsize=9, va="top")
        ax0.text(0.95, y, val, transform=ax0.transAxes,
                 color=color, fontsize=11, fontweight="bold", va="top", ha="right")

    # Top 5 IPs vulnérables (bar)
    ax1 = fig.add_subplot(gs[0, 1])
    top5 = network_report.most_vulnerable_hosts[:5]
    if top5:
        ips_t = [h.ip.split(".")[-1] + " (...)" for h in top5]
        scores_t = [h.vuln_score for h in top5]
        bars = ax1.barh(ips_t, scores_t,
                        color=[STYLE["critical"], STYLE["high"], STYLE["high"],
                               STYLE["medium"], STYLE["medium"]][:len(top5)],
                        height=0.6, zorder=3)
        _setup_ax(ax1, title="Top 5 IPs à risque", xlabel="Score", ylabel="")
        ax1.invert_yaxis()
        for bar, val in zip(bars, scores_t):
            ax1.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                     str(val), va="center", color=STYLE["fg"], fontsize=8)

    #  Distribution sévérité (pie compact)
    ax2 = fig.add_subplot(gs[0, 2])
    sev_c = Counter()
    for ip, r in network_report.all_open_ports_flat():
        sev_c[r.vuln["severity"] if r.vuln else "NONE"] += 1
    order = ["CRITICAL","HIGH","MEDIUM","LOW","NONE"]
    lbls  = [s for s in order if sev_c[s] > 0]
    szs   = [sev_c[s] for s in lbls]
    clrs  = [SEV_COLORS[s] for s in lbls]
    if szs:
        ax2.set_facecolor(STYLE["bg"])
        wedges, _, autotexts = ax2.pie(
            szs, colors=clrs, autopct="%1.0f%%",
            startangle=90, counterclock=False,
            wedgeprops={"width": 0.5, "edgecolor": STYLE["bg"], "linewidth": 1.5},
            pctdistance=0.78,
        )
        for t in autotexts:
            t.set_fontsize(7)
            t.set_color(STYLE["bg"])
        ax2.set_title("Répartition sévérités", color=STYLE["fg"], fontsize=10,
                      fontweight="bold", pad=6)

    # Top 8 ports ouverts (bar vertical)
    ax3 = fig.add_subplot(gs[1, :2])
    port_c = Counter(r.port for _, r in network_report.all_open_ports_flat())
    top8 = port_c.most_common(8)
    if top8:
        import socket as _s
        def svc(p):
            try: return _s.getservbyport(p, "tcp")
            except: return "?"
        xlabels = [f":{p}\n{svc(p)}" for p, _ in top8]
        yvals   = [c for _, c in top8]
        bar_clrs = []
        for p, _ in top8:
            v = get_vulnerability(p)
            bar_clrs.append(SEV_COLORS.get(v["severity"], STYLE["none"]) if v else STYLE["none"])
        bars = ax3.bar(range(len(top8)), yvals, color=bar_clrs, zorder=3)
        ax3.set_xticks(range(len(top8)))
        ax3.set_xticklabels(xlabels, fontsize=8, color=STYLE["fg"])
        _setup_ax(ax3, title="Top 8 ports les plus fréquents", ylabel="Hôtes")
        for bar, val in zip(bars, yvals):
            ax3.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                     str(val), ha="center", va="bottom", color=STYLE["fg"], fontsize=8)

    # Légende sévérité (bas droite)
    ax4 = fig.add_subplot(gs[1, 2])
    ax4.set_facecolor(STYLE["bg2"])
    ax4.axis("off")
    for spine in ax4.spines.values():
        spine.set_edgecolor(STYLE["grid"])
    ax4.set_title("Échelle de sévérité", color=STYLE["fg"], fontsize=10,
                  fontweight="bold", pad=6)
    sev_info = [
        ("CRITICAL", 4, "RDP, SMB, VNC, Redis…"),
        ("HIGH",     3, "FTP, RPC, SNMP, SQL…"),
        ("MEDIUM",   2, "HTTP, SSH, SMTP…"),
        ("LOW",      1, "HTTPS, admin alt."),
        ("NONE",     0, "Port sans CVE connue"),
    ]
    for i, (sev, score, ex) in enumerate(sev_info):
        y = 0.88 - i * 0.17
        rect = mpatches.FancyBboxPatch((0.02, y - 0.05), 0.12, 0.12,
                                        boxstyle="round,pad=0.01",
                                        facecolor=SEV_COLORS[sev],
                                        transform=ax4.transAxes, clip_on=False)
        ax4.add_patch(rect)
        ax4.text(0.18, y + 0.02, f"{sev}  (score {score})",
                 transform=ax4.transAxes, color=STYLE["fg"],
                 fontsize=8, fontweight="bold", va="center")
        ax4.text(0.18, y - 0.06, ex,
                 transform=ax4.transAxes, color=STYLE["none"],
                 fontsize=7, va="center")

    path = os.path.join(output_dir, "00_dashboard.png")
    return _save(fig, path)


#  Fonction principale 
def generate_all_graphs(network_report, output_dir: str) -> dict:
    """
    Génère tous les graphiques. Retourne un dict {nom: chemin}.
    """
    os.makedirs(output_dir, exist_ok=True)
    paths = {}

    funcs = [
        ("dashboard",      plot_dashboard),
        ("ports_par_ip",   plot_open_ports_per_ip),
        ("severite",       plot_severity_distribution),
        ("score_vuln",     plot_vuln_score_per_ip),
        ("top_ports",      plot_top_open_ports),
        ("heatmap",        plot_heatmap),
    ]
    for name, fn in funcs:
        try:
            p = fn(network_report, output_dir)
            if p:
                paths[name] = p
        except Exception as e:
            print(f"  [!] Graphique '{name}' ignoré : {e}")

    return paths
