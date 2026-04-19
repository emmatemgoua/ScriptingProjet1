"""
utils.py — Validation des entrées, parsing et base de vulnérabilités
"""
import ipaddress
import socket


# Base de vulnérabilités connues par port
VULNERABILITIES: dict = {
    21:   {"service": "FTP",          "severity": "HIGH",     "cves": ["CVE-2011-2523"], "desc": "Transfert en clair, anonymous login possible"},
    22:   {"service": "SSH",          "severity": "MEDIUM",   "cves": ["CVE-2023-38408"], "desc": "Brute-force possible, versions vulnérables connues"},
    23:   {"service": "Telnet",       "severity": "CRITICAL", "cves": ["CVE-2020-10188"], "desc": "Protocole non chiffré, credentials en clair"},
    25:   {"service": "SMTP",         "severity": "MEDIUM",   "cves": ["CVE-2020-7247"],  "desc": "Open relay, énumération d'utilisateurs"},
    53:   {"service": "DNS",          "severity": "MEDIUM",   "cves": ["CVE-2023-50387"], "desc": "DNS amplification, cache poisoning"},
    80:   {"service": "HTTP",         "severity": "MEDIUM",   "cves": ["CVE-2021-41773"], "desc": "Trafic non chiffré, XSS/injection possibles"},
    110:  {"service": "POP3",         "severity": "HIGH",     "cves": ["CVE-2003-0143"],  "desc": "Authentification en clair"},
    111:  {"service": "RPC",          "severity": "HIGH",     "cves": ["CVE-2017-8779"],  "desc": "Exposition des services RPC"},
    135:  {"service": "MS-RPC",       "severity": "HIGH",     "cves": ["CVE-2003-0352"],  "desc": "Exécution de code à distance"},
    139:  {"service": "NetBIOS",      "severity": "HIGH",     "cves": ["CVE-2017-0144"],  "desc": "EternalBlue, partage SMB non sécurisé"},
    143:  {"service": "IMAP",         "severity": "MEDIUM",   "cves": ["CVE-2021-38371"], "desc": "Authentification potentiellement en clair"},
    161:  {"service": "SNMP",         "severity": "HIGH",     "cves": ["CVE-2002-0013"],  "desc": "Community string par défaut 'public'"},
    389:  {"service": "LDAP",         "severity": "HIGH",     "cves": ["CVE-2021-44228"], "desc": "LDAP injection, log4shell vecteur"},
    443:  {"service": "HTTPS",        "severity": "LOW",      "cves": ["CVE-2014-0160"],  "desc": "Heartbleed sur OpenSSL anciens"},
    445:  {"service": "SMB",          "severity": "CRITICAL", "cves": ["CVE-2017-0144"],  "desc": "EternalBlue / WannaCry"},
    512:  {"service": "rexec",        "severity": "CRITICAL", "cves": [],                 "desc": "Exécution distante sans chiffrement"},
    513:  {"service": "rlogin",       "severity": "CRITICAL", "cves": [],                 "desc": "Login distant non sécurisé"},
    514:  {"service": "rsh",          "severity": "CRITICAL", "cves": [],                 "desc": "Shell distant sans authentification forte"},
    1433: {"service": "MSSQL",        "severity": "HIGH",     "cves": ["CVE-2020-0618"],  "desc": "SQL injection, accès BDD exposé"},
    1521: {"service": "Oracle DB",    "severity": "HIGH",     "cves": ["CVE-2012-1675"],  "desc": "TNS Poison, accès base de données"},
    2049: {"service": "NFS",          "severity": "HIGH",     "cves": ["CVE-2017-7895"],  "desc": "Montage de partages réseau non sécurisé"},
    3306: {"service": "MySQL",        "severity": "HIGH",     "cves": ["CVE-2016-6662"],  "desc": "Accès base de données, brute-force"},
    3389: {"service": "RDP",          "severity": "CRITICAL", "cves": ["CVE-2019-0708"],  "desc": "BlueKeep — RCE sans authentification"},
    4444: {"service": "Backdoor",     "severity": "CRITICAL", "cves": [],                 "desc": "Port typique reverse shell/backdoor"},
    5432: {"service": "PostgreSQL",   "severity": "HIGH",     "cves": ["CVE-2019-10164"], "desc": "Accès base de données exposé"},
    5900: {"service": "VNC",          "severity": "CRITICAL", "cves": ["CVE-2019-15681"], "desc": "Accès bureau à distance, auth faible"},
    6379: {"service": "Redis",        "severity": "CRITICAL", "cves": ["CVE-2022-0543"],  "desc": "Pas d'auth par défaut, RCE possible"},
    8080: {"service": "HTTP-alt",     "severity": "MEDIUM",   "cves": ["CVE-2021-42013"], "desc": "Proxy/admin web souvent sans auth"},
    8443: {"service": "HTTPS-alt",    "severity": "LOW",      "cves": [],                 "desc": "Interface admin alternative"},
    9200: {"service": "Elasticsearch","severity": "CRITICAL", "cves": ["CVE-2021-22145"], "desc": "Pas d'auth par défaut, données exposées"},
    27017:{"service": "MongoDB",      "severity": "CRITICAL", "cves": ["CVE-2019-2389"],  "desc": "Pas d'auth par défaut, base exposée"},
}

SEVERITY_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
SEVERITY_COLOR = {
    "CRITICAL": "#D32F2F",
    "HIGH":     "#F57C00",
    "MEDIUM":   "#FBC02D",
    "LOW":      "#388E3C",
    "NONE":     "#9E9E9E",
}


def get_vulnerability(port: int) -> dict | None:
    return VULNERABILITIES.get(port)


def severity_score(port: int) -> int:
    vuln = get_vulnerability(port)
    if not vuln:
        return 0
    return SEVERITY_SCORE.get(vuln["severity"], 0)


def validate_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def get_hosts_from_cidr(cidr: str) -> list:
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(h) for h in net.hosts()]


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        # On peut garder un fallback socket au cas où l'utilisateur entre un nom d'hôte
        try:
            socket.gethostbyname(ip)
            return True
        except socket.gaierror:
            return False


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Impossible de résoudre '{host}': {e}")


def parse_port_range(port_input: str) -> tuple:
    port_input = port_input.strip()
    try:
        if "-" in port_input:
            parts = [int(p.strip()) for p in port_input.split("-")]
            if len(parts) != 2: raise ValueError
            a, b = parts
        else:
            a = b = int(port_input)
        
        # Validation groupée
        for p in (a, b): _check_port(p)
        if a > b: raise ValueError(f"Début ({a}) supérieur à fin ({b})")
        
        return (a, b)
    except ValueError:
        raise ValueError(f"Format de port invalide : '{port_input}'. Utilisez 'port' ou 'début-fin'.")


def _check_port(port: int) -> None:
    if not (1 <= port <= 65535):
        raise ValueError(f"Port {port} hors plage [1-65535].")


def get_service_name(port: int) -> str:
    # On regarde d'abord dans ta base personnalisée
    if port in VULNERABILITIES:
        return VULNERABILITIES[port]["service"]
    # Sinon on demande au système
    try:
        return socket.getservbyport(port, "tcp")
    except (OSError, OverflowError):
        return "inconnu"


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, secs = divmod(seconds, 60)
    return f"{int(minutes)}m {secs:.2f}s"
