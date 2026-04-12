import socket
import sys


def validate_ip(ip: str) -> bool:
    """
    Valide une adresse IPv4 ou résout un hostname.
    Retourne True si valide, False sinon.
    """
    # Tentative de résolution DNS (couvre aussi les IPs directes)
    try:
        socket.getaddrinfo(ip, None)
        return True
    except socket.gaierror:
        return False


def resolve_host(host: str) -> str:
    """
    Résout un hostname en adresse IP.
    Retourne l'IP résolue ou l'IP d'origine si déjà valide.
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Impossible de résoudre l'hôte '{host}' : {e}")


def parse_port_range(port_input: str) -> tuple[int, int]:
    """
    Parse une plage de ports depuis une chaîne (ex: '20-100' ou '80').
    Retourne un tuple (port_debut, port_fin).
    Lève ValueError si le format est invalide.
    """
    port_input = port_input.strip()

    # Port unique
    if "-" not in port_input:
        try:
            port = int(port_input)
            _validate_port_value(port)
            return (port, port)
        except ValueError:
            raise ValueError(f"Port invalide : '{port_input}'. Entrez un entier entre 1 et 65535.")

    # Plage de ports
    parts = port_input.split("-")
    if len(parts) != 2:
        raise ValueError(f"Format de plage invalide : '{port_input}'. Utilisez le format 'debut-fin' (ex: 20-100).")

    try:
        port_debut = int(parts[0].strip())
        port_fin = int(parts[1].strip())
    except ValueError:
        raise ValueError(f"Les ports doivent être des entiers. Reçu : '{port_input}'.")

    _validate_port_value(port_debut)
    _validate_port_value(port_fin)

    if port_debut > port_fin:
        raise ValueError(
            f"Le port de début ({port_debut}) doit être inférieur ou égal au port de fin ({port_fin})."
        )

    return (port_debut, port_fin)


def _validate_port_value(port: int) -> None:
    """Vérifie qu'un port est dans la plage valide [1, 65535]."""
    if not (1 <= port <= 65535):
        raise ValueError(f"Port {port} hors plage. Les ports valides sont entre 1 et 65535.")


def get_service_name(port: int) -> str:
    """
    Tente d'identifier le nom du service associé à un port.
    Retourne le nom du service ou 'inconnu' si non trouvé.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "inconnu"


def format_duration(seconds: float) -> str:
    """Formate une durée en secondes en chaîne lisible."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.2f}s"
