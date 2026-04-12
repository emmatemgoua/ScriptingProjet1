# Port Scanner — Outil de diagnostic réseau TCP

Outil de scan de ports TCP développé en Python, structuré en trois modules.  
Usage réservé aux machines locales et réseaux autorisés.

---

## Architecture

port_scanner
main.py      :  interface utilisateur, orchestration, affichage
scanner.py   : logique de scan TCP, structures de données
utils.py     : validation IP, parsing des entrées, helpers



## Prérequis

- Python 3.10+ (pour les type hints modernes)
- Aucune dépendance externe — modules standards uniquement : `socket`, `sys`, `time`

## Utilisation

### Mode interactif

