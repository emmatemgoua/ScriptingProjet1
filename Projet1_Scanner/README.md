# Port Scanner — Outil de diagnostic réseau TCP

Port Scanner est un outil de scan de ports TCP développé en Python, structuré en quatres 
modules.  Son usage est réservée aux machines locales et réseaux autorisés.


## Architecture

port_scanner
main.py      :  interface utilisateur, orchestration, affichage
scanner.py   : logique de scan TCP, structures de données
utils.py     : validation IP, parsing des entrées, helpers
grapher      : presentation Graphique 



## Prérequis

- Python 3.10+ (pour les type hints modernes)
- Aucune dépendance externe — modules standards uniquement : `socket`, `sys`, `time`

## Utilisation

### Mode interactif

bash
python main.py


Le programme guide l'utilisateur étape par étape :
1. Saisie de l'hôte cible (IP ou hostname)
2. Plage de ports (ex : `20-100`, ou port unique `80`)
3. Timeout par port (défaut : 1.0 s)
4. Délai entre scans (défaut : 0.05 s)

### Mode ligne de commande

```bash
python main.py --host 192.168.1.1 --ports 20-100
python main.py --host localhost --ports 1-1024 --timeout 0.5 --delay 0
python main.py --host 10.0.0.1 --ports 80 --timeout 2
```

Argument & Description                              

--host: Adresse IP ou hostname cible             
--ports : Plage de ports (`20-100` ou `80`)        
--timeout: Timeout par connexion (secondes)         
--delay: Délai entre chaque scan (secondes)       


## Fonctionnalités

- **Validation des entrées** : IP/hostname, plage de ports [1–65535], cohérence début < fin
- **Résolution DNS** : accepte les hostnames (ex: `google.com`, `localhost`)
- **Scan TCP** via `socket.connect_ex()` — non-bloquant avec timeout configurable
- **Banner grabbing** : tente de lire la bannière des services ouverts
- **Identification des services** : via `socket.getservbyport()` (HTTP, SSH, FTP…)
- **Affichage en temps réel** : barre de progression + ports ouverts affichés immédiatement
- **Rapport final** : tableau des ports ouverts avec service et bannière
- **Délai simulé** : `time.sleep()` entre chaque scan (respect du cahier des charges)
- **Interruption propre** : `Ctrl+C` arrête le scan sans erreur
- **Avertissement plage large** : confirmation demandée au-delà de 10 000 ports



## Choix techniques

 Choix & Justification 
Socket.connect_ex(): Retourne un code d'erreur au lieu de lever une exception, 
ce qui est plus efficace pour le scan 
Socket.AF_INET + SOCK_STREAM:  TCP uniquement, conforme au cahier des charges 
Dataclass` pour les résultats  Structure claire, modifiable, sans boilerplate 
Callback de progression  Découplage entre la logique de scan et l'affichage 
Argparse` : Double mode interactif/CLI sans code dupliqué 
Couleurs ANSI : Lisibilité en terminal sans dépendance externe 


## Cadre éthique

Ce projet est destiné exclusivement à :
- des machines locales 
- des environnements de test et de lab
- des réseaux sur lesquels nous disposons une autorisation explicite

**Scanner un système sans autorisation est illégal.**


