# utils.py
import hashlib
import os
import logging
from typing import Optional

logging.basicConfig(
    filename='audit_securite.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_evenement(message: str) -> None:
    """
    Enregistre une action dans le journal d'audit pour le suivi de sécurité.
    
    :param message: Description de l'action effectuée.
    """
    logging.info(message)

def hacher_mot_de_passe(mdp: str) -> bytes:
    """
    Génère une empreinte numérique sécurisée (hachage salé) pour éviter le stockage en clair.
    
    :param mdp: Le mot de passe original.
    :return: Le sel concaténé au hachage (format bytes).
    """
    # Création d'un sel aléatoire de 16 octets
    sel = os.urandom(16)
    
    # Hachage PBKDF2 avec SHA-256 (Robuste contre les attaques par dictionnaire)
    hachage = hashlib.pbkdf2_hmac(
        'sha256', 
        mdp.encode('utf-8'), 
        sel, 
        100000
    )
    log_evenement("Action : Génération d'un hachage sécurisé.")
    return sel + hachage

def sauvegarder_empreinte(mdp: str, nom_fichier: str = "shadow_copy.txt") -> None:
    """
    Enregistre l'empreinte hachée dans un fichier pour l'audit.
    
    :param mdp: Le mot de passe à traiter.
    :param nom_fichier: Nom du fichier de stockage.
    :raises IOError: En cas d'erreur d'écriture sur le disque.
    """
    try:
        empreinte = hacher_mot_de_passe(mdp)
        with open(nom_fichier, "ab") as f:
            f.write(empreinte + b"\n")
        log_evenement(f"Succès : Empreinte sauvegardée dans {nom_fichier}.")
    except Exception as e:
        log_evenement(f"Erreur : Échec de la sauvegarde ({str(e)}).")
        raise
