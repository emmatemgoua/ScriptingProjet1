# checker.py
import re
from typing import List, Tuple

class PasswordPolicyError(Exception):
    """Exception personnalisée pour les violations de politique de sécurité métier."""
    pass

def valider_complexite_iso27001(mdp: str) -> bool:
    """
    Vérifie la conformité du mot de passe selon les standards ISO 27001.
    
    Critères :
    - Minimum 12 caractères.
    - Présence de majuscules, minuscules, chiffres et caractères spéciaux.
    
    :param mdp: La chaîne de caractères à analyser.
    :return: True si le mot de passe est conforme.
    :raises PasswordPolicyError: Si le mot de passe ne respecte pas la politique.
    """
    # 1. Vérification de la longueur (ISO 27001 préconise la robustesse)
    if len(mdp) < 12:
        raise PasswordPolicyError("La politique ISO 27001 exige un minimum de 12 caractères.")

    # 2. Vérification de la diversité via Regex
    # (?=.*[a-z]) : au moins une minuscule
    # (?=.*[A-Z]) : au moins une majuscule
    # (?=.*[0-9]) : au moins un chiffre
    # (?=.*[!@#$%^&*]) : au moins un caractère spécial
    regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?\":{}|<>]).*$"
    
    if not re.match(regex, mdp):
        raise PasswordPolicyError("Le mot de passe doit contenir des majuscules, minuscules, chiffres et caractères spéciaux.")

    return True

def evaluer_robustesse(mdp: str) -> Tuple[str, List[str]]:
    """
    Analyse détaillée du mot de passe pour fournir un feedback utilisateur.
    
    :param mdp: Le mot de passe à tester.
    :return: Un tuple contenant le niveau (Faible, Moyen, Fort) et une liste de conseils.
    """
    conseils: List[str] = []
    score: int = 0

    # Analyse de la longueur
    if len(mdp) >= 12: score += 2
    elif len(mdp) >= 8: score += 1
    else: conseils.append("Augmentez la longueur au-delà de 8 caractères.")

    # Analyse de la diversité
    if re.search(r"[A-Z]", mdp): score += 1
    else: conseils.append("Ajoutez des lettres majuscules.")
    
    if re.search(r"[0-9]", mdp): score += 1
    else: conseils.append("Ajoutez des chiffres.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", mdp): score += 1
    else: conseils.append("Ajoutez des symboles spéciaux.")

    # Détection de motifs faibles (Audit de sécurité)
    motifs_communs = ["123", "password", "qwerty", "admin", "azerty"]
    if any(motif in mdp.lower() for motif in motifs_communs):
        score = max(0, score - 2)
        conseils.append("Évitez les suites logiques ou mots courants (ex: 123, password).")

    # Détermination du niveau final
    if score >= 5:
        return "FORT", conseils
    elif score >= 3:
        return "MOYEN", conseils
    else:
        return "FAIBLE", conseils
