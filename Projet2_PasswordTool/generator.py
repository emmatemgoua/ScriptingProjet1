# generator.py
import secrets
import string

def generer_mot_de_passe(longueur=12, maj=True, chiffres=True, speciaux=True):
    # Base : lettres minuscules (toujours incluses pour la diversité)
    caracteres = string.ascii_lowercase
    
    if maj:
        caracteres += string.ascii_uppercase
    if chiffres:
        caracteres += string.digits
    if speciaux:
        caracteres += string.punctuation
        
    # Génération sécurisée [cite: 34, 61]
    mdp = ''.join(secrets.choice(caracteres) for _ in range(longueur))
    return mdp
