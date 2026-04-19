# generator.py
import secrets
import string
from typing import Optional

def generer_mot_de_passe(
    longueur: int = 12, 
    inclure_maj: bool = True, 
    inclure_chiffres: bool = True, 
    inclure_speciaux: bool = True
) -> str:
    
    # Alphabet de base (minuscules)
    alphabet = string.ascii_lowercase
    
    if inclure_maj:
        alphabet += string.ascii_uppercase
    if inclure_chiffres:
        alphabet += string.digits
    if inclure_speciaux:
        alphabet += string.punctuation
        
    # secrets.choice est utilisé pour la sécurité au lieu de random.choice
    mdp = ''.join(secrets.choice(alphabet) for _ in range(longueur))
    return mdp
