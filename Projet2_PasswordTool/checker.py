# checker.py
import re

def verifier_complexite(mdp):
    score = 0
    feedback = []

    # Critère 1 : Longueur [cite: 24]
    if len(mdp) >= 12:
        score += 2
    elif len(mdp) >= 8:
        score += 1
    else:
        feedback.append("- Trop court (min 8 caractères recommandé)")

    # Critère 2 : Diversité [cite: 25]
    if re.search(r"[A-Z]", mdp): score += 1
    else: feedback.append("- Ajoutez des majuscules")
    
    if re.search(r"[0-9]", mdp): score += 1
    else: feedback.append("- Ajoutez des chiffres")
    
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", mdp): score += 1
    else: feedback.append("- Ajoutez des caractères spéciaux")

    # Critère 3 : Motifs faibles [cite: 26]
    motifs_interdits = ["123", "password", "qwerty", "admin"]
    if any(motif in mdp.lower() for motif in motifs_interdits):
        score = max(0, score - 2)
        feedback.append("- Contient un motif trop simple (ex: 123)")

    # Résultat attendu [cite: 28]
    if score >= 4:
        niveau = "FORT"
    elif score >= 2:
        niveau = "MOYEN"
    else:
        niveau = "FAIBLE"
        
    return niveau, feedback
