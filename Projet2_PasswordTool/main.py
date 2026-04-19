import sys
from generator import generer_mot_de_passe
from checker import valider_complexite_iso27001, PasswordPolicyError, evaluer_robustesse
from utils import log_evenement, sauvegarder_empreinte

def afficher_header() -> None:
    print("\n" + "="*45)
    print("🛡️  SECURE PASS TOOL - AUDIT & COMPLIANCE")
    print("="*45)

def executer_outil() -> None:
    log_evenement("Démarrage de l'application par l'utilisateur.")
    afficher_header()

    while True:
        print("\n1. Générer un mot de passe (Conforme ISO 27001)")
        print("2. Analyser la robustesse d'un mot de passe")
        print("3. Quitter")
        
        choix = input("\nAction requise > ")

        try:
            if choix == "1":
                try:
                    long = int(input("Longueur souhaitée (min 12) : "))
                    # Génération
                    mdp = generer_mot_de_passe(longueur=long)
                    print(f"\n Mot de passe généré : {mdp}")
                    
                    # Validation immédiate par la politique métier
                    valider_complexite_iso27001(mdp)
                    log_evenement(f"Succès : MDP généré et conforme (longueur: {long}).")
                    
                    # Option de sauvegarde (Hachage)
                    sauver = input("Sauvegarder l'empreinte pour l'audit ? (o/n) : ")
                    if sauver.lower() == 'o':
                        sauvegarder_empreinte(mdp)
                except ValueError:
                    print("!!!Erreur : La longueur doit être un nombre entier.")
                except PasswordPolicyError as e:
                    print(f"!!!Alerte Politique : {e}")

            elif choix == "2":
                mdp_test = input("Entrez le mot de passe à tester : ")
                # 1. Évaluation pédagogique
                niveau, conseils = evaluer_robustesse(mdp_test)
                print(f"\n~Diagnostic : Niveau {niveau}")
                for c in conseils:
                    print(f"   - {c}")
                
                # 2. Validation stricte ISO 27001
                try:
                    valider_complexite_iso27001(mdp_test)
                    print("Statut : CONFORME .")
                    log_evenement("Test de conformité ISO 27001 réussi.")
                except PasswordPolicyError as e:
                    print(f"Statut : NON-CONFORME ({e})")
                    log_evenement(f"Échec de conformité détecté : {e}")

            elif choix == "3":
                log_evenement("Fermeture sécurisée de l'application.")
                print("\nSession terminée. Rapport d'audit disponible dans audit_securite.log")
                sys.exit(0)

            else:
                print(" Option invalide.")

        except Exception as e:
            log_evenement(f"Erreur système critique : {str(e)}")
            print(f" Une erreur inattendue est survenue : {e}")

if __name__ == "__main__":
    executer_outil()
