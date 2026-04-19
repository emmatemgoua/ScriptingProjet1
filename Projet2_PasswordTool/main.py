# main.py
from generator import generer_mot_de_passe
from checker import verifier_complexite

def afficher_menu():
    print("\n" + "="*30)
    print("  GESTIONNAIRE DE SÉCURITÉ")
    print("="*30)
    print("1. Générer un mot de passe")
    print("2. Tester la complexité")
    print("3. Quitter")
    return input("\nChoix : ")

def executer():
    while True:
        choix = afficher_menu()
        
        if choix == "1":
            try:
                long = int(input("Longueur (8-20) : "))
                mdp = generer_mot_de_passe(longueur=long)
                print(f"\nMot de passe généré : {mdp}")
            except ValueError:
                print("Erreur : Veuillez entrer un nombre valide.")
                
        elif choix == "2":
            mdp_a_tester = input("Entrez le mot de passe à tester : ")
            niveau, conseils = verifier_complexite(mdp_a_tester)
            print(f"\nRésultat : {niveau}")
            for c in conseils:
                print(c)
                
        elif choix == "3":
            print("Au revoir !")
            break
        else:
            print("Option invalide.")

if __name__ == "__main__":
    executer()
