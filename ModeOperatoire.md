Documentation Technique : Scanner de Ports Python (Projet N°1)

 1. Présentation Générale
Ce projet consiste en la création dun outil de diagnostic réseau permettant didentifier les ports ouverts sur une machine cible. Il est conçu pour aider à détecter les services exposés et anticiper les vulnérabilités dans un cadre professionnel de cybersécurité.

 2. Étapes de Réalisation du Projet
Le développement a suivi une approche méthodologique pour garantir la robustesse et la modularité du code :

1.  Analyse du besoin : Étude du cahier des charges pour définir les spécifications (IP cible, plage de ports, gestion des erreurs).
2.  Conception de larchitecture : Répartition du code en quatre modules distincts (`main`, `scanner`, `utils`, `grapher`) pour assurer une meilleure maintenance.
3.  Développement des fonctions utilitaires : Création dans `utils.py` des algorithmes de validation dadresse IP et de parsing des entrées utilisateur pour sécuriser le script.
4.  Implémentation du moteur de scan : Utilisation du module `socket` dans `scanner.py` pour gérer les tentatives de connexion TCP et identifier létat des ports.
5.  Gestion de la robustesse : Intégration de blocs `try...except` pour gérer les interruptions (Ctrl+C) et les erreurs réseau.
6.  Simulation et temporisation : Ajout de pauses via `time.sleep()` entre chaque scan pour simuler un comportement réaliste.
7.  Tests et validation : Vérification du bon fonctionnement sur des machines locales et des environnements de test autorisés.

 3. Architecture du Projet
 `main.py` : Orchestration globale et interface utilisateur.
 `scanner.py` : Logique technique du scan des ports.
 `utils.py` : Fonctions de validation et de traitement des données.
 `grapher.py` : Module complémentaire pour la visualisation des résultats.

 4. Mode Opératoire
 Utilisation
1.  Exécuter le fichier principal : `python main.py`.
2.  Saisir ladresse IP de la cible à analyser.
3.  Indiquer la plage de ports (exemple : 20-100).
4.  Consulter la liste des ports identifiés comme "ouverts".

 Choix Techniques
 Langage : Python 3 pour sa lisibilité et ses bibliothèques réseau natives.
 Modules standards : `socket` pour la communication réseau, `sys` pour les paramètres système, et `time` pour la gestion des délais.

 5. Cadre Éthique
Lutilisation de ce script est strictement réservée à un usage pédagogique ou professionnel autorisé. Le scan de systèmes tiers sans autorisation explicite est formellement interdit.

