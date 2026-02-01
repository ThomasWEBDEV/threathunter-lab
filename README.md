# ThreatHunter Lab

## Description

Projet de déploiement d'un honeypot SSH pour la collecte et l'analyse d'attaques réelles en environnement contrôlé. Ce projet démontre des compétences en sécurité défensive, threat intelligence et analyse de logs.

## Objectifs pédagogiques

- Déploiement d'infrastructure de sécurité (honeypot Cowrie)
- Collecte d'IoC (Indicators of Compromise) en conditions réelles
- Analyse approfondie de logs d'attaques
- Extraction de patterns et comportements malveillants
- Visualisation de données de sécurité
- Documentation technique professionnelle

## Architecture
```
Internet → Firewall → Honeypot SSH (Cowrie) → Logs → Analyse Python → Visualisations
```

## Structure du projet
```
threathunter-lab/
├── data/           # Logs bruts et données collectées
├── scripts/        # Scripts Python d'analyse
├── docs/           # Documentation et rapport final
└── README.md       # Ce fichier
```

## Statut du projet

EN COURS - Phase 1 : Configuration infrastructure

## Étape 2 — Analyse des logs

### Ce qui a été fait
- Connexion SSH admin sur le serveur (port 2222)
- Lecture et interprétation des logs Cowrie (`cowrie.log` et `cowrie.json`)
- Identification d'un scanner automatisé extérieur (IP `36.95.238.13`) sur 2 sessions
- Rapatriement des logs JSON en local dans `data/`
- Création du script `scripts/parser.py` qui :
  - Charge les logs au format NDJSON
  - Filtre les événements externes (exclut l'IP propre du serveur)
  - Extrait les sessions, tentatives de login et commandes
  - Affiche un rapport formaté dans le terminal

### Comment lancer le parser
```bash
python3 scripts/parser.py
```

### Résultats actuels
- 2 sessions externes détectées depuis l'IP `36.95.238.13`
- Comportement type d'un scanner automatisé : connexion sur le port 22, aucune commande exécutée, timeout après 120 secondes
- Le honeypot simule une connexion réussie pour piéger l'attaquant sans exposer de système réel

### Prochaines étapes
- Géolocalisation des IPs attaquantes
- Visualisations avec matplotlib
- Rapport final pour la candidature mastère
