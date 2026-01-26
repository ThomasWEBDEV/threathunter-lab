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
