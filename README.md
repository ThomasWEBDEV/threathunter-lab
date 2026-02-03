# threathunter-lab

Projet de déploiement et d'analyse d'un honeypot SSH pour la détection et l'étude d'attaques réelles sur Internet.

---

## Qu'est-ce que c'est ?

On déploie un serveur SSH volontairement exposé sur Internet (honeypot). Les attaquants ne savent pas que c'est un piège. Tout ce qu'ils font est enregistré, sans qu'ils puissent toucher à quoi que ce soit de réel. On analyse ensuite leurs comportements.

---

## Infrastructure

| Composant | Détail |
|---|---|
| Cloud | AWS EC2 (Ubuntu) |
| Honeypot | Cowrie SSH |
| Port exposé | 22 (honeypot — attire les attaquants) |
| Port admin | 2222 (SSH réel, protégé par groupe de sécurité AWS) |
| IP serveur | 51.44.84.225 |
| IP interne AWS | 172.31.15.59 |

---

## Structure du projet
```
threathunter-lab/
├── data/
│   ├── cowrie.json                # Logs bruts du honeypot (1056 événements)
│   ├── geolocations.json          # Données de géolocalisation des IPs
│   ├── botnet_correlation.json    # Résultats corrélation botnets
│   └── malware_worm.bin           # Malware capturé (30 Mo)
├── scripts/
│   ├── parser.py                  # Parse les logs JSON → rapport terminal
│   ├── visualize.py               # Génère le dashboard matplotlib
│   ├── geolocate.py               # Géolocalise les IPs attaquantes
│   └── correlate_botnets.py       # Corrèle les botnets par pattern
├── output/
│   └── cowrie_dashboard.png       # Dashboard visuel des attaques
├── screenshots/
│   ├── honeypot1.jpg              # Dashboard v1
│   ├── honeypoy2.jpg              # Dashboard v2
│   └── honeypot3.jpg              # Dashboard v3 (final)
├── docs/
│   ├── malware_analysis.md        # Analyse détaillée du malware WORM
│   ├── geographic_analysis.md     # Analyse géographique des attaques
│   ├── botnet_correlation.md      # Corrélation et identification des botnets
│   └── rapport_final.md           # Rapport de synthèse complet
└── README.md                      # Ce fichier
```

---

## Résultats — Chiffres clés

| Métrique | Valeur |
|---|---|
| Durée du projet | 2 jours (01-03 février 2026) |
| Événements capturés | 1056 |
| Sessions SSH | 187 |
| IPs uniques | 19 |
| Pays d'origine | 8 |
| Tentatives de login | 63 |
| Commandes exécutées | 73 |
| Malwares capturés | 1 (30 Mo) |
| WORM détectés | 2 |
| Botnets identifiés | 1 (2 IPs) |

---

## Commandes essentielles

### Connexion admin au serveur
```bash
ssh -i ~/.ssh/web-server-02-key.pem -p 2222 ubuntu@51.44.84.225
```

### Sur le serveur — voir les derniers logs
```bash
# Dernières attaques en temps réel
sudo tail -50 /home/cowrie/cowrie/var/log/cowrie/cowrie.log

# Suivre les logs en continu (Ctrl+C pour arrêter)
sudo tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log

# Nombre de lignes dans le log JSON
sudo wc -l /home/cowrie/cowrie/var/log/cowrie/cowrie.json

# Copier vers /tmp pour rapatrier
sudo cp /home/cowrie/cowrie/var/log/cowrie/cowrie.json /tmp/cowrie.json
sudo chmod 644 /tmp/cowrie.json
```

### En local — rapatrier et analyser
```bash
# Télécharger les logs depuis le serveur
scp -i ~/.ssh/web-server-02-key.pem -P 2222 ubuntu@51.44.84.225:/tmp/cowrie.json data/cowrie.json

# Vérifier le nombre de lignes
wc -l data/cowrie.json

# Lancer le parser (rapport texte terminal)
python3 scripts/parser.py

# Géolocaliser les IPs
python3 scripts/geolocate.py

# Corrélation des botnets
python3 scripts/correlate_botnets.py

# Générer le dashboard visuel
python3 scripts/visualize.py

# Ouvrir le dashboard
xdg-open output/cowrie_dashboard.png
```

---

## Dashboard — Visualisations

Le dashboard génère 4 graphiques :

1. **Timeline des Sessions SSH** — Vue chronologique de toutes les sessions par IP
2. **Top 15 IPs par nombre de sessions** — Les attaquants les plus actifs
3. **Top 10 mots de passe testés** — Les credentials les plus utilisés
4. **Durée des sessions par IP** — Identification des sessions anormalement longues (WORM)

---

## Attaques détectées

### 1. Scanners — Reconnaissance passive
IPs : 36.95.238.13, 54.144.193.250, 205.210.31.153, 35.180.112.84, 3.137.73.221, 198.235.24.6, 82.147.84.195, 82.147.84.55, 147.185.132.49

Ces machines testent juste si le port SSH est ouvert. Elles se connectent rapidement et repartent sans essayer de se loger.

### 2. Brute-force automatisé — Tentatives de mot de passe
IPs : 64.225.65.182, 161.35.156.145, 165.232.83.65, 167.71.67.121, 165.232.86.21, 174.138.6.172, 164.92.208.187, 134.122.52.74, 167.99.37.125, 104.248.88.200

Botnets qui testent automatiquement des mots de passe courants. Après un login "réussi", ils lancent des commandes de reconnaissance système pour décider quel payload déployer.

### 3. Brute-force ciblé — Scanner sophistiqué
IP : 172.105.19.132 (Canada - Linode)

100+ sessions en 3 minutes. Teste 60 credentials spécifiques à des distros : `vagrant`, `osboxes.org`, `freenas`, `rasplex`, `alpine`, `openmediavault`. Scanner très sophistiqué qui cible des environnements précis.

### 4. WORM — Attaques les plus sérieuses
IPs : 66.116.205.1, 113.240.110.0 (Chine)

Les deux ont uploadé le même malware (30 Mo) et tenté de se propager vers 50 autres machines chacun. Analyse complète disponible dans `docs/malware_analysis.md`.

**Malware capturé :**
- SHA256: 94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00
- Type: ELF 64-bit, Go (Golang)
- Comportement: SSH WORM P2P avec cryptomining
- Source: `panchansminingisland/rootkit.go`

---

## Répartition géographique

| Pays | IPs | % |
|---|---|---|
| États-Unis | 7 | 36.8% |
| Pays-Bas | 6 | 31.6% |
| Canada | 2 | 10.5% |
| Russie | 1 | 5.3% |
| Chine | 1 | 5.3% |
| Allemagne | 1 | 5.3% |
| Indonésie | 1 | 5.3% |

La majorité des IPs proviennent de datacenters cloud (USA/Pays-Bas). Les vraies origines sont probablement masquées.

---

## Sécurisation du serveur (fait le 02/02/2026)

### fail2ban
- Installé et configuré sur le port 2222 (SSH admin)
- 3 tentatives max sur 10 minutes → ban 1 heure
- Le honeypot (port 22) est volontairement laissé ouvert

### SSH admin durci
- Port : 2222
- PasswordAuthentication : non (clé uniquement)
- PermitRootLogin : non

---

## Compétences démontrées

- Déploiement infrastructure cloud (AWS)
- Configuration honeypot (Cowrie)
- Analyse de logs et threat intelligence
- Reverse engineering malware (analyse statique)
- Scripting Python (parsing, visualisation, corrélation)
- Géolocalisation et tracking d'attaquants
- Documentation technique professionnelle
- Versionnage Git

---

## Documentation complète

Tous les détails techniques sont disponibles dans le dossier `docs/` :
- `malware_analysis.md` — Analyse complète du WORM
- `geographic_analysis.md` — Répartition mondiale des attaques
- `botnet_correlation.md` — Identification des botnets
- `rapport_final.md` — Synthèse complète du projet
