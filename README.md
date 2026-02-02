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
│   └── cowrie.json            # Logs bruts du honeypot (233 événements)
├── scripts/
│   ├── parser.py              # Parse les logs JSON → rapport terminal
│   └── visualize.py           # Génère le dashboard matplotlib (4 graphiques)
├── output/
│   └── cowrie_dashboard.png   # Dashboard visuel des attaques
├── screenshots/
│   ├── honeypot1.jpg          # Dashboard v1 (première version)
│   └── honeypoy2.jpg          # Dashboard v2 (version détaillée finale)
└── README.md                  # Ce fichier
```

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

# Lancer la visualisation (génère le dashboard)
python3 scripts/visualize.py

# Ouvrir le dashboard
xdg-open output/cowrie_dashboard.png
```

---

## Dashboard — Ce que montre chaque graphique

### 1. Timeline des Sessions SSH (haut gauche)
Chaque ligne = une IP. Chaque barre = une session avec l'heure exacte affichée dessus.
Les barres courtes = scanners ou brute-forceurs qui partent vite.
La barre rouge (66.116.205.1) = le WORM qui reste longtemps pour uploader son malware.

### 2. Nombre de Sessions par IP (haut droite)
Compte combien de fois chaque IP s'est reconnectée.
Plus de sessions = plus de tentatives de mot de passe.
Le WORM n'a eu besoin qu'une seule session pour faire son coup.

### 3. Mots de passe les plus testés (bas gauche)
Les credentials les plus utilisés par les attaquants, avec les IPs sources à droite de chaque barre.
`password` et `admin` = les classiques testés en premier par tous les bots.

### 4. Durée des Sessions par IP (bas droite)
Chaque point = une session avec sa durée exacte en secondes.
Tous les points à gauche (0-9s) = scanners et brute-forceurs rapides.
Le point rouge en haut à droite = le WORM à 222s, annoté avec une explication.

### Légende globale (en bas)
Toutes les IPs avec leur couleur et leur type d'attaque. On peut tout identifier d'un coup d'œil.

---

## Attaques détectées (journée du 01/02/2026)

### 1. Scanners — Reconnaissance passive
IPs : 36.95.238.13, 54.144.193.250, 205.210.31.153, 35.180.112.84

Ces machines testent juste si le port SSH est ouvert. Elles se connectent rapidement et repartent sans essayer de se loger. Comme un cambrioleur qui teste les poignées de porte.

- Aucun login tenté
- Durée de session : 0 à 9 secondes
- Aucun danger réel

### 2. Brute-force automatisé — Tentatives de mot de passe
IPs : 64.225.65.182, 161.35.156.145, 165.232.83.65

Un même botnet opère depuis 3 IPs différentes. Il teste automatiquement des mots de passe très courants sur des dizaines de machines en parallèle.

Credentials testés : password, admin, 12345, qwerty, 12345678, 123456789, 1234, password1

Après un login "réussi" (Cowrie fait semblant d'accepter), le botnet lance une grande commande de reconnaissance :
- Détecte l'architecture CPU/GPU via uname, /proc/cpuinfo, lspci
- Vérifie le nombre de processeurs
- Analyse le système pour décider quel payload déployer (cryptominer sur GPU, etc.)

Client utilisé : SSH-2.0-Go — un outil de scanning écrit en Go, très rapide.

- 22 sessions en tout sur les 3 IPs
- Sessions très courtes (0 à 2.7 secondes)

### 3. WORM — Attaque la plus sérieuse
IP : 66.116.205.1

C'est l'attaque la plus avancée capturée. Déroulement étape par étape :

1. Login avec root / ubuntu — Cowrie accepte (faux)
2. Upload SFTP d'un fichier malveillant déguisé en sshd (le processus SSH normal)
3. Exécution du malware avec une liste de 50 IPs cibles :
```
chmod +x ./.274911462705534352/sshd
nohup ./.274911462705534352/sshd [50 IPs cibles] &
```
4. Le malware essaie de se propager automatiquement vers ces 50 autres machines. C'est la définition d'un worm : un programme qui se réplique seul.

Malware capturé :
```
SHA256: 94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00
Emplacement serveur: /var/lib/cowrie/downloads/
```

- Durée session : 222 secondes (la plus longue de la journée)
- Fichier malveillant archivé pour analyse ultérieure

---

## Statistiques

| Métrique | Valeur |
|---|---|
| Événements totaux | 233 |
| IPs externes distinctes | 8 |
| Sessions externes | 28 |
| Tentatives de login | 15 |
| Commandes exécutées | 57 |
| Malwares capturés | 1 |

---

## Prochaines étapes

- Analyser le malware capturé (hash SHA256)
- Apprendre à contrer ces attaques (fail2ban, clés SSH uniquement, etc.)
- Attendre de nouvelles attaques et mettre à jour l'analyse
- Rapport final du projet

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
