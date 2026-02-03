# Rapport final — Projet threathunter-lab

## Vue d'ensemble du projet

**Objectif :** Déployer un honeypot SSH sur Internet et analyser les attaques réelles captées en conditions réelles.

**Durée :** 2 jours (01/02/2026 - 03/02/2026)

**Résultat :** 1056 événements capturés, 19 IPs uniques, 2 WORM détectés, 1 malware analysé

---

## Infrastructure technique

### Serveur de production
- Cloud : AWS EC2 (Ubuntu 24.04)
- IP publique : 51.44.84.225
- Région : eu-west-3 (Paris)

### Services déployés
- **Port 22** : Cowrie honeypot (piège SSH)
- **Port 2222** : SSH admin sécurisé (clé uniquement)

### Sécurisation
- fail2ban configuré sur port 2222
- PasswordAuthentication désactivé
- PermitRootLogin désactivé
- Groupe de sécurité AWS restreint

---

## Attaques capturées — Résumé chiffré

| Métrique | Valeur |
|---|---|
| Événements totaux | 1056 |
| Sessions SSH | 187 |
| IPs uniques | 19 |
| Pays d'origine | 8 |
| Tentatives de login | 63 |
| Commandes exécutées | 73 |
| Malwares capturés | 1 (30 Mo) |
| WORM détectés | 2 |

---

## Chronologie des attaques majeures

### 01/02/2026 — WORM #1 (66.116.205.1)
- **18:58 UTC** : Connexion réussie avec ubuntu:ubuntu
- **Durée** : 222 secondes
- **Action** : Upload malware via SFTP
- **Propagation** : Vers 50 IPs cibles
- **Hash** : 94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00

### 03/02/2026 — WORM #2 (113.240.110.0 - Chine)
- **08:18 UTC** : Connexion réussie
- **Durée** : 227 secondes
- **Action** : Même malware, même comportement
- **Origine** : IP résidentielle chinoise

### 03/02/2026 — Brute-force massif (172.105.19.132 - Canada)
- **10:26-10:29 UTC** : 100+ sessions en 3 minutes
- **Credentials** : 60 mots de passe spécifiques (vagrant, freenas, osboxes.org...)
- **Type** : Scanner sophistiqué ciblant des distros spécifiques

---

## Analyse du malware

### Identité
- Type : ELF 64-bit, dynamically linked, stripped
- Langage : Go (Golang)
- Taille : 30 Mo
- Projet source : `panchansminingisland/rootkit.go`

### Fonctionnalités
1. **Propagation P2P** — communication peer-to-peer sans serveur central
2. **Brute-force SSH** — fonction `sshtry` teste des credentials
3. **Upload SFTP** — déploie une copie de lui-même
4. **Reconnaissance système** — collecte CPU, mémoire via gopsutil
5. **Dissimulation** — se renomme `sshd` pour se fondre dans les processus

### Objectif final
Cryptomining — le nom "panchansminingisland" indique que le malware utilise les machines infectées pour miner de la crypto-monnaie (probablement Monero).

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

**Observation clé :** La majorité des IPs (USA/Pays-Bas) sont des serveurs cloud loués ou compromis. Les vraies origines sont probablement en Asie et Europe de l'Est.

---

## Botnets identifiés

### Botnet Credentials #1
- **IPs** : 34.90.47.28, 91.92.241.59 (Pays-Bas)
- **Comportement** : Test de `root:` (mot de passe vide)
- **Type** : Scanner basique cherchant des serveurs mal configurés

Aucun autre botnet détecté — la plupart des attaquants opèrent indépendamment.

---

## Enseignements et bonnes pratiques

### Ce qui fonctionne pour se défendre

1. **Désactiver l'authentification par mot de passe**
   - Clés SSH uniquement
   - Empêche 100% du brute-force

2. **fail2ban**
   - Bloque automatiquement après 3 tentatives
   - Rate limiting efficace

3. **Port non-standard pour l'admin**
   - Port 2222 au lieu de 22
   - Réduit le bruit des scanners automatiques

4. **Monitoring actif**
   - Logs centralisés
   - Alertes sur comportements suspects

### Ce qui ne fonctionne PAS

1. ❌ Bloquer par pays — les attaquants changent de pays en 2 minutes
2. ❌ Bloquer IP par IP — les botnets ont des milliers d'IPs
3. ❌ Compter sur la "sécurité par l'obscurité" — les scanners trouvent tout

---

## Compétences démontrées

### Techniques
- Déploiement d'infrastructure cloud (AWS EC2)
- Configuration de services de sécurité (Cowrie, fail2ban)
- Analyse de logs au format JSON
- Reverse engineering de malware (analyse statique)
- Scripting Python (parsing, visualisation, corrélation)
- Géolocalisation d'IPs
- Corrélation de botnets

### Méthodologies
- Analyse d'incidents de sécurité
- Threat intelligence
- Documentation technique
- Versionnage Git
- Rapport d'analyse professionnel

---

## Outils utilisés

| Outil | Usage |
|---|---|
| AWS EC2 | Hébergement honeypot |
| Cowrie | Honeypot SSH |
| fail2ban | Protection brute-force |
| Python | Scripts d'analyse |
| matplotlib | Visualisation données |
| ip-api.com | Géolocalisation |
| strings | Analyse malware statique |
| Git/GitHub | Versionnage |

---

## Livrables du projet

1. ✅ Infrastructure honeypot déployée et sécurisée
2. ✅ 1056 événements capturés et analysés
3. ✅ Malware WORM analysé (rapport complet)
4. ✅ Dashboard visuel (4 graphiques)
5. ✅ Analyse géographique des attaques
6. ✅ Corrélation des botnets
7. ✅ Documentation complète (README + 4 rapports)
8. ✅ Code source versionnés (GitHub)

---

## Conclusion

En 48 heures, le honeypot a capturé 19 IPs distinctes originaires de 8 pays différents. Deux WORM SSH actifs ont été identifiés et un malware de 30 Mo a été analysé statiquement. L'analyse révèle que les attaques automatisées sur les serveurs SSH exposés sont constantes — même un serveur fraîchement déployé reçoit des tentatives de connexion en quelques heures.

Les techniques observées (brute-force, propagation WORM, cryptomining) sont représentatives des menaces réelles auxquelles les entreprises font face quotidiennement. La sécurisation mise en place (clés SSH, fail2ban, durcissement) démontre les bonnes pratiques essentielles pour protéger une infrastructure de production.

Ce projet illustre l'ensemble du cycle d'un analyste SOC : déploiement, monitoring, détection, analyse, documentation et remédiation.
