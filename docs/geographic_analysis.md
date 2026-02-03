# Analyse géographique des attaques

## Vue d'ensemble

Sur les 19 IPs uniques ayant attaqué notre honeypot, voici leur répartition géographique :

| Pays | Nombre d'IPs | % |
|---|---|---|
| États-Unis | 7 | 36.8% |
| Pays-Bas | 6 | 31.6% |
| Canada | 2 | 10.5% |
| Russie | 1 | 5.3% |
| Chine | 1 | 5.3% |
| Allemagne | 1 | 5.3% |
| Indonésie | 1 | 5.3% |

## Observations clés

### 1. Dominance des datacenters occidentaux

**États-Unis (7 IPs) et Pays-Bas (6 IPs) = 68% des attaques**

Ces pays ne sont pas les sources originales des attaques. Ce sont des hubs de cloud providers :
- USA : Amazon AWS, DigitalOcean, Linode
- Pays-Bas : DigitalOcean Amsterdam, Hetzner

Les attaquants louent ou compromettent des serveurs cloud bon marché pour lancer leurs attaques. Pourquoi ?
- Bande passante illimitée
- IPs "propres" pas encore blacklistées
- Facile de créer et détruire des serveurs rapidement
- Juridiquement compliqué à tracer

### 2. Les vraies origines suspectées

**Chine (113.240.110.0) — WORM #2**
- Attaque la plus longue : 227 secondes
- Upload de malware via SFTP
- Propagation automatique vers 50 IPs
- C'est probablement une machine résidentielle infectée en Chine

**Russie (5.101.64.6)**
- Scanner basique
- Connexion courte

**Indonésie (36.94.118.113)**
- Scanner avec timeout de 120s répété
- Comportement automatisé

### 3. Canada (2 IPs)

Les deux IPs canadiennes sont probablement aussi des serveurs cloud (DigitalOcean Toronto).

## Détails par IP notable

### IP la plus agressive : 172.105.19.132 (Canada - Linode)

- 100+ sessions en 3 minutes
- Brute-force très ciblé avec mots de passe spécifiques à des distros
- `vagrant`, `osboxes.org`, `freenas`, `rasplex`
- Ce n'est pas un bot générique — c'est un scanner spécialisé

### WORM chinois : 113.240.110.0

- Session unique de 227 secondes
- Upload malware SHA256:94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00
- Commande exécutée : propagation vers 50 nouvelles IPs
- Très certainement une machine compromise faisant partie d'un botnet

### Scanner Docker : 91.92.241.59 (Pays-Bas)

- Commande : `cat /proc/1/mounts` pour détecter si c'est un container
- Cherche spécifiquement des honeypots
- Plus sophistiqué que les autres scanners

## Conclusion

La géographie des attaques est trompeuse. Les IPs américaines et néerlandaises ne sont pas les attaquants réels — ce sont des serveurs cloud compromis ou loués. Les vraies origines sont probablement :
- Asie (Chine, Indonésie) pour les WORM
- Europe de l'Est (Russie) pour les scanners
- Partout ailleurs pour le reste, cachés derrière des VPN et des proxies

Les attaquants utilisent l'infrastructure cloud occidentale comme bouclier.
