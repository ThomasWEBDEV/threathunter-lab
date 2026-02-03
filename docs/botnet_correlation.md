# Corrélation des botnets

## Méthodologie

On cherche les IPs qui font **exactement les mêmes actions**. Si 3 IPs testent les mêmes 50 mots de passe dans le même ordre, c'est qu'elles sont contrôlées par le même programme.

Deux types de corrélation :
1. **Par credentials** — IPs qui testent les mêmes combinaisons user:password
2. **Par commandes** — IPs qui exécutent les mêmes commandes après login

## Résultats

### Botnet détecté : Credential Botnet #1

**IPs membres :**
- 34.90.47.28 (Pays-Bas)
- 91.92.241.59 (Pays-Bas)

**Comportement commun :**
- Credential testé : `root:` (root avec mot de passe vide)
- Les deux IPs testent exactement le même credential
- Espacées de quelques heures seulement

**Analyse :**

Ces deux IPs font partie du même scanner automatisé. Elles testent si le serveur accepte un login root sans mot de passe — une mauvaise config très courante. Le fait qu'elles viennent toutes les deux des Pays-Bas confirme qu'elles sont probablement hébergées chez le même cloud provider (DigitalOcean Amsterdam).

**Type d'attaque :** Scanner basique de type "low-hanging fruit" — cherche les serveurs mal configurés.

---

## IPs isolées — Pas de corrélation

**172.105.19.132 (Canada - Linode)**
- 60 credentials testés
- Tous spécifiques à des distros (vagrant, osboxes.org, freenas)
- **Conclusion :** Scanner sophistiqué indépendant, pas un botnet

**113.240.110.0 (Chine) — WORM**
- Aucun credential — login direct avec ubuntu:ubuntu
- Commandes complexes de propagation
- **Conclusion :** Fait partie d'un botnet WORM, mais on n'a capturé qu'un seul nœud

**104.248.88.200 (Pays-Bas)**
- Credentials : 1, 12, 123
- Pattern de brute-force incrémental
- **Conclusion :** Bot indépendant

---

## Statistiques

| Métrique | Valeur |
|---|---|
| Total IPs uniques | 19 |
| IPs avec tentatives login | 5 |
| IPs avec commandes | 4 |
| Botnets credentials | 1 (2 IPs) |
| Botnets commandes | 0 |

---

## Pourquoi si peu de corrélation ?

La majorité des IPs (14/19) sont des **scanners passifs** qui :
- Se connectent
- Ne tentent aucun login
- Repartent immédiatement (timeout ou scan de port)

Seulement 5 IPs ont réellement essayé de se connecter. Sur ces 5, la plupart utilisent des stratégies différentes. C'est normal — il n'y a pas un seul gros botnet, mais plein de petits bots indépendants qui scannent Internet en permanence.

---

## Implications pour la défense

### 1. Ne pas bloquer par IP uniquement

Le botnet qu'on a détecté utilise déjà 2 IPs différentes. Demain il en utilisera 10 autres. Bloquer les IPs une par une ne sert à rien.

### 2. Bloquer par pattern

Au lieu de bloquer `34.90.47.28`, on bloque "toute IP qui teste root avec mot de passe vide". Comme ça on attrape tout le botnet d'un coup.

### 3. Corrélation = Threat Intelligence

En partageant ces infos avec d'autres entreprises, on peut identifier les botnets actifs au niveau mondial. Si 100 entreprises voient les mêmes 2 IPs avec le même comportement, on confirme que c'est un botnet.

---

## Conclusion

On a détecté 1 botnet actif (2 IPs néerlandaises testant root:) et plusieurs attaquants indépendants. La faible corrélation est normale pour un honeypot exposé quelques jours seulement — les gros botnets coordonnés mettent des semaines à apparaître.

Les IPs les plus dangereuses (WORM chinois, scanner Linode) opèrent seules et ne font pas partie de botnets massifs — elles sont plus sophistiquées.
