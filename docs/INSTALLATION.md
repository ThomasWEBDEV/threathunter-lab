# Installation du Honeypot Cowrie - web-server-02

## Infrastructure

- **Provider :** AWS EC2
- **Instance :** web-server-02
- **Type :** t3.micro (Free Tier)
- **OS :** Ubuntu 24.04 LTS
- **Région :** eu-north-1 (Stockholm)
- **IP publique :** 51.44.84.225

## Ports configurés

| Port | Service | Rôle |
|------|---------|------|
| 22 | Cowrie (twistd) | Honeypot SSH |
| 2222 | sshd | Admin SSH (clé uniquement) |

## Sécurité

- SSH admin sur port 2222 (clé RSA uniquement)
- Fail2ban activé (bloque après 3 tentatives)
- Cowrie simule un faux serveur Linux
- Aucune commande ne s'exécute vraiment sur le honeypot

## Script d'installation

Tout installé via un seul script bash :

1. Mise à jour système (apt update/upgrade)
2. Dépendances (git, python3, pip, authbind)
3. Utilisateur cowrie créé
4. Cowrie cloné depuis GitHub
5. Environnement virtuel Python configuré
6. cowrie_plugin.py modifié (port 22)
7. systemd socket désactivé
8. authbind configuré pour port 22
9. Fail2ban installé et activé

## Démarrage Cowrie
```bash
sudo -u cowrie bash -c "cd /home/cowrie/cowrie && authbind --deep cowrie-env/bin/twistd --umask=0022 --pidfile var/run/cowrie.pid --logger cowrie.python.logfile.logger cowrie"
```

## Connexion admin
```bash
ssh -i ~/.ssh/web-server-02-key.pem -p 2222 ubuntu@51.44.84.225
```

## Vérification
```bash
# Cowrie tourne ?
sudo ss -tlnp | grep 22

# Logs en temps réel
sudo -u cowrie tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log
```

## Statut

- [x] Serveur AWS créé
- [x] Cowrie installé et fonctionnel
- [x] Honeypot sur port 22
- [x] SSH admin sur port 2222
- [x] Fail2ban activé
- [ ] Collecte de données (en cours 24/7)
- [ ] Scripts Python d'analyse
- [ ] Rapport final
