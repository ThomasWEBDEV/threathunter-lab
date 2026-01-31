# Installation du Honeypot Cowrie

## Infrastructure

- **Provider :** AWS EC2
- **Type instance :** t3.micro (Free Tier)
- **OS :** Ubuntu 24.04 LTS
- **Région :** eu-north-1 (Stockholm)
- **IP publique :** 13.60.183.154

## Étapes d'installation réalisées

### 1. Mise à jour du système
```bash
sudo apt update
sudo apt upgrade -y
```

### 2. Installation des dépendances
```bash
sudo apt install -y git python3-venv python3-pip libssl-dev libffi-dev build-essential
```

### 3. Création utilisateur dédié
```bash
sudo adduser --disabled-password --gecos "" cowrie
```

### 4. Téléchargement Cowrie
```bash
sudo -u cowrie git clone https://github.com/cowrie/cowrie /home/cowrie/cowrie
```

### 5. Environnement virtuel Python
```bash
sudo -u cowrie python3 -m venv /home/cowrie/cowrie/cowrie-env
sudo -u cowrie /home/cowrie/cowrie/cowrie-env/bin/pip install --upgrade pip
sudo -u cowrie /home/cowrie/cowrie/cowrie-env/bin/pip install -r /home/cowrie/cowrie/requirements.txt
sudo -u cowrie /home/cowrie/cowrie/cowrie-env/bin/pip install -e /home/cowrie/cowrie/
sudo -u cowrie /home/cowrie/cowrie/cowrie-env/bin/pip install twisted
```

### 6. Configuration Cowrie
```bash
sudo -u cowrie cp /home/cowrie/cowrie/etc/cowrie.cfg.dist /home/cowrie/cowrie/etc/cowrie.cfg
sudo -u cowrie sed -i 's/hostname = svr04/hostname = web-server-prod/' /home/cowrie/cowrie/etc/cowrie.cfg
sudo -u cowrie sed -i 's/#\[output_jsonlog\]/[output_jsonlog]/' /home/cowrie/cowrie/etc/cowrie.cfg
sudo -u cowrie sed -i '/\[output_jsonlog\]/,/^\[/ s/^#enabled = .*/enabled = true/' /home/cowrie/cowrie/etc/cowrie.cfg
```

### 7. Démarrage Cowrie
```bash
sudo -u cowrie bash -c "cd /home/cowrie/cowrie && cowrie-env/bin/twistd --umask=0022 --pidfile var/run/cowrie.pid --logger cowrie.python.logfile.logger cowrie"
```

**Vérification :**
```bash
sudo -u cowrie /home/cowrie/cowrie/cowrie-env/bin/cowrie status
```

**Résultat :** cowrie is running (PID: 18432)

## Prochaines étapes

- [ ] Ouvrir port 22 dans Security Group AWS
- [ ] Tester connexion SSH honeypot
- [ ] Monitoring logs temps réel
- [ ] Collecte données 7 jours
