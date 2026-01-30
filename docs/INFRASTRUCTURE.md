# Infrastructure du projet

## Serveur AWS EC2

- Provider: AWS Free Tier
- Type: t3.micro (1 vCPU, 1 GB RAM)
- OS: Ubuntu 24.04 LTS
- Région: eu-north-1 (Stockholm)
- IP publique: 13.60.183.154
- État: Opérationnel

## Connexion SSH
```bash
ssh -i ~/.ssh/web-server-key.pem ubuntu@13.60.183.154
```

## Prochaines étapes

- Installation Cowrie
- Configuration firewall
- Collecte de données
