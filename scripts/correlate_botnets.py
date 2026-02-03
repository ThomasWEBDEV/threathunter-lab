import json
from collections import defaultdict, Counter

LOG_FILE = "data/cowrie.json"
OWN_IP = "51.44.84.225"

def load_logs():
    events = []
    with open(LOG_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                e = json.loads(line)
                if e.get("src_ip") != OWN_IP:
                    events.append(e)
    return events

def get_credentials_by_ip(events):
    """Retourne {ip: [liste de credentials testés]}"""
    creds_by_ip = defaultdict(list)
    for e in events:
        if e.get("eventid") == "cowrie.login.success":
            ip = e.get("src_ip")
            user = e.get("username", "")
            pwd = e.get("password", "")
            cred = f"{user}:{pwd}"
            creds_by_ip[ip].append(cred)
    return creds_by_ip

def get_commands_by_ip(events):
    """Retourne {ip: [liste de commandes exécutées]}"""
    cmds_by_ip = defaultdict(list)
    for e in events:
        if e.get("eventid") == "cowrie.command.input":
            ip = e.get("src_ip")
            cmd = e.get("input", "").strip()
            if cmd:
                cmds_by_ip[ip].append(cmd)
    return cmds_by_ip

def find_identical_patterns(data_by_ip, pattern_name):
    """Trouve les IPs qui ont exactement les mêmes patterns"""
    # Convertit les listes en tuples pour pouvoir les comparer
    patterns = {}
    for ip, items in data_by_ip.items():
        if items:  # Ignore les IPs sans patterns
            pattern = tuple(sorted(set(items)))  # Pattern unique trié
            if pattern not in patterns:
                patterns[pattern] = []
            patterns[pattern].append(ip)
    
    # Trouve les patterns partagés par plusieurs IPs
    botnets = []
    for pattern, ips in patterns.items():
        if len(ips) > 1:  # Au moins 2 IPs
            botnets.append({
                "pattern": list(pattern),
                "ips": ips,
                "count": len(ips)
            })
    
    return botnets

# --- MAIN ---
print("="*60)
print("  CORRÉLATION DES BOTNETS")
print("="*60)

events = load_logs()

# 1. Corrélation par credentials
print("\n[1] Recherche de botnets par credentials identiques...\n")
creds_by_ip = get_credentials_by_ip(events)
creds_botnets = find_identical_patterns(creds_by_ip, "credentials")

if creds_botnets:
    for i, botnet in enumerate(creds_botnets, 1):
        print(f"--- BOTNET CREDENTIALS #{i} ---")
        print(f"IPs membres : {', '.join(botnet['ips'])}")
        print(f"Nombre d'IPs : {botnet['count']}")
        print(f"Credentials testés ({len(botnet['pattern'])}) :")
        for cred in botnet['pattern'][:10]:  # Affiche max 10
            print(f"  - {cred}")
        if len(botnet['pattern']) > 10:
            print(f"  ... et {len(botnet['pattern']) - 10} autres")
        print()
else:
    print("Aucun botnet détecté par credentials.\n")

# 2. Corrélation par commandes
print("[2] Recherche de botnets par commandes identiques...\n")
cmds_by_ip = get_commands_by_ip(events)
cmds_botnets = find_identical_patterns(cmds_by_ip, "commands")

if cmds_botnets:
    for i, botnet in enumerate(cmds_botnets, 1):
        print(f"--- BOTNET COMMANDES #{i} ---")
        print(f"IPs membres : {', '.join(botnet['ips'])}")
        print(f"Nombre d'IPs : {botnet['count']}")
        print(f"Commandes exécutées ({len(botnet['pattern'])}) :")
        for cmd in botnet['pattern']:
            # Tronque les commandes très longues
            if len(cmd) > 100:
                print(f"  - {cmd[:100]}... (tronqué)")
            else:
                print(f"  - {cmd}")
        print()
else:
    print("Aucun botnet détecté par commandes.\n")

# 3. Stats générales
print("[3] Statistiques générales\n")
total_ips = len(set(e.get("src_ip") for e in events))
ips_with_creds = len([ip for ip, creds in creds_by_ip.items() if creds])
ips_with_cmds = len([ip for ip, cmds in cmds_by_ip.items() if cmds])

print(f"Total IPs uniques : {total_ips}")
print(f"IPs ayant tenté un login : {ips_with_creds}")
print(f"IPs ayant exécuté des commandes : {ips_with_cmds}")
print(f"Botnets identifiés (credentials) : {len(creds_botnets)}")
print(f"Botnets identifiés (commandes) : {len(cmds_botnets)}")

# Sauvegarde
output = {
    "credentials_botnets": creds_botnets,
    "commands_botnets": cmds_botnets,
    "stats": {
        "total_ips": total_ips,
        "ips_with_credentials": ips_with_creds,
        "ips_with_commands": ips_with_cmds
    }
}

with open("data/botnet_correlation.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"\n[+] Résultats sauvegardés : data/botnet_correlation.json")
print("="*60)
