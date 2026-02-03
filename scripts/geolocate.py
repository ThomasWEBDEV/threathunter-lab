import json
import requests
import time
from collections import Counter

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

def get_unique_ips(events):
    ips = set()
    for e in events:
        ip = e.get("src_ip")
        if ip:
            ips.add(ip)
    return list(ips)

def geolocate_ip(ip):
    """Utilise ip-api.com (gratuit, 45 req/min)"""
    try:
        url = f"http://ip-api.com/json/{ip}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "??"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "org": data.get("isp", "Unknown")
                }
        return {"ip": ip, "country": "Unknown", "country_code": "??"}
    except Exception as e:
        print(f"Erreur: {e}")
        return {"ip": ip, "country": "Unknown", "country_code": "??"}

# --- MAIN ---
events = load_logs()
unique_ips = get_unique_ips(events)

print(f"[+] {len(unique_ips)} IPs uniques à géolocaliser")
print("[+] Récupération des données...\n")

geo_data = []
for i, ip in enumerate(unique_ips, 1):
    print(f"[{i}/{len(unique_ips)}] {ip}...", end=" ")
    info = geolocate_ip(ip)
    geo_data.append(info)
    print(f"{info['country_code']} - {info['country']}")
    time.sleep(1.5)  # 45 req/min = 1.5s entre chaque

# Sauvegarde
with open("data/geolocations.json", "w") as f:
    json.dump(geo_data, f, indent=2)

print(f"\n[+] Données sauvegardées : data/geolocations.json")

# Stats par pays
countries = Counter(g["country"] for g in geo_data if g["country"] != "Unknown")
print("\n=== TOP 10 PAYS ATTAQUANTS ===")
for country, count in countries.most_common(10):
    print(f"  {country:25} : {count} IPs")
