import json
from datetime import datetime
from collections import defaultdict

# IP du serveur AWS (on exclut des résultats)
OWN_IP = "51.44.84.225"

def load_logs(filepath):
    """Charge les logs JSON Cowrie (format NDJSON - une entrée par ligne)"""
    events = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events

def filter_external(events):
    """Filtre les événements provenant d'IPs externes uniquement"""
    return [e for e in events if e.get("src_ip") != OWN_IP]

def extract_connections(events):
    """Extrait les connexions par session"""
    sessions = defaultdict(list)
    for event in events:
        session_id = event.get("session")
        if session_id:
            sessions[session_id].append(event)
    return sessions

def extract_login_attempts(events):
    """Extrait les tentatives de login (succès simulés par Cowrie)"""
    logins = []
    for event in events:
        if event.get("eventid") == "cowrie.login.success":
            logins.append({
                "ip": event.get("src_ip"),
                "username": event.get("username"),
                "password": event.get("password"),
                "timestamp": event.get("timestamp"),
                "session": event.get("session")
            })
    return logins

def extract_commands(events):
    """Extrait les commandes exécutées par les attaquants"""
    commands = []
    for event in events:
        if event.get("eventid") == "cowrie.command.input":
            commands.append({
                "ip": event.get("src_ip"),
                "command": event.get("input"),
                "timestamp": event.get("timestamp"),
                "session": event.get("session")
            })
    return commands

def print_report(events):
    """Affiche un rapport lisible dans le terminal"""
    external = filter_external(events)
    sessions = extract_connections(external)
    logins = extract_login_attempts(external)
    commands = extract_commands(external)

    print("=" * 50)
    print("  RAPPORT HONEYPOT COWRIE - threathunter-lab")
    print("=" * 50)

    print(f"\n[+] Événements totaux          : {len(events)}")
    print(f"[+] Événements externes         : {len(external)}")
    print(f"[+] Sessions externes           : {len(sessions)}")
    print(f"[+] Tentatives de login         : {len(logins)}")
    print(f"[+] Commandes exécutées         : {len(commands)}")

    if sessions:
        print("\n--- Sessions externes détectées ---")
        for session_id, session_events in sessions.items():
            ip = session_events[0].get("src_ip", "unknown")
            start = session_events[0].get("timestamp", "unknown")
            # Cherche la durée dans l'événement session.closed
            duration = "inconnue"
            for e in session_events:
                if e.get("eventid") == "cowrie.session.closed":
                    duration = f"{e.get('duration')}s"
            print(f"\n  Session : {session_id}")
            print(f"  IP source : {ip}")
            print(f"  Début     : {start}")
            print(f"  Durée     : {duration}")

    if logins:
        print("\n--- Tentatives de login ---")
        for login in logins:
            print(f"\n  IP       : {login['ip']}")
            print(f"  User     : {login['username']}")
            print(f"  Password : {login['password']}")
            print(f"  Horodatage : {login['timestamp']}")

    if commands:
        print("\n--- Commandes exécutées ---")
        for cmd in commands:
            print(f"\n  IP      : {cmd['ip']}")
            print(f"  Commande: {cmd['command']}")
            print(f"  Horodatage : {cmd['timestamp']}")

    print("\n" + "=" * 50)

# Point d'entrée
if __name__ == "__main__":
    logs = load_logs("data/cowrie.json")
    print_report(logs)
