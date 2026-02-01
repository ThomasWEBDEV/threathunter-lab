import json
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
from collections import defaultdict, Counter

# --- Config ---
LOG_FILE = "data/cowrie.json"
OWN_IP = "51.44.84.225"

# Couleurs par IP
COLORS = {
    "66.116.205.1":    "#e74c3c",  # rouge - worm
    "64.225.65.182":   "#3498db",  # bleu - brute-force
    "161.35.156.145":  "#2ecc71",  # vert - brute-force
    "165.232.83.65":   "#9b59b6",  # violet - brute-force
    "205.210.31.153":  "#f39c12",  # orange - scanner
    "36.95.238.13":    "#1abc9c",  # cyan - scanner
    "54.144.193.250":  "#e67e22",  # orange sombre - scanner rapide
    "35.180.112.84":   "#95a5a6",  # gris - scanner rapide
}

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

def parse_ts(ts_str):
    """Parse le timestamp ISO en datetime"""
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

def get_sessions(events):
    """Retourne liste de sessions avec IP, début, durée"""
    sessions = defaultdict(dict)
    for e in events:
        sid = e.get("session")
        if not sid:
            continue
        if "ip" not in sessions[sid]:
            sessions[sid]["ip"] = e.get("src_ip")
            sessions[sid]["start"] = parse_ts(e["timestamp"])
        if e.get("eventid") == "cowrie.session.closed":
            sessions[sid]["duration"] = float(e.get("duration", 0))
    # Filtre sessions sans durée
    return {k: v for k, v in sessions.items() if "duration" in v}

def get_logins(events):
    return [e for e in events if e.get("eventid") == "cowrie.login.success"]

def get_commands(events):
    return [e for e in events if e.get("eventid") == "cowrie.command.input"]

# --- MAIN ---
events = load_logs()
sessions = get_sessions(events)
logins = get_logins(events)
commands = get_commands(events)

fig, axes = plt.subplots(2, 2, figsize=(16, 10))
fig.suptitle("Honeypot Cowrie — Analyse des Attaques", fontsize=16, fontweight="bold", y=1.02)
fig.patch.set_facecolor("#1e1e2e")
for ax in axes.flat:
    ax.set_facecolor("#2a2a3e")
    ax.tick_params(colors="white")
    ax.title.set_color("white")
    ax.xaxis.label.set_color("white")
    ax.yaxis.label.set_color("white")
    for spine in ax.spines.values():
        spine.set_color("#444")

# =============================================
# 1. TIMELINE des sessions (haut gauche)
# =============================================
ax = axes[0, 0]
ax.set_title("Timeline des Sessions", fontsize=13, pad=10)

ip_order = sorted(set(s["ip"] for s in sessions.values()))
y_map = {ip: i for i, ip in enumerate(ip_order)}

for sid, s in sessions.items():
    ip = s["ip"]
    start = s["start"]
    dur = s["duration"]
    color = COLORS.get(ip, "#ccc")
    # Largeur minimale pour être visible même si dur=0
    width = max(dur, 3)
    ax.barh(
        y=y_map[ip],
        width=width,
        left=mdates.date2num(start),
        height=0.4,
        color=color,
        edgecolor="#000",
        linewidth=0.5,
        alpha=0.85
    )

ax.set_yticks(range(len(ip_order)))
ax.set_yticklabels(ip_order, fontsize=9, color="white")
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=30))
# Borne l'axe X sur les données réelles
all_starts = [mdates.date2num(s["start"]) for s in sessions.values()]
ax.set_xlim(min(all_starts) - 0.02, max(all_starts) + 0.02)
ax.set_xlabel("Heure (UTC)", fontsize=10)
plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha="right")

# =============================================
# 2. Nombre de sessions par IP (haut droite)
# =============================================
ax = axes[0, 1]
ax.set_title("Sessions par IP", fontsize=13, pad=10)

ip_counts = Counter(s["ip"] for s in sessions.values())
ips = list(ip_counts.keys())
counts = list(ip_counts.values())
colors = [COLORS.get(ip, "#ccc") for ip in ips]

bars = ax.barh(ips, counts, color=colors, edgecolor="#000", linewidth=0.5, height=0.5)
ax.set_xlabel("Nombre de sessions", fontsize=10)

# Labels sur les barres
for bar, count in zip(bars, counts):
    ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
            str(count), va="center", color="white", fontsize=10, fontweight="bold")

ax.set_xlim(0, max(counts) + 1.5)
ax.tick_params(axis="y", labelsize=9)

# =============================================
# 3. Top credentials testés (bas gauche)
# =============================================
ax = axes[1, 0]
ax.set_title("Credentials les plus utilisés", fontsize=13, pad=10)

cred_counter = Counter(e.get("password", "") for e in logins)
top_creds = cred_counter.most_common(8)
labels = [c[0] for c in top_creds]
values = [c[1] for c in top_creds]

# Gradient de couleurs
cmap = plt.cm.plasma
cred_colors = [cmap(i / len(labels)) for i in range(len(labels))]

bars = ax.barh(labels, values, color=cred_colors, edgecolor="#000", linewidth=0.5, height=0.5)
ax.set_xlabel("Nombre d'utilisations", fontsize=10)

for bar, val in zip(bars, values):
    ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height()/2,
            str(val), va="center", color="white", fontsize=10, fontweight="bold")

ax.set_xlim(0, max(values) + 0.8)
ax.tick_params(axis="y", labelsize=10)
ax.invert_yaxis()

# =============================================
# 4. Durées de session par IP (bas droite)
# =============================================
ax = axes[1, 1]
ax.set_title("Durée des Sessions par IP", fontsize=13, pad=10)

# Regroupe les durées par IP
dur_by_ip = defaultdict(list)
for s in sessions.values():
    dur_by_ip[s["ip"]].append(s["duration"])

# Tri par durée max décroissante
sorted_ips = sorted(dur_by_ip.keys(), key=lambda ip: max(dur_by_ip[ip]), reverse=True)

for i, ip in enumerate(sorted_ips):
    durations = dur_by_ip[ip]
    color = COLORS.get(ip, "#ccc")
    ax.scatter(durations, [i]*len(durations), color=color, s=80, edgecolors="#000", linewidth=0.8, zorder=3)
    # Ligne horizontale légère
    ax.axhline(y=i, color="#333", linewidth=0.5, zorder=1)

ax.set_yticks(range(len(sorted_ips)))
ax.set_yticklabels(sorted_ips, fontsize=9, color="white")
ax.set_xlabel("Durée (secondes)", fontsize=10)
ax.set_xlim(-10, max(max(dur_by_ip[ip]) for ip in dur_by_ip) + 20)

# Annotation sur le point le plus haut (worm)
max_ip = sorted_ips[0]
max_dur = max(dur_by_ip[max_ip])
ax.annotate("← WORM (222s)", xy=(max_dur, 0), xytext=(max_dur - 60, 0.7),
            color="#e74c3c", fontsize=9, fontweight="bold",
            arrowprops=dict(arrowstyle="->", color="#e74c3c", lw=1.5))

# =============================================
plt.tight_layout(rect=[0, 0, 1, 0.93])
plt.savefig("output/cowrie_dashboard.png", dpi=150, facecolor=fig.get_facecolor(), bbox_inches="tight", pad_inches=0.5)
print("[+] Dashboard sauvegardé : output/cowrie_dashboard.png")
# plt.show()
