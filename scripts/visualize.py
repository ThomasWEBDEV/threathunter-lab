import json
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
from datetime import datetime, timedelta
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

# Labels descriptifs par IP
LABELS = {
    "66.116.205.1":    "WORM",
    "64.225.65.182":   "Brute-force",
    "161.35.156.145":  "Brute-force",
    "165.232.83.65":   "Brute-force",
    "205.210.31.153":  "Scanner",
    "36.95.238.13":    "Scanner",
    "54.144.193.250":  "Scanner rapide",
    "35.180.112.84":   "Scanner rapide",
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
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

def get_sessions(events):
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

# Figure grande et claire
fig, axes = plt.subplots(2, 2, figsize=(22, 14))
fig.suptitle("🛡️  Honeypot Cowrie — Analyse des Attaques  |  01/02/2026",
             fontsize=20, fontweight="bold", color="white", y=0.98)
fig.patch.set_facecolor("#1a1a2e")

for ax in axes.flat:
    ax.set_facecolor("#16213e")
    ax.tick_params(colors="white", labelsize=10)
    ax.title.set_color("white")
    ax.xaxis.label.set_color("white")
    ax.yaxis.label.set_color("white")
    for spine in ax.spines.values():
        spine.set_color("#0f3460")

# =============================================
# 1. TIMELINE des sessions (haut gauche)
# =============================================
ax = axes[0, 0]
ax.set_title("⏱️  Timeline des Sessions SSH", fontsize=15, fontweight="bold", pad=12)

# Tri les IPs par heure de première connexion
ip_first = {}
for s in sessions.values():
    ip = s["ip"]
    if ip not in ip_first or s["start"] < ip_first[ip]:
        ip_first[ip] = s["start"]
ip_order = sorted(ip_first.keys(), key=lambda ip: ip_first[ip])
y_map = {ip: i for i, ip in enumerate(ip_order)}

for sid, s in sessions.items():
    ip = s["ip"]
    start = s["start"]
    dur = s["duration"]
    color = COLORS.get(ip, "#ccc")
    # Conversion durée en jours pour l'axe X (matplotlib utilise des jours)
    width_days = max(dur, 60) / 86400  # minimum 60s pour être visible
    ax.barh(
        y=y_map[ip],
        width=width_days,
        left=mdates.date2num(start),
        height=0.35,
        color=color,
        edgecolor="#000",
        linewidth=0.6,
        alpha=0.85
    )
    # Heure exacte sur chaque barre
    ax.text(mdates.date2num(start) + width_days / 2, y_map[ip],
            start.strftime("%H:%M:%S"), va="center", ha="center",
            fontsize=7.5, color="white", fontweight="bold")

# Labels Y : IP + type d'attaque
ax.set_yticks(range(len(ip_order)))
ax.set_yticklabels(
    [f"{ip}  ({LABELS.get(ip, '?')})" for ip in ip_order],
    fontsize=9, color="white"
)
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=30))
all_starts = [mdates.date2num(s["start"]) for s in sessions.values()]
ax.set_xlim(min(all_starts) - 0.015, max(all_starts) + 0.015)
ax.set_xlabel("Heure (UTC)", fontsize=11)
plt.setp(ax.xaxis.get_majorticklabels(), rotation=25, ha="right")
ax.grid(axis="x", color="#0f3460", linestyle="--", alpha=0.4)

# =============================================
# 2. Sessions par IP (haut droite)
# =============================================
ax = axes[0, 1]
ax.set_title("📊  Nombre de Sessions par IP", fontsize=15, fontweight="bold", pad=12)

ip_counts = Counter(s["ip"] for s in sessions.values())
# Tri par nombre de sessions décroissant
sorted_ips_count = sorted(ip_counts.keys(), key=lambda ip: ip_counts[ip])
counts = [ip_counts[ip] for ip in sorted_ips_count]
colors_bar = [COLORS.get(ip, "#ccc") for ip in sorted_ips_count]

bars = ax.barh(range(len(sorted_ips_count)), counts, color=colors_bar,
               edgecolor="#000", linewidth=0.6, height=0.5)
ax.set_xlabel("Nombre de sessions", fontsize=11)

# Labels Y : IP + type
ax.set_yticks(range(len(sorted_ips_count)))
ax.set_yticklabels(
    [f"{ip}  ({LABELS.get(ip, '?')})" for ip in sorted_ips_count],
    fontsize=9, color="white"
)

# Nombre sur chaque barre
for bar, count in zip(bars, counts):
    ax.text(bar.get_width() + 0.15, bar.get_y() + bar.get_height() / 2,
            str(count), va="center", color="white", fontsize=11, fontweight="bold")

ax.set_xlim(0, max(counts) + 1.8)
ax.grid(axis="x", color="#0f3460", linestyle="--", alpha=0.4)

# =============================================
# 3. Credentials testés (bas gauche)
# =============================================
ax = axes[1, 0]
ax.set_title("🔐  Mots de passe les plus testés par les attaquants",
             fontsize=15, fontweight="bold", pad=12)

cred_counter = Counter(e.get("password", "") for e in logins)
top_creds = cred_counter.most_common(10)
labels_cred = [c[0] for c in top_creds]
values_cred = [c[1] for c in top_creds]

# Quelle IP a utilisé quel mot de passe
cred_ips = defaultdict(list)
for e in logins:
    cred_ips[e.get("password", "")].append(e.get("src_ip", "?"))

cmap = plt.cm.plasma
cred_colors = [cmap(i / max(len(labels_cred) - 1, 1)) for i in range(len(labels_cred))]

bars = ax.barh(range(len(labels_cred)), values_cred, color=cred_colors,
               edgecolor="#000", linewidth=0.6, height=0.5)
ax.set_xlabel("Nombre d'utilisations", fontsize=11)

# Labels Y : mot de passe + IPs qui l'ont utilisé
ax.set_yticks(range(len(labels_cred)))
ax.set_yticklabels(labels_cred, fontsize=10, color="white", fontweight="bold")

# Nombre + IPs sources à droite de chaque barre
for i, (bar, val) in enumerate(zip(bars, values_cred)):
    pwd = labels_cred[i]
    ips_src = ", ".join(set(cred_ips[pwd]))
    ax.text(bar.get_width() + 0.08, bar.get_y() + bar.get_height() / 2,
            f"{val}×  ← {ips_src}", va="center", color="white", fontsize=8)

ax.set_xlim(0, max(values_cred) + 1.2)
ax.grid(axis="x", color="#0f3460", linestyle="--", alpha=0.4)

# =============================================
# 4. Durée des sessions par IP (bas droite)
# =============================================
ax = axes[1, 1]
ax.set_title("⏰  Durée des Sessions par IP (en secondes)",
             fontsize=15, fontweight="bold", pad=12)

dur_by_ip = defaultdict(list)
for s in sessions.values():
    dur_by_ip[s["ip"]].append(s["duration"])

# Tri par durée max croissante → le WORM en haut
sorted_ips_dur = sorted(dur_by_ip.keys(), key=lambda ip: max(dur_by_ip[ip]))

for i, ip in enumerate(sorted_ips_dur):
    durations = dur_by_ip[ip]
    color = COLORS.get(ip, "#ccc")
    # Ligne horizontale de référence
    ax.axhline(y=i, color="#0f3460", linewidth=0.6, zorder=1)
    # Points
    ax.scatter(durations, [i] * len(durations), color=color, s=120,
               edgecolors="#000", linewidth=1, zorder=3)
    # Durée exacte sur chaque point
    for d in durations:
        ax.text(d + 3, i + 0.12, f"{d:.1f}s", fontsize=7.5, color="white", va="bottom")

# Labels Y : IP + type
ax.set_yticks(range(len(sorted_ips_dur)))
ax.set_yticklabels(
    [f"{ip}  ({LABELS.get(ip, '?')})" for ip in sorted_ips_dur],
    fontsize=9, color="white"
)
ax.set_xlabel("Durée de la session (secondes)", fontsize=11)

# Borne X
max_all = max(max(dur_by_ip[ip]) for ip in dur_by_ip)
ax.set_xlim(-15, max_all + 40)
ax.grid(axis="x", color="#0f3460", linestyle="--", alpha=0.4)

# Annotation WORM (en haut)
worm_y = len(sorted_ips_dur) - 1
worm_dur = max(dur_by_ip["66.116.205.1"])
ax.annotate("🔴 WORM — Upload malware\n    + propagation vers 50 IPs",
            xy=(worm_dur, worm_y),
            xytext=(worm_dur - 120, worm_y - 1.2),
            color="#e74c3c", fontsize=9, fontweight="bold",
            arrowprops=dict(arrowstyle="->", color="#e74c3c", lw=2.5),
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#1a1a2e", edgecolor="#e74c3c"))

# =============================================
# Légende globale en bas
# =============================================
legend_patches = [
    mpatches.Patch(color=COLORS["66.116.205.1"],   label="66.116.205.1  — WORM (malware uploadé)"),
    mpatches.Patch(color=COLORS["64.225.65.182"],  label="64.225.65.182  — Brute-force automatisé"),
    mpatches.Patch(color=COLORS["161.35.156.145"], label="161.35.156.145 — Brute-force automatisé"),
    mpatches.Patch(color=COLORS["165.232.83.65"],  label="165.232.83.65  — Brute-force automatisé"),
    mpatches.Patch(color=COLORS["205.210.31.153"], label="205.210.31.153 — Scanner (ZGrab)"),
    mpatches.Patch(color=COLORS["36.95.238.13"],   label="36.95.238.13   — Scanner (timeout 120s)"),
    mpatches.Patch(color=COLORS["54.144.193.250"], label="54.144.193.250 — Scanner rapide"),
    mpatches.Patch(color=COLORS["35.180.112.84"],  label="35.180.112.84  — Scanner rapide"),
]
fig.legend(handles=legend_patches, loc="lower center", ncol=4,
           fontsize=9, facecolor="#1a1a2e", edgecolor="#0f3460",
           labelcolor="white", frameon=True, bbox_to_anchor=(0.5, 0.01))

# =============================================
plt.tight_layout(rect=[0, 0.06, 1, 0.95])
plt.savefig("output/cowrie_dashboard.png", dpi=150,
            facecolor=fig.get_facecolor(), bbox_inches="tight", pad_inches=0.4)
print("[+] Dashboard sauvegardé : output/cowrie_dashboard.png")
