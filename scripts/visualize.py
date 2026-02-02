import json
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
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

# --- MAIN ---
events = load_logs()
sessions = get_sessions(events)
logins = get_logins(events)

fig, axes = plt.subplots(2, 2, figsize=(18, 11))
fig.suptitle("Honeypot Cowrie — Analyse des Attaques  |  Mise à jour " + datetime.now().strftime("%d/%m/%Y"),
             fontsize=16, fontweight="bold", color="white", y=0.98)
fig.patch.set_facecolor("#1a1a2e")

for ax in axes.flat:
    ax.set_facecolor("#16213e")
    ax.tick_params(colors="white", labelsize=9)
    ax.title.set_color("white")
    ax.xaxis.label.set_color("white")
    ax.yaxis.label.set_color("white")
    for spine in ax.spines.values():
        spine.set_color("#0f3460")

# =============================================
# 1. TIMELINE simplifiée (haut gauche)
# =============================================
ax = axes[0, 0]
ax.set_title("Timeline des Sessions SSH", fontsize=13, fontweight="bold", pad=10)

# Top 15 IPs par nombre de sessions pour la timeline
ip_counts = Counter(s["ip"] for s in sessions.values())
top_ips_timeline = [ip for ip, _ in ip_counts.most_common(15)]
y_map = {ip: i for i, ip in enumerate(top_ips_timeline)}

# Palette de couleurs
colors_palette = plt.cm.tab20(range(20))

for sid, s in sessions.items():
    ip = s["ip"]
    if ip not in top_ips_timeline:
        continue
    start = s["start"]
    dur = s["duration"]
    color = colors_palette[top_ips_timeline.index(ip) % 20]
    width_days = max(dur, 30) / 86400
    ax.barh(
        y=y_map[ip],
        width=width_days,
        left=mdates.date2num(start),
        height=0.5,
        color=color,
        edgecolor="#000",
        linewidth=0.4,
        alpha=0.8
    )

ax.set_yticks(range(len(top_ips_timeline)))
ax.set_yticklabels(top_ips_timeline, fontsize=8, color="white")
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.xaxis.set_major_locator(mdates.HourLocator(interval=2))
all_starts = [mdates.date2num(s["start"]) for s in sessions.values() if s["ip"] in top_ips_timeline]
if all_starts:
    ax.set_xlim(min(all_starts) - 0.01, max(all_starts) + 0.01)
ax.set_xlabel("Heure (UTC)", fontsize=10)
plt.setp(ax.xaxis.get_majorticklabels(), rotation=25, ha="right")
ax.grid(axis="x", color="#0f3460", linestyle="--", alpha=0.3)

# =============================================
# 2. Sessions par IP (haut droite)
# =============================================
ax = axes[0, 1]
ax.set_title("Top 15 IPs — Nombre de Sessions", fontsize=13, fontweight="bold", pad=10)

top_ips_count = ip_counts.most_common(15)
ips_display = [ip for ip, _ in top_ips_count]
counts_display = [count for _, count in top_ips_count]

bars = ax.barh(range(len(ips_display)), counts_display,
               color=[colors_palette[i % 20] for i in range(len(ips_display))],
               edgecolor="#000", linewidth=0.4, height=0.6)
ax.set_xlabel("Nombre de sessions", fontsize=10)

ax.set_yticks(range(len(ips_display)))
ax.set_yticklabels(ips_display, fontsize=8, color="white")

for bar, count in zip(bars, counts_display):
    ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2,
            str(count), va="center", color="white", fontsize=9, fontweight="bold")

ax.set_xlim(0, max(counts_display) + 1.5)
ax.grid(axis="x", color="#0f3460", linestyle="--", alpha=0.3)

# =============================================
# 3. Top credentials (bas gauche)
# =============================================
ax = axes[1, 0]
ax.set_title("Top 10 Mots de passe testés", fontsize=13, fontweight="bold", pad=10)

cred_counter = Counter(e.get("password", "") for e in logins)
top_creds = cred_counter.most_common(10)
labels_cred = [c[0] for c in top_creds]
values_cred = [c[1] for c in top_creds]

cmap = plt.cm.plasma
cred_colors = [cmap(i / max(len(labels_cred) - 1, 1)) for i in range(len(labels_cred))]

bars = ax.barh(range(len(labels_cred)), values_cred, color=cred_colors,
               edgecolor="#000", linewidth=0.4, height=0.6)
ax.set_xlabel("Nombre d'utilisations", fontsize=10)

ax.set_yticks(range(len(labels_cred)))
ax.set_yticklabels(labels_cred, fontsize=9, color="white", fontweight="bold")

for bar, val in zip(bars, values_cred):
    ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
            f"{val}×", va="center", color="white", fontsize=9, fontweight="bold")

ax.set_xlim(0, max(values_cred) + 0.8)
ax.grid(axis="x", color="#0f3460", linestyle="--", alpha=0.3)

# =============================================
# 4. Durée des sessions (bas droite)
# =============================================
ax = axes[1, 1]
ax.set_title("Durée des Sessions (Top 15 IPs)", fontsize=13, fontweight="bold", pad=10)

dur_by_ip = defaultdict(list)
for s in sessions.values():
    if s["ip"] in top_ips_timeline:
        dur_by_ip[s["ip"]].append(s["duration"])

sorted_ips_dur = sorted(dur_by_ip.keys(), key=lambda ip: max(dur_by_ip[ip]))

for i, ip in enumerate(sorted_ips_dur):
    durations = dur_by_ip[ip]
    color = colors_palette[top_ips_timeline.index(ip) % 20]
    ax.axhline(y=i, color="#0f3460", linewidth=0.4, zorder=1)
    ax.scatter(durations, [i] * len(durations), color=color, s=80,
               edgecolors="#000", linewidth=0.6, zorder=3, alpha=0.8)

ax.set_yticks(range(len(sorted_ips_dur)))
ax.set_yticklabels(sorted_ips_dur, fontsize=8, color="white")
ax.set_xlabel("Durée (secondes)", fontsize=10)

if dur_by_ip:
    max_all = max(max(dur_by_ip[ip]) for ip in dur_by_ip)
    ax.set_xlim(-5, max_all + 15)
ax.grid(axis="x", color="#0f3460", linestyle="--", alpha=0.3)

# =============================================
plt.tight_layout(rect=[0, 0.02, 1, 0.96])
plt.savefig("output/cowrie_dashboard.png", dpi=150,
            facecolor=fig.get_facecolor(), bbox_inches="tight", pad_inches=0.3)
print(f"[+] Dashboard sauvegardé : output/cowrie_dashboard.png")
print(f"[+] Sessions analysées : {len(sessions)}")
print(f"[+] IPs uniques : {len(set(s['ip'] for s in sessions.values()))}")
