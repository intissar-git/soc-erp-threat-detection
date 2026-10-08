#!/usr/bin/env python3
import os, json, base64, io, smtplib, statistics, urllib3
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict

import requests
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import markdown2
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CONFIGURATION
ES_URL = os.getenv("ES_URL", "https://localhost:9200")
ES_USER = os.getenv("ES_USER", "admin")
ES_PASS = os.getenv("ES_PASS", "SecretPassword")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", SMTP_USER)
EMAIL_TO = os.getenv("EMAIL_TO", "soc-analyst@company.com")
ORG_NAME = os.getenv("ORG_NAME", "SOC Wazuh - ERP Odoo")
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"), exist_ok=True)

NOW = datetime.now(timezone.utc)
START = NOW - timedelta(hours=24)
STAMP = NOW.strftime("%Y%m%d_%H%M")
HTML_FILE = os.path.join(REPORTS_DIR, f"soc_report_{STAMP}.html")
PDF_FILE = os.path.join(REPORTS_DIR, f"soc_report_{STAMP}.pdf")

# PALETTES DE SÉVÉRITÉ
SEV_MATRIX = [
    ("CRITIQUE", 12, 99, "#e74c3c", "bc", " ", 4),
    ("ELEV", 9, 11, "#e67e22", "bh", " ", 3),
    ("MOYEN", 6, 8, "#f39c12", "bm", " ", 2),
    ("FAIBLE", 1, 5, "#27ae60", "bl", " ", 1),
]

def level_to_sev(level: int) -> tuple:
    for label, lo, hi, color, css, emoji, prio in SEV_MATRIX:
        if lo <= level <= hi:
            return label, color, css, emoji, prio
    return "FAIBLE", "#27ae60", "bl", " ", 1

def max_level_of(group: list) -> int:
    return max((a.get("rule", {}).get("level", 0) for a in group), default=0)

# 1. RÉCUPÉRATION DES ALERTES
def get_alerts(size: int = 2000) -> list:
    query = {
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}}
        ]}},
        "sort": [
            {"rule.level": {"order": "desc"}},
            {"@timestamp": {"order": "desc"}},
        ],
        "size": size,
    }
    print("Récupération alertes Wazuh (24h)...")
    try:
        r = requests.get(
            f"{ES_URL}/wazuh-alerts-*/_search",
            auth=(ES_USER, ES_PASS),
            headers={"Content-Type": "application/json"},
            json=query, verify=False, timeout=30
        )
        r.raise_for_status()
        alerts = [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]
        print(f"{len(alerts)} alertes récupérées")
        return alerts
    except Exception as e:
        print(f"Erreur OpenSearch : {e}")
        return []

# 2. STATISTIQUES
def compute_stats(alerts: list) -> dict:
    sev_counts = {lbl: 0 for lbl, _, _, _, _, _, _ in SEV_MATRIX}
    rules = Counter()
    ips = Counter()
    agents = Counter()
    mitre_t = Counter()
    mitre_id = Counter()
    hourly = defaultdict(int)
    auth_fail = 0

    for a in alerts:
        lvl = a.get("rule", {}).get("level", 0)
        desc = a.get("rule", {}).get("description", "Inconnu")
        src = a.get("data", {}).get("srcip", "") or ""
        ag = a.get("agent", {}).get("name", "unknown")

        label, _, _, _, _ = level_to_sev(lvl)
        sev_counts[label] += 1
        rules[desc] += 1
        if src and src not in ("0.0.0.0", "N/A", ""):
            ips[src] += 1
        agents[ag] += 1

        mf = a.get("rule", {}).get("mitre", {})
        if isinstance(mf, dict):
            for t in mf.get("tactic", []): mitre_t[t] += 1
            for i in mf.get("id", []): mitre_id[i] += 1
        elif isinstance(mf, list):
            for item in mf:
                if isinstance(item, str):
                    mitre_id[item] += 1
                elif isinstance(item, dict):
                    for t in item.get("tactic", []): mitre_t[t] += 1
                    if item.get("id"): mitre_id[item["id"]] += 1

        if any(k in desc.lower() for k in ("authentication fail", "invalid user", "brute force", "failed password", "echec", "invalid password")):
            auth_fail += 1

        ts = a.get("@timestamp", "")
        if ts and len(ts) >= 13:
            try: hourly[int(ts[11:13])] += 1
            except: pass

    return {
        "total": len(alerts),
        "severity": sev_counts,
        "auth_fail": auth_fail,
        "top_rules": rules.most_common(10),
        "top_ips": ips.most_common(10),
        "top_agents": agents.most_common(5),
        "mitre_tactic": mitre_t.most_common(10),
        "mitre_id": mitre_id.most_common(10),
        "hourly": dict(sorted(hourly.items())),
    }

# 3. TRI SÉVÉRITÉ + SÉLECTION
def group_and_sort(alerts: list) -> list[tuple]:
    grouped: dict[str, list] = defaultdict(list)
    for a in alerts:
        grouped[a.get("rule", {}).get("description", "Inconnu")].append(a)

    enriched = []
    for desc, group in grouped.items():
        mx = max_level_of(group)
        lbl, col, css, emoji, prio = level_to_sev(mx)
        enriched.append((desc, group, mx, lbl, col, emoji, css, prio))

    enriched.sort(key=lambda x: (-x[7], -len(x[1])))
    return enriched

def select_for_llm(sorted_groups: list) -> list[tuple]:
    to_analyze, moyen_n = [], 0
    for item in sorted_groups:
        _, _, _, sev_lbl, _, _, _, _ = item
        if sev_lbl in ("CRITIQUE", "ELEV"):
            to_analyze.append(item)
        elif sev_lbl == "MOYEN" and moyen_n < 3:
            to_analyze.append(item)
            moyen_n += 1
    return to_analyze

# 4. ANOMALY DETECTION
def detect_anomalies(alerts: list, stats: dict) -> list[dict]:
    anomalies = []
    total = stats["total"]
    if not total: return anomalies

    hourly_vals = list(stats["hourly"].values())
    if len(hourly_vals) >= 4:
        mean = statistics.mean(hourly_vals)
        std = statistics.stdev(hourly_vals) if len(hourly_vals) > 1 else 0
        if std > 0:
            for hour, count in stats["hourly"].items():
                z = (count - mean) / std
                if z > 2.5:
                    anomalies.append({
                        "type": "Pic Temporel Anormal", "icon": " ", "sev": "CRITIQUE",
                        "detail": f"Pic {hour:02d}h00 UTC : {count} alertes",
                        "recommendation": f"Investiguer les logs entre {hour:02d}h00 et {hour+1:02d}h00 UTC"
                    })

    for ip, count in stats["top_ips"]:
        pct = count / total * 100
        if pct > 25:
            anomalies.append({
                "type": "IP Flooding", "icon": " ", "sev": "CRITIQUE" if pct > 50 else "ELEV",
                "detail": f"IP {ip} {pct:.1f}% des alertes",
                "recommendation": f"IP déjà transmise à Shuffle pour blocage Azure. Vérifier le Security Group."
            })

    if stats["auth_fail"]:
        auth_pct = stats["auth_fail"] / total * 100
        if auth_pct > 40:
            anomalies.append({
                "type": "Burst Brute-Force", "icon": " ", "sev": "CRITIQUE",
                "detail": f"{stats['auth_fail']} échecs auth ({auth_pct:.1f}% du total)",
                "recommendation": "Activer le verrouillage de compte Odoo et ajouter un CAPTCHA."
            })

    anomalies.sort(key=lambda x: {"CRITIQUE": 0, "ELEV": 1, "MOYEN": 2}.get(x["sev"], 3))
    return anomalies

# 5. GRAPHIQUES
_BG = "#1a1f35"; _DARKER = "#0a0e1a"; _BORDER = "#2d3561"; _FG = "#e0e0e0"
plt.rcParams.update({
    "figure.facecolor": _BG, "axes.facecolor": _BG, "text.color": _FG,
    "axes.labelcolor": _FG, "xtick.color": _FG, "ytick.color": _FG,
    "axes.edgecolor": _BORDER, "grid.color": _BORDER,
    "axes.spines.top": False, "axes.spines.right": False,
})

def _b64(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=130, bbox_inches="tight", facecolor=_BG, edgecolor="none")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()

def chart_timeline(hourly: dict, anomaly_hours: set):
    if not hourly: return None
    hours = list(range(24)); counts = [hourly.get(h, 0) for h in hours]
    colors = ["#e74c3c" if h in anomaly_hours else "#3498db" for h in hours]
    fig, ax = plt.subplots(figsize=(11, 3.5))
    ax.bar(hours, counts, color=colors, alpha=0.85, width=0.75, edgecolor=_DARKER)
    ax.set_title("Timeline Alertes 24h", fontsize=11)
    ax.set_xticks(range(0, 24, 2)); ax.grid(axis="y", alpha=0.2)
    fig.tight_layout(); return _b64(fig)

def chart_severity_pie(sev: dict):
    pairs = [(lbl, sev.get(lbl, 0), col) for lbl, _, _, col, _, _, _ in SEV_MATRIX if sev.get(lbl, 0) > 0]
    if not pairs: return None
    labels = [p[0] for p in pairs]; vals = [p[1] for p in pairs]; colors = [p[2] for p in pairs]
    fig, ax = plt.subplots(figsize=(4.5, 4.2))
    wedges, _, autotexts = ax.pie(vals, colors=colors, autopct="%.1f %%", startangle=90, wedgeprops=dict(width=0.6, edgecolor=_DARKER, linewidth=2))
    for at in autotexts: at.set_color("white"); at.set_fontsize(9)
    ax.legend(wedges, [f"{l} ({v})" for l, v in zip(labels, vals)], loc="lower center", bbox_to_anchor=(0.5, -0.22), fontsize=8, frame=False, ncol=2)
    fig.tight_layout(); return _b64(fig)

def chart_top_rules(top_rules: list):
    if not top_rules: return None
    items = top_rules[:8]; labels = [r[:45] + "..." if len(r) > 45 else r for r, _ in items]
    vals = [v for _, v in items]; colors = plt.cm.Reds(np.linspace(0.45, 0.9, len(items)))
    fig, ax = plt.subplots(figsize=(9, max(3.5, len(items) * 0.55)))
    ax.barh(range(len(labels)), vals, color=colors[:-1], edgecolor=_DARKER, height=0.65)
    ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels, fontsize=8); ax.invert_yaxis()
    ax.set_title("Top 8 Règles Déclenchées", fontsize=11); ax.grid(axis="x", alpha=0.2)
    fig.tight_layout(); return _b64(fig)

def chart_top_ips(top_ips: list):
    if not top_ips: return None
    labels = [ip for ip, _ in top_ips[:10]]; vals = [v for _, v in top_ips[:10]]
    colors = plt.cm.Reds(np.linspace(0.4, 0.9, len(labels)))
    fig, ax = plt.subplots(figsize=(6.5, max(3, len(labels) * 0.5)))
    ax.barh(labels, vals, color=colors, edgecolor=_DARKER, height=0.65)
    ax.invert_yaxis(); ax.set_title("Top IPs Sources", fontsize=11); ax.grid(axis="x", alpha=0.2)
    fig.tight_layout(); return _b64(fig)

def chart_mitre(mitre_t: list):
    if not mitre_t: return None
    tactics = [t for t, _ in mitre_t[:8]]; vals = [v for _, v in mitre_t[:8]]
    palette = ["#9b59b6", "#8e44ad", "#7d3c98", "#6c3483", "#5b2c6f", "#4a235a", "#6c3483", "#7d3c98"][:len(tactics)]
    fig, ax = plt.subplots(figsize=(7, 3.5))
    ax.bar(range(len(tactics)), vals, color=palette, alpha=0.85, edgecolor=_DARKER)
    ax.set_xticks(range(len(tactics))); ax.set_xticklabels(tactics, rotation=30, ha="right", fontsize=8)
    ax.set_title("Tactiques MITRE ATT&CK", fontsize=11); ax.grid(axis="y", alpha=0.2)
    fig.tight_layout(); return _b64(fig)

def _img(b64, alt=""):
    if not b64: return '<p class="no-data">Données insuffisantes</p>'
    return f'<img src="data:image/png;base64,{b64}" alt="{alt}">'

# 6. SYSTÈME LLM RÈGLE ABSOLUE : PAS DE SUGGESTION BLOCAGE IP
_NO_IP_BLOCK = """
RÈGLE ABSOLUE ET INTRANSIGEANTE :
Le SOC dispose DÉJÀ d'un système automatique de blocage d'IP via Azure Security Group et Shuffle SOAR.
TU NE DOIS SOUS AUCUN PRÉTEXTE suggérer de "bloquer l'IP", "bannir l'IP", "blacklister", "bloquer la source", "utiliser iptables", ou modifier le pare-feu réseau.
Toute suggestion liée au blocage IP est strictement interdite.
Concentre-toi UNIQUEMENT sur : le durcissement applicatif d'Odoo, la configuration fine de Wazuh, la politique de mot de passe, l'activation du 2FA, ou la gestion des droits.
"""

def _groq(prompt: str, max_tokens: int = 1200) -> str:
    client = Groq(api_key=GROQ_API_KEY)
    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": "Tu es un analyste SOC senior spécialisé en sécurité ERP Odoo et Wazuh IDS.\n"
                                          "Réponds TOUJOURS en français, format markdown structuré.\n"
                                          "Sois précis, concis, orienté action.\n" + _NO_IP_BLOCK},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2, max_tokens=max_tokens,
    )
    return resp.choices[0].message.content

def prompt_executive(stats: dict, anomalies: list) -> str:
    sev = stats["severity"]
    anom = "\n".join(f"- [{a['sev']}] {a['type']}: {a['detail']}" for a in anomalies) or "Aucune"
    rules = "\n".join(f"- {r}: {c} alertes" for r, c in stats["top_rules"][:5])
    mitre = ", ".join(t for t, _ in stats["mitre_tactic"][:5]) or "Non identifié"

    return f"""Tu es CISO. Génère un résumé exécutif SOC professionnel.
{_NO_IP_BLOCK}

## Données 24h
| Sévérité | Nb |
| --- | --- |
| CRITIQUE (>=12) | {sev.get('CRITIQUE',0)} |
| ELEV (9-11) | {sev.get('ELEV',0)} |
| MOYEN (6-8) | {sev.get('MOYEN',0)} |
| FAIBLE (1-5) | {sev.get('FAIBLE',0)} |
| Total | {stats['total']} |

## Anomalies
{anom}

## Top Menaces
{rules}

## Tactiques MITRE
{mitre}

### État Global de Sécurité
[2-3 phrases]

### Niveau de Risque : [CRITIQUE / ELEV / MODÉRÉ / FAIBLE]
[Justification courte]

### Top 3 Actions Immédiates (48h)
(Rappel strict: AUCUN BLOCAGE IP NE DOIT ÊTRE SUGGÉRÉ ICI)
1. **[Action applicative Odoo ou config Wazuh]**
2. **[Action applicative Odoo ou config Wazuh]**
3. **[Action applicative Odoo ou config Wazuh]**
"""

def prompt_rule_analysis(rule_desc: str, group: list, max_lvl: int, sev_lbl: str, sev_col: str) -> str:
    mitre_ids, mitre_tactics = set(), set()
    for a in group:
        mf = a.get("rule", {}).get("mitre", {})
        if isinstance(mf, dict):
            for i in mf.get("id", []): mitre_ids.add(i)
            for t in mf.get("tactic", []): mitre_tactics.add(t)
        elif isinstance(mf, list):
            for item in mf:
                if isinstance(item, str): mitre_ids.add(item)
                elif isinstance(item, dict):
                    if item.get("id"): mitre_ids.add(item["id"])
                    for t in item.get("tactic", []): mitre_tactics.add(t)

    src_ips = list({a.get("data", {}).get("srcip", "") for a in group if a.get("data", {}).get("srcip", "") not in ("", "N/A", "0.0.0.0")})[:5]

    return f"""Analyse SOC expert Odoo. Analyse cette alerte Wazuh.
{_NO_IP_BLOCK}

## Contexte
- **Règle :** {rule_desc}
- **Volume :** {len(group)} alertes
- **Sévérité max :** Niveau {max_lvl}/15 **{sev_lbl}**
- **IPs sources :** {', '.join(src_ips) if src_ips else 'Non identifiées'}

## Classification
| Champ | Valeur |
| --- | --- |
| Type d'attaque | [catégorie] |
| Criticité | **{sev_lbl}** (Niv {max_lvl}) |
| MITRE | {', '.join(sorted(mitre_ids)) or '[à identifier]'} |
| Score de risque | [X/10] |

## Analyse
[Ce qui s'est passé]

## Impact Odoo
[Impact métier]

## Remédiation Immédiate (AUCUN BLOCAGE IP)
1. **[Config Odoo/Wazuh]** : [Détail]
2. **[Config Odoo/Wazuh]** : [Détail]

## Prévention Long Terme (AUCUN BLOCAGE IP)
- **Wazuh** : [Règle]
- **Odoo** : [Paramètre]
"""

def html_to_pdf(html_path: str, pdf_path: str) -> bool:
    try:
        from weasyprint import HTML as WP
        WP(filename=html_path).write_pdf(pdf_path)
        size_kb = os.path.getsize(pdf_path) // 1024
        print(f"PDF généré : {pdf_path} ({size_kb} KB)")
        return True
    except Exception as e:
        print(f"PDF erreur : {e}")
        return False

def send_email(html_path: str, pdf_path: str | None, stats: dict, anomalies: list):
    if not (SMTP_USER and SMTP_PASS and EMAIL_TO):
        print("Email non configuré.")
        return
    subj = f'[SOC] Rapport Sécurité {NOW.strftime("%d/%m/%Y")} - {stats["total"]} alertes'
    msg = MIMEMultipart("mixed")
    msg["Subject"] = subj; msg["From"] = EMAIL_FROM or SMTP_USER; msg["To"] = EMAIL_TO

    body = MIMEMultipart("alternative")
    body.attach(MIMEText("Veuillez trouver ci-joint le rapport PDF généré.", "plain", "utf-8"))
    with open(html_path, encoding="utf-8") as f:
        body.attach(MIMEText(f.read(), "html", "utf-8"))
    msg.attach(body)

    if pdf_path and os.path.exists(pdf_path):
        with open(pdf_path, "rb") as f:
            part = MIMEBase("application", "pdf"); part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f'attachment; filename="soc_report_{NOW.strftime("%Y%m%d_%H%M")}.pdf"')
            msg.attach(part)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.starttls(); server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, EMAIL_TO, msg.as_string())
            print(f"Email envoyé à {EMAIL_TO}")
    except Exception as e:
        print(f"Erreur envoi : {e}")

def main():
    print("SOC Report Generator v3.1 (Page de garde + No IP Block)")
    alerts = get_alerts(size=2000)
    stats = compute_stats(alerts)
    sorted_groups = group_and_sort(alerts)
    anomalies = detect_anomalies(alerts, stats)
    anomaly_hours = {a.get("hour") for a in anomalies if "hour" in a}

    charts = {
        "timeline": chart_timeline(stats["hourly"], anomaly_hours),
        "severity": chart_severity_pie(stats["severity"]),
        "top_rules": chart_top_rules(stats["top_rules"]),
        "top_ips": chart_top_ips(stats["top_ips"]),
        "mitre": chart_mitre(stats["mitre_tactic"]),
    }

    exec_summary = ""
    if alerts and GROQ_API_KEY:
        try:
            exec_summary = _groq(prompt_executive(stats, anomalies), max_tokens=900)
            print("Résumé exécutif généré")
        except Exception as e:
            print(f"Erreur Exec : {e}")

    # Note: La génération HTML complète a été omise pour la concision.
    # Vous devez inclure votre fonction generate_html() ici.
    # html = generate_html(stats, charts, anomalies, exec_summary, sorted_groups, rule_analyses)
    
    # Pour l'exemple, on suppose que le fichier HTML est généré
    # with open(HTML_FILE, "w", encoding="utf-8") as f:
    #     f.write(html)
    
    print("\nConversion PDF...")
    # pdf_ok = html_to_pdf(HTML_FILE, PDF_FILE)
    pdf_ok = False # Placeholder
    
    print("\nEnvoi Gmail...")
    # send_email(HTML_FILE, PDF_FILE if pdf_ok else None, stats, anomalies)
    print("TERMINÉ")

if __name__ == "__main__":
    main()