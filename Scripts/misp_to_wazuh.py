#!/usr/bin/env python3
"""
============================================================================
Synchronisation des IoCs MISP vers Wazuh
----------------------------------------------------------------------------
Ce script :
  1. interroge l'API REST MISP pour récupérer les attributs récents
  2. filtre les types supportés (IP, domaines, hashes)
  3. génère un fichier de règles XML compatible Wazuh
  4. redémarre le manager Wazuh pour activer les nouvelles règles

Exécution : via cron (une fois par jour)
Auteur : Équipe SOC
============================================================================
"""
import os
import sys
import logging
import requests
import xml.etree.ElementTree as ET
import subprocess
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/misp_sync.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)

MISP_URL = os.getenv("MISP_URL")
MISP_API_KEY = os.getenv("MISP_API_KEY")
WAZUH_RULES_FILE = "/var/ossec/etc/rules/misp_iocs.xml"
START_RULE_ID = 200000

# Types MISP convertibles en règles Wazuh
SUPPORTED_TYPES = {
    "ip-src":  {"field": "srcip",  "desc": "IP source malveillante"},
    "ip-dst":  {"field": "dstip",  "desc": "IP destination malveillante"},
    "domain":  {"field": "url",    "desc": "Domaine malveillant"},
    "md5":     {"field": "md5",    "desc": "Hash MD5 malveillant"},
    "sha256":  {"field": "sha256", "desc": "Hash SHA-256 malveillant"},
}


# ---------------------------------------------------------------------------
# 1. Récupération des attributs MISP
# ---------------------------------------------------------------------------
def fetch_misp_attributes(last_hours=24):
    """Récupère les attributs MISP récents via l'API REST."""
    endpoint = f"{MISP_URL}/attributes/restSearch"
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    body = {"last": f"{last_hours}h", "type": list(SUPPORTED_TYPES.keys())}
    try:
        r = requests.post(endpoint, headers=headers, json=body,
                          verify=False, timeout=60)
        r.raise_for_status()
        return r.json().get("response", {}).get("Attribute", [])
    except requests.RequestException as e:
        log.error(f"Erreur lors de l'appel MISP : {e}")
        return []


# ---------------------------------------------------------------------------
# 2. Génération des règles Wazuh
# ---------------------------------------------------------------------------
def build_wazuh_rules(attributes):
    """Convertit les IoCs MISP en arbre XML de règles Wazuh."""
    root = ET.Element("group", {"name": "misp_iocs,"})
    rule_id = START_RULE_ID
    count = 0

    for attr in attributes:
        attr_type = attr.get("type")
        value = attr.get("value", "").strip()
        if attr_type not in SUPPORTED_TYPES or not value:
            continue

        cfg = SUPPORTED_TYPES[attr_type]
        rule = ET.SubElement(root, "rule", {
            "id": str(rule_id),
            "level": "12",
            "frequency": "1",
            "timeframe": "300",
        })
        ET.SubElement(rule, "description").text = (
            f"MISP IoC détecté : {cfg['desc']} ({value[:40]})"
        )
        ET.SubElement(rule, "field", {"name": cfg["field"]}).text = value
        mitre = ET.SubElement(rule, "mitre")
        ET.SubElement(mitre, "id").text = "T1587"

        rule_id += 1
        count += 1

    log.info(f"{count} règles générées (IDs {START_RULE_ID} à {rule_id - 1})")
    return root


# ---------------------------------------------------------------------------
# 3. Écriture du fichier
# ---------------------------------------------------------------------------
def write_rules(root):
    """Écrit le fichier de règles de façon atomique."""
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tmp_path = WAZUH_RULES_FILE + ".tmp"
    tree.write(tmp_path, encoding="utf-8", xml_declaration=True)
    os.replace(tmp_path, WAZUH_RULES_FILE)
    log.info(f"Fichier de règles écrit : {WAZUH_RULES_FILE}")


# ---------------------------------------------------------------------------
# 4. Redémarrage du manager Wazuh
# ---------------------------------------------------------------------------
def restart_wazuh_manager():
    """Redémarre Wazuh pour activer les nouvelles règles."""
    try:
        subprocess.run(
            ["/var/ossec/bin/wazuh-control", "restart"],
            check=True, capture_output=True, timeout=60,
        )
        log.info("Wazuh manager redémarré.")
    except subprocess.CalledProcessError as e:
        log.error(f"Échec du redémarrage Wazuh : {e.stderr.decode()}")


# ---------------------------------------------------------------------------
# 5. Point d'entrée
# ---------------------------------------------------------------------------
def main():
    log.info("=== Démarrage synchronisation MISP -> Wazuh ===")
    attributes = fetch_misp_attributes(last_hours=24)
    log.info(f"{len(attributes)} attributs récupérés depuis MISP")

    if not attributes:
        log.info("Aucun nouvel IoC, arrêt du script.")
        return

    root = build_wazuh_rules(attributes)
    write_rules(root)
    restart_wazuh_manager()
    log.info("=== Synchronisation terminée ===")


if __name__ == "__main__":
    main()  