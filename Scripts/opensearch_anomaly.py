import os
import requests
import urllib3
import time
import sys
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration (chargée depuis .env)
INDEXER_URL = os.getenv("ES_URL", "https://localhost:9200")
AUTH = (os.getenv("ES_USER", "admin"), os.getenv("ES_PASS", "SecretPassword"))
DETECTOR_ID = os.getenv("DETECTOR_ID", "your_detector_id_here")

# Règles Wazuh personnalisées pour les attaques web Odoo
ODOO_RULE_IDS = ["100005", "100006", "100008", "100009", "100010"]

def stop_detector(detector_id):
    """Arrête le détecteur s'il est en cours d'exécution."""
    stop_url = f"{INDEXER_URL}/_plugins/_anomaly_detection/detectors/{detector_id}/_stop"
    try:
        response = requests.post(stop_url, auth=AUTH, verify=False, timeout=30)
        if response.status_code in [200, 404]:
            print(f"[*] Detector {detector_id} stopped or not running.")
        else:
            print(f"[-] Stop response: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error stopping detector: {e}")

def start_detector(detector_id):
    """Démarre le détecteur."""
    start_url = f"{INDEXER_URL}/_plugins/_anomaly_detection/detectors/{detector_id}/_start"
    try:
        response = requests.post(start_url, auth=AUTH, verify=False, timeout=30)
        if response.status_code == 200:
            print(f"[+] Detector {detector_id} started successfully.")
        else:
            print(f"[-] Start failed: {response.status_code} - {response.text}")
        return response
    except requests.exceptions.RequestException as e:
        print(f"[!] Error starting detector: {e}")
        return None

def update_detector(detector_id):
    """Met à jour la configuration du détecteur avec un filtre sur les IDs de règles Odoo."""
    url = f"{INDEXER_URL}/_plugins/_anomaly_detection/detectors/{detector_id}"
    payload = {
        "name": "odoo-web-attack-detector",
        "description": "Anomaly detector for Odoo web attacks (brute force, path traversal, web scanning)",
        "time_field": "timestamp",
        "indices": ["wazuh-alerts-*"],
        "filter_query": {
            "bool": {
                "filter": [
                    {"terms": {"rule.id": ODOO_RULE_IDS}}
                ]
            }
        },
        "feature_attributes": [
            {
                "feature_id": "event_count",
                "feature_name": "event_count",
                "feature_enabled": True,
                "aggregation_query": {
                    "event_count": {"value_count": {"field": "_id"}}
                }
            }
        ],
        "detection_interval": {"period": {"interval": 1, "unit": "MINUTES"}},
        "window_delay": {"period": {"interval": 1, "unit": "MINUTES"}}
    }
    try:
        response = requests.put(url, auth=AUTH, json=payload, verify=False, timeout=30)
        if response.status_code == 200:
            print(f"[+] Detector updated successfully. Filtering on rule IDs: {', '.join(ODOO_RULE_IDS)}")
            return True
        else:
            print(f"[-] Update failed: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[!] Error updating detector: {e}")
        return False

def get_detector_status(detector_id):
    """Récupère et affiche le statut actuel du détecteur."""
    status_url = f"{INDEXER_URL}/_plugins/_anomaly_detection/detectors/{detector_id}"
    try:
        response = requests.get(status_url, auth=AUTH, verify=False, timeout=30)
        if response.status_code == 200:
            data = response.json()
            status = data.get("detector", {}).get("status", "Unknown")
            print(f"[*] Detector status: {status}")
            return status
        else:
            print(f"[-] Status check failed: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Error checking status: {e}")
        return None

def main():
    print("=" * 60)
    print(" OpenSearch Anomaly Detection - Detector Configuration")
    print("=" * 60)
    print(f"[*] Detector ID: {DETECTOR_ID}")
    print(f"[*] Target rule IDs: {', '.join(ODOO_RULE_IDS)}\n")

    print("[*] Step 1: Stopping existing detector...")
    stop_detector(DETECTOR_ID)
    time.sleep(2)

    print("[*] Step 2: Updating detector configuration...")
    success = update_detector(DETECTOR_ID)
    time.sleep(2)

    if success:
        print("[*] Step 3: Starting detector...")
        start_detector(DETECTOR_ID)
        time.sleep(3)

        print("[*] Step 4: Verifying detector status...")
        status = get_detector_status(DETECTOR_ID)
        print()
        if status == "RUNNING":
            print("[+] Detector is now RUNNING successfully.")
            print("[*] The detector will now analyze Odoo attack patterns in real-time.")
        else:
            print("[!] Detector status is not RUNNING. Manual intervention may be required.")
    else:
        print("[!] Detector update failed. Please check the configuration and try again.")
        sys.exit(1)
    print("=" * 60)

if __name__ == "__main__":
    main()