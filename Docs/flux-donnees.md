# 🔄 Flux de données — SOC ERP Threat Detection

Ce document détaille le parcours d'une donnée (log, alerte, incident) à travers
les différents composants de l'architecture, depuis l'endpoint supervisé
jusqu'à la réponse automatisée et la génération de rapport.

> 📷 Se référer à la **Figure 1** du [README](../README.md) pour la vue d'ensemble.

## Légende des flux

| Type de flèche | Signification |
|---|---|
| 🔵 Flèche bleue | Trafic réseau (communication entre composants) |
| ⚪ Flèche blanche | Logs ou données transmises |

---

## 1.Périmètre exposé — Surface d'attaque

L'**ERP Odoo** est déployé sur une machine virtuelle **Microsoft Azure** et expose
un point d'entrée accessible depuis Internet via l'**Internet Gateway**.

- Un attaquant (**Kali Linux**) tente d'atteindre l'ERP depuis Internet.
- Le **pare-feu natif Azure (NSG / Azure Firewall)** filtre le trafic entrant :
  - Blocage des IP malveillantes connues.
  - Filtrage des ports et protocoles non autorisés.
  - Toute tentative suspecte est journalisée.

➡️ **Sortie :** trafic légitime autorisé vers l'ERP ; tentatives suspectes bloquées et journalisées.

---

## 2.  Collecte sur l'endpoint — Wazuh Agent

Un **Wazuh Agent (`W.agent`)** est installé directement sur le serveur hébergeant
l'ERP Odoo. Il joue le rôle de sonde locale.

**Rôle :**
- Surveillance des fichiers critiques (FIM — File Integrity Monitoring).
- Lecture des logs applicatifs Odoo et des logs système.
- Détection des modifications de configuration, connexions suspectes,
  élévations de privilèges.
- Envoi chiffré (port 1514/TCP) de tous les événements vers le **Wazuh Server**.

➡️ **Sortie :** flux continu de logs bruts + événements de sécurité vers le SIEM.

---

## 3.  Traitement SIEM — Wazuh

Le **Wazuh Server** reçoit les événements et applique :

1. **Décodage** — extraction des champs (IP source, utilisateur, action, etc.).
2. **Corrélation** — application des règles personnalisées alignées **MITRE ATT&CK**.
3. **Génération d'alertes** — lorsqu'une règle est déclenchée.

Deux branches de sortie :

- **Branche A — Stockage & visualisation :**
  - Les événements sont envoyés vers le **Wazuh Indexer** (indexation).
  - Le **Wazuh Dashboard** permet la recherche, la visualisation et la création de tableaux de bord SOC.
  - Les données sont ensuite transmises à la **stack ELK** via l'intégration
    *wazuh server integration* :
    - **Logstash** ingère et normalise.
    - **Elasticsearch** stocke et indexe.
    - **Kibana** offre la couche de visualisation avancée (dashboards personnalisés,
      corrélations historiques, rétention longue durée).

- **Branche B — Détection IA :**
  - Le plugin **OpenSearch Anomaly Detection** analyse les séries temporelles
    (volume de logs, fréquence d'événements, patterns inhabituels).
  - Il détecte les **déviations non supervisées** sans règle explicite
    (comportements anormaux, pics inattendus).

➡️ **Sortie :** alertes qualifiées + anomalies détectées, prêtes à être orchestrées.

---

## 4. Orchestration SOAR — Shuffle

Le **Wazuh Server** transmet les alertes critiques à **Shuffle**, la
plateforme SOAR (Security Orchestration, Automation and Response).

**Shuffle déclenche un playbook** qui peut exécuter plusieurs actions en parallèle :

| Action | Composant cible | Objectif |
|---|---|---|
| Enrichissement IP | **VirusTotal** | Vérifier la réputation d'une adresse IP ou d'un hash. |
| Enrichissement IOC | **MISP** | Croiser avec les indicateurs de compromission connus. |
| Blocage réseau | **API Azure** | Ajouter une règle NSG pour bloquer l'IP source. |
| Notification | **Gmail** | Envoyer une alerte aux analystes SOC (temps réel). |
| Création d'incident | **TheHive** | Ouvrir un cas d'investigation traçable. |
| Analyse approfondie | **Cortex** | Lancer des analyseurs (sandbox, WHOIS, réputation) sur les observables. |

➡️ **Sortie :** incident documenté, enrichi, et réponse appliquée automatiquement.

---

## 5.Gestion des incidents — TheHive / Cortex / MISP

Une fois l'incident créé dans **TheHive** :

- **Cortex** exécute les analyseurs demandés par le playbook et renvoie les résultats
  dans la fiche d'incident.
- **MISP** fournit le contexte Threat Intelligence (campagnes, acteurs, IOC associés)
  et peut aussi recevoir de nouveaux IOC générés par l'investigation.
- Les analystes SOC suivent, qualifient et clôturent l'incident depuis TheHive.

➡️ **Sortie :** incident enrichi, qualifié et archivé avec sa chronologie complète.

---

## 6. 📄 Génération de rapport — Flux planifié (LLM Groq)

> ⚠️ **Note :** ce flux **n'apparaît pas sur la Figure 1**, qui illustre
> uniquement la chaîne temps réel (détection → réponse → notification).
> La génération de rapport est un **flux batch planifié**, exécuté en marge
> du SOC.

**Déclenchement :**
- Une tâche **cron** s'exécute **toutes les 24 heures** sur le serveur.
- Elle interroge les incidents et alertes **clôturés dans les dernières 24 h**
  (TheHive API + Wazuh API).

**Traitement :**
- Un script Python agrège les données synthétiques (pas de logs bruts).
- Il envoie le tout à l'**API Groq (LLaMA 3.3 70B)**.
- Le LLM produit :
  - un résumé exécutif de la journée,
  - une classification des menaces (criticité, catégorie MITRE),
  - des recommandations d'action.

**Diffusion :**
- Le rapport est exporté en **PDF**.
- Il est **envoyé automatiquement par Gmail** à l'**analyste SOC**
  (via la même intégration Gmail visible sur le schéma, mais sur un canal
  différent de celui des alertes temps réel).

➡️ **Sortie :** rapport quotidien PDF reçu par l'analyste SOC chaque matin,
sans intervention manuelle.

---

### 🔀 Deux usages distincts de Gmail

| Canal | Déclencheur | Destinataire | Contenu |
|---|---|---|---|
| **Alertes temps réel** | Shuffle (à chaque incident) | Analyste SOC | Notification d'alerte brute |
| **Rapport quotidien** | Cron (toutes les 24 h) | Analyste SOC | PDF synthétique (LLM) |

C'est le **même service Gmail**, mais **deux playbooks différents**.

## Points clés à retenir

- **Chaque étape est traçable** : de l'événement brut jusqu'au rapport final.
- **Deux moteurs de détection complémentaires** : règles MITRE (déterministe)
  + Anomaly Detection (statistique).
- **La réponse est automatisée** mais supervisable : chaque action Shuffle
  laisse une trace dans TheHive.
- **Deux flux distincts** : un flux **temps réel** (détection → réponse) et
  un flux **planifié** (rapport quotidien via cron + LLM).
 