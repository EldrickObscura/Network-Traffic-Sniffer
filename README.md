
# Network Traffic Sniffer

## Introduction

Le **Network Traffic Sniffer** est un outil de capture et d'analyse du trafic réseau développé en Python. Il permet de capturer les paquets réseau en temps réel et d'analyser différents types de requêtes (HTTP, DNS, FTP). L'objectif principal de cet outil est de détecter les anomalies et les comportements suspects dans les paquets réseau, comme la présence de mots-clés sensibles dans les requêtes HTTP ou DNS, ainsi que des connexions FTP risquées. 

Il génère des logs détaillés pour chaque paquet capturé, afin de fournir un rapport clair sur les éventuelles anomalies détectées.

### Fonctionnalités :
- Capture du trafic réseau HTTP, DNS et FTP.
- Détection de requêtes DNS suspectes avec des mots-clés sensibles.
- Détection d'un nombre élevé de requêtes vers un même domaine (potentielle attaque de type DoS).
- Détection de connexions FTP risquées avec l'utilisation des commandes `USER` et `PASS`.
- Sauvegarde des informations dans un fichier log `traffic_log.txt`.

## Installation

1. **Clonez le dépôt :**

   ```bash
   git clone https://github.com/votre-repository/Network-Traffic-Sniffer.git
   cd Network-Traffic-Sniffer
   ```

2. **Créez un environnement virtuel (optionnel mais recommandé) :**

   Si vous souhaitez utiliser un environnement virtuel Python, créez-le avec la commande suivante :

   ```bash
   python3 -m venv venv
   ```

   Activez l'environnement virtuel :

   - Sur Linux/Mac :
     ```bash
     source venv/bin/activate
     ```
   - Sur Windows :
     ```bash
     venv\Scripts\activate
     ```

3. **Installez les dépendances nécessaires :**

   Assurez-vous d'avoir **Python 3.x** installé sur votre machine. Ensuite, installez les dépendances via **pip** avec la commande suivante :

   ```bash
   pip install -r requirements.txt
   ```

4. **Vérifiez l'installation des dépendances :**

   Vous pouvez vérifier que **Scapy** est correctement installé en exécutant la commande suivante :

   ```bash
   pip show scapy
   ```

## Utilisation

1. **Exécution du sniffer :**

   Une fois que vous avez installé les dépendances, vous pouvez exécuter le script **`sniffer.py`** en spécifiant l'interface réseau que vous souhaitez surveiller. Par exemple, si vous voulez analyser l'interface `eth0`, utilisez la commande suivante :

   ```bash
   python3 sniffer.py eth0
   ```

   Remplacez **`eth0`** par le nom de l'interface réseau que vous souhaitez surveiller. Vous pouvez trouver le nom de votre interface en exécutant la commande `ifconfig` (Linux/Mac) ou `ipconfig` (Windows).

## Explication de la logique de détection

### Critères de détection

- **Requêtes DNS suspectes** : Si un domaine contient des mots-clés sensibles tels que "admin", "login", ou "secret", il est considéré comme suspect.
- **Requêtes HTTP avec des mots-clés sensibles** : Si l'URL d'une requête HTTP contient l'un des mots-clés sensibles, cela est enregistré comme une anomalie.
- **Connexion FTP risquée** : Si un paquet FTP contient les mots "USER" ou "PASS", cela indique une tentative de connexion FTP et est marqué comme potentiellement risqué.
- **Requêtes anormalement fréquentes vers un même domaine** : Si un domaine reçoit plus de 10 requêtes (configurable), cela est enregistré comme une anomalie.

### Fonctionnalités principales

1. **Capture du trafic réseau** : Le sniffer capture les paquets sur les ports 80 (HTTP), 53 (DNS) et 21 (FTP).
2. **Détection des anomalies** : Le sniffer analyse les paquets capturés et détecte les anomalies en fonction des critères définis (mots-clés sensibles, nombre de requêtes, etc.).
3. **Enregistrement des logs** : Les anomalies détectées sont enregistrées dans un fichier **`traffic_log.txt`**.

## Exemples de sortie

Voici un exemple de sortie que vous trouverez dans le fichier **`traffic_log.txt`**. Ce fichier contient les détails des paquets capturés et des anomalies détectées.

Extrait du fichier **`traffic_log.txt`** :

```
[2025-03-08 18:31:14] 192.168.1.173 -> 192.168.1.1
Requête : DNS
Domaine/URL : example.com
Statut : NORMAL
Explication : Aucune anomalie détectée

[2025-03-08 18:32:45] 192.168.1.173 -> 192.168.1.1
Requête : HTTP
Domaine/URL : login.example.com
Statut : ANORMAL
Explication : URL suspecte contenant un mot-clé sensible

[2025-03-08 18:58:50] 192.168.1.173 -> 192.168.1.1
Requête : FTP
Domaine/URL : FTP Request
Statut : ANORMAL
Explication : Connexion FTP détectée, commande USER suivie de PASS
```

## Remarques

- **Permissions administratives** : Sur certains systèmes d'exploitation, l'exécution du sniffer peut nécessiter des privilèges administratifs. Assurez-vous d'exécuter le script avec les droits appropriés (par exemple, `sudo` sur Linux).
- **Interfaces réseau** : Le nom de l'interface réseau peut varier en fonction de votre système. Utilisez `ifconfig` (Linux/Mac) ou `ipconfig` (Windows) pour vérifier le nom de votre interface réseau.
- **Attention aux faux positifs** : Si vous capturez un grand nombre de paquets, il peut y avoir des faux positifs dans les anomalies détectées, en particulier dans des réseaux à fort trafic.

---

**Auteurs** : [David Eldrick]        

**Date** : Mars 2025
