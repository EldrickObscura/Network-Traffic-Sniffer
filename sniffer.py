import scapy.all as scapy
import datetime
import re

# Définition des critères de détection
SENSITIVE_KEYWORDS = ["admin", "login", "secret"]
MAX_REQUESTS_PER_DOMAIN = 10  # Nombre maximal de requêtes autorisées vers un domaine

domain_request_counts = {}  # Stockage des requêtes par domaine

def extract_domain(payload):
    """Extrait le domaine d'une requête HTTP."""
    try:
        domain_match = re.search(r"Host: (.*?)\r\n", payload)
        return domain_match.group(1) if domain_match else "UNKNOWN"
    except Exception as e:
        print(f"Erreur lors de l'extraction du domaine : {e}")
        return "UNKNOWN"

def detect_anomalies(packet):
    """Détecte les anomalies dans un paquet réseau."""
    anomalies = []

    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

        # Détection DNS
        if packet.haslayer(scapy.DNSQR):
            domain = packet[scapy.DNSQR].qname.decode()
            if any(keyword in domain for keyword in SENSITIVE_KEYWORDS):
                anomalies.append(f"Requête DNS suspecte vers {domain}")

        # Détection HTTP et FTP
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            try:
                payload = packet[scapy.Raw].load.decode(errors="ignore")
                if "HTTP" in payload:
                    domain = extract_domain(payload)
                    if domain != "UNKNOWN":
                        domain_request_counts[domain] = domain_request_counts.get(domain, 0) + 1

                        if domain_request_counts[domain] > MAX_REQUESTS_PER_DOMAIN:
                            anomalies.append(f"Nombre de requêtes anormalement élevé vers {domain}")

                    if any(keyword in payload for keyword in SENSITIVE_KEYWORDS):
                        anomalies.append("URL suspecte contenant un mot-clé sensible")

                elif "USER" in payload or "PASS" in payload:
                    anomalies.append("Connexion FTP détectée, potentiellement risquée")
            except Exception as e:
                print(f"Erreur lors du traitement du paquet TCP : {e}")

    return anomalies

def process_packet(packet):
    """Traite un paquet capturé et enregistre les informations uniquement si pertinent."""
    if packet.haslayer(scapy.IP):
        try:
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            request_type = "UNKNOWN"
            domain_url = "UNKNOWN"

            # Identification DNS
            if packet.haslayer(scapy.DNSQR):
                request_type = "DNS"
                domain_url = packet[scapy.DNSQR].qname.decode()

            # Identification HTTP et FTP
            elif packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
                try:
                    payload = packet[scapy.Raw].load.decode(errors="ignore")
                    if "HTTP" in payload:
                        request_type = "HTTP"
                        domain_url = extract_domain(payload)
                    elif "USER" in payload or "PASS" in payload:
                        request_type = "FTP"
                        domain_url = "FTP Request"  # Vous pouvez ajouter un domaine si nécessaire
                except Exception as e:
                    print(f"Erreur lors de l'analyse du paquet Raw : {e}")

            # Détection d'anomalies
            anomalies = detect_anomalies(packet)
            status = "ANORMAL" if anomalies else "NORMAL"
            explanation = ", ".join(anomalies) if anomalies else "Aucune anomalie détectée"

            # Enregistrer uniquement si le paquet est HTTP, DNS ou FTP
            if request_type != "UNKNOWN":  # On n'enregistre pas les paquets "UNKNOWN"
                # Construction de la ligne de log
                log_entry = f"[{timestamp}] {src_ip} -> {dst_ip}\n"
                log_entry += f"Requête : {request_type}\n"
                log_entry += f"Domaine/URL : {domain_url}\n"
                log_entry += f"Statut : {status}\n"
                log_entry += f"Explication : {explanation}\n\n"

                # Affichage et sauvegarde des logs
                print(log_entry)
                with open("traffic_log.txt", "a") as f:
                    f.write(log_entry)
        except Exception as e:
            print(f"Erreur lors du traitement du paquet IP : {e}")

def sniff_traffic(interface):
    """Capture le trafic réseau uniquement sur HTTP, DNS et FTP, et enregistre uniquement les paquets pertinents."""
    try:
        print(f"🔎 Capture du trafic sur {interface} (HTTP, DNS, FTP, et autres)...")
        scapy.sniff(iface=interface, store=False, prn=process_packet)
    except Exception as e:
        print(f"Erreur lors de la capture des paquets : {e}")

if __name__ == "__main__":
    interface = "Wi-Fi"  # Remplace par ton interface réseau correcte (ex: wlan0, eth0)
    sniff_traffic(interface)
