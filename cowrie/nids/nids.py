from scapy.all import sniff, TCP, IP
from datetime import datetime
import time
import subprocess
from collections import defaultdict

# Ports à surveiller
SSH_PORT = 2222
TELNET_PORT = 2223

# Variables pour la détection
brute_force_attempts = defaultdict(list)  # Tentatives par IP
telnet_activities = defaultdict(list)  # Activités Telnet par IP
blocked_ips = set()

# Limite et fenêtre pour le brute-force
LIMIT_ATTEMPTS = 10
TIME_WINDOW = 60  # En secondes

# Chemin des fichiers de logs
LOG_FILE = "/app/logs/alerts.log"

def log_alert(message):
    """
    Enregistre un message d'alerte dans le fichier des alertes.
    """
    try:
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"[{datetime.now()}] {message}\n")
        print(message)
    except Exception as e:
        print(f"Error writing to alert log file: {e}")

def block_ip(ip):
    """
    Bloque une adresse IP via iptables et termine ses connexions actives.
    """
    if ip not in blocked_ips:
        try:
            # Ajouter une règle iptables
            command = f"iptables -A INPUT -s {ip} -j DROP"
            subprocess.run(command.split(), check=True)
            log_alert(f"[ACTION] Blocked IP {ip}")
            blocked_ips.add(ip)

            # Terminer les connexions actives pour l'IP
            kill_command = f"pkill -f 'telnet.*{ip}'"
            subprocess.run(kill_command, shell=True, check=False)
            log_alert(f"[ACTION] Terminated active Telnet sessions for IP {ip}")
        except Exception as e:
            log_alert(f"[ERROR] Failed to block IP {ip}: {e}")

def detect_bruteforce(packet):
    """
    Détecte une attaque par force brute en surveillant les paquets SYN.
    """
    if IP in packet and TCP in packet:
        ip_source = packet[IP].src
        port_dest = packet[TCP].dport

        # Surveiller uniquement le port SSH et les paquets SYN
        if port_dest == SSH_PORT and packet[TCP].flags == "S":
            timestamp = time.time()

            # Enregistrer la tentative pour cette IP
            brute_force_attempts[ip_source].append(timestamp)

            # Nettoyer les tentatives plus anciennes que la fenêtre
            brute_force_attempts[ip_source] = [
                t for t in brute_force_attempts[ip_source] if timestamp - t <= TIME_WINDOW
            ]

            # Vérifier le seuil d'attaques
            if len(brute_force_attempts[ip_source]) > LIMIT_ATTEMPTS:
                log_alert(f"[ALERT] Possible SSH brute-force from {ip_source} (Attempts: {len(brute_force_attempts[ip_source])})")
                block_ip(ip_source)

def detect_telnet_activity(packet):
    """
    Surveille les activités Telnet pour détecter des commandes malveillantes.
    """
    if IP in packet and TCP in packet and packet[TCP].dport == TELNET_PORT:
        ip_source = packet[IP].src
        payload = bytes(packet[TCP].payload).decode("utf-8", errors="ignore")

        # Détecter une commande suspecte
        if "/etc/passwd" in payload or "passwd" in payload:
            log_alert(f"[ALERT] Sensitive file access detected via Telnet from {ip_source}: {payload}")
            telnet_activities[ip_source].append(payload)
            block_ip(ip_source)

def process_packet(packet):
    """
    Traite les paquets capturés.
    """
    if TCP in packet:
        detect_bruteforce(packet)
        detect_telnet_activity(packet)

if __name__ == "__main__":
    print("Starting NIDS...")
    log_alert("NIDS service started. Monitoring network traffic.")
    try:
        # Surveiller l'interface `lo` en mode host
        sniff(iface="lo", filter="tcp", prn=process_packet, store=False)
    except KeyboardInterrupt:
        log_alert("NIDS service stopped.")
        print("NIDS stopped.")
    except Exception as e:
        log_alert(f"NIDS encountered an error: {e}")
        print(f"Unexpected error: {e}")
