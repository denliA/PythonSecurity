from scapy.all import sniff, TCP
from datetime import datetime
import subprocess
import re

# Ports à surveiller
SSH_PORT = 2222
TELNET_PORT = 2223

# Variables pour la détection
ssh_attempts = {}
telnet_activity = []

# Chemin du fichier d'alertes
LOG_FILE = "/app/logs/alerts.log"

def log_alert(message):
    """
    Enregistre un message d'alerte dans le fichier de logs.
    """
    try:
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"[{datetime.now()}] {message}\n")
        print(message)
    except Exception as e:
        print(f"Error writing to log file: {e}")

def detect_bruteforce(packet):
    """
    Détecte un bruteforce SSH en surveillant les connexions sur le port 2222.
    """
    if packet[TCP].dport == SSH_PORT:
        src_ip = packet[0][1].src
        timestamp = datetime.now()

        # Compter les tentatives par IP
        if src_ip not in ssh_attempts:
            ssh_attempts[src_ip] = []
        ssh_attempts[src_ip].append(timestamp)

        # Vérifier si bruteforce (exemple : 5 tentatives en 10 secondes)
        recent_attempts = [t for t in ssh_attempts[src_ip] if (timestamp - t).seconds <= 10]
        ssh_attempts[src_ip] = recent_attempts  # Nettoyage des anciennes tentatives

        if len(recent_attempts) > 5:
            log_alert(f"[ALERT] Possible SSH brute-force from {src_ip}")

def detect_telnet_activity(packet):
    """
    Surveille les activités Telnet pour détecter des commandes malveillantes.
    """
    if packet[TCP].dport == TELNET_PORT:
        payload = bytes(packet[TCP].payload).decode("utf-8", errors="ignore")
        telnet_activity.append(payload)

        # Détecter une commande suspecte comme "cat /etc/passwd"
        if "cat /etc/passwd" in payload or re.search(r"passwd", payload):
            log_alert(f"[ALERT] Sensitive file access detected via Telnet: {payload}")

def process_packet(packet):
    """
    Gère les paquets capturés.
    """
    if TCP in packet:
        detect_bruteforce(packet)
        detect_telnet_activity(packet)

def get_last_bridge_interface():
    """
    Récupère dynamiquement le dernier bridge dans la liste obtenue via `ip link`.
    """
    try:
        interfaces_output = subprocess.check_output(["ip", "link"]).decode("utf-8")
        bridges = re.findall(r"br-[a-f0-9]+", interfaces_output)
        if bridges:
            last_bridge = bridges[-1]
            return last_bridge
        else:
            log_alert("No bridge interface found. Defaulting to eth0.")
            return "eth0"
    except Exception as e:
        log_alert(f"Error detecting bridge interface: {e}")
        return "eth0"

if __name__ == "__main__":
    print("Starting NIDS...")
    log_alert("NIDS service started. Monitoring network traffic.")
    try:
        bridge_interface = get_last_bridge_interface()
        log_alert(f"Using interface: {bridge_interface}")
        sniff(iface=bridge_interface, filter="tcp", prn=process_packet, store=False)
    except KeyboardInterrupt:
        log_alert("NIDS service stopped.")
        print("NIDS stopped.")
    except Exception as e:
        log_alert(f"NIDS encountered an error: {e}")
        print(f"Unexpected error: {e}")
