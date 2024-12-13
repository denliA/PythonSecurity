#!/bin/bash

# Nom du service Docker Compose
SERVICE_NAME="cowrie-honeypot"

# Vérifiez si Docker Compose est installé
if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose n'est pas installé. Veuillez l'installer et réessayer."
    exit 1
fi

# Réinitialiser le fichier alerts.log
> nids/logs/alerts.log

# Vérifiez si le conteneur existe déjà
if docker ps -a --format '{{.Names}}' | grep -Eq "^${SERVICE_NAME}\$"; then
    echo "Le conteneur '$SERVICE_NAME' existe déjà. Suppression..."
    docker-compose down
else
    echo "Aucun conteneur existant nommé '$SERVICE_NAME'."
fi

# Lancer le service avec Docker Compose
echo "Lancement du service Cowrie avec Docker Compose..."
docker-compose up -d --build

if [ $? -eq 0 ]; then
    echo "Cowrie est en cours d'exécution !"
else
    echo "Échec du lancement de Cowrie."
    exit 1
fi
