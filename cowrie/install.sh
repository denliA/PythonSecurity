#!/bin/bash

# Vérifiez si Docker est installé
if ! command -v docker &> /dev/null; then
    echo "Docker n'est pas installé. Installez Docker et réessayez."
    exit 1
fi

# Pull de l'image officielle de Cowrie
echo "Téléchargement de l'image Cowrie..."
docker pull cowrie/cowrie:latest

# Exécution du conteneur
echo "Lancement du conteneur Cowrie..."
docker run -d \
    --name cowrie-honeypot \
    -p 2222:2222 \
    -v $(pwd)/data:/cowrie/var \
    cowrie/cowrie:latest

# Vérification
if [ $? -eq 0 ]; then
    echo "Honeypot Cowrie en cours d'exécution !"
else
    echo "Échec du lancement du conteneur Cowrie."
fi
