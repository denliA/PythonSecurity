# Utiliser une image Python comme base
FROM python:3.11-slim

# Installer les dépendances nécessaires
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copier le script NIDS dans le conteneur
WORKDIR /app
COPY nids.py /app/nids.py

# Commande par défaut pour exécuter le script
CMD ["python3", "nids.py"]
