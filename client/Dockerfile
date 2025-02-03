# Usa l'immagine base curl modificata da OQS
FROM openquantumsafe/curl:latest

# Passa temporaneamente all'utente root per installare pacchetti di sistema
USER root

# Crea una directory di lavoro
WORKDIR /app

# Copia lo script Python
COPY start_client.py /app/start_client.py

# Installa Python e librerie necessarie
RUN apk update && apk add --no-cache python3 py3-pip py3-psutil

# Comando per eseguire lo script e mantenere il container attivo
CMD ["sh", "-c", "sleep 7 && python3 /app/start_client.py && tail -f /dev/null"]

# Comando per mantenere il container attivo senza avviare lo script
#CMD ["sh", "-c", "tail -f /dev/null"]
