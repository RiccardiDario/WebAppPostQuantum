# Usa l'immagine base curl modificata da OQS
FROM openquantumsafe/curl:latest

# Passa temporaneamente all'utente root per installare pacchetti di sistema
USER root

# Crea una directory di lavoro
WORKDIR /app

# Copia lo script Python
COPY analyze_requests.py /app/analyze_requests.py

# Installa Python e librerie necessarie
RUN apk update && apk add --no-cache python3 py3-pip py3-psutil

# Torna all'utente predefinito
#USER oqs

# Comando per eseguire lo script e mantenere il container attivo
CMD ["sh", "-c", "sleep 7 && python3 /app/analyze_requests.py && tail -f /dev/null"]
