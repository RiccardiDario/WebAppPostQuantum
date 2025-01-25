# Usa l'immagine base curl modificata da OQS
FROM openquantumsafe/curl:latest

# Passa temporaneamente all'utente root per installare pacchetti di sistema
USER root

# Crea una directory di lavoro
WORKDIR /app

# Copia lo script Python
COPY analyze_requests.py /app/analyze_requests.py

# Installa Python3, pip e pacchetti necessari forzando il blocco
RUN apk add --no-cache python3 py3-pip py3-psutil libpcap-dev gcc musl-dev linux-headers tshark \
    && PIP_BREAK_SYSTEM_PACKAGES=1 pip install --no-cache-dir scapy psutil pyshark

# Torna all'utente predefinito
#USER oqs

# Comando per eseguire lo script e mantenere il container attivo
CMD ["sh", "-c", "python3 /app/analyze_requests.py && tail -f /dev/null"]
