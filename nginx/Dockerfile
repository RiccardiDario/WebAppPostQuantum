FROM openquantumsafe/nginx:latest

# Passa a root per eventuali modifiche
USER root

# Installa Python e librerie necessarie
RUN apk update && apk add --no-cache python3 py3-pip py3-psutil

# Copia i file di configurazione
COPY nginx.conf /opt/nginx/nginx-conf/nginx.conf

# Copia lo script di monitoraggio
COPY monitor_nginx.py /opt/nginx/scripts/monitor_nginx.py

# Comando per avviare Nginx e lo script
CMD ["sh", "-c", "nginx -c nginx-conf/nginx.conf -g 'daemon off;' & python3 /opt/nginx/scripts/monitor_nginx.py"]