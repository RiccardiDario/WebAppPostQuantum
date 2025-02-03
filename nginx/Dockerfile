FROM openquantumsafe/nginx:latest

# Passa a root per eventuali modifiche
USER root

# Installa Python e librerie necessarie
RUN apk update && apk add --no-cache python3 py3-pip py3-psutil

# Copia i file di configurazione e gli script
COPY nginx.conf /opt/nginx/nginx-conf/nginx.conf
COPY start_server.py /opt/nginx/scripts/start_server.py

# Comando per avviare il monitoraggio continuo e Nginx
CMD ["sh", "-c", "sleep 5 && python3 /opt/nginx/scripts/start_server.py  & nginx -c /opt/nginx/nginx-conf/nginx.conf -g 'daemon off;'"]