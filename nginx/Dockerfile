FROM openquantumsafe/nginx:latest

# Passa a root per eventuali modifiche
USER root

# Installa Python e librerie necessarie
RUN apk update && apk add --no-cache python3 py3-pip py3-psutil iproute2

# Copia i file di configurazione e gli script
COPY nginx.conf /opt/nginx/nginx-conf/nginx.conf
COPY continuous_monitor.py /opt/nginx/scripts/continuous_monitor.py
COPY analyze_performance.py /opt/nginx/scripts/analyze_performance.py

# Comando per avviare il monitoraggio continuo e Nginx
CMD ["sh", "-c", "sleep 5 && python3 /opt/nginx/scripts/continuous_monitor.py & python3 /opt/nginx/scripts/analyze_performance.py  & nginx -c /opt/nginx/nginx-conf/nginx.conf -g 'daemon off;'"]