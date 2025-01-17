# Usa l'immagine Python
FROM python:3.9-slim

# Imposta la directory di lavoro
WORKDIR /app

# Copia i file dell'applicazione
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Comando per avviare l'app Flask
CMD ["python", "app.py"]
