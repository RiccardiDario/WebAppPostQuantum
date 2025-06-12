Prima di avviare il progetto bisgona controllare l'estensione del file generate_certs.sh. Github tende a salvare i file con la codifica CRLF. Questa codifica rende il file non leggibile dal container cert-generator. Per ovviare a ciò basta cambiare la codifica in LF (in VS code è l'opzione in basso a destra)


Per avviare l'intero progetto basta eseguire docker compose up -d.
Il processo di build delle immagini richiede un tempo non trascurabile (circa 5 m) impiegando ingenti risorse. Quindi si consiglia prima di buildare le immagini, dopo averlo fatto stopparle e riavviare il tutto. Così da avere un'esecuzione pulita. 

L'algoritmo di kem e di firma possono essere cambiati nella sezione aposita nel docker compose.

All'interno del container docker è possibile lanciare una richiesta HTTPS attraverso PycURL o cURL nel seguente modo:
cURL: curl --tlsv1.3 --cacert /opt/certs/CA.crt -v https://192.168.1.100
 
PycURL: python3 -c "import pycurl; from io import BytesIO; b = BytesIO(); c = pycurl.Curl(); c.setopt(c.URL, 'https://192.168.1.100'); c.setopt(c.CAINFO, '/opt/certs/CA.crt'); c.setopt(c.SSLVERSION, c.SSLVERSION_TLSv1_3); c.setopt(c.VERBOSE, True); c.setopt(c.WRITEDATA, b); c.perform(); print('HTTP Response Code:', c.getinfo(c.RESPONSE_CODE)); print('Response body:\\n', b.getvalue().decode()); c.close()"


Per fermare i container e quindi terminare tutto il processo eseguire il comando docker compose down

Per eseguire i test automatici bisogna aver python con i pacchetti psutil, matplotlib, pandas, numpy. Nel caso il pc host ha un s.o windows è possibile creare un ambiente virtuale contenente tutti i pacchetti necessari con lo script setup_env.ps1
