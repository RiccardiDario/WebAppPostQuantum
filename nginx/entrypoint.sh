#!/bin/sh

OPENSSL_CONF="/etc/ssl/openssl.cnf"

# Se il file non esiste, lo crea da zero
if [ ! -f "$OPENSSL_CONF" ]; then
    echo "Il file $OPENSSL_CONF non esiste. Lo sto creando..."
    cat > "$OPENSSL_CONF" <<EOL
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
EOL
else
    echo "Il file $OPENSSL_CONF esiste già, procedo con le modifiche..."
    sed -i '/\[provider_sect\]/,/^\[/c\[provider_sect]\ndefault = default_sect\noqsprovider = oqsprovider_sect' "$OPENSSL_CONF"

    if ! grep -q '\[default_sect\]' "$OPENSSL_CONF"; then
        echo -e '\n[default_sect]\nactivate = 1' >> "$OPENSSL_CONF"
    else
        sed -i '/\[default_sect\]/,/^\[/c\[default_sect]\nactivate = 1' "$OPENSSL_CONF"
    fi

    if ! grep -q '\[oqsprovider_sect\]' "$OPENSSL_CONF"; then
        echo -e '\n[oqsprovider_sect]\nactivate = 1' >> "$OPENSSL_CONF"
    fi

    if grep -q 'providers = provider_sect' "$OPENSSL_CONF"; then
        sed -i '/providers = provider_sect/d' "$OPENSSL_CONF"
    fi

    echo -e '\n[openssl_init]\nproviders = provider_sect\n' >> "$OPENSSL_CONF"
fi

# Mostra la versione di OpenSSL
echo "Versione OpenSSL utilizzata:"
openssl version

# Controlla se il provider OQS è installato
if [ ! -d "/usr/local/lib/ossl-modules" ]; then
    echo "Errore: la cartella /usr/local/lib/ossl-modules non esiste, OQS-Provider potrebbe non essere installato correttamente."
fi

# Avvia Nginx
exec nginx -g "daemon off;"