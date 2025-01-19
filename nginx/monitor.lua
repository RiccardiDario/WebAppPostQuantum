local log_file = "/opt/nginx/logs/access.log"

-- Funzione per eseguire un comando
function execute_command(cmd)
    local handle = io.popen(cmd)
    local result = handle:read("*a")
    handle:close()
    return result
end

-- Monitora il file di log
local file = io.open(log_file, "r")
file:seek("end") -- Salta le righe esistenti

while true do
    local line = file:read("*line")
    if line then
        print("Nuova richiesta: " .. line)
        execute_command("python3 /opt/nginx/scripts/monitor_nginx.py &")
    else
        os.execute("sleep 0.1") -- Riduci l'uso di CPU
    end
end
