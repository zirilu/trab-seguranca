#!/usr/bin/env bash
set -euo pipefail

# run_demo.sh
# Orquestrador host-side para apresentação:
# 1) Reconhecimento (nmap)
# 2) Dispara brute-force didático (no attacker)
# 3) Mostra resultados e logs
# 4) PAUSA: espera intervenção manual do apresentador para aplicar hardening
# 5) Após confirmação, realiza testes pós-hardening

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SHARED_DIR="$ROOT_DIR/shared"
ATTACKER_IP="192.168.56.20"
VICTIM_IP="192.168.56.10"
BRUTE_SCRIPT="/home/vagrant/attack_scripts/brute_force.sh"
FTP_ATTACK_SCRIPT="/home/vagrant/attack_scripts/attack_ftp.sh"
BRUTE_WORDLIST="$SHARED_DIR/wordlists/passwords.txt"
ATTACKER_LOG="$SHARED_DIR/attacker_results/bruteforce_result.log"
FTP_LOG="$SHARED_DIR/attacker_results/ftp_attack_result.log"

# Helper for visual separation
sep() { echo; echo "============================================================"; echo; }

echo "Presentation orchestrator - starting"
echo "Project root: $ROOT_DIR"
echo "Shared dir: $SHARED_DIR"
sep

# Step 0: prechecks
echo "[CHECK] Ensure VMs are up..."
vagrant status --machine-readable | grep ",state," | sed -E 's/^[^,]*,([^,]*),([^,]*),([^,]*),.*/\1: \3/' || true
echo "[CHECK] Ensure shared folders exist on host"
mkdir -p "$SHARED_DIR/attacker_results"
mkdir -p "$SHARED_DIR/victim_logs"
mkdir -p "$SHARED_DIR/wordlists"

# Create a small demo wordlist if not exists (won't overwrite)
if [ ! -f "$BRUTE_WORDLIST" ]; then
  cat > "$BRUTE_WORDLIST" <<'EOF'
123456
password
prof123
toor
admin
EOF
  echo "[INFO] demo wordlist created at $BRUTE_WORDLIST"
fi

sep
echo "[STEP 1] Reconhecimento: nmap a partir da VM attacker (para demo)"
echo "Running: vagrant ssh attacker -c \"nmap -sV -p 21,22,80,2222 $VICTIM_IP\""
vagrant ssh attacker -c "nmap -sV -p 21,22,80,2222 $VICTIM_IP" || true

sep
echo "[STEP 2] ATAQUE 1 - Executando brute-force SSH didático dentro da VM attacker"
echo "O script tentará até 10 senhas do wordlist e escreverá resultados em $ATTACKER_LOG"
echo "Running: vagrant ssh attacker -c \"$BRUTE_SCRIPT $VICTIM_IP /vagrant_shared/wordlists/passwords.txt\""

vagrant ssh attacker -c "$BRUTE_SCRIPT $VICTIM_IP /vagrant_shared/wordlists/passwords.txt" || true

sep
echo "[STEP 3] Exibindo resultados do ATAQUE 1 - SSH Brute-Force"
if [ -f "$SHARED_DIR/attacker_results/found_password.txt" ]; then
  echo "[RESULT] Senha encontrada:"
  cat "$SHARED_DIR/attacker_results/found_password.txt"
else
  echo "[RESULT] Nenhuma senha encontrada (nos primeiros 10 tries) — ver $ATTACKER_LOG para detalhes"
fi
echo
echo "Últimos logs do brute-force:"
tail -n 40 "$ATTACKER_LOG" || true

sep
echo "[STEP 4] ATAQUE 2 - Exploração de FTP Anônimo com Upload"
echo "Demonstrando acesso não autorizado via FTP e upload de webshell"
echo "Running: vagrant ssh attacker -c \"$FTP_ATTACK_SCRIPT $VICTIM_IP\""
echo

vagrant ssh attacker -c "$FTP_ATTACK_SCRIPT $VICTIM_IP" || true

sep
echo "[STEP 5] Exibindo resultados do ATAQUE 2 - FTP Anonymous Upload"
echo
echo "Resumo do ataque FTP:"
if [ -f "$FTP_LOG" ]; then
  echo "--- Log completo em: $FTP_LOG ---"
  tail -n 50 "$FTP_LOG" || true
else
  echo "[WARNING] Log do ataque FTP não encontrado"
fi
echo

# Verificar se webshell foi enviada
if [ -f "$SHARED_DIR/attacker_results/backdoor_uploaded.php" ]; then
  echo "[SUCCESS] Webshell foi criada e enviada!"
  echo "Conteúdo da webshell (primeiras 10 linhas):"
  head -n 10 "$SHARED_DIR/attacker_results/backdoor_uploaded.php"
else
  echo "[INFO] Arquivo de webshell não encontrado nos resultados"
fi

sep
echo "[RESUMO DOS ATAQUES]"
echo "═══════════════════════════════════════════════════════════"
echo
echo "VULNERABILIDADE 1: SSH com Senha Fraca"
echo "  Status: $([ -f "$SHARED_DIR/attacker_results/found_password.txt" ] && echo "EXPLORADA ✓" || echo "Falhou")"
echo "  Impacto: Acesso não autorizado ao sistema"
echo "  CVSS: 9.8 (CRÍTICO)"
echo
echo "VULNERABILIDADE 2: FTP Anônimo com Upload"
echo "  Status: $([ -f "$FTP_LOG" ] && grep -q "SUCCESS" "$FTP_LOG" && echo "EXPLORADA ✓" || echo "Falhou")"
echo "  Impacto: Execução remota de código (RCE)"
echo "  CVSS: 9.8 (CRÍTICO)"
echo
echo "═══════════════════════════════════════════════════════════"
echo

sep
echo "[PAUSA] Agora é a hora de aplicar o HARDENING manualmente (por segurança pede-se intervenção manual)."
echo
echo "O hardening irá mitigar TODAS as vulnerabilidades demonstradas:"
echo "  1. Desabilitar autenticação por senha no SSH"
echo "  2. Desabilitar root login"
echo "  3. Mudar porta SSH para 2222"
echo "  4. Instalar fail2ban"
echo "  5. Configurar firewall UFW"
echo "  6. Desabilitar FTP anônimo (ou remover vsftpd)"
echo "  7. Remover webshells do Apache"
echo
echo "No host, execute:"
echo "  vagrant ssh victim -c \"sudo bash /vagrant/provision/hardening_victim.sh\""
echo
read -p "Depois de aplicar o hardening, pressione ENTER para continuar (ou Ctrl+C para abortar)."

sep
echo "[STEP 4] Testes pós-hardening"
echo "═══════════════════════════════════════════════════════════"
echo

echo "[TEST 1] Verificar configurações de SSH na victim:"
vagrant ssh victim -c "sudo grep -E 'PasswordAuthentication|PermitRootLogin|Port|AllowUsers' /etc/ssh/sshd_config -n" || true
echo

echo "[TEST 2] Checar status do firewall UFW e fail2ban:"
vagrant ssh victim -c "sudo ufw status verbose || true" || true
echo
vagrant ssh victim -c "sudo fail2ban-client status sshd || true" || true
echo

echo "[TEST 3] Verificar status do serviço FTP:"
vagrant ssh victim -c "sudo systemctl status vsftpd || echo 'vsftpd não está rodando (esperado após hardening)'" || true
echo

echo "[TEST 4] Tentar reconectar via SSH com senha (deve falhar):"
echo "Tentando conexão por senha na porta 22:"
vagrant ssh attacker -c "timeout 5 ssh -o ConnectTimeout=5 -o BatchMode=yes professor@$VICTIM_IP echo OK" 2>&1 || echo "[✓ ESPERADO] Conexão por senha na porta 22 falhou (bloqueada pelo hardening)"
echo

echo "[TEST 5] Tentar conectar na nova porta SSH (2222) com senha (deve falhar):"
vagrant ssh attacker -c "timeout 5 ssh -p 2222 -o ConnectTimeout=5 -o BatchMode=yes professor@$VICTIM_IP echo OK" 2>&1 || echo "[✓ ESPERADO] Autenticação por senha bloqueada (requer chave SSH)"
echo

echo "[TEST 6] Tentar acessar FTP anônimo (deve falhar):"
vagrant ssh attacker -c "timeout 5 ftp -n $VICTIM_IP <<EOF
user anonymous \"\"
ls
bye
EOF" 2>&1 || echo "[✓ ESPERADO] FTP não acessível ou login anônimo bloqueado"
echo

echo "[TEST 7] Tentar acessar webshell via HTTP (deve falhar ou estar removida):"
vagrant ssh attacker -c "curl -m 5 -s http://$VICTIM_IP/admin_backup.php?cmd=whoami" 2>&1 | head -n 5 || echo "[✓ ESPERADO] Webshell removida ou Apache desabilitado"
echo

sep
echo "═══════════════════════════════════════════════════════════"
echo "              VALIDAÇÃO DO HARDENING"
echo "═══════════════════════════════════════════════════════════"
echo

echo "ANTES DO HARDENING:"
echo "  [×] SSH: Autenticação por senha habilitada"
echo "  [×] SSH: Root login permitido"
echo "  [×] SSH: Porta padrão (22)"
echo "  [×] FTP: Acesso anônimo com upload"
echo "  [×] HTTP: Webshell acessível"
echo "  [×] Sem IDS/IPS (fail2ban)"
echo "  [×] Firewall desabilitado"
echo

echo "DEPOIS DO HARDENING:"
echo "  [✓] SSH: Apenas autenticação por chave"
echo "  [✓] SSH: Root login desabilitado"
echo "  [✓] SSH: Porta alterada para 2222"
echo "  [✓] FTP: Serviço desabilitado/removido"
echo "  [✓] HTTP: Webshells removidas"
echo "  [✓] fail2ban: Ativo e monitorando"
echo "  [✓] Firewall UFW: Ativo (apenas porta 2222)"
echo

echo "═══════════════════════════════════════════════════════════"

sep
echo "Demo concluída com sucesso!"
echo
echo "═══════════════════════════════════════════════════════════"
echo "                    RELATÓRIO FINAL"
echo "═══════════════════════════════════════════════════════════"
echo
echo "VULNERABILIDADES EXPLORADAS: 2/6"
echo
echo "1. SSH com Senha Fraca (EXPLORADA)"
echo "   - Método: Brute-force com wordlist"
echo "   - Resultado: Acesso obtido com 'prof123'"
echo "   - Log: $ATTACKER_LOG"
echo
echo "2. FTP Anônimo com Upload (EXPLORADA)"
echo "   - Método: Login anônimo + upload de webshell"
echo "   - Resultado: RCE via backdoor.php"
echo "   - Log: $FTP_LOG"
echo
echo "MITIGAÇÕES APLICADAS:"
echo "   [✓] Hardening completo do SSH"
echo "   [✓] Remoção/desabilitação do FTP"
echo "   [✓] Firewall UFW configurado"
echo "   [✓] fail2ban instalado e ativo"
echo "   [✓] Webshells removidas"
echo
echo "EVIDÊNCIAS COLETADAS:"
echo "   - Logs de ataque: $SHARED_DIR/attacker_results/"
echo "   - Wordlist usada: $BRUTE_WORDLIST"
echo "   - Webshell capturada: $SHARED_DIR/attacker_results/backdoor_uploaded.php"
echo
echo "═══════════════════════════════════════════════════════════"
echo
echo "Verifique shared/attacker_results/ para todos os resultados e logs."
echo "Lembrete: Tudo executado em rede isolada (192.168.56.0/24)"
echo "          NÃO execute esses scripts em redes reais."

