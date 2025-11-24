#!/usr/bin/env bash
set -e

export DEBIAN_FRONTEND=noninteractive

# atualiza
apt-get update -y
apt-get upgrade -y

# 1) desabilitar root login
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# 2) desabilitar autenticação por senha, exigir chaves (atenção: antes de rodar, garantir que a chave pública do admin esteja em /root/.ssh/authorized_keys ou no usuário professor)
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# 3) mudar porta SSH para 2222 (reduz ruído de scans básicos)
sed -i 's/^#*Port .*/Port 2222/' /etc/ssh/sshd_config
grep -q "^Port 2222" /etc/ssh/sshd_config || echo "Port 2222" >> /etc/ssh/sshd_config

# 4) instalar fail2ban
apt-get install -y fail2ban

# criar configuração básica fail2ban para ssh
cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
systemctl restart fail2ban

# 5) firewall básico com ufw
apt-get install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow 2222/tcp
ufw --force enable

# 6) limitar usuários que podem logar via SSH (apenas professor)
grep -q "^AllowUsers professor" /etc/ssh/sshd_config || echo "AllowUsers professor" >> /etc/ssh/sshd_config

# 7) aplicar atualizações automáticas (unattended-upgrades)
apt-get install -y unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

# 8) remover/desabilitar FTP anônimo (mitigar vulnerabilidade 2)
echo ""
echo "[HARDENING] Removendo FTP anônimo..."
systemctl stop vsftpd 2>/dev/null || true
systemctl disable vsftpd 2>/dev/null || true
apt-get remove -y vsftpd 2>/dev/null || true
apt-get autoremove -y
echo "✓ FTP removido"

# 9) remover webshells e desabilitar PHP perigoso (mitigar vulnerabilidade 3)
echo ""
echo "[HARDENING] Removendo webshells e configurando Apache..."
rm -f /var/www/html/admin_backup.php 2>/dev/null || true
rm -f /var/www/html/view.php 2>/dev/null || true
rm -f /var/www/html/.env 2>/dev/null || true
rm -rf /srv/ftp 2>/dev/null || true

# Desabilitar PHP ou remover Apache completamente
systemctl stop apache2 2>/dev/null || true
systemctl disable apache2 2>/dev/null || true
# Opção 1: Remover Apache completamente (mais seguro)
apt-get remove -y apache2 php libapache2-mod-php 2>/dev/null || true
# Opção 2: Se precisar manter Apache, apenas desabilitar PHP
# sed -i 's/^allow_url_include = On/allow_url_include = Off/' /etc/php/*/apache2/php.ini
# sed -i 's/^expose_php = On/expose_php = Off/' /etc/php/*/apache2/php.ini
echo "✓ Webshells removidas e Apache desabilitado"

# 10) corrigir permissões de binários SUID (mitigar vulnerabilidade 4)
echo ""
echo "[HARDENING] Corrigindo binários SUID mal configurados..."
chmod 755 /usr/local/bin/backup_find 2>/dev/null || true
chmod 755 /usr/local/bin/backup_editor 2>/dev/null || true
rm -f /usr/local/bin/backup_find 2>/dev/null || true
rm -f /usr/local/bin/backup_editor 2>/dev/null || true

# Remover capabilities perigosas
PYTHON3_PATH=$(which python3 2>/dev/null)
if [ -n "$PYTHON3_PATH" ]; then
    setcap -r "$PYTHON3_PATH" 2>/dev/null || true
fi
echo "✓ Binários SUID corrigidos"

# 11) restringir permissões de logs (mitigar vulnerabilidade 5)
echo ""
echo "[HARDENING] Restringindo acesso aos logs..."
chmod 640 /var/log/auth.log 2>/dev/null || true
chmod 640 /var/log/syslog 2>/dev/null || true
chmod 750 /var/log
chown root:adm /var/log/auth.log 2>/dev/null || true
chown root:adm /var/log/syslog 2>/dev/null || true

# Remover logs com credenciais expostas
rm -f /var/log/app_config.log 2>/dev/null || true
rm -f /var/backups/passwords_backup.txt 2>/dev/null || true
chmod 600 /home/professor/.bash_history 2>/dev/null || true

# Habilitar logrotate
systemctl enable logrotate.timer 2>/dev/null || true
systemctl start logrotate.timer 2>/dev/null || true
echo "✓ Permissões de logs restritas"

# 12) instalar e configurar auditd (monitoramento adicional)
echo ""
echo "[HARDENING] Instalando sistema de auditoria..."
apt-get install -y auditd
systemctl enable auditd
systemctl start auditd

# Adicionar regras de auditoria para comandos executados
cat > /etc/audit/rules.d/audit.rules <<EOF
# Auditar execuções de comandos
-a always,exit -F arch=b64 -S execve -k exec_commands

# Auditar mudanças em arquivos sensíveis
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Auditar tentativas de login
-w /var/log/auth.log -p wa -k auth_log_changes
EOF

service auditd restart 2>/dev/null || true
echo "✓ auditd configurado"

# 13) limitar configurações SSH adicionais
echo ""
echo "[HARDENING] Aplicando configurações SSH adicionais..."
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^#*MaxSessions.*/MaxSessions 2/' /etc/ssh/sshd_config
sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config
grep -q "^MaxAuthTries" /etc/ssh/sshd_config || echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
grep -q "^MaxSessions" /etc/ssh/sshd_config || echo "MaxSessions 2" >> /etc/ssh/sshd_config
grep -q "^LoginGraceTime" /etc/ssh/sshd_config || echo "LoginGraceTime 30" >> /etc/ssh/sshd_config
echo "✓ SSH rate limiting configurado"

systemctl restart ssh
echo "Hardening applied at $(date)" > /vagrant_shared/hardening_done.txt