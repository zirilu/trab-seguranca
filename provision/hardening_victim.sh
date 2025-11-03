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
sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config || echo "Port 2222" >> /etc/ssh/sshd_config

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

systemctl restart ssh
echo "Hardening applied at $(date)" > /vagrant_shared/hardening_done.txt