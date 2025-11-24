#!/usr/bin/env bash
set -e

export DEBIAN_FRONTEND=noninteractive

# atualiza e instala SSH
apt-get update -y
apt-get upgrade -y
apt-get install -y openssh-server vim

# habilita e garante que o sshd está rodando
systemctl enable ssh
systemctl restart ssh

# cria usuário professor com senha fraca (só para simulação)
useradd -m -s /bin/bash professor || true
echo "professor:prof123" | chpasswd

# habilitar root com senha fraca (propositalmente inseguro para a demo)
echo "root:toor" | chpasswd

# configura sshd para permitir senhas e root login (vulnerabilidade)
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
# garante que permitrootlogin e passwordauth estão presentes (fallback)
grep -q "PermitRootLogin yes" /etc/ssh/sshd_config || echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
grep -q "PasswordAuthentication yes" /etc/ssh/sshd_config || echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
grep -q "PubkeyAuthentication yes" /etc/ssh/sshd_config || echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config

systemctl restart ssh

# garante diretório de logs compartilhado
mkdir -p /vagrant_shared/victim_logs
chown -R vagrant:vagrant /vagrant_shared

# cria um arquivo que o "atacante" pode modificar para demonstrar manipulação
echo "Relatório institucional - CONFIDENCIAL" > /home/professor/relatorio_institucional.txt
chown professor:professor /home/professor/relatorio_institucional.txt

# baixa utilitários úteis para análise local
apt-get install -y net-tools iproute2

# registra status
echo "Provision victim finished at $(date)" > /vagrant_shared/victim_provision_done.txt
