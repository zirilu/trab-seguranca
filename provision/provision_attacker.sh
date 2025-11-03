#!/usr/bin/env bash
set -e

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get upgrade -y

apt-get install -y openssh-client nmap net-tools curl

# cria pasta compartilhada
mkdir -p /vagrant_shared/attacker_results
chown -R vagrant:vagrant /vagrant_shared

echo "Provision attacker finished at $(date)" > /vagrant_shared/attacker_provision_done.txt