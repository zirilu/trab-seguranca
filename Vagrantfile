# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "ubuntu/focal64"  # Ubuntu Server 20.04 LTS (pode alterar para a versão desejada)

  # pasta compartilhada para pegar logs / evidências
  config.vm.synced_folder "./shared", "/vagrant_shared"

  # VM vítima (professor)
  config.vm.define "victim" do |victim|
    victim.vm.hostname = "victim"
    victim.vm.network "private_network", ip: "192.168.56.10"
    victim.vm.provider "virtualbox" do |vb|
      vb.name = "lab_victim"
      vb.memory = 1024
      vb.cpus = 1
    end
    victim.vm.provision "shell", path: "provision/provision_victim.sh"
  end

  # VM atacante (aluno)
  config.vm.define "attacker" do |attacker|
    attacker.vm.hostname = "attacker"
    attacker.vm.network "private_network", ip: "192.168.56.20"
    attacker.vm.provider "virtualbox" do |vb|
      vb.name = "lab_attacker"
      vb.memory = 1024
      vb.cpus = 1
    end
    attacker.vm.provision "shell", path: "provision/provision_attacker.sh"
  end

  # Não expor portas para o host (mantém isolado)
  config.vm.boot_timeout = 600
end