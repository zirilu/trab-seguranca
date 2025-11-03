# Laboratório de Segurança de Redes — trab-seguranca

Este repositório contém um pequeno laboratório Vagrant/VirtualBox com duas VMs:

- `victim` (IP: 192.168.56.10) — VM alvo, inicialmente configurada com vulnerabilidades intencionais.
- `attacker` (IP: 192.168.56.20) — VM atacante com ferramentas de análise.

Pasta sincronizada do host: `./shared` → `/vagrant_shared` nas VMs.

---

## Pré-requisitos

- Git
- Vagrant (recomendado >= 2.2.x)
- VirtualBox (compatível com a versão do Vagrant)
- Conexão com a Internet (para baixar a box `ubuntu/focal64` na primeira execução)

---

## Estrutura principal

- `Vagrantfile` — define as VMs `victim` e `attacker`, rede privada e pasta sincronizada `./shared`.
- `provision/provision_victim.sh` — prepara a VM vítima (intencionalmente vulnerável: senhas fracas, SSH com senha e root habilitado).
- `provision/provision_attacker.sh` — instala ferramentas (nmap, curl, etc.) e prepara diretório `/vagrant_shared/attacker_results`.
- `provision/hardening_victim.sh` — script opcional para endurecer a VM vítima (desabilita root/password auth, muda porta SSH, instala fail2ban/ufw, etc.).
- `shared/` — pasta do host compartilhada com as VMs (deve existir antes de `vagrant up`).

---

## Passos rápidos para executar o ambiente

1. Certifique-se de que a pasta `shared/` existe na raiz do projeto (crie se necessário):

```powershell
New-Item -ItemType Directory -Path .\shared\attacker_results -Force
New-Item -ItemType Directory -Path .\shared\victim_logs -Force
```

2. Subir as VMs e provisionar:

```powershell
vagrant up
```

3. Verificar status e conectar:

```powershell
vagrant status
vagrant ssh victim
vagrant ssh attacker
```

4. Dentro da VM `victim`, verifique `/vagrant_shared` e arquivos de prova:

```bash
ls -la /vagrant_shared
ls -la /vagrant_shared/victim_logs
cat /home/professor/relatorio_institucional.txt
```

5. Aplicar o hardening (opcional — ATENÇÃO às chaves SSH):

```bash
# dentro da VM victim
sudo bash /vagrant/provision/hardening_victim.sh
```

**Observação importante:** o `hardening_victim.sh` desabilita PasswordAuthentication e PermitRootLogin. Antes de rodá-lo, certifique-se de ter acesso por chave pública (coloque a chave pública em `/root/.ssh/authorized_keys` ou no usuário `professor`) para não se trancar fora.

---

## Parar / destruir

```powershell
vagrant halt          # parar VMs
vagrant destroy -f    # destruir VMs
```

## Preparação no host

mkdir -p shared                # cria a pasta compartilhada (se ainda não existir)
vagrant up                     # sobe as VMs e roda provision (provision_victim.sh na victim)
vagrant ssh victim -c "cat /vagrant_shared/victim_provision_done.txt"  # confirma provision da victim
vagrant ssh attacker -c "cat /vagrant_shared/attacker_provision_done.txt"  # confirma provision do attacker


---

## Snapshot antes do ataque (host)

vagrant snapshot save victim before_attack    # salva snapshot da victim antes do ataque
vagrant snapshot save attacker before_attack  # salva snapshot do attacker (opcional)


---

## Reconhecimento (do attacker)

vagrant ssh attacker                          # entra no attacker
nmap -sV -p 22 192.168.56.10                 # varre a porta 22 na victim para descobrir serviço SSH
ss -tuln                                     # lista serviços locais (opcional para contexto no attacker)
exit                                          # sai do attacker


---

## Exploração: login com senha fraca (do attacker)

vagrant ssh attacker
ssh professor@192.168.56.10                  # conecta como professor usando senha 'prof123' (demo)
# dentro da sessão SSH na victim (agora você está logado como professor)
echo "ALTERADO PELO ATACANTE - prova de acesso" >> /home/professor/relatorio_institucional.txt
exit                                          # volta pro attacker
exit                                          # volta pro host (se precisar)


---

## Coleta imediata de evidências (na victim) — copia logs e gera hashes

vagrant ssh victim -c "sudo mkdir -p /vagrant_shared/victim_logs && sudo chown -R vagrant:vagrant /vagrant_shared"
vagrant ssh victim -c "sudo cp --preserve=mode,ownership,timestamps /var/log/auth.log /vagrant_shared/victim_logs/auth.log.copy"  # copia auth.log preservando metadados
vagrant ssh victim -c "sudo sha256sum /vagrant_shared/victim_logs/auth.log.copy > /vagrant_shared/victim_logs/auth.log.copy.sha256"  # gera hash SHA256 do log copiado
vagrant ssh victim -c "grep 'Accepted' /var/log/auth.log | sudo tee /vagrant_shared/victim_logs/ssh_accepted.txt > /dev/null"  # salva entradas de login aceito
vagrant ssh victim -c "sha256sum /vagrant_shared/victim_logs/ssh_accepted.txt > /vagrant_shared/victim_logs/ssh_accepted.txt.sha256"  # hash do arquivo de aceitos
# no host: listar arquivos coletados
ls -l shared/victim_logs


---

## (Opcional) Criar imagem forense rápida da VM (pode demorar)

vagrant ssh victim -c "sudo dd if=/dev/sda of=/vagrant_shared/victim_disk_image.dd bs=4M status=progress"  # cria imagem do disco (demo)
vagrant ssh victim -c "sha256sum /vagrant_shared/victim_disk_image.dd > /vagrant_shared/victim_disk_image.dd.sha256"  # gera hash da imagem


---

## Aplicar Hardening (rodar script) — após coletar evidências

vagrant ssh victim -c "sudo bash /vagrant/provision/hardening_victim.sh"  # executa hardening_victim.sh como root


---

## Verificações pós-hardening (na victim)

vagrant ssh victim -c "sudo grep -E 'PasswordAuthentication|PermitRootLogin|Port|AllowUsers' /etc/ssh/sshd_config -n"  # checa config SSH (deve mostrar PasswordAuthentication no, PermitRootLogin no, Port 2222, AllowUsers professor)
vagrant ssh victim -c "sudo ufw status verbose"       # checa status do firewall
vagrant ssh victim -c "sudo fail2ban-client status sshd"  # checa status do fail2ban


---

## Teste de acesso pós-hardening (do attacker)

vagrant ssh attacker
ssh professor@192.168.56.10                        # tentativa por senha: deve falhar com "Permission denied (publickey)" ou "Connection refused"
ssh -i ~/.ssh/id_demo -p 2222 professor@192.168.56.10  # conexão com chave e porta 2222 (se chave estiver instalada) - deve passar se chave for autorizada
exit


---

## Se der merda (se trancar) — restaurar snapshot (host)

vagrant snapshot restore victim before_attack  # restaura a victim ao estado anterior ao ataque/hardening
vagrant snapshot restore attacker before_attack  # restaura o attacker (opcional)


---

## Reprovisionar / Forçar provision se precisar (host)

vagrant provision victim   # roda só o provision da victim novamente (não destrói)
vagrant provision          # roda provision em todas as VMs


---

## Limpeza final (se quiser resetar tudo)

vagrant destroy -f         # destrói todas as VMs (perde dados que não estão em ./shared)
rm -rf .vagrant            # remove metadados do vagrant (opcional)


---

## Comandos úteis extras (rápido)

vagrant status                       # mostra status das VMs
vagrant ssh victim                   # abre shell na victim
vagrant ssh attacker                 # abre shell no attacker
vagrant ssh victim -c "sudo tail -n 200 /var/log/auth.log"  # ver últimos logs auth
vagrant ssh victim -c "sudo dpkg --configure -a"           # reparo dpkg se tiver problema de apt lock 
