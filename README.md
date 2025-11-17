# Laboratório de Segurança de Redes — Documentação para Apresentação

> **Repositório:** seguranca-trabalho

---

> ⚠️ **Aviso:** Este laboratório foi desenvolvido para ambiente isolado (*Vagrant private_network*) e contém scripts que realizam ataques didáticos (força bruta). Execute apenas em ambiente controlado.

---

## Sumário

1. Objetivo do projeto  
2. Estrutura do repositório  
3. Pré-requisitos (host)  
4. Checklist rápido (antes da apresentação)  
5. Fluxo da apresentação — comandos em ordem  
6. Comandos de demonstração / forense (detalhados)  
7. Como aplicar o hardening (quando e como)  
8. Como reverter o hardening  
9. Troubleshooting rápido  
10. Arquivos importantes  
11. Vulnerabilidades abordadas  
12. Dicas para apresentação  
13. Comandos úteis finais  

---

## 1 — Objetivo do projeto

Simular um incidente de acesso não autorizado via SSH, realizar uma demonstração controlada de exploração (força bruta em senha fraca), coletar evidências forenses, aplicar uma mitigação (hardening) e validar as defesas.

O foco é didático: agir como uma consultoria de segurança — diagnóstico → exploração controlada → coleta forense → mitigação → validação.

---

## 2 — Estrutura do repositório

```
seguranca-trabalho/
├─ Vagrantfile
├─ provision/
│  ├── provision_victim.sh
│  ├── provision_attacker.sh
│  ├── hardening_victim.sh
│  └── revert_hardening.sh
├─ presentation/
│  └── run_demo.sh
└─ shared/
   ├── attacker_results/
   ├── victim_logs/
   └── wordlists/
```

- **./shared (host)** ⇄ **/vagrant_shared (VMs)**  
  Todos os arquivos de evidência devem ficar em `shared/`.

---

## 3 — Pré-requisitos (host)

- Git (opcional)
- Vagrant (≥ 2.2.x recomendado)
- VirtualBox compatível
- Terminal (Linux/macOS/WSL recomendado)
- Estar na pasta raiz do projeto ao rodar os comandos abaixo
- Rodar o comando chmod +x presentantion/run_demo.sh

---

## 4 — Checklist rápido (antes da apresentação)

- ✅ Criar pasta shared:
  ```sh
  mkdir -p shared/attacker_results shared/victim_logs shared/wordlists
  ```

- ✅ Tornar o orquestrador executável:
  ```sh
  chmod +x presentation/run_demo.sh
  ```

- ✅ Tornar o script de reversão executável:
  ```sh
  chmod +x provision/revert_hardening.sh
  ```

- ✅ (Recomendado) Criar snapshot antes do hardening:
  ```sh
  vagrant snapshot save victim before_hardening
  vagrant snapshot save attacker before_hardening
  ```

- ✅ Gerar/ter a chave pública do attacker se for aplicar hardening sem snapshot.

---

## 5 — Fluxo da apresentação — comandos em ordem

Execute os blocos abaixo na raiz do projeto (onde está o Vagrantfile).

**5.0 — Preparar compartilhamento**
```sh
mkdir -p shared/attacker_results shared/victim_logs shared/wordlists
```

**5.1 — Subir VMs e provisionar**
```sh
vagrant up
```

**5.2 — Confirmar provisionamento**
```sh
vagrant ssh victim -c "cat /vagrant_shared/victim_provision_done.txt"
vagrant ssh attacker -c "cat /vagrant_shared/attacker_provision_done.txt"
```

**5.3 — (Opcional) Snapshot antes do ataque**
```sh
vagrant snapshot save victim before_hardening
vagrant snapshot save attacker before_hardening
```

**5.4 — Rodar orquestrador da demo (host)**
```sh
./presentation/run_demo.sh
```
O script realiza reconhecimento + brute force, exibe resultados e pausa solicitando intervenção manual para aplicar o hardening na victim.

> Não pressione ENTER até ter aplicado o hardening (ou preparado a chave) — veja instruções abaixo.

---

## 6 — Comandos de demonstração / forense (detalhados)

**A) Reconhecimento (manual)**
```sh
vagrant ssh attacker -c "nmap -sV -p 22,2222 192.168.56.10"
```

**B) Ataque didático (força bruta)**  
(O orquestrador chama este script; para rodar manualmente:)
```sh
vagrant ssh attacker -c "/home/vagrant/attack_scripts/brute_force.sh 192.168.56.10 /vagrant_shared/wordlists/passwords.txt"
```
Resultados:  
- `shared/attacker_results/bruteforce_result.log`  
- `shared/attacker_results/found_password.txt` (se houver sucesso)

**C) Prova de manipulação (após login)**  
No attacker (após `ssh professor@192.168.56.10`):
```sh
# dentro da sessão SSH na victim
echo "ALTERADO PELO ATACANTE - prova de acesso" >> /home/professor/relatorio_institucional.txt
exit
```

**D) Coleta de evidências (preservando metadados)**
```sh
vagrant ssh victim -c "sudo mkdir -p /vagrant_shared/victim_logs && sudo chown -R vagrant:vagrant /vagrant_shared"
vagrant ssh victim -c "sudo cp --preserve=mode,ownership,timestamps /var/log/auth.log /vagrant_shared/victim_logs/auth.log.copy"
vagrant ssh victim -c "sudo sha256sum /vagrant_shared/victim_logs/auth.log.copy > /vagrant_shared/victim_logs/auth.log.copy.sha256"
vagrant ssh victim -c "sudo grep 'Accepted' /var/log/auth.log | sudo tee /vagrant_shared/victim_logs/ssh_accepted.txt > /dev/null"
vagrant ssh victim -c "sha256sum /vagrant_shared/victim_logs/ssh_accepted.txt > /vagrant_shared/victim_logs/ssh_accepted.txt.sha256"
```
Opcional — imagem forense (pode demorar):
```sh
vagrant ssh victim -c "sudo dd if=/dev/sda of=/vagrant_shared/victim_disk_image.dd bs=4M status=progress"
vagrant ssh victim -c "sha256sum /vagrant_shared/victim_disk_image.dd > /vagrant_shared/victim_disk_image.dd.sha256"
```

---

## 7 — Como aplicar o hardening (quando e como)

Durante a pausa do `run_demo.sh`, aplique o hardening em outro terminal (host). Antes disso, recomenda-se garantir a chave pública do attacker para o usuário professor, evitando lockout.

**7.1 — Gerar e copiar a chave pública do attacker (recomendado antes do hardening)**
```sh
vagrant ssh attacker -c "ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_demo -N '' && cat ~/.ssh/id_demo.pub" > shared/attacker_id_demo.pub
vagrant ssh victim -c "sudo mkdir -p /home/professor/.ssh && sudo cp /vagrant_shared/attacker_id_demo.pub /home/professor/.ssh/authorized_keys && sudo chown -R professor:professor /home/professor/.ssh"
```

**7.2 — Executar o hardening (após preparação)**
```sh
vagrant ssh victim -c "sudo bash /vagrant/provision/hardening_victim.sh"
```

**7.3 — Voltar ao `run_demo.sh` e pressionar ENTER**

Ao pressionar ENTER, o orquestrador executará os testes pós-hardening automaticamente.

---

## 8 — Como reverter o hardening

Se quiser retornar ao estado vulnerável para repetir a demonstração:

```sh
chmod +x provision/revert_hardening.sh
vagrant ssh victim -c "sudo bash /vagrant/provision/revert_hardening.sh"
# ou, se houver snapshot
vagrant snapshot restore victim before_hardening
```

---

## 9 — Troubleshooting rápido (erros comuns)

- **No such file or directory ao ler indicadores em /vagrant_shared:**  
  Crie `shared/` no host e reprovisione:  
  `mkdir -p shared && vagrant provision victim`

- **Permission denied (publickey) pós-hardening:**  
  Não copiou a chave pública para `/home/professor/.ssh/authorized_keys`. Veja seção 7.1.

- **No route to host ao ssh na porta 22:**  
  Provavelmente o hardening mudou a porta para 2222 ou o `ufw` bloqueou a 22. Teste porta 2222 com chave.

- **Attacker banido:**  
  O `fail2ban` pode banir por tentativas. Se `fail2ban-client` não existir, verifique `iptables`/`nftables` e remova a regra que contenha o IP do attacker ou insira `ACCEPT` temporário.

---

## 10 — Arquivos importantes

- `Vagrantfile` — define VMs, IPs e provisionamento.
- `provision/provision_victim.sh` — configura a VM vítima (usuário professor, senhas fracas, SSH com senha).
- `provision/provision_attacker.sh` — instala ferramentas no attacker e cria `brute_force.sh`.
- `provision/hardening_victim.sh` — script de mitigação (porta 2222, fail2ban, ufw, desabilita senha).
- `provision/revert_hardening.sh` — restaura o estado vulnerável.
- `presentation/run_demo.sh` — orquestrador host-side (reconhecimento → ataque → pausa → testes pós-hardening).
- `shared/` — evidências persistentes: attacker_results/, victim_logs/, wordlists/.

---

## 11 — Vulnerabilidades abordadas

1. Senha fraca / previsível  
2. Autenticação por senha habilitada no SSH  
3. `PermitRootLogin yes`  
4. SSH na porta 22 sem proteções  
5. Rede pouco segmentada  
6. Falta de atualizações automáticas  
7. Contas compartilhadas / credenciais fracas  
8. Ausência de bloqueio por tentativas (até o hardening)  
9. Serviços desnecessários ativos  
10. Permissões de arquivos sensíveis mal configuradas  

> O relatório teórico exigido pelo enunciado deve detalhar estas e **5 vulnerabilidades adicionais encontradas pelo grupo**.

---

## 12 — Dicas para apresentação e arguição

- Mostre evidências (hashes SHA256) — isso fortalece a cadeia de custódia.
- Explique o porquê de cada mitigação no hardening (trade-offs).
- Tenha o script `revert_hardening.sh` e/ou snapshot para refazer rapidamente casos de teste.
- Garanta ao avaliador que os ataques são em ambiente isolado e para fins educacionais.

---

## 13 — Comandos úteis finais (cole em `commands.txt` se quiser)

```sh
# preparar ambiente
mkdir -p shared/attacker_results shared/victim_logs shared/wordlists

# subir vagrant
vagrant up

# checar provisionamento
vagrant ssh victim -c "cat /vagrant_shared/victim_provision_done.txt"
vagrant ssh attacker -c "cat /vagrant_shared/attacker_provision_done.txt"

# snapshot (recomendado)
vagrant snapshot save victim before_hardening
vagrant snapshot save attacker before_hardening

# rodar apresentação (orquestrador)
./presentation/run_demo.sh

# aplicar hardening (durante pausa)
vagrant ssh victim -c "sudo bash /vagrant/provision/hardening_victim.sh"

# reverter hardening
vagrant ssh victim -c "sudo bash /vagrant/provision/revert_hardening.sh"

# reprovisionar victim
vagrant provision victim

# destruir tudo quando terminar
vagrant destroy -f
rm -rf .vagrant
```

---

## Subir no GitHub

1. Inicializar repositório e commitar:

    ```sh
    git init
    git add .
    git commit -m "Laboratório de segurança - entrega"
    git branch -M main
    # adicionar remote (substitua <url>) e push
    git remote add origin <url>
    git push -u origin main
    ```

2. **Não suba chaves privadas ou evidências sensíveis; adicione `.gitignore` para `shared/`, se necessário.**

---

## Vulnerabilidades Não Exploradas — Descrições, Vetores e Mitigação

### 1) Serviços Desnecessários Expostos (ex.: FTP, Telnet, RPC)

**Descrição:**  
Serviços legados ou em desuso podem rodar com configurações inseguras, abrindo portas desnecessárias para o atacante.

**Caminho de Exploração (PoC didática):**
```sh
# Identificar serviços abertos
sudo ss -tuln
sudo nmap -sV 192.168.56.10
```
Se `vsftpd` estiver ativo e mal configurado, um atacante pode se conectar, realizar uploads/downloads ou explorar vulnerabilidades conhecidas da versão.

**Impacto:**  
Exposição de credenciais, exfiltração de arquivos, ponto de apoio para movimentação lateral.

**Detecção / Evidência:**  
Logs de conexão (`/var/log/syslog`, `/var/log/auth.log`), saída de `ss`/`nmap`, pacotes de rede suspeitos.

**Mitigação no Hardening:**  
O script de hardening atual não remove serviços automaticamente, mas a política de redução da superfície é indireta — o `ufw` nega conexões inbound por padrão, reduzindo a exposição.  
**Recomendação:** Adapte `hardening_victim.sh` para desabilitar/remover serviços desnecessários:
```sh
sudo systemctl disable --now vsftpd || true
sudo apt-get remove --purge -y vsftpd || true
```
Inclua essas linhas no hardening para fechar esse vetor.

**Medidas adicionais:**  
Inventário de serviços, lista branca (only necessary), monitoramento contínuo e lockdown de portas via firewall.

---

### 2) Pacotes Desatualizados / Vulnerabilidades Conhecidas (CVE)

**Descrição:**  
Versões antigas de aplicativos ou serviços (por exemplo, OpenSSH, libc, webservers) podem ter exploits públicos divulgados.

**Caminho de Exploração (PoC didática):**
```sh
# Descobrir versões
sudo apt list --installed | grep openssh
vagrant ssh attacker -c "nmap -sV 192.168.56.10"
```
Buscar CVEs públicas para a versão e tentar PoC (somente em laboratório).

**Impacto:**  
Execução remota de código, escalonamento de privilégio, persistência do atacante.

**Detecção / Evidência:**  
Logs de crashes, segfaults, conexões anômalas; vulnerabilidades identificadas por scanners (nikto, nessus).

**Mitigação no Hardening:**  
O `hardening_victim.sh` instala `unattended-upgrades` para aplicar atualizações automáticas, reduzindo a janela de exposição.  
O script também realiza upgrade forçado via `apt-get upgrade`.

**Medidas adicionais:**  
Gerenciamento de patches, scanners de vulnerabilidade periódicos, inventário de softwares.

---

### 3) Permissões Incorretas de Arquivos Sensíveis (ex.: relatorio_institucional.txt)

**Descrição:**  
Arquivos sensíveis com permissões abertas (644 ou 777) permitem leitura/alteração por usuários não autorizados.

**Caminho de Exploração (PoC didática):**
```sh
# Listar permissões do arquivo
ls -l /home/professor/relatorio_institucional.txt
```
Se o atacante tiver acesso à conta ou via serviço mal configurado, pode ler/alterar.

**Impacto:**  
Vazamento de informações, adulteração de evidências, danos à reputação.

**Detecção / Evidência:**  
Alterações de timestamps, diffs, logs de alteração; hash SHA256 antes e depois evidenciam manipulação.

**Mitigação no Hardening:**  
O hardening não altera permissões de arquivos individuais por padrão, mas recomenda restringir acessos.  
Inclua no script:
```sh
sudo chown professor:professor /home/professor/relatorio_institucional.txt
sudo chmod 600 /home/professor/relatorio_institucional.txt
```
Garante acesso apenas ao proprietário do arquivo.

**Medidas adicionais:**  
Controle de integridade (AIDE/Tripwire), backups assinados, políticas DLP.

---

### 4) SSH: Ciphers / KEX / MAC Fracos e Configuração Insegura

**Descrição:**  
Algoritmos de criptografia fracos permitem downgrade attacks ou exploração de vulnerabilidades conhecidas.

**Caminho de Exploração (PoC didática):**
```sh
# Auditar configurações
sudo sshd -T | grep -E 'ciphers|macs|kex'

# Forçar cipher antigo (em ambiente de teste)
ssh -o Ciphers=aes128-cbc professor@192.168.56.10
```
Se conectar, indica suporte a cipher fraca.

**Impacto:**  
Facilita interceptação (se o key exchange for fraco), ataques man-in-the-middle.

**Mitigação no Hardening:**  
O hardening foca em `PasswordAuthentication no`, `PermitRootLogin no`, fail2ban e ufw. Para fechar este vetor, inclua obrigatoriedade de ciphers fortes no `sshd_config`:
```sh
echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com' | sudo tee -a /etc/ssh/sshd_config
echo 'KexAlgorithms curve25519-sha256@libssh.org' | sudo tee -a /etc/ssh/sshd_config
echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com' | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart ssh
```

**Medidas adicionais:**  
Manter OpenSSH atualizado, auditorias regulares, testes de compatibilidade (balanceamento segurança/compatibilidade).

---

### 5) Falta de Logging Remoto / Integridade dos Logs

**Descrição:**  
Logs apenas locais podem ser apagados ou adulterados por um atacante com acesso root — ausência de cópia remota enfraquece a cadeia de custódia.

**Caminho de Exploração (PoC didática):**
```sh
# Atacante trunca ou edita log
sudo truncate -s 0 /var/log/auth.log
```
Ou edita entradas do log para ocultar rastros.

**Impacto:**  
Perda de evidências, manipulação de provas, dificultando a investigação.

**Mitigação no Hardening:**  
Já há cópia de logs para `shared/` (host), formando mitigação manual.  
Para reforçar:
- Configurar `rsyslog` ou `syslog-ng` para enviar logs críticos ao host ou servidor remoto.
- Habilitar `auditd` para eventos sensíveis:
```sh
# Exemplo (requer listener no host)
# Adicionar em /etc/rsyslog.conf: *.* @<host-ip>:514
apt-get install -y auditd
systemctl enable --now auditd
```

**Medidas adicionais:**  
WORM storage para logs, assinatura/hash periódico (append-only), integração com SIEM.

---

### 6) Falta de Segmentação de Rede (Rede Plana do Laboratório)

**Descrição:**  
Rede do laboratório na mesma VLAN facilita movimentos laterais e acessos indevidos entre hosts.

**Caminho de Exploração (PoC didática):**
```sh
# Scan na rede interna
nmap -sV 192.168.56.0/24
```
Comprometendo a victim, o atacante pode tentar pivô para outros hosts.

**Impacto:**  
Escalonamento do incidente, comprometimento em cadeia de outros sistemas.

**Mitigação no Hardening:**  
Mitigação local não resolve segmentação — é requisito de arquitetura.  
**Recomende no relatório:**
- Segmentação dos ambientes em VLANs.
- ACLs entre segmentos.
- Isolamento de serviços críticos (DB, AD) em redes separadas.

**Medidas adicionais:**  
Firewalls entre segmentos, jump hosts com MFA, Zero Trust para serviços sensíveis.

---

### 7) Exposição de Credenciais em Scripts/Configurações (Hard-Coded Secrets)

**Descrição:**  
Scripts de provisionamento podem conter senhas em texto claro (ex.: `echo "professor:prof123" | chpasswd`), postura insegura para produção.

**Caminho de Exploração (PoC didática):**
```sh
# Extrair credenciais em texto claro
grep -R "prof123" -n .
```
Facilita comprometimento de contas por quem acessar o repo ou disco da VM.

**Impacto:**  
Comprometimento rápido de contas e senhas.

**Mitigação no Hardening:**  
No laboratório, o uso de credenciais fracas foi intencional para fins didáticos.  
Em produção **nunca** se deve embutir credenciais em código.

**Boas práticas:**
- Uso de variáveis de ambiente seguras.
- Vaults (ex.: HashiCorp Vault).
- Prompts interativos para inserção de senhas.
- Rotação automática de senhas e uso de autenticação por chave.

---

## Conclusão desta Seção

Cada vulnerabilidade acima representa vetores de ataque reais — muitos simples de explorar quando combinados (por exemplo: serviços expostos + credenciais fracas).  
O `hardening_victim.sh` cobre parte dos vetores (SSH sem senha, bloqueio root, fail2ban, ufw, atualizações automáticas), mas **não é solução única:** é essencial complementar o script com os controles adicionais listados acima:  
- Remoção de serviços desnecessários;
- Ciphers fortes no SSH;
- Envio remoto e integridade de logs;
- Permissões restritas de arquivos;
- Inventário e atualização periódica de pacotes;
- Segmentação de rede.


---
