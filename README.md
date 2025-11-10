Laboratório de Segurança de Redes — Documentação para Apresentação

> Repositório: seguranca-trabalho



Aviso: este laboratório foi feito para ambiente isolado (Vagrant private_network) e tem scripts que realizam ataques didáticos (brute‑force) — execute apenas em ambiente controlado.


---

Sumário

1. Objetivo do projeto


2. Estrutura do repositório


3. Pré‑requisitos (host)


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

1 — Objetivo do projeto

Simular um incidente de acesso não autorizado via SSH, executar uma demonstração controlada de exploração (força bruta em senha fraca), coletar evidências forenses, aplicar uma mitigação (hardening) e validar a mitigação.

O foco é didático: agir como consultoria de segurança — diagnóstico → exploração controlada → coleta forense → mitigação → validação.


---

2 — Estrutura do repositório

seguranca-trabalho/
├─ Vagrantfile
├─ provision/
│  ├─ provision_victim.sh
│  ├─ provision_attacker.sh
│  ├─ hardening_victim.sh
│  └─ revert_hardening.sh
├─ presentation/
│  └─ run_demo.sh
└─ shared/
   ├─ attacker_results/
   ├─ victim_logs/
   └─ wordlists/

./shared (host) ⇄ /vagrant_shared (VMs). Tudo que for evidência deve ficar em shared/.



---

3 — Pré‑requisitos (host)

Git (opcional)

Vagrant (≥ 2.2.x recomendado)

VirtualBox compatível

Terminal (Linux/macOS/WSL recomendado)

Estar na pasta raiz do projeto ao rodar os comandos abaixo



---

4 — Checklist rápido (antes da apresentação)

✅ Criar pasta shared:


mkdir -p shared/attacker_results shared/victim_logs shared/wordlists

✅ Tornar o orquestrador executável:


chmod +x presentation/run_demo.sh

✅ Tornar o revert executável:


chmod +x provision/revert_hardening.sh

✅ (Recomendado) snapshot antes do hardening:


vagrant snapshot save victim before_hardening
vagrant snapshot save attacker before_hardening

✅ Gerar/ter a chave pública do attacker se for aplicar hardening sem snapshot.



---

5 — Fluxo da apresentação — comandos em ordem

Execute os blocos abaixo na raiz do projeto (onde está o Vagrantfile).

5.0 — Preparar shared

mkdir -p shared/attacker_results shared/victim_logs shared/wordlists

5.1 — Subir VMs e provisionar

vagrant up

5.2 — Confirmar provision

vagrant ssh victim -c "cat /vagrant_shared/victim_provision_done.txt"
vagrant ssh attacker -c "cat /vagrant_shared/attacker_provision_done.txt"

5.3 — (Opcional) Snapshot antes do ataque

vagrant snapshot save victim before_hardening
vagrant snapshot save attacker before_hardening

5.4 — Rodar orquestrador da demo (host)

./presentation/run_demo.sh

O script fará reconhecimento + brute‑force, exibirá resultados e pausará solicitando a intervenção manual para aplicar o hardening na victim.

> Não pressione ENTER até ter aplicado o hardening (ou preparado a chave) — instruções abaixo.




---

6 — Comandos de demonstração / forense (detalhados)

6.A — Reconhecimento (manual)

vagrant ssh attacker -c "nmap -sV -p 22,2222 192.168.56.10"

6.B — Ataque didático (brute‑force)

(O orquestrador chama este script; para rodar manualmente):

vagrant ssh attacker -c "/home/vagrant/attack_scripts/brute_force.sh 192.168.56.10 /vagrant_shared/wordlists/passwords.txt"

Resultados: shared/attacker_results/bruteforce_result.log e shared/attacker_results/found_password.txt se houver sucesso.

6.C — Prova de manipulação (após login)

No attacker (após ssh professor@192.168.56.10):

# dentro da sessão SSH na victim
echo "ALTERADO PELO ATACANTE - prova de acesso" >> /home/professor/relatorio_institucional.txt
exit

6.D — Coleta de evidências (preservando metadados)

vagrant ssh victim -c "sudo mkdir -p /vagrant_shared/victim_logs && sudo chown -R vagrant:vagrant /vagrant_shared"
vagrant ssh victim -c "sudo cp --preserve=mode,ownership,timestamps /var/log/auth.log /vagrant_shared/victim_logs/auth.log.copy"
vagrant ssh victim -c "sudo sha256sum /vagrant_shared/victim_logs/auth.log.copy > /vagrant_shared/victim_logs/auth.log.copy.sha256"
vagrant ssh victim -c "sudo grep 'Accepted' /var/log/auth.log | sudo tee /vagrant_shared/victim_logs/ssh_accepted.txt > /dev/null"
vagrant ssh victim -c "sha256sum /vagrant_shared/victim_logs/ssh_accepted.txt > /vagrant_shared/victim_logs/ssh_accepted.txt.sha256"

Opcional — imagem forense (pode demorar):

vagrant ssh victim -c "sudo dd if=/dev/sda of=/vagrant_shared/victim_disk_image.dd bs=4M status=progress"
vagrant ssh victim -c "sha256sum /vagrant_shared/victim_disk_image.dd > /vagrant_shared/victim_disk_image.dd.sha256"


---

7 — Como aplicar o hardening (quando e como)

Durante a pausa do run_demo.sh, aplique o hardening em outro terminal (host). Antes disso, recomenda‑se garantir a chave pública do attacker no professor para evitar lockout.

7.1 — Gerar e copiar a chave pública do attacker (recomendado antes do hardening)

vagrant ssh attacker -c "ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_demo -N '' && cat ~/.ssh/id_demo.pub" > shared/attacker_id_demo.pub
vagrant ssh victim -c "sudo mkdir -p /home/professor/.ssh && sudo cp /vagrant_shared/attacker_id_demo.pub /home/professor/.ssh/authorized_keys && sudo chown -R professor:professor /home/professor/.ssh && sudo chmod 700 /home/professor/.ssh && sudo chmod 600 /home/professor/.ssh/authorized_keys"

7.2 — Executar o hardening (após preparação)

vagrant ssh victim -c "sudo bash /vagrant/provision/hardening_victim.sh"

7.3 — Voltar ao run_demo.sh e pressionar ENTER

Ao pressionar ENTER o orquestrador executará os testes pós‑hardening automaticamente.


---

8 — Como reverter o hardening

Se quiser voltar ao estado vulnerável para repetir a demo:

chmod +x provision/revert_hardening.sh
vagrant ssh victim -c "sudo bash /vagrant/provision/revert_hardening.sh"
# ou, se tiver snapshot
vagrant snapshot restore victim before_hardening


---

9 — Troubleshooting rápido (erros comuns)

No such file or directory ao ler indicadores em /vagrant_shared: crie shared/ no host e reprovisione: mkdir -p shared && vagrant provision victim.

Permission denied (publickey) pós‑hardening: não copiou a chave pública para /home/professor/.ssh/authorized_keys. Veja seção 7.1.

No route to host ao ssh ... port 22: provavel que o hardening mudou a porta para 2222 ou ufw bloqueou 22. Teste porta 2222 com chave.

Attacker banido: fail2ban pode banir por tentativas. Se fail2ban-client não existir, verifique iptables/nftables e remova regra que contenha o IP do attacker ou insira ACCEPT temporário.



---

10 — Arquivos importantes

Vagrantfile — define VMs, IPs e provision.

provision/provision_victim.sh — configura victim vulnerável (usuário professor, senhas fracas, ssh com senha).

provision/provision_attacker.sh — instala ferramentas no attacker e cria brute_force.sh.

provision/hardening_victim.sh — script de mitigação (porta 2222, fail2ban, ufw, desabilita senha).

provision/revert_hardening.sh — restaura o estado vulnerável.

presentation/run_demo.sh — orquestrador host‑side (reconhecimento → ataque → pausa → testes pós‑hardening).

shared/ — evidências persistentes: attacker_results/, victim_logs/, wordlists/.



---

11 — Vulnerabilidades abordadas

1. Senha fraca / previsível


2. Autenticação por senha habilitada no SSH


3. PermitRootLogin yes


4. SSH na porta 22 sem proteções


5. Rede pouco segmentada


6. Falta de atualizações automáticas


7. Contas compartilhadas / credenciais fracas


8. Ausência de bloqueio por tentativas (até o hardening)


9. Serviços desnecessários ativos


10. Permissões de arquivos sensíveis mal configuradas



> O relatório teórico exigido pelo enunciado deve detalhar estas e 5 vulnerabilidades adicionais encontradas pelo grupo.




---

12 — Dicas para apresentação e arguição

Mostre evidências (hashes SHA256) — isso fortalece a cadeia de custódia.

Explique o porquê de cada mitigação no hardening (trade‑offs).

Tenha o revert_hardening.sh e/ou snapshot para refazer rapidamente casos de teste.

Seja claro ao avaliador que os ataques são em ambiente isolado e para fins educacionais.



---

13 — Comandos úteis finais (cole em commands.txt se quiser)

# preparar ambiente
mkdir -p shared/attacker_results shared/victim_logs shared/wordlists

# subir vagrant
vagrant up

# checar provision
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


---

Subir no GitHub

1. Inicializar repo e commitar:



git init
git add .
git commit -m "Laboratório de segurança - entrega"
git branch -M main
# adicionar remote e push (substitua <url>)
git remote add origin <url>
git push -u origin main

2. Não suba chaves privadas ou evidências sensíveis; adicione .gitignore para shared/ se necessário.




---
