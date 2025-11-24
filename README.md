# Trabalho de Segurança de Redes - Auditoria e Demonstração de Vulnerabilidades

## 📋 Sobre o Projeto

Este projeto demonstra um ambiente de laboratório controlado para análise de vulnerabilidades, ataques de segurança e aplicação de medidas de hardening em sistemas Linux. O cenário simula um ambiente acadêmico com duas máquinas virtuais: uma vítima (servidor) e uma atacante.

## 🎯 Objetivo

Realizar uma auditoria completa de segurança demonstrando:
- Identificação e exploração de vulnerabilidades reais
- Análise forense digital e resposta a incidentes
- Aplicação de contramedidas e hardening
- Documentação de evidências e impactos

---

## 🔍 1. Análise de Vulnerabilidades e Vetores de Ataque

### 1.1 Identificação de Vulnerabilidades

#### **Vulnerabilidade 1: SSH com Autenticação por Senha Fraca**
- **Descrição**: Serviço SSH configurado para aceitar autenticação por senha sem MFA (Multi-Factor Authentication)
- **Risco**: Permite ataques de força bruta automatizados
- **CVSS Score**: 9.8 (CRÍTICO)
- **CWE**: CWE-521 (Weak Password Requirements)

#### **Vulnerabilidade 2: Servidor FTP Anônimo com Upload Habilitado**
- **Descrição**: vsftpd configurado para permitir login anônimo com permissão de escrita
- **Risco**: Permite upload de webshells e backdoors sem autenticação
- **CVSS Score**: 9.8 (CRÍTICO)
- **CWE**: CWE-306 (Missing Authentication)

#### **Vulnerabilidade 3: Local File Inclusion (LFI) + Remote Code Execution**
- **Descrição**: Aplicação web PHP vulnerável permitindo leitura de arquivos arbitrários e webshell exposta
- **Risco**: Acesso a arquivos sensíveis (senhas, logs) e execução remota de comandos
- **CVSS Score**: 9.8 (CRÍTICO)
- **CWE**: CWE-22 (Path Traversal), CWE-94 (Code Injection)

#### **Vulnerabilidade 4: Binários SUID Mal Configurados**
- **Descrição**: Binários (\`find\`, \`vim\`) com bit SUID root permitindo escalação de privilégios
- **Risco**: Usuário comum pode obter acesso root ao sistema
- **CVSS Score**: 8.8 (ALTO)
- **CWE**: CWE-250 (Execution with Unnecessary Privileges)

#### **Vulnerabilidade 5: Logs com Permissões Inseguras**
- **Descrição**: Arquivos de log com permissões 644 (legíveis por todos) contendo credenciais em texto claro
- **Risco**: Exposição de informações sensíveis (senhas, tokens, comandos executados)
- **CVSS Score**: 7.5 (ALTO)
- **CWE**: CWE-532 (Information Exposure Through Log Files)

#### **Vulnerabilidade 6: Ausência de IDS/IPS**
- **Descrição**: Sistema sem fail2ban, AIDE ou qualquer sistema de detecção de intrusão
- **Risco**: Ataques de força bruta e port scanning passam despercebidos
- **CVSS Score**: 5.3 (MÉDIO)
- **CWE**: CWE-778 (Insufficient Logging)

### 1.2 Análise dos Vetores de Ataque

#### **Vetor 1: Engenharia Social e Observação**
- Obtenção de credenciais através de observação ou phishing
- Exploração da confiança do usuário em senhas previsíveis

#### **Vetor 2: Acesso Remoto Não Autorizado (SSH)**
- Ataque de força bruta automatizado com wordlist
- Exploração de autenticação por senha sem limitação de tentativas
- Ausência de notificação de tentativas de login suspeitas

#### **Vetor 3: Exploração de Serviços de Rede Mal Configurados**
- FTP anônimo para upload de payloads maliciosos
- Aplicação web vulnerável (LFI) para exfiltração de dados
- Webshell para persistência e execução remota

#### **Vetor 4: Escalação de Privilégios**
- Exploração de binários SUID para obter acesso root
- Capabilities mal configuradas no Python

#### **Vetor 5: Persistência e Manipulação**
- Modificação de arquivos confidenciais
- Instalação de backdoors para acesso futuro
- Exfiltração de dados sensíveis

---

## 🔬 2. Análise Forense Digital e Resposta a Incidentes

### 2.1 Cadeia de Custódia das Evidências

#### Metodologia de Coleta
\`\`\`bash
# 1. Criar imagem forense do sistema
sudo dd if=/dev/sda of=/mnt/evidence/victim_disk.img bs=4M status=progress
sudo sha256sum /mnt/evidence/victim_disk.img > /mnt/evidence/victim_disk.img.sha256

# 2. Documentar timestamp da coleta
date --iso-8601=seconds >> /mnt/evidence/collection_timestamp.txt

# 3. Montar imagem em modo read-only
sudo mkdir /mnt/forensics
sudo mount -o ro,loop /mnt/evidence/victim_disk.img /mnt/forensics
\`\`\`

#### Garantias da Cadeia de Custódia
- **Integridade**: Hash SHA-256 documentado de todas as evidências
- **Não-repúdio**: Timestamp criptográfico com servidor NTP confiável
- **Rastreabilidade**: Logs de acesso com identificação do analista
- **Isolamento**: Análise em máquina segregada da rede de produção

### 2.2 Análise de Logs Críticos

#### **Log 1: Autenticação SSH (\`/var/log/auth.log\`)**
\`\`\`bash
# Identificar tentativas de login
sudo grep "Failed password" /var/log/auth.log
\`\`\`

**Evidências coletadas**:
- **IP do atacante**: 192.168.56.20
- **Usuário comprometido**: professor
- **Timestamp do ataque**: 2025-11-24 19:57:34 UTC
- **Porta de origem**: 35038

#### **Log 2: Auditoria de Comandos Executados**
\`\`\`bash
sudo grep "professor" /var/log/auth.log | grep -i "session opened"
sudo ausearch -ui professor -ts today
\`\`\`

#### **Log 3: Acesso HTTP (Apache)**
\`\`\`bash
sudo grep "view.php?file=" /var/log/apache2/access.log
sudo grep "admin_backup.php" /var/log/apache2/access.log
\`\`\`

### 2.3 Artefatos de Ataque Identificados

| Artefato | Localização | Descrição |
|----------|-------------|-----------|
| Webshell | \`/var/www/html/admin_backup.php\` | Backdoor PHP para RCE |
| Payload FTP | \`/srv/ftp/upload/backdoor.php\` | Tentativa de upload malicioso |
| Credenciais | \`/shared/attacker_results/found_password.txt\` | Senha descoberta |
| Shadow file | \`/shared/attacker_results/shadow_file.txt\` | Cópia exfiltrada |

---

## ⚠️ 3. Análise de Riscos e Impactos

### 3.1 Impacto Institucional

#### **Impactos Técnicos**
- **Confidencialidade**: Exposição de credenciais de professores, dados de pesquisa
- **Integridade**: Manipulação de arquivos institucionais, alteração de registros
- **Disponibilidade**: Risco de ransomware, perda de acesso a sistemas críticos

#### **Impactos Financeiros**
- Custo de resposta ao incidente: R\$ 50.000 - R\$ 200.000
- Investimento em segurança: R\$ 100.000+
- Multas LGPD: Até R\$ 50 milhões ou 2% do faturamento

#### **Impactos Reputacionais**
- Perda de confiança de alunos, professores e parceiros
- Danos à imagem institucional em rankings
- Exposição negativa na mídia

### 3.2 Impacto Humano e Ético

#### **Consequências para a Vítima (Professor)**
- **Privacidade**: Exposição de informações pessoais e profissionais
- **Psicológico**: Estresse, ansiedade, sensação de vulnerabilidade
- **Profissional**: Danos à reputação acadêmica
- **Legal**: Complicações se dados sensíveis foram comprometidos

#### **Responsabilidades Éticas**
- Notificar imediatamente as vítimas
- Transparência com a comunidade acadêmica
- Compliance com LGPD (Lei nº 13.709/2018)

---

## 🛡️ 4. Contramedidas e Hardening Aplicado

### 4.1 Medidas Implementadas

#### **SSH**
- Desabilitar autenticação por senha (apenas chaves)
- Desabilitar login root
- Alterar porta (22 → 2222)
- Implementar fail2ban (bloqueio após 3 tentativas)

#### **Rede**
- Firewall UFW ativo
- Remoção de serviços desnecessários (FTP, Apache)

#### **Sistema**
- Correção de binários SUID
- Restrição de permissões de logs (640)
- Instalação de auditd
- Atualizações automáticas

---

## 🚀 Instruções de Uso

### Pré-requisitos
- VirtualBox e Vagrant instalados
- Mínimo 4GB RAM disponível

### Execução

\`\`\`bash
# 1. Subir as VMs
vagrant up

# 2. Adicionar vulnerabilidades
vagrant provision victim --provision-with vulnerabilities

# 3. Executar demonstração
bash presentation/run_demo.sh

# 4. Aplicar hardening (quando pausar)
vagrant ssh victim -c "sudo bash /vagrant/provision/hardening_victim.sh"

# 5. Destruir VMs
vagrant destroy -f
\`\`\`

---

## ⚠️ Aviso Legal

**Este projeto é exclusivamente para fins educacionais**. A execução destes ataques em sistemas sem autorização é **CRIME** (Lei nº 12.737/2012).

- Utilize apenas em redes isoladas
- Nunca execute em ambientes de produção
- Obtenha autorização antes de qualquer teste

---

## 📚 Referências

- NIST Cybersecurity Framework
- OWASP Top 10
- CIS Benchmarks for Linux
- LGPD - Lei nº 13.709/2018

---

**Novembro de 2025**
