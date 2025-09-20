# Análise de Resposta a Incidente: O Backdoor de Certificados Digitais "ValidAgent"

Este documento detalha a análise de um comprometimento de longa duração em uma estação de trabalho corporativa, que revelou uma operação de fraude de identidade digital mascarada por problemas de performance.

## Sumário Executivo

Uma investigação iniciada para diagnosticar uma severa lentidão de inicialização (boot de +6 minutos) em uma estação de trabalho (`WORKSTATION-01`) revelou um cenário de comprometimento duplo. A lentidão foi atribuída a um software de segurança bancária legítimo (`core.exe` - Warsaw), conhecido por ser invasivo. Operando em paralelo, foi descoberto um backdoor sofisticado (`vagent.exe`), ativo desde pelo menos agosto de 2023. Este malware, apelidado de "ValidAgent", se disfarçava como um software de certificação digital legítimo e sua função primária era a geração fraudulenta de certificados digitais A1 em nome de terceiros, além de possuir capacidades de roubo de credenciais. A análise de memória foi crucial para desvendar a arquitetura da ameaça.

## Análise e Linha do Tempo da Investigação

A investigação progrediu através de múltiplas fases de análise forense.

#### 1. Triagem Inicial e Análise Viva (Live Analysis)

* **Sintomas:** Lentidão extrema na inicialização; relatos históricos de atividade de controle remoto ("mouse mexendo sozinho").
* **Comandos Iniciais:**
    * `netstat -anob`: Revelou um processo `vagent.exe` atuando como "listener" (servidor) em uma porta alta e aleatória.
    * `wmic process get ...`: A análise detalhada de processos mostrou que um segundo suspeito, `core.exe`, estava rodando sem um caminho de executável visível (uma tática de evasão). O `vagent.exe` foi localizado em `%APPDATA%\Valid\Valid Agent Server`.
* **Logs de Eventos:** A análise dos logs de Segurança do Windows revelou um **Evento ID 5379** ("As credenciais do Gerenciador de Credenciais foram lidas") com a operação **"Enumerar Credenciais"**, ocorrendo no logon do usuário `ADMIN-USER`. Isso confirmou uma atividade de roubo de senhas.

#### 2. Análise de Memória Forense (Volatility)

A aquisição de um dump da memória RAM foi o ponto de virada da investigação. A análise com o framework Volatility 3 revelou a verdadeira natureza dos processos.

* **Plugin `windows.cmdline`:**
    * Revelou o caminho completo do `core.exe` como sendo `C:\Program Files\Topaz OFD\Warsaw\core.exe`, identificando-o como o software de segurança bancária e causa dos problemas de performance.
    * Confirmou o caminho completo do `vagent.exe` em `AppData\Roaming`.
* **Plugin `windows.pslist`:**
    * Mapeou as relações de parentesco dos processos, provando os mecanismos de persistência:
        * `services.exe (PID 900) -> core.exe (PID 3588)`: Persistência a nível de sistema (Serviço).
        * `explorer.exe (PID 7116) -> vagent.exe (PID 11168)`: Persistência a nível de usuário (acionado no logon).

## Análise do Malware: Perfil do "ValidAgent"

A análise combinada dos logs do malware (`vagent.log`, `listener-crypto.log`), strings do executável e comportamento observado permitiu traçar o perfil completo do `vagent.exe`.

* **Tipo:** Backdoor modular e ferramenta de fraude.
* **Linguagem:** Escrito em Go (Golang).
* **Persistência:** Chave de registro `Run` ou Tarefa Agendada que o executa a partir do `explorer.exe` no logon do usuário.
* **Comando e Controle (C2):** Utiliza o protocolo **WebSocket** para comunicação com o servidor do atacante, aguardando comandos.
* **Evasão:**
    * **Mascaramento:** Utiliza o nome e o caminho de instalação de um software legítimo (Valid Certificadora) para evitar detecção. Tentou invocar um plugin adicional (`listener-vsentinel.exe`), imitando outro produto de segurança (SentinelOne).
    * **Técnicas de Carregamento:** A falha na extração do executável pela análise de memória (`windows.dumpfiles`) sugere o uso de técnicas de carregamento não-padrão, como *Process Hollowing* ou *Reflective Loading*.
* **Carga Útil (Payload):**
    * **Fraude de Identidade:** Sua função primária é gerenciar o plugin `listener-crypto.exe` para criar remotamente certificados digitais A1 fraudulentos em nome de vítimas, cujos nomes e CPFs foram encontrados nos logs.
    * **Roubo de Credenciais:** Aciona a enumeração de todas as credenciais salvas no cofre do Windows.

## Mapeamento para o MITRE ATT&CK®

As Táticas, Técnicas e Procedimentos (TTPs) observados para o `vagent.exe` incluem:

| Tática | Técnica (ID) | Descrição |
| :--- | :--- | :--- |
| **Persistência** | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001) | O `vagent.exe` é iniciado pelo `explorer.exe`, indicando uma persistência ligada ao logon do usuário. |
| **Defense Evasion** | Masquerading (T1036) | O malware usa nomes e caminhos de diretório de softwares legítimos ("Valid", "vsentinel") para se camuflar. |
| **Credential Access** | OS Credential Dumping: Credential Manager (T1003.005) | O Evento 5379 confirma a enumeração de credenciais do cofre do Windows. |
| **Command and Control** | Application Layer Protocol: WebSockets (T1071.001) | O `vagent.log` indica o uso de WebSockets para comunicação com o C2. |
| **Impact** | Account Access Removal (T1531) | A geração de certificados fraudulentos pode ser usada para assumir o controle de contas e remover o acesso do proprietário legítimo. |


## Conclusão

A investigação demonstrou como um problema de performance pode mascarar uma operação criminal sofisticada e de longa duração. A análise forense de memória foi essencial para contornar as técnicas de evasão do malware e identificar corretamente os diferentes atores no sistema. O incidente destaca a importância de investigar anomalias de performance com rigor e a crescente sofisticação de malwares que utilizam táticas de mascaramento para se misturar a softwares legítimos.

## Indicadores de Comprometimento (IoCs)

* **Caminho do Arquivo:** `%APPDATA%\Valid\Valid Agent Server - Cliente\vagent.exe`
* **Nome do Arquivo de Log:** `%APPDATA%\Valid\Valid Agent Server - Cliente\listener-crypto.log`
* **Nome do Arquivo de Log:** `%APPDATA%\Valid\Valid Agent Server - Cliente\vagent.log`
* **Evento de Segurança:** `Event ID 5379` com a operação "Enumerar Credenciais" ocorrendo no logon.
* **Processo Pai:** `vagent.exe` sendo executado como um processo filho do `explorer.exe`.

