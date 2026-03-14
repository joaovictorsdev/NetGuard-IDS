"""
rule_criticalports.py
=====================
Regra de detecção de conexões em portas de alto risco.

Alerta quando qualquer host externo tenta conectar em serviços
que normalmente não deveriam ser acessíveis de fora da rede:

    RDP   (3389) — acesso remoto Windows, alvo frequente de ransomware
    Telnet (23)  — protocolo legado sem criptografia
    VNC   (5900) — acesso gráfico remoto sem criptografia
    SMB   (445)  — compartilhamentos Windows (WannaCry, NotPetya)
    Redis (6379) — banco em memória, frequentemente exposto sem senha
    MongoDB (27017) — banco sem autenticação por padrão em versões antigas
    Elasticsearch (9200) — índice de busca exposto sem auth
    Docker API (2375) — API Docker sem TLS (permite execução de containers)

Lógica:
    Qualquer TCP SYN para essas portas de um IP não-local gera alerta.
    É diferente das outras regras — não precisa de volume, UMA conexão
    já é suspeita o suficiente para merecer atenção.
"""

import time
from modules.base_rule import BaseRule


class RuleCriticalPorts(BaseRule):

    NOME = "CriticalPorts"

    COOLDOWN_SEGUNDOS = 300  # 5 minutos entre alertas do mesmo IP/porta

    # Portas críticas com descrição do risco
    PORTAS_CRITICAS = {
        23:    ("Telnet",        "ALTA",    "Protocolo sem criptografia — credenciais trafegam em texto claro."),
        135:   ("MSRPC",         "MÉDIA",   "Windows RPC — vetor para exploits como EternalBlue."),
        139:   ("NetBIOS",       "MÉDIA",   "NetBIOS — expõe nomes de máquinas e compartilhamentos."),
        445:   ("SMB",           "CRÍTICA", "Protocolo SMB — alvo do WannaCry, NotPetya e outros ransomwares."),
        1433:  ("MSSQL",         "ALTA",    "SQL Server exposto — risco de extração de dados ou execução de comandos."),
        2375:  ("Docker API",    "CRÍTICA", "API Docker sem TLS — permite criar containers e escalar privilégios."),
        2376:  ("Docker TLS",    "ALTA",    "API Docker com TLS — acesso ao daemon Docker."),
        3389:  ("RDP",           "CRÍTICA", "Remote Desktop — alvo frequente de brute force e exploits RDP."),
        4444:  ("Metasploit",    "CRÍTICA", "Porta padrão do Metasploit reverse shell — possível C2 ativo."),
        5900:  ("VNC",           "ALTA",    "VNC sem criptografia — acesso gráfico remoto exposto."),
        6379:  ("Redis",         "ALTA",    "Redis frequentemente configurado sem senha — acesso direto ao banco."),
        9200:  ("Elasticsearch", "ALTA",    "Elasticsearch sem autenticação — dados indexados expostos."),
        27017: ("MongoDB",       "ALTA",    "MongoDB sem auth — banco de dados acessível sem credenciais."),
        31337: ("Back Orifice",  "CRÍTICA", "Porta histórica de backdoors (Back Orifice, etc)."),
    }

    def inicializar(self, estado):
        super().inicializar(estado)
        self._ultimo_alerta = {}  # (ip, porta) → timestamp

    def analisar(self, pkt):
        """
        Detecta tentativas de conexão TCP em portas críticas.

        Qualquer TCP SYN para uma porta crítica vindo de um IP
        externo (não loopback) é considerado suspeito.
        """
        try:
            from scapy.layers.inet import IP, TCP
            import ipaddress

            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return None

            tcp = pkt[TCP]
            ip = pkt[IP]

            # Apenas SYN (início de conexão)
            flags = str(tcp.flags)
            if "S" not in flags or "A" in flags:
                return None

            porta = tcp.dport
            if porta not in self.PORTAS_CRITICAS:
                return None

            origem = ip.src
            destino = ip.dst

            # Ignora tráfego loopback (127.x.x.x)
            try:
                if ipaddress.ip_address(origem).is_loopback:
                    return None
            except ValueError:
                return None

            servico, severidade, risco = self.PORTAS_CRITICAS[porta]
            chave = (origem, porta)
            agora = time.time()

            ultimo = self._ultimo_alerta.get(chave, 0)
            if agora - ultimo < self.COOLDOWN_SEGUNDOS:
                return None

            self._ultimo_alerta[chave] = agora

            return self._criar_alerta(
                tipo=f"Conexão em Porta Crítica: {servico} ({porta})",
                severidade=severidade,
                ip_origem=origem,
                ip_destino=destino,
                descricao=(
                    f"{origem} tentou conectar na porta {porta} ({servico}). "
                    f"{risco}"
                ),
                evidencia=f"Porta: {porta}/{servico} | Flags TCP: {flags}",
                pacotes=1,
            )

        except Exception:
            pass

        return None