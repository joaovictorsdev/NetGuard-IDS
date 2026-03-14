"""
rule_bruteforce.py
==================
Regra de detecção de Brute Force em serviços de autenticação.

Detecta tentativas repetidas de conexão nas portas de serviços
que exigem autenticação — comportamento típico de ataques
de força bruta com ferramentas como Hydra, Medusa e Patator.

Serviços monitorados:
    SSH  (porta 22)  — alvos mais comuns em servidores Linux
    FTP  (porta 21)  — acesso a arquivos
    RDP  (porta 3389)— acesso remoto Windows
    SMB  (porta 445) — compartilhamentos Windows
    MySQL(porta 3306)— banco de dados
    SMTP (porta 25)  — servidores de email

Lógica de detecção:
    Conta conexões TCP SYN de um mesmo IP de origem
    para a mesma porta de serviço nos últimos N segundos.

    Limiar padrão: 10 tentativas em 15 segundos
    (um humano digitando senha não ultrapassa isso)
"""

import time
from collections import defaultdict
from modules.base_rule import BaseRule


class RuleBruteForce(BaseRule):
    """
    Detecta brute force em serviços de autenticação.

    Configurações:
        JANELA_SEGUNDOS: Janela de contagem (padrão: 15s)
        LIMIAR_TENTATIVAS: Conexões para disparar alerta (padrão: 10)
        COOLDOWN: Segundos entre alertas do mesmo IP/porta (padrão: 120s)
    """

    NOME = "BruteForce"

    JANELA_SEGUNDOS = 15
    LIMIAR_TENTATIVAS = 10
    COOLDOWN_SEGUNDOS = 120

    # Portas monitoradas e seus nomes de serviço
    PORTAS_SERVICOS = {
        21:   "FTP",
        22:   "SSH",
        23:   "Telnet",
        25:   "SMTP",
        110:  "POP3",
        143:  "IMAP",
        445:  "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
    }

    def inicializar(self, estado):
        super().inicializar(estado)

        # Por (ip_origem, porta_destino): lista de timestamps de tentativas
        self._tentativas = defaultdict(list)  # (ip, porta) → [ts, ...]

        # Último alerta por (ip, porta)
        self._ultimo_alerta = {}  # (ip, porta) → timestamp

    def analisar(self, pkt):
        """
        Verifica se o pacote é mais uma tentativa de brute force.

        Analisa apenas pacotes TCP SYN para portas de serviços
        monitorados. Conta tentativas por (IP, porta) na janela.
        """
        try:
            from scapy.layers.inet import IP, TCP

            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return None

            tcp = pkt[TCP]
            ip = pkt[IP]

            # Apenas pacotes TCP SYN (início de conexão)
            # SYN sem ACK = nova tentativa de conectar
            flags = str(tcp.flags)
            if "S" not in flags or "A" in flags:
                return None

            porta_destino = tcp.dport
            servico = self.PORTAS_SERVICOS.get(porta_destino)

            if not servico:
                return None  # Porta não monitorada

            origem = ip.src
            destino = ip.dst
            chave = (origem, porta_destino)
            agora = time.time()

            # Adiciona tentativa e limpa janela
            self._tentativas[chave].append(agora)
            self._tentativas[chave] = [
                ts for ts in self._tentativas[chave]
                if agora - ts <= self.JANELA_SEGUNDOS
            ]

            count = len(self._tentativas[chave])

            if count >= self.LIMIAR_TENTATIVAS:
                # Verifica cooldown
                ultimo = self._ultimo_alerta.get(chave, 0)
                if agora - ultimo < self.COOLDOWN_SEGUNDOS:
                    return None

                self._ultimo_alerta[chave] = agora
                taxa = count / self.JANELA_SEGUNDOS

                return self._criar_alerta(
                    tipo=f"Brute Force {servico}",
                    severidade="CRÍTICA",
                    ip_origem=origem,
                    ip_destino=destino,
                    descricao=(
                        f"{origem} fez {count} tentativas de conexão "
                        f"em {servico} (porta {porta_destino}) "
                        f"em {self.JANELA_SEGUNDOS}s "
                        f"(taxa: {taxa:.1f} tentativas/s). "
                        f"Indica ataque de força bruta automatizado."
                    ),
                    evidencia=(
                        f"Serviço: {servico} | "
                        f"Porta: {porta_destino} | "
                        f"Tentativas: {count} em {self.JANELA_SEGUNDOS}s"
                    ),
                    pacotes=count,
                )

        except Exception:
            pass

        return None