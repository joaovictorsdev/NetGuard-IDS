"""
rule_portscan.py
================
Regra de detecção de Port Scan.

Detecta quando um único IP tenta se conectar a muitas portas
diferentes em um curto período de tempo — comportamento típico
de ferramentas como nmap, masscan e zmap.

Técnicas detectadas:
    - SYN Scan (TCP SYN sem completar handshake — "stealth scan")
    - Connect Scan (TCP SYN+ACK completo)
    - NULL/FIN/XMAS Scan (flags TCP incomuns)
    - UDP Scan (tentativas de conexão UDP em múltiplas portas)

Lógica de detecção:
    Janela de tempo deslizante por IP:
    - Conta quantas portas DISTINTAS um IP tentou acessar nos últimos N segundos
    - Se ultrapassar o limiar → Port Scan detectado

    Limiar padrão: 15 portas distintas em 10 segundos

Referência: SANS Institute — Intrusion Detection FAQ
"""

import time
from collections import defaultdict
from modules.base_rule import BaseRule


class RulePortScan(BaseRule):
    """
    Detecta port scans baseado em volume de portas distintas por IP.

    Configurações:
        JANELA_SEGUNDOS: Janela de tempo para contagem (padrão: 10s)
        LIMIAR_PORTAS:   Portas distintas para disparar alerta (padrão: 15)
        COOLDOWN:        Segundos entre alertas do mesmo IP (padrão: 60s)
    """

    NOME = "PortScan"

    # Limiar de portas distintas para considerar como scan
    JANELA_SEGUNDOS = 10
    LIMIAR_PORTAS = 15

    # Após alertar um IP, espera este tempo antes de alertar novamente
    COOLDOWN_SEGUNDOS = 60

    def inicializar(self, estado):
        super().inicializar(estado)

        # Por IP: lista de (timestamp, porta) das conexões recentes
        # defaultdict evita KeyError ao acessar IPs novos
        self._conexoes = defaultdict(list)  # ip → [(ts, porta), ...]

        # Registro do último alerta por IP (evita spam de alertas)
        self._ultimo_alerta = {}  # ip → timestamp

    def analisar(self, pkt):
        """
        Verifica se o pacote faz parte de um port scan em andamento.

        Analisa pacotes TCP SYN e UDP. Mantém janela deslizante
        de portas acessadas por IP e dispara alerta se ultrapassar
        o limiar configurado.
        """
        try:
            from scapy.layers.inet import IP, TCP, UDP

            if not pkt.haslayer(IP):
                return None

            ip = pkt[IP]
            origem = ip.src
            destino = ip.dst
            agora = time.time()

            porta = None

            # TCP: detecta SYN scan (flag S sem A) e outros scans
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                flags = str(tcp.flags)

                # SYN scan: apenas flag SYN (sem ACK) — tentativa de conexão
                # FIN/NULL/XMAS scans: flags incomuns usadas para evasão
                if "S" in flags and "A" not in flags:
                    porta = tcp.dport
                elif flags in ("F", "", "FPU"):  # FIN, NULL, XMAS
                    porta = tcp.dport

            # UDP scan: qualquer pacote UDP para nova porta
            elif pkt.haslayer(UDP):
                porta = pkt[UDP].dport

            if not porta:
                return None

            # Adiciona conexão à janela deslizante do IP
            self._conexoes[origem].append((agora, porta))

            # Remove entradas fora da janela de tempo
            self._conexoes[origem] = [
                (ts, p) for ts, p in self._conexoes[origem]
                if agora - ts <= self.JANELA_SEGUNDOS
            ]

            # Conta portas DISTINTAS na janela atual
            portas_distintas = set(p for _, p in self._conexoes[origem])

            if len(portas_distintas) >= self.LIMIAR_PORTAS:
                # Verifica cooldown — não alerta o mesmo IP repetidamente
                ultimo = self._ultimo_alerta.get(origem, 0)
                if agora - ultimo < self.COOLDOWN_SEGUNDOS:
                    return None

                self._ultimo_alerta[origem] = agora

                # Lista das primeiras 10 portas para evidência
                amostra = sorted(list(portas_distintas))[:10]
                portas_str = ", ".join(str(p) for p in amostra)
                if len(portas_distintas) > 10:
                    portas_str += f" ... (+{len(portas_distintas)-10} mais)"

                return self._criar_alerta(
                    tipo="Port Scan",
                    severidade="ALTA",
                    ip_origem=origem,
                    ip_destino=destino,
                    descricao=(
                        f"{origem} tentou conectar em {len(portas_distintas)} portas "
                        f"distintas em {self.JANELA_SEGUNDOS}s. "
                        f"Indica reconhecimento de serviços ativos (nmap/masscan)."
                    ),
                    evidencia=f"Portas: {portas_str}",
                    pacotes=len(self._conexoes[origem]),
                )

        except Exception:
            pass

        return None