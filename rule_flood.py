"""
rule_flood.py
=============
Regra de detecção de Ping Flood e ICMP Flood.

Detecta volumes anormais de pacotes ICMP de um único IP,
indicando possível ataque de negação de serviço (DoS).

Ataques detectados:
    - Ping Flood (ICMP Echo Request em volume)
    - Smurf Attack (ICMP para broadcast)
    - ICMP Flood genérico (qualquer tipo ICMP em volume)

Lógica de detecção:
    Conta pacotes ICMP de um mesmo IP de origem nos últimos N segundos.
    Limiar padrão: 50 pacotes ICMP em 5 segundos (= 10 pps)
    Um ping humano normal: 1 pps (1 por segundo)
"""

import time
from collections import defaultdict
from modules.base_rule import BaseRule


class RuleFlood(BaseRule):

    NOME = "ICMPFlood"

    JANELA_SEGUNDOS = 5
    LIMIAR_PACOTES = 50       # 50 pacotes em 5s = 10 pps (muito acima do normal)
    COOLDOWN_SEGUNDOS = 30

    def inicializar(self, estado):
        super().inicializar(estado)
        self._icmp_por_ip = defaultdict(list)  # ip → [timestamps]
        self._ultimo_alerta = {}

    def analisar(self, pkt):
        try:
            from scapy.layers.inet import IP, ICMP

            if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
                return None

            ip = pkt[IP]
            icmp = pkt[ICMP]
            origem = ip.src
            destino = ip.dst
            agora = time.time()

            # Monitora apenas Echo Request (tipo 8) — o ping comum
            # Tipo 0 = Echo Reply, normalmente gerado localmente
            if icmp.type not in (8, 0):
                return None

            self._icmp_por_ip[origem].append(agora)
            self._icmp_por_ip[origem] = [
                ts for ts in self._icmp_por_ip[origem]
                if agora - ts <= self.JANELA_SEGUNDOS
            ]

            count = len(self._icmp_por_ip[origem])

            if count >= self.LIMIAR_PACOTES:
                ultimo = self._ultimo_alerta.get(origem, 0)
                if agora - ultimo < self.COOLDOWN_SEGUNDOS:
                    return None

                self._ultimo_alerta[origem] = agora
                taxa = count / self.JANELA_SEGUNDOS

                # Detecta possível Smurf (destino é broadcast)
                tipo_ataque = "Ping Flood"
                if destino.endswith(".255") or destino == "255.255.255.255":
                    tipo_ataque = "Smurf Attack (ICMP Broadcast)"

                return self._criar_alerta(
                    tipo=tipo_ataque,
                    severidade="ALTA",
                    ip_origem=origem,
                    ip_destino=destino,
                    descricao=(
                        f"{origem} enviou {count} pacotes ICMP em "
                        f"{self.JANELA_SEGUNDOS}s (taxa: {taxa:.0f} pps). "
                        f"Volume muito acima do normal — possível ataque DoS."
                    ),
                    evidencia=(
                        f"ICMP tipo {icmp.type} | "
                        f"{count} pacotes em {self.JANELA_SEGUNDOS}s | "
                        f"Taxa: {taxa:.0f} pkt/s"
                    ),
                    pacotes=count,
                )

        except Exception:
            pass

        return None