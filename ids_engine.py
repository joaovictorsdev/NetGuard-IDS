"""
ids_engine.py
=============
Motor principal do IDS (Intrusion Detection System).

Responsável por:
    - Capturar pacotes via Scapy (igual ao NetAnalyzer)
    - Passar cada pacote para os módulos de detecção (rules)
    - Gerenciar alertas gerados
    - Manter estado de sessões e contadores por IP
    - Notificar callbacks (terminal, dashboard, arquivo de log)

Arquitetura:
    Pacote → ids_engine → [rule_portscan, rule_bruteforce,
                            rule_flood, rule_dns, rule_criticalports]
                       → Alerta → [log, terminal, dashboard]

Referências:
    - Snort Rule Writing Guide
    - OWASP Network Intrusion Detection
    - RFC 793 (TCP), RFC 792 (ICMP)
"""

import threading
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Callable, List

try:
    from scapy.all import sniff, get_if_list
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


# ─────────────────────────────────────────────
# Estruturas de dados
# ─────────────────────────────────────────────

@dataclass
class Alerta:
    """Representa um alerta de intrusão gerado pelo IDS."""
    id: int                          # ID sequencial do alerta
    timestamp: str                   # Horário de geração
    tipo: str                        # Ex: "Port Scan", "Brute Force SSH"
    severidade: str                  # "CRÍTICA", "ALTA", "MÉDIA", "BAIXA"
    ip_origem: str                   # IP do atacante
    ip_destino: str                  # IP alvo
    descricao: str                   # Descrição detalhada do ataque
    evidencia: str                   # Dados técnicos que confirmam a detecção
    regra: str                       # Nome da regra que gerou o alerta
    pacotes_envolvidos: int = 0      # Quantos pacotes ativaram a regra
    resolvido: bool = False          # Para gestão no dashboard


@dataclass
class EstadoIDS:
    """Estado global do IDS — compartilhado entre todos os módulos de regras."""
    inicio: str
    interface: str
    ativa: bool = True

    # Contadores gerais
    total_pacotes: int = 0
    total_alertas: int = 0

    # Lista de alertas gerados (janela dos últimos 1000)
    alertas: List[Alerta] = field(default_factory=list)
    MAX_ALERTAS: int = 1000

    # Contadores por severidade
    por_severidade: dict = field(default_factory=lambda: {
        "CRÍTICA": 0, "ALTA": 0, "MÉDIA": 0, "BAIXA": 0
    })

    # Próximo ID de alerta
    _proximo_id: int = 1

    def adicionar_alerta(self, alerta: Alerta):
        """Adiciona um alerta ao estado, mantendo a janela máxima."""
        alerta.id = self._proximo_id
        self._proximo_id += 1
        self.total_alertas += 1
        self.por_severidade[alerta.severidade] = \
            self.por_severidade.get(alerta.severidade, 0) + 1
        self.alertas.append(alerta)
        if len(self.alertas) > self.MAX_ALERTAS:
            self.alertas.pop(0)


# ─────────────────────────────────────────────
# Motor principal
# ─────────────────────────────────────────────

class IDSEngine:
    """
    Motor de detecção de intrusões.

    Captura pacotes de rede e aplica múltiplas regras de detecção
    em cada pacote. Quando uma regra detecta um ataque, gera um
    Alerta e notifica os callbacks registrados.

    Args:
        interface (str): Interface de rede a monitorar
        filtro_bpf (str): Filtro BPF para restringir captura
        verbose (bool): Exibe alertas no terminal em tempo real
        callback_alerta (Callable): Função chamada a cada novo alerta
    """

    VERSAO = "1.0.0"

    def __init__(
        self,
        interface: str = "",
        filtro_bpf: str = "",
        verbose: bool = True,
        callback_alerta: Optional[Callable] = None,
    ):
        if not SCAPY_OK:
            raise ImportError("Scapy não encontrado: pip install scapy")

        self.interface = interface or self._detectar_interface()
        self.filtro_bpf = filtro_bpf
        self.verbose = verbose
        self.callback_alerta = callback_alerta

        self.estado: Optional[EstadoIDS] = None
        self._thread: Optional[threading.Thread] = None
        self._parar = threading.Event()
        self._lock = threading.Lock()

        # Carrega módulos de regras
        self._carregar_regras()

    # ──────────────────────────────────────────
    # Controle
    # ──────────────────────────────────────────

    def iniciar(self) -> EstadoIDS:
        """Inicia a captura e monitoramento em background."""
        self._parar.clear()
        self.estado = EstadoIDS(
            inicio=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            interface=self.interface,
        )

        # Inicializa estado em cada regra
        for regra in self._regras:
            regra.inicializar(self.estado)

        self._log(f"\n{'='*58}")
        self._log(f"  NetGuard IDS v{self.VERSAO} — Sistema de Detecção de Intrusões")
        self._log(f"{'='*58}")
        self._log(f"  Interface : {self.interface}")
        self._log(f"  Filtro    : {self.filtro_bpf or '(nenhum)'}")
        self._log(f"  Regras    : {len(self._regras)} carregadas")
        self._log(f"  Início    : {self.estado.inicio}")
        self._log(f"{'='*58}\n")

        self._thread = threading.Thread(
            target=self._loop_captura,
            daemon=True,
            name="IDS-Capture",
        )
        self._thread.start()
        return self.estado

    def parar(self):
        """Para o monitoramento."""
        self._parar.set()
        if self.estado:
            self.estado.ativa = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._log("[*] IDS encerrado.")

    def esta_ativo(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ──────────────────────────────────────────
    # Loop de captura
    # ──────────────────────────────────────────

    def _loop_captura(self):
        """Thread de captura — passa cada pacote pelas regras."""
        try:
            sniff(
                iface=self.interface if self.interface != "any" else None,
                filter=self.filtro_bpf or None,
                prn=self._processar_pacote,
                stop_filter=lambda p: self._parar.is_set(),
                store=False,
            )
        except PermissionError:
            self._log("\n[ERRO] Execute com sudo: sudo python main.py\n")
        except Exception as e:
            self._log(f"\n[ERRO] Falha na captura: {e}")

    def _processar_pacote(self, pkt):
        """
        Processa um pacote capturado.

        Aplica todas as regras ao pacote. Se uma regra gerar um alerta,
        registra no estado e notifica os callbacks.
        """
        with self._lock:
            if not self.estado:
                return
            self.estado.total_pacotes += 1

        # Aplica cada regra ao pacote
        for regra in self._regras:
            try:
                alerta = regra.analisar(pkt)
                if alerta:
                    with self._lock:
                        self.estado.adicionar_alerta(alerta)

                    # Exibe no terminal
                    if self.verbose:
                        self._log_alerta(alerta)

                    # Notifica callback externo (dashboard)
                    if self.callback_alerta:
                        self.callback_alerta(alerta)

            except Exception:
                continue  # Ignora erros em regras individuais

    # ──────────────────────────────────────────
    # Carregamento de regras
    # ──────────────────────────────────────────

    def _carregar_regras(self):
        """Carrega todos os módulos de regras de detecção."""
        from modules.rule_portscan import RulePortScan
        from modules.rule_bruteforce import RuleBruteForce
        from modules.rule_flood import RuleFlood
        from modules.rule_dns import RuleDNS
        from modules.rule_criticalports import RuleCriticalPorts

        self._regras = [
            RulePortScan(),
            RuleBruteForce(),
            RuleFlood(),
            RuleDNS(),
            RuleCriticalPorts(),
        ]

    # ──────────────────────────────────────────
    # Utilitários
    # ──────────────────────────────────────────

    def _detectar_interface(self) -> str:
        try:
            interfaces = get_if_list()
            for prefixo in ("eth", "enp", "ens", "wlan", "wlp"):
                for iface in interfaces:
                    if iface.startswith(prefixo):
                        return iface
            return "lo"
        except Exception:
            return "eth0"

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    def _log_alerta(self, alerta: Alerta):
        """Exibe alerta no terminal com cores por severidade."""
        cores = {
            "CRÍTICA": "\033[41m\033[97m",   # Fundo vermelho
            "ALTA":    "\033[31m",            # Vermelho
            "MÉDIA":   "\033[33m",            # Amarelo
            "BAIXA":   "\033[36m",            # Ciano
        }
        reset = "\033[0m"
        cor = cores.get(alerta.severidade, "")

        print(
            f"{cor}[ALERTA #{alerta.id}] [{alerta.severidade}] "
            f"{alerta.tipo}{reset}\n"
            f"  Origem : {alerta.ip_origem}\n"
            f"  Alvo   : {alerta.ip_destino}\n"
            f"  Info   : {alerta.descricao}\n"
        )