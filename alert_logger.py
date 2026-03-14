"""
alert_logger.py
===============
Módulo de persistência e logging de alertas do IDS.

Salva alertas em:
    - Arquivo de log texto (formato legível, append contínuo)
    - Arquivo JSON (um objeto por linha — JSON Lines format)
      Compatível com ferramentas SIEM como Elasticsearch, Splunk

Formato JSON Lines (JSONL):
    Cada linha é um objeto JSON completo e independente.
    Vantagem: permite processar alertas linha por linha sem
    carregar o arquivo inteiro na memória.

Exemplo de linha JSONL:
    {"id": 1, "timestamp": "14:32:05", "tipo": "Port Scan", ...}
"""

import json
import os
from datetime import datetime


class AlertLogger:
    """
    Gerencia persistência de alertas em disco.

    Args:
        diretorio (str): Pasta onde os logs serão salvos
    """

    def __init__(self, diretorio: str = "logs"):
        self.diretorio = diretorio
        os.makedirs(diretorio, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.arquivo_log   = os.path.join(diretorio, f"ids_{ts}.log")
        self.arquivo_jsonl = os.path.join(diretorio, f"ids_{ts}.jsonl")

        # Escreve cabeçalho no log texto
        self._escrever_log(
            f"{'='*60}\n"
            f"NetGuard IDS — Log de Alertas\n"
            f"Iniciado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"
            f"{'='*60}\n"
        )

    def registrar(self, alerta):
        """
        Persiste um alerta nos arquivos de log.

        Chamado automaticamente pelo IDS a cada novo alerta.

        Args:
            alerta (Alerta): Objeto de alerta a ser salvo
        """
        # Log texto — formato legível por humanos
        entrada_log = (
            f"\n[{alerta.timestamp}] ALERTA #{alerta.id}\n"
            f"  Tipo       : {alerta.tipo}\n"
            f"  Severidade : {alerta.severidade}\n"
            f"  IP Origem  : {alerta.ip_origem}\n"
            f"  IP Destino : {alerta.ip_destino}\n"
            f"  Descrição  : {alerta.descricao}\n"
            f"  Evidência  : {alerta.evidencia}\n"
            f"  Regra      : {alerta.regra}\n"
        )
        self._escrever_log(entrada_log)

        # JSON Lines — para integração com ferramentas SIEM
        entrada_json = {
            "id": alerta.id,
            "timestamp": alerta.timestamp,
            "tipo": alerta.tipo,
            "severidade": alerta.severidade,
            "ip_origem": alerta.ip_origem,
            "ip_destino": alerta.ip_destino,
            "descricao": alerta.descricao,
            "evidencia": alerta.evidencia,
            "regra": alerta.regra,
            "pacotes": alerta.pacotes_envolvidos,
        }
        self._escrever_jsonl(entrada_json)

    def listar_logs(self) -> list:
        """Lista todos os arquivos de log disponíveis."""
        arquivos = []
        for nome in sorted(os.listdir(self.diretorio), reverse=True):
            caminho = os.path.join(self.diretorio, nome)
            if os.path.isfile(caminho):
                tamanho = os.path.getsize(caminho)
                arquivos.append({
                    "nome": nome,
                    "tamanho": f"{tamanho/1024:.1f} KB",
                    "extensao": nome.rsplit(".", 1)[-1],
                })
        return arquivos

    def _escrever_log(self, texto: str):
        try:
            with open(self.arquivo_log, "a", encoding="utf-8") as f:
                f.write(texto)
        except Exception:
            pass

    def _escrever_jsonl(self, dados: dict):
        try:
            with open(self.arquivo_jsonl, "a", encoding="utf-8") as f:
                f.write(json.dumps(dados, ensure_ascii=False) + "\n")
        except Exception:
            pass