# 🛡️ NetGuard IDS — Sistema de Detecção de Intrusões

IDS (Intrusion Detection System) em Python com detecção de 5 tipos de ataque
e dashboard web em tempo real.

---

## ⚠️ Requisitos

```bash
sudo python main.py      # CLI requer root para captura de pacotes
sudo python dashboard.py # Dashboard também requer root
```

---

## 🔍 Ataques detectados

| Regra | Ataque | Severidade | Lógica |
|-------|--------|------------|--------|
| `rule_portscan.py` | Port Scan (nmap/masscan) | Alta | 15+ portas distintas em 10s |
| `rule_bruteforce.py` | Brute Force SSH/FTP/RDP | Crítica | 10+ SYN para mesma porta em 15s |
| `rule_flood.py` | Ping Flood / Smurf | Alta | 50+ ICMP de mesmo IP em 5s |
| `rule_dns.py` | DNS Tunneling, DGA, Flood | Média/Alta | Subdomínio longo, queries excessivas |
| `rule_criticalports.py` | Acesso a portas críticas | Crítica/Alta | Qualquer SYN para RDP/SMB/Docker/etc |

---

## 📁 Estrutura

```
ids/
├── main.py                  ← CLI
├── ids_engine.py            ← Motor principal
├── alert_logger.py          ← Persistência em .log e .jsonl
├── dashboard.py             ← Flask web UI
├── requirements.txt
└── modules/
    ├── base_rule.py         ← Classe base das regras
    ├── rule_portscan.py     ← Detecção de port scan
    ├── rule_bruteforce.py   ← Detecção de brute force
    ├── rule_flood.py        ← Detecção de ICMP flood
    ├── rule_dns.py          ← Detecção de DNS suspeito
    └── rule_criticalports.py← Portas de alto risco
```

---

## 🚀 Instalação e uso

```bash
pip install -r requirements.txt

# CLI
sudo python main.py
sudo python main.py -i eth0 -f "not port 22"

# Dashboard web → http://localhost:5002
sudo python dashboard.py
```

---

## 📝 Logs

Alertas salvos em `./logs/` em dois formatos:
- `.log` — texto legível por humanos
- `.jsonl` — JSON Lines para integração com SIEM (Elasticsearch, Splunk)

---

## ➕ Como adicionar nova regra

```python
# modules/rule_minha_regra.py
from modules.base_rule import BaseRule

class RuleMinhaRegra(BaseRule):
    NOME = "MinhaRegra"

    def inicializar(self, estado):
        super().inicializar(estado)
        # inicializa contadores

    def analisar(self, pkt):
        # lógica de detecção
        # retorna self._criar_alerta(...) ou None
        pass
```

Registre em `ids_engine.py` → método `_carregar_regras()`.

---

*Desenvolvido para fins educacionais — Portfólio de Cibersegurança*