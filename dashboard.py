"""
dashboard.py
============
Dashboard web do NetGuard IDS — Interface Flask em tempo real.

Exibe alertas de intrusão conforme são gerados, com:
    - Feed ao vivo de alertas (SSE — Server-Sent Events)
    - Contadores por severidade
    - Gráfico de alertas por tipo
    - Tabela de IPs mais suspeitos
    - Log completo com filtro por severidade

Rotas:
    GET  /                       → Dashboard principal
    GET  /api/alertas            → Alertas recentes (JSON)
    GET  /api/stats              → Estatísticas (JSON)
    POST /api/ids/iniciar        → Inicia monitoramento
    POST /api/ids/parar          → Para monitoramento
    GET  /api/interfaces         → Lista interfaces
    GET  /api/logs               → Lista arquivos de log

Como executar:
    sudo python dashboard.py
    Acesse: http://localhost:5002
"""

from flask import Flask, render_template_string, request, jsonify
import threading
import os

app = Flask(__name__)
app.secret_key = "netguard-ids-2024"

_ids = None
_estado = None
_logger = None
_lock = threading.Lock()

LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)

# ─────────────────────────────────────────────
# Template HTML
# ─────────────────────────────────────────────

TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetGuard IDS Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0f; color: #e2e8f0; }

  nav { background: #0f1117; border-bottom: 1px solid #1a1a2e; padding: 1rem 2rem; display: flex; align-items: center; gap: 1rem; }
  nav h1 { font-size: 1.3rem; color: #f87171; }
  .status-badge { padding: 0.2rem 0.7rem; border-radius: 99px; font-size: 0.78rem; font-weight: 600; }
  .status-off  { background: #1f1f1f; color: #64748b; }
  .status-on   { background: #1c0a0a; color: #f87171; animation: blink 1.5s infinite; }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.5} }

  .container { max-width: 1200px; margin: 0 auto; padding: 1.5rem; }

  /* Controles */
  .controls { background: #0f1117; border: 1px solid #1a1a2e; border-radius: 12px; padding: 1.2rem; margin-bottom: 1.5rem; display: flex; gap: 1rem; align-items: flex-end; flex-wrap: wrap; }
  .form-group { display: flex; flex-direction: column; gap: 0.3rem; min-width: 140px; }
  label { font-size: 0.78rem; color: #64748b; text-transform: uppercase; }
  select, input { background: #0a0a0f; border: 1px solid #1a1a2e; color: #e2e8f0; padding: 0.5rem 0.7rem; border-radius: 6px; font-size: 0.9rem; }
  .btn { padding: 0.55rem 1.2rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.9rem; font-weight: 600; }
  .btn-start  { background: #b91c1c; color: white; }
  .btn-start:hover { background: #991b1b; }
  .btn-stop   { background: #374151; color: white; }
  .btn-stop:hover { background: #4b5563; }
  .btn:disabled { background: #1f2937; color: #4b5563; cursor: not-allowed; }

  /* Cards de severidade */
  .sev-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 1rem; margin-bottom: 1.5rem; }
  .sev-card { background: #0f1117; border: 1px solid var(--cor); border-radius: 10px; padding: 1rem; text-align: center; border-top: 3px solid var(--cor); }
  .sev-card .count { font-size: 2.2rem; font-weight: 700; color: var(--cor); }
  .sev-card .label { font-size: 0.78rem; color: #64748b; margin-top: 0.2rem; }

  /* Grid de conteúdo */
  .content-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem; }
  .card { background: #0f1117; border: 1px solid #1a1a2e; border-radius: 10px; padding: 1.2rem; }
  .card h3 { font-size: 0.85rem; color: #64748b; text-transform: uppercase; letter-spacing: .05em; margin-bottom: 1rem; }

  /* Feed de alertas */
  .alert-feed { max-height: 380px; overflow-y: auto; }
  .alert-item { border-left: 3px solid var(--cor); background: #0a0a0f; border-radius: 0 6px 6px 0; padding: 0.7rem 0.9rem; margin-bottom: 0.5rem; }
  .alert-item .header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem; }
  .alert-item .badge { padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; background: var(--cor); color: #fff; }
  .alert-item .tipo { font-size: 0.88rem; font-weight: 600; color: #e2e8f0; }
  .alert-item .ts { font-size: 0.75rem; color: #4b5563; margin-left: auto; font-family: monospace; }
  .alert-item .info { font-size: 0.78rem; color: #6b7280; }
  .alert-item .evidencia { font-size: 0.75rem; color: #374151; font-family: monospace; margin-top: 0.2rem; }

  /* Tabela de IPs */
  .ip-table { font-size: 0.85rem; width: 100%; }
  .ip-row { display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid #0f1117; }
  .ip-row .ip { color: #94a3b8; font-family: monospace; }
  .ip-row .cnt { color: #f87171; font-weight: 600; }

  /* Filtros */
  .filters { display: flex; gap: 0.4rem; margin-bottom: 1rem; flex-wrap: wrap; }
  .filter-btn { padding: 0.25rem 0.7rem; border: 1px solid #1a1a2e; border-radius: 6px; background: #0a0a0f; color: #64748b; cursor: pointer; font-size: 0.8rem; }
  .filter-btn:hover, .filter-btn.active { border-color: #f87171; color: #f87171; }

  .empty { color: #374151; text-align: center; padding: 2rem; font-size: 0.9rem; }

  @media (max-width: 768px) {
    .sev-grid { grid-template-columns: repeat(2,1fr); }
    .content-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<nav>
  <h1>🛡️ NetGuard IDS</h1>
  <span id="status-badge" class="status-badge status-off">● INATIVO</span>
  <span style="color:#4b5563;font-size:.82rem;margin-left:.5rem" id="pkt-count">0 pacotes analisados</span>
</nav>

<div class="container">

  <!-- Controles -->
  <div class="controls">
    <div class="form-group">
      <label>Interface</label>
      <select id="iface-sel"></select>
    </div>
    <div class="form-group">
      <label>Filtro BPF (opcional)</label>
      <input type="text" id="filtro" placeholder="tcp, not port 22..."/>
    </div>
    <button class="btn btn-start" id="btn-start" onclick="iniciar()">🔴 Iniciar Monitoramento</button>
    <button class="btn btn-stop"  id="btn-stop"  onclick="parar()" disabled>⏹ Parar</button>
  </div>

  <!-- Contadores de severidade -->
  <div class="sev-grid">
    <div class="sev-card" style="--cor:#dc2626"><div class="count" id="cnt-critica">0</div><div class="label">🔴 Crítica</div></div>
    <div class="sev-card" style="--cor:#ea580c"><div class="count" id="cnt-alta">0</div><div class="label">🟠 Alta</div></div>
    <div class="sev-card" style="--cor:#d97706"><div class="count" id="cnt-media">0</div><div class="label">🟡 Média</div></div>
    <div class="sev-card" style="--cor:#2563eb"><div class="count" id="cnt-baixa">0</div><div class="label">🔵 Baixa</div></div>
  </div>

  <!-- Conteúdo principal -->
  <div class="content-grid">

    <!-- Feed de alertas -->
    <div class="card" style="grid-column: 1 / -1;">
      <h3>📋 Alertas em tempo real</h3>
      <div class="filters">
        <button class="filter-btn active" data-sev="TODAS">Todas</button>
        <button class="filter-btn" data-sev="CRÍTICA">🔴 Crítica</button>
        <button class="filter-btn" data-sev="ALTA">🟠 Alta</button>
        <button class="filter-btn" data-sev="MÉDIA">🟡 Média</button>
        <button class="filter-btn" data-sev="BAIXA">🔵 Baixa</button>
      </div>
      <div class="alert-feed" id="alert-feed">
        <div class="empty">Aguardando início do monitoramento...</div>
      </div>
    </div>

    <!-- Gráfico de tipos -->
    <div class="card">
      <h3>📊 Alertas por tipo</h3>
      <canvas id="chart-tipos" height="200"></canvas>
    </div>

    <!-- Top IPs suspeitos -->
    <div class="card">
      <h3>🚨 Top IPs suspeitos</h3>
      <div id="top-ips"><div class="empty">—</div></div>
    </div>

  </div>
</div>

<script>
const CORES = { "CRÍTICA":"#dc2626","ALTA":"#ea580c","MÉDIA":"#d97706","BAIXA":"#2563eb" };

const ctxTipos = document.getElementById('chart-tipos').getContext('2d');
const chartTipos = new Chart(ctxTipos, {
  type: 'bar',
  data: { labels: [], datasets: [{ data: [], backgroundColor: '#dc2626', borderRadius: 4 }] },
  options: {
    animation: false, indexAxis: 'y', responsive: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#4b5563' }, grid: { color: '#0f1117' } },
      y: { ticks: { color: '#94a3b8', font: { size: 11 } }, grid: { display: false } }
    }
  }
});

let filtroAtivo = 'TODAS';
let intervalo = null;

async function carregarInterfaces() {
  const r = await fetch('/api/interfaces');
  const d = await r.json();
  const s = document.getElementById('iface-sel');
  s.innerHTML = d.interfaces.map(i => `<option>${i}</option>`).join('');
}

async function iniciar() {
  const r = await fetch('/api/ids/iniciar', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ interface: document.getElementById('iface-sel').value, filtro_bpf: document.getElementById('filtro').value })
  });
  const d = await r.json();
  if (d.sucesso) {
    document.getElementById('btn-start').disabled = true;
    document.getElementById('btn-stop').disabled = false;
    document.getElementById('status-badge').className = 'status-badge status-on';
    document.getElementById('status-badge').textContent = '● MONITORANDO';
    intervalo = setInterval(atualizar, 2000);
  }
}

async function parar() {
  await fetch('/api/ids/parar', { method: 'POST' });
  document.getElementById('btn-start').disabled = false;
  document.getElementById('btn-stop').disabled = true;
  document.getElementById('status-badge').className = 'status-badge status-off';
  document.getElementById('status-badge').textContent = '● INATIVO';
  if (intervalo) clearInterval(intervalo);
}

async function atualizar() {
  const [ar, sr] = await Promise.all([fetch('/api/alertas?n=50'), fetch('/api/stats')]);
  const alertas = await ar.json();
  const stats   = await sr.json();

  document.getElementById('pkt-count').textContent = `${(stats.total_pacotes||0).toLocaleString()} pacotes analisados`;
  document.getElementById('cnt-critica').textContent = stats.por_severidade?.['CRÍTICA'] || 0;
  document.getElementById('cnt-alta').textContent    = stats.por_severidade?.['ALTA']    || 0;
  document.getElementById('cnt-media').textContent   = stats.por_severidade?.['MÉDIA']   || 0;
  document.getElementById('cnt-baixa').textContent   = stats.por_severidade?.['BAIXA']   || 0;

  // Feed de alertas
  const feed = document.getElementById('alert-feed');
  const lista = alertas.alertas || [];
  const filtrados = filtroAtivo === 'TODAS' ? lista : lista.filter(a => a.severidade === filtroAtivo);

  if (filtrados.length === 0) {
    feed.innerHTML = '<div class="empty">Nenhum alerta' + (filtroAtivo !== 'TODAS' ? ' desta severidade' : '') + ' ainda.</div>';
  } else {
    feed.innerHTML = filtrados.slice().reverse().map(a => {
      const cor = CORES[a.severidade] || '#64748b';
      return `<div class="alert-item" style="--cor:${cor}">
        <div class="header">
          <span class="badge" style="--cor:${cor}">${a.severidade}</span>
          <span class="tipo">${a.tipo}</span>
          <span class="ts">${a.timestamp}</span>
        </div>
        <div class="info">Origem: <strong>${a.ip_origem}</strong> → ${a.ip_destino}</div>
        <div class="evidencia">${a.evidencia}</div>
      </div>`;
    }).join('');
  }

  // Gráfico de tipos
  if (stats.por_tipo) {
    const sorted = Object.entries(stats.por_tipo).sort((a,b) => b[1]-a[1]).slice(0,6);
    chartTipos.data.labels = sorted.map(([k]) => k);
    chartTipos.data.datasets[0].data = sorted.map(([,v]) => v);
    chartTipos.update('none');
  }

  // Top IPs
  if (stats.top_ips && stats.top_ips.length > 0) {
    document.getElementById('top-ips').innerHTML = stats.top_ips.map(([ip, cnt]) =>
      `<div class="ip-row"><span class="ip">${ip}</span><span class="cnt">${cnt} alertas</span></div>`
    ).join('');
  }
}

// Filtros
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    filtroAtivo = btn.dataset.sev;
    atualizar();
  });
});

carregarInterfaces();
</script>
</body>
</html>"""


# ─────────────────────────────────────────────
# Rotas
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(TEMPLATE)


@app.route("/api/ids/iniciar", methods=["POST"])
def iniciar():
    global _ids, _estado, _logger
    dados = request.get_json() or {}
    try:
        from ids_engine import IDSEngine
        from alert_logger import AlertLogger

        with _lock:
            if _ids and _ids.esta_ativo():
                return jsonify({"sucesso": False, "erro": "IDS já ativo"})

            _logger = AlertLogger(diretorio=LOGS_DIR)

            def on_alerta(alerta):
                _logger.registrar(alerta)

            _ids = IDSEngine(
                interface=dados.get("interface", ""),
                filtro_bpf=dados.get("filtro_bpf", ""),
                verbose=False,
                callback_alerta=on_alerta,
            )
            _estado = _ids.iniciar()

        return jsonify({"sucesso": True})
    except Exception as e:
        return jsonify({"sucesso": False, "erro": str(e)})


@app.route("/api/ids/parar", methods=["POST"])
def parar():
    global _ids
    with _lock:
        if _ids:
            _ids.parar()
    return jsonify({"sucesso": True})


@app.route("/api/alertas")
def get_alertas():
    n = int(request.args.get("n", 50))
    if not _estado:
        return jsonify({"alertas": []})
    alertas = _estado.alertas[-n:]
    return jsonify({"alertas": [
        {"id": a.id, "timestamp": a.timestamp, "tipo": a.tipo,
         "severidade": a.severidade, "ip_origem": a.ip_origem,
         "ip_destino": a.ip_destino, "descricao": a.descricao,
         "evidencia": a.evidencia, "pacotes": a.pacotes_envolvidos}
        for a in alertas
    ]})


@app.route("/api/stats")
def get_stats():
    if not _estado:
        return jsonify({"total_pacotes": 0, "total_alertas": 0,
                        "por_severidade": {}, "por_tipo": {}, "top_ips": []})

    # Agrupa por tipo
    por_tipo = {}
    ip_count = {}
    for a in _estado.alertas:
        por_tipo[a.tipo] = por_tipo.get(a.tipo, 0) + 1
        ip_count[a.ip_origem] = ip_count.get(a.ip_origem, 0) + 1

    top_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:10]

    return jsonify({
        "total_pacotes": _estado.total_pacotes,
        "total_alertas": _estado.total_alertas,
        "por_severidade": _estado.por_severidade,
        "por_tipo": por_tipo,
        "top_ips": top_ips,
    })


@app.route("/api/interfaces")
def get_interfaces():
    try:
        from scapy.all import get_if_list
        return jsonify({"interfaces": get_if_list()})
    except Exception:
        return jsonify({"interfaces": ["eth0", "wlan0", "lo"]})


@app.route("/api/logs")
def get_logs():
    if not _logger:
        return jsonify({"logs": []})
    return jsonify({"logs": _logger.listar_logs()})


if __name__ == "__main__":
    print("\n" + "="*50)
    print("  NetGuard IDS Dashboard")
    print("  http://localhost:5002")
    print("  Execute com sudo!")
    print("="*50 + "\n")
    app.run(debug=False, host="0.0.0.0", port=5002)