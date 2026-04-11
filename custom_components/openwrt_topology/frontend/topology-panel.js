const PANEL_TAG = "openwrt-topology-panel";

function esc(v) {
  return String(v)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function metric(v, unit = "") {
  if (v === null || v === undefined) return "?";
  return unit ? `${v} ${unit}` : String(v);
}

class OpenWrtTopologyPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._snapshot = null;
    this._selected = null;
    this._error = null;
  }

  set hass(hass) {
    this._hass = hass;
    if (!this._initialized) {
      this._initialized = true;
      this.render();
      this.load();
    }
  }

  static get properties() {
    return { hass: {} };
  }

  async load() {
    this._error = null;
    this.render();
    try {
      if (this._hass && typeof this._hass.callApi === "function") {
        this._snapshot = await this._hass.callApi("GET", "openwrt_topology/snapshot");
      } else {
        const resp = await fetch("/api/openwrt_topology/snapshot", {
          headers: { Accept: "application/json" },
          credentials: "same-origin",
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        this._snapshot = await resp.json();
      }
      if (!this._selected && Array.isArray(this._snapshot.nodes) && this._snapshot.nodes.length) {
        this._selected = this._snapshot.nodes[0].id;
      }
    } catch (err) {
      this._error = err.message || String(err);
    }
    this.render();
  }

  laneFor(node) {
    const t = String(node.type || "unknown").toLowerCase();
    if (t === "router" || t === "gateway") return 0;
    if (t === "ap" || t === "access_point" || t === "switch" || t === "interface" || t === "ssid" || t === "unknown") return 1;
    return 2;
  }

  colorFor(node) {
    const t = String(node.type || "unknown").toLowerCase();
    const a = node.attributes || {};
    if (node.status === "inactive") return "#475569";
    if (t === "router" || t === "gateway") return "#1d4ed8";
    if (t === "ap" || t === "access_point") return "#059669";
    if (t === "interface") {
      const band = String(a.band || "").toLowerCase();
      if (band.includes("5")) return "#7c3aed";
      if (band.includes("6")) return "#db2777";
      return "#059669";
    }
    if (t === "ssid") return "#7c3aed";
    if (t === "client") {
      const sig = a.signal;
      if (sig === null || sig === undefined) return "#0891b2";
      if (sig >= -50) return "#059669";
      if (sig >= -65) return "#0891b2";
      if (sig >= -75) return "#d97706";
      return "#dc2626";
    }
    return "#64748b";
  }

  shapeClassFor(node) {
    const t = String(node.type || "unknown").toLowerCase();
    if (t === "router" || t === "gateway") return "shape-router";
    if (t === "interface" || t === "ap" || t === "access_point" || t === "switch") return "shape-square";
    if (t === "ssid") return "shape-diamond";
    return "shape-pill";
  }

  computeLayout(nodes) {
    const byLane = [[], [], []];
    for (const node of nodes) byLane[this.laneFor(node)].push(node);

    const pos = {};
    const laneX = [140, 400, 700];
    const clientCount = byLane[2].length;
    const maxItems = Math.max(byLane[0].length, byLane[1].length, clientCount);
    const canvasH = Math.max(650, maxItems * 56 + 80);

    for (let lane = 0; lane < byLane.length; lane += 1) {
      const list = byLane[lane];
      const step = Math.max(50, Math.floor((canvasH - 80) / Math.max(1, list.length)));
      for (let i = 0; i < list.length; i += 1) {
        pos[list[i].id] = { x: laneX[lane], y: 60 + i * step };
      }
    }
    pos._canvasH = canvasH;
    return pos;
  }

  detailsHtml(node) {
    if (!node) return '<div class="hint">Node auswaehlen</div>';
    const a = node.attributes || {};
    const rows = [
      ["Name", node.label || node.id],
      ["Typ", node.type],
      ["ID", node.id],
      ["IP", a.ip || node.ip],
      ["Status", node.status],
      ["Signal", a.signal !== null && a.signal !== undefined ? `${a.signal} dBm` : null],
      ["Bitrate", a.bitrate],
      ["SSID", a.ssid],
      ["Band", a.band],
      ["Channel", a.channel],
      ["Radio", a.radio],
      ["Hostname", a.hostname],
      ["MAC", a.mac],
      ["Inferred", node.inferred ? "ja" : "nein"],
      ["Valid", node.valid === false ? "false" : "true"],
      ["Source", node.source],
    ].filter(([, v]) => v !== null && v !== undefined && v !== "");
    const body = rows
      .map(([k, v]) => `<div class="row"><span class="k">${esc(k)}:</span><span class="v">${esc(v)}</span></div>`)
      .join("");
    const hints = [
      node.inferred ? '<div class="hint inf">Wert abgeleitet, nicht gemessen.</div>' : "",
      node.valid === false ? '<div class="hint warn">Datenfehler.</div>' : "",
    ].join("");
    return `${body}${hints}`;
  }

  wireHandlers() {
    this.shadowRoot.querySelectorAll(".node").forEach((el) => {
      el.addEventListener("click", () => {
        this._selected = el.getAttribute("data-id");
        this.render();
      });
    });
    const reload = this.shadowRoot.getElementById("reload");
    if (reload) reload.addEventListener("click", () => this.load());
  }

  render() {
    const snap = this._snapshot;
    const nodes = Array.isArray(snap?.nodes) ? snap.nodes : [];
    const edges = Array.isArray(snap?.edges) ? snap.edges : [];
    const layout = this.computeLayout(nodes);
    const canvasH = layout._canvasH || 700;
    const selected = nodes.find((n) => n.id === this._selected) || null;

    const meta = snap?.meta || {};
    const stats = `${meta.node_count || nodes.length} Nodes  |  ${meta.client_count || 0} Clients  |  ${meta.interface_count || 0} Interfaces`;

    const edgeSvg = edges
      .map((e) => {
        const from = e.from || e.source;
        const to = e.to || e.target;
        const p1 = layout[from];
        const p2 = layout[to];
        if (!p1 || !p2) return "";
        const isClient = String(e.relationship || "").includes("client");
        const dashed = e.inferred ? "4,5" : isClient ? "6,4" : "";
        const color = e.inferred ? "#475569" : isClient ? "#334155" : "#475569";
        const w = isClient ? "1.5" : "2";
        return `<line x1="${p1.x}" y1="${p1.y}" x2="${p2.x}" y2="${p2.y}" stroke="${color}" stroke-width="${w}" ${dashed ? `stroke-dasharray="${dashed}"` : ""} />`;
      })
      .join("");

    const nodeHtml = nodes
      .map((n) => {
        const p = layout[n.id] || { x: 0, y: 0 };
        const cls = [
          "node",
          this.shapeClassFor(n),
          n.status === "inactive" ? "inactive" : "",
          n.valid === false ? "invalid" : "",
          n.inferred ? "inferred" : "",
          this._selected === n.id ? "selected" : "",
        ]
          .filter(Boolean)
          .join(" ");
        const bg = this.colorFor(n);
        return `<button class="${cls}" data-id="${esc(n.id)}" style="left:${p.x}px;top:${p.y}px;--node-bg:${bg}">
            <span>${esc(n.label || n.id)}</span>
          </button>`;
      })
      .join("");

    this.shadowRoot.innerHTML = `
      <style>
        :host { display:block; height:100%; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
        .page { height:100%; display:grid; grid-template-columns:1fr 320px; grid-template-rows:auto 1fr; background:#0f172a; color:#e2e8f0; }
        .head { grid-column:1/3; padding:8px 16px; background:#1e293b; border-bottom:1px solid #334155; display:flex; justify-content:space-between; align-items:center; }
        .head h2 { margin:0; font-size:15px; font-weight:600; letter-spacing:.3px; }
        .head .stats { font-size:12px; color:#94a3b8; }
        #reload { background:#334155; color:#e2e8f0; border:1px solid #475569; border-radius:6px; padding:5px 14px; cursor:pointer; font-size:13px; }
        #reload:hover { background:#475569; }
        .canvas { position:relative; overflow:auto; }
        .canvas-inner { position:relative; width:900px; min-height:${canvasH}px; margin:6px; }
        svg { position:absolute; inset:0; pointer-events:none; }
        .lane-label { position:absolute; top:10px; font-size:11px; color:#64748b; font-weight:600; text-transform:uppercase; letter-spacing:1px; }
        .lane-0 { left:80px; } .lane-1 { left:340px; } .lane-2 { left:650px; }
        .node { position:absolute; transform:translate(-50%,-50%); background:var(--node-bg,#64748b); color:#fff; border:2px solid rgba(255,255,255,.15); min-width:80px; min-height:32px; padding:4px 10px; cursor:pointer; font-size:12px; font-weight:500; transition:all .15s; }
        .node:hover { filter:brightness(1.2); z-index:10; }
        .shape-router { border-radius:10px; min-width:130px; font-size:14px; font-weight:700; border:3px solid rgba(255,255,255,.3); }
        .shape-square { border-radius:8px; }
        .shape-pill { border-radius:16px; }
        .shape-diamond { transform:translate(-50%,-50%) rotate(45deg); border-radius:6px; }
        .shape-diamond span { display:inline-block; transform:rotate(-45deg); }
        .inactive { opacity:.35; }
        .invalid { border-color:#ef4444 !important; }
        .inferred { outline:2px dashed #fbbf24; outline-offset:3px; }
        .selected { box-shadow:0 0 0 3px #3b82f6,0 0 12px rgba(59,130,246,.4); z-index:20; }
        .side { border-left:1px solid #1e293b; padding:16px; overflow:auto; background:#1e293b; }
        .side h3 { margin:0 0 12px; font-size:14px; font-weight:600; color:#94a3b8; text-transform:uppercase; letter-spacing:1px; }
        .row { margin-bottom:5px; font-size:13px; display:flex; }
        .k { min-width:100px; color:#64748b; flex-shrink:0; }
        .v { color:#e2e8f0; word-break:break-all; }
        .hint { margin-top:12px; font-size:12px; padding:6px 8px; border-radius:6px; }
        .hint.inf { background:#1e3a5f; color:#93c5fd; }
        .hint.warn { background:#451a03; color:#fca5a5; }
        .error { color:#fca5a5; padding:20px; }
        .legend { margin-top:20px; border-top:1px solid #334155; padding-top:12px; }
        .legend h4 { margin:0 0 8px; font-size:12px; color:#64748b; text-transform:uppercase; }
        .legend-item { display:flex; align-items:center; gap:8px; margin-bottom:4px; font-size:12px; }
        .legend-dot { width:12px; height:12px; border-radius:3px; flex-shrink:0; }
      </style>
      <div class="page">
        <div class="head">
          <div>
            <h2>OpenWrt Network Topology</h2>
            <div class="stats">${esc(stats)}</div>
          </div>
          <button id="reload">Neu laden</button>
        </div>
        <div class="canvas">
          ${this._error ? `<div class="error">Fehler: ${esc(this._error)}</div>` : ""}
          <div class="canvas-inner">
            <div class="lane-label lane-0">Router</div>
            <div class="lane-label lane-1">Interfaces</div>
            <div class="lane-label lane-2">Clients</div>
            <svg viewBox="0 0 900 ${canvasH}" preserveAspectRatio="none">${edgeSvg}</svg>
            ${nodeHtml}
          </div>
        </div>
        <div class="side">
          <h3>Details</h3>
          ${this.detailsHtml(selected)}
          <div class="legend">
            <h4>Legende</h4>
            <div class="legend-item"><div class="legend-dot" style="background:#1d4ed8"></div> Router</div>
            <div class="legend-item"><div class="legend-dot" style="background:#059669"></div> Interface (2.4 GHz)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#7c3aed"></div> Interface (5 GHz)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#059669"></div> Client (gut: &gt;-50 dBm)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#0891b2"></div> Client (ok / unbekannt)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#d97706"></div> Client (schwach: -65...-75)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#dc2626"></div> Client (schlecht: &lt;-75)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#475569"></div> Inaktiv</div>
          </div>
        </div>
      </div>
    `;
    this.wireHandlers();
  }
}

if (!customElements.get(PANEL_TAG)) {
  customElements.define(PANEL_TAG, OpenWrtTopologyPanel);
}
