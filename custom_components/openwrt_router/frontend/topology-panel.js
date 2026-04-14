const PANEL_TAG = "openwrt-topology-panel";

function esc(v) {
  return String(v || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function sigQ(dbm) {
  if (dbm === null || dbm === undefined) return null;
  if (dbm >= -65) return "good";
  if (dbm >= -75) return "fair";
  return "poor";
}

const SIG_DE = { good: "gut", fair: "mittel", poor: "schwach" };
const ICONS = { gw: "🌐", ap: "📶", iface: "📡", wifi: "💻", lan: "🖥️" };

function nodeIcon(node) {
  const t = node.type;
  if (t === "router") return node.role === "gateway" ? ICONS.gw : ICONS.ap;
  if (t === "interface") return ICONS.iface;
  if (t === "client") {
    const sig = (node.attributes || {}).signal;
    return sig !== null && sig !== undefined ? ICONS.wifi : ICONS.lan;
  }
  return "❓";
}

// Layout constants — must match render() group label calculations
const COL_X = { router: 125, iface: 375, client: 660 };
const HALF_W = { router: 82, iface: 76, client: 70 };
const ROW_H = 106;
const GROUP_GAP = 24;
const START_Y = 60;
const CANVAS_W = 900;

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

  static get properties() { return { hass: {} }; }

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
    } catch (err) {
      this._error = err.message || String(err);
    }
    this.render();
  }

  // ── Layout ─────────────────────────────────────────────────────

  computeLayout(nodes, edges) {
    const routers = nodes.filter(n => n.type === "router");
    const ifaces  = nodes.filter(n => n.type === "interface");
    const clients = nodes.filter(n => n.type === "client");

    routers.sort((a, b) => {
      if (a.role === "gateway" && b.role !== "gateway") return -1;
      if (b.role === "gateway" && a.role !== "gateway") return 1;
      return (a.label || "").localeCompare(b.label || "");
    });

    const routerGroups = routers.map(r => {
      const myIfaces = ifaces.filter(i => (i.attributes || {}).ap_mac === r.id);
      const myClients = [];
      for (const f of myIfaces) {
        const fc = clients.filter(c =>
          edges.some(e => (e.from === f.id && e.to === c.id) || (e.to === f.id && e.from === c.id))
        );
        myClients.push(...fc);
      }
      const directClients = clients.filter(c =>
        !myClients.includes(c) &&
        edges.some(e => (e.from === r.id && e.to === c.id) || (e.to === r.id && e.from === c.id))
      );
      myClients.push(...directClients);
      return { router: r, ifaces: myIfaces, clients: myClients };
    });

    const assignedIds = new Set(routerGroups.flatMap(g => g.clients.map(c => c.id)));
    const orphans = clients.filter(c => !assignedIds.has(c.id));
    if (orphans.length > 0 && routerGroups.length > 0) routerGroups[0].clients.push(...orphans);

    const pos = {};
    let y = START_Y;

    for (const g of routerGroups) {
      const gStart = y;
      const gRows = Math.max(1, g.ifaces.length, g.clients.length);
      pos[g.router.id] = { x: COL_X.router, y: gStart + Math.floor((gRows * ROW_H) / 2) };
      g.ifaces.forEach((f, i)  => { pos[f.id] = { x: COL_X.iface,  y: gStart + i * ROW_H + ROW_H / 2 }; });
      g.clients.forEach((c, i) => { pos[c.id] = { x: COL_X.client, y: gStart + i * ROW_H + ROW_H / 2 }; });
      y = gStart + gRows * ROW_H + GROUP_GAP;
    }

    for (const f of ifaces) {
      if (!pos[f.id]) { pos[f.id] = { x: COL_X.iface, y }; y += ROW_H; }
    }

    pos._canvasH = Math.max(500, y + 40);
    pos._routerGroups = routerGroups;
    return pos;
  }

  // ── Node card HTML ──────────────────────────────────────────────

  nodeCardHtml(node, layout) {
    const p = layout[node.id] || { x: 0, y: 0 };
    const a = node.attributes || {};
    const t = node.type;
    const isGw     = t === "router" && node.role === "gateway";
    const isAP     = t === "router" && !isGw;
    const isIface  = t === "interface";
    const isClient = t === "client";

    // Card variant class
    let cls = "node";
    if (isGw) cls += " node-gw";
    else if (isAP) cls += " node-ap";
    else if (isIface) {
      const b = String(a.band || "").toLowerCase();
      if (b.includes("5"))      cls += " node-i5";
      else if (b.includes("6")) cls += " node-i6";
      else                       cls += " node-i24";
    } else if (isClient) cls += " node-cli";
    if (this._selected === node.id) cls += " selected";
    if (node.status === "inactive" || node.status === "offline") cls += " inactive";
    if (node.inferred) cls += " inferred";

    // Status dot
    const dot = node.status === "disabled" ? "disabled"
      : (node.status === "inactive" || node.status === "offline") ? "offline"
      : "online";

    // Text content
    const name = esc(node.label || node.id);
    let sub = "", sub2 = "", extra = "";

    if (t === "router") {
      sub = esc(a.host_ip || a.ip || "");
      sub2 = esc(a.model || "OpenWrt");
      if (isGw) {
        const ok = a.wan_connected;
        extra = `<span class="wan wan-${ok ? "ok" : "no"}">${ok ? "WAN ✓" : "WAN ✗"}</span>`;
      }
    } else if (isIface) {
      sub = esc(a.ssid || "");
      if (a.channel) sub2 = `Kanal ${esc(String(a.channel))}`;
    } else if (isClient) {
      sub = esc(a.ip || a.mac || "");
      const q = sigQ(a.signal);
      if (q) extra = `<span class="sig sig-${q}">${esc(String(a.signal))} dBm (${SIG_DE[q]})</span>`;
    }

    return `<div class="${cls}" data-id="${esc(node.id)}"
          style="left:${p.x}px;top:${p.y}px">
        <div class="dot dot-${dot}"></div>
        <div class="nicon">${nodeIcon(node)}</div>
        <div class="nname">${name}</div>
        ${sub  ? `<div class="nsub">${sub}</div>`  : ""}
        ${sub2 ? `<div class="nsub">${sub2}</div>` : ""}
        ${extra}
      </div>`;
  }

  // ── Bezier SVG edges ────────────────────────────────────────────

  bezier(x1, y1, x2, y2, cls) {
    const mx = (x1 + x2) / 2;
    return `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" class="${cls}"/>`;
  }

  colOf(x) {
    return x < 260 ? "router" : x < 530 ? "iface" : "client";
  }

  edgesHtml(edges, layout) {
    return edges.map(e => {
      const from = e.from || e.source, to = e.to || e.target;
      const p1 = layout[from], p2 = layout[to];
      if (!p1 || !p2) return "";

      const rel = String(e.relationship || "");
      let cls;
      if      (rel.includes("uplink") && rel.includes("wifi")) cls = "e-uplink-wifi";
      else if (rel.includes("uplink"))                          cls = "e-uplink-lan";
      else if (rel.includes("mesh"))                            cls = "e-mesh";
      else if (rel.includes("client") && rel.includes("wifi")) cls = "e-wifi";
      else if (rel.includes("client"))                          cls = "e-lan";
      else                                                      cls = "e-internal";
      if (e.inferred) cls += " e-inf";

      const x1 = p1.x + HALF_W[this.colOf(p1.x)];
      const x2 = p2.x - HALF_W[this.colOf(p2.x)];
      return this.bezier(x1, p1.y, x2, p2.y, cls);
    }).join("");
  }

  // ── Details sidebar ─────────────────────────────────────────────

  detailsHtml(node) {
    if (!node) return '<div class="hint">Node auswählen für Details</div>';
    const a = node.attributes || {};
    const rows = [
      ["Name",     node.label || node.id],
      ["Typ",      node.type],
      ["Rolle",    node.role],
      ["ID",       node.id],
      ["IP",       a.host_ip || a.ip],
      ["MAC",      a.mac],
      ["Status",   node.status],
      ["Signal",   a.signal != null ? `${a.signal} dBm` : null],
      ["SSID",     a.ssid],
      ["Band",     a.band],
      ["Kanal",    a.channel],
      ["WAN",      a.wan_connected != null ? (a.wan_connected ? "verbunden" : "getrennt") : null],
      ["WAN Proto",a.wan_proto],
      ["Firmware", a.firmware],
      ["Modell",   a.model],
      ["Uplink",   a.link_type],
      ["Abgeleitet", node.inferred ? "ja" : null],
    ].filter(([, v]) => v != null && v !== "");
    return rows.map(([k, v]) =>
      `<div class="row"><span class="k">${esc(k)}:</span><span class="v">${esc(String(v))}</span></div>`
    ).join("");
  }

  wireHandlers() {
    this.shadowRoot.querySelectorAll(".node").forEach(el => {
      el.addEventListener("click", () => {
        this._selected = el.getAttribute("data-id");
        this.render();
      });
    });
    const btn = this.shadowRoot.getElementById("reload");
    if (btn) btn.addEventListener("click", () => this.load());
  }

  // ── Main render ─────────────────────────────────────────────────

  render() {
    const snap   = this._snapshot;
    const nodes  = Array.isArray(snap?.nodes) ? snap.nodes : [];
    const edges  = Array.isArray(snap?.edges) ? snap.edges : [];
    const meta   = snap?.meta || {};
    const layout = this.computeLayout(nodes, edges);
    const H      = layout._canvasH || 500;
    const sel    = nodes.find(n => n.id === this._selected) || null;
    const stats  = `${meta.router_count || 0} Router · ${meta.client_count || 0} Clients · ${meta.interface_count || 0} Interfaces`;

    const nodesHtml = nodes.map(n => this.nodeCardHtml(n, layout)).join("");
    const svgEdges  = this.edgesHtml(edges, layout);

    // Group labels + separator lines for multi-router view
    const groups = layout._routerGroups || [];
    let grpHtml = "";
    if (groups.length > 1) {
      let gy = START_Y;
      for (const g of groups) {
        const rows = Math.max(1, g.ifaces.length, g.clients.length);
        const lbl  = g.router.role === "gateway" ? "Gateway" : "AP";
        grpHtml += `<div class="glbl" style="top:${gy - 18}px">${esc(lbl)}: ${esc(g.router.label || g.router.id)}</div>`;
        const endY = gy + rows * ROW_H;
        if (g !== groups[groups.length - 1]) {
          grpHtml += `<div class="gsep" style="top:${endY + GROUP_GAP / 2 - 1}px"></div>`;
        }
        gy = endY + GROUP_GAP;
      }
    }

    this.shadowRoot.innerHTML = `
      <style>
        :host {
          display:block; height:100%;
          font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
          /* ── FritzBox-style color palette ── */
          --cg:   #0a84ff;   /* gateway / WAN blue   */
          --cr:   #5e5ce6;   /* radio / AP purple    */
          --cl:   #32ade6;   /* LAN cyan             */
          --good: #30d158;   /* signal good green    */
          --fair: #ffd60a;   /* signal fair yellow   */
          --poor: #ff453a;   /* signal poor red      */
          --bg:   #1c1c1e;
          --card: #2c2c2e;
          --bdr:  #3a3a3c;
          --txt:  #f5f5f7;
          --mut:  #8e8e93;
          --head: #1e293b;
          --rad:  12px;
        }

        .page { height:100%; display:grid; grid-template-columns:1fr 300px; grid-template-rows:auto 1fr; background:var(--bg); color:var(--txt); }

        /* ── Header ── */
        .head { grid-column:1/3; padding:10px 16px; background:var(--head); border-bottom:1px solid var(--bdr); display:flex; justify-content:space-between; align-items:center; }
        .head h2 { margin:0; font-size:15px; font-weight:600; }
        .stats  { font-size:12px; color:var(--mut); margin-top:2px; }
        #reload { background:#334155; color:var(--txt); border:1px solid #475569; border-radius:6px; padding:5px 14px; cursor:pointer; font-size:13px; }
        #reload:hover { background:#475569; }

        /* ── Canvas ── */
        .canvas { overflow:auto; }
        .inner  { position:relative; width:${CANVAS_W}px; min-height:${H}px; margin:10px; }
        svg     { position:absolute; inset:0; pointer-events:none; overflow:visible; width:${CANVAS_W}px; height:${H}px; }

        .clbl { position:absolute; top:10px; font-size:10px; color:var(--mut); font-weight:600; text-transform:uppercase; letter-spacing:1px; }
        .c0 { left:47px; } .c1 { left:297px; } .c2 { left:590px; }
        .glbl { position:absolute; left:8px; font-size:10px; color:var(--mut); font-weight:600; text-transform:uppercase; letter-spacing:.5px; }
        .gsep { position:absolute; left:8px; right:8px; height:1px; background:var(--bdr); }

        /* ── FritzBox-style card nodes ── */
        .node {
          position:absolute; transform:translate(-50%,-50%);
          background:var(--card); border:1px solid var(--bdr);
          border-radius:var(--rad); padding:8px 12px; width:156px;
          cursor:pointer; transition:box-shadow .15s; user-select:none;
        }
        .node:hover  { box-shadow:0 0 0 2px rgba(255,255,255,.12); }
        .node.selected { box-shadow:0 0 0 2px var(--cg),0 0 14px rgba(10,132,255,.3); z-index:20; }
        .node.inactive { opacity:.4; }
        .node.inferred { outline:2px dashed var(--fair); outline-offset:3px; }

        .node-gw  { border-color:var(--cg); background:#0a84ff14; }
        .node-ap  { border-color:var(--cr); background:#5e5ce614; }
        .node-i24 { border-color:var(--good); background:#30d15814; }
        .node-i5  { border-color:var(--cr);   background:#5e5ce614; }
        .node-i6  { border-color:#bf5af2;      background:#bf5af214; }
        .node-cli { border-color:var(--bdr); }

        /* Status dot */
        .dot { position:absolute; top:8px; right:8px; width:7px; height:7px; border-radius:50%; }
        .dot-online   { background:var(--good); }
        .dot-disabled { background:var(--mut); }
        .dot-offline  { background:var(--poor); }

        .nicon { font-size:18px; margin-bottom:2px; }
        .nname { font-weight:600; font-size:12px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:130px; }
        .nsub  { color:var(--mut); font-size:10px; margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }

        /* Signal pill */
        .sig { display:inline-block; margin-top:4px; padding:1px 6px; border-radius:20px; font-size:10px; font-weight:600; }
        .sig-good { background:#30d15820; color:var(--good); }
        .sig-fair { background:#ffd60a20; color:var(--fair); }
        .sig-poor { background:#ff453a20; color:var(--poor); }

        /* WAN badge */
        .wan { display:inline-block; margin-top:4px; padding:1px 6px; border-radius:20px; font-size:10px; font-weight:600; }
        .wan-ok { background:#30d15820; color:var(--good); }
        .wan-no { background:#ff453a20; color:var(--poor); }

        /* ── Bezier connector lines ── */
        .e-internal   { stroke:var(--cg);   stroke-width:2;   fill:none; opacity:.5; }
        .e-wifi       { stroke:var(--cr);   stroke-width:1.5; fill:none; opacity:.6; stroke-dasharray:6 3; }
        .e-lan        { stroke:var(--cl);   stroke-width:1.5; fill:none; opacity:.6; }
        .e-uplink-lan  { stroke:var(--fair); stroke-width:2.5; fill:none; opacity:.8; }
        .e-uplink-wifi { stroke:var(--cr);   stroke-width:2.5; fill:none; opacity:.8; stroke-dasharray:6 3; }
        .e-mesh        { stroke:var(--mut);  stroke-width:2;   fill:none; opacity:.5; stroke-dasharray:4 4; }
        .e-inf         { opacity:.3; stroke-dasharray:4 5; }

        /* ── Sidebar ── */
        .side { border-left:1px solid var(--bdr); padding:16px; overflow:auto; background:#1a1a1c; }
        .side h3 { margin:0 0 12px; font-size:13px; font-weight:600; color:var(--mut); text-transform:uppercase; letter-spacing:1px; }
        .row { margin-bottom:5px; font-size:12px; display:flex; gap:4px; }
        .k   { min-width:110px; color:var(--mut); flex-shrink:0; }
        .v   { color:var(--txt); word-break:break-all; }
        .hint { font-size:12px; color:var(--mut); padding:12px 0; }
        .err  { color:#fca5a5; padding:20px; }

        /* ── Legend ── */
        .legend { margin-top:20px; border-top:1px solid var(--bdr); padding-top:12px; }
        .legend h4 { margin:0 0 8px; font-size:11px; color:var(--mut); text-transform:uppercase; }
        .li { display:flex; align-items:center; gap:8px; margin-bottom:4px; font-size:11px; color:var(--mut); }
        .ld { width:10px; height:10px; border-radius:3px; flex-shrink:0; }
        .ll { width:24px; height:0; flex-shrink:0; }
      </style>

      <div class="page">
        <div class="head">
          <div>
            <h2>🗺️ OpenWrt Mesh Topology</h2>
            <div class="stats">${esc(stats)}</div>
          </div>
          <button id="reload">Neu laden</button>
        </div>

        <div class="canvas">
          ${this._error ? `<div class="err">Fehler: ${esc(this._error)}</div>` : ""}
          <div class="inner">
            <div class="clbl c0">Router</div>
            <div class="clbl c1">Interfaces</div>
            <div class="clbl c2">Clients</div>
            ${grpHtml}
            <svg>${svgEdges}</svg>
            ${nodesHtml}
          </div>
        </div>

        <div class="side">
          <h3>Details</h3>
          ${this.detailsHtml(sel)}
          <div class="legend">
            <h4>Legende</h4>
            <div class="li"><div class="ld" style="background:var(--cg)"></div> Gateway</div>
            <div class="li"><div class="ld" style="background:var(--cr)"></div> AP Router</div>
            <div class="li"><div class="ld" style="background:var(--good)"></div> WLAN 2.4 GHz</div>
            <div class="li"><div class="ld" style="background:var(--cr)"></div> WLAN 5 GHz</div>
            <div class="li"><div class="ld" style="background:#bf5af2"></div> WLAN 6 GHz</div>
            <div class="li"><div class="ll" style="border-top:2px solid var(--cg);opacity:.7"></div> WAN / intern</div>
            <div class="li"><div style="width:24px;height:0;border-top:2px dashed var(--cr);opacity:.8"></div> WLAN</div>
            <div class="li"><div class="ll" style="border-top:2px solid var(--cl)"></div> LAN</div>
            <div class="li"><div style="width:24px;height:0;border-top:2px dashed var(--mut)"></div> Mesh (inferred)</div>
            <div class="li"><span class="sig sig-good">gut (&gt;−65)</span></div>
            <div class="li"><span class="sig sig-fair">mittel</span></div>
            <div class="li"><span class="sig sig-poor">schwach (&lt;−75)</span></div>
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
