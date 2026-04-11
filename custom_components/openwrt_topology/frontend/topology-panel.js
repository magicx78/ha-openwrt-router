const PANEL_TAG = "openwrt-topo-panel-v2";

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

  colorFor(node) {
    const t = String(node.type || "unknown").toLowerCase();
    const a = node.attributes || {};
    const role = String(node.role || "").toLowerCase();
    if (node.status === "inactive" || node.status === "offline") return "#475569";
    if (t === "router" || t === "gateway") {
      return role === "gateway" ? "#d97706" : "#1d4ed8";
    }
    if (t === "interface" || t === "ap" || t === "access_point") {
      const band = String(a.band || "").toLowerCase();
      if (band.includes("5")) return "#7c3aed";
      if (band.includes("6")) return "#db2777";
      return "#059669";
    }
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
    const role = String(node.role || "").toLowerCase();
    if (t === "router" || t === "gateway") {
      return role === "gateway" ? "shape-gateway" : "shape-router";
    }
    if (t === "interface" || t === "ap" || t === "access_point" || t === "switch") return "shape-square";
    return "shape-pill";
  }

  computeLayout(nodes, edges) {
    // Group nodes by router (ap_mac attribute = router_id)
    const routers = nodes.filter((n) => n.type === "router");
    const ifaces = nodes.filter((n) => n.type === "interface");
    const clients = nodes.filter((n) => n.type === "client");

    // Sort: gateway first, then alphabetical
    routers.sort((a, b) => {
      if (a.role === "gateway" && b.role !== "gateway") return -1;
      if (b.role === "gateway" && a.role !== "gateway") return 1;
      return (a.label || "").localeCompare(b.label || "");
    });

    // Build router → interfaces → clients mapping
    const routerGroups = routers.map((r) => {
      const rId = r.id;
      const myIfaces = ifaces.filter((i) => (i.attributes || {}).ap_mac === rId);
      const myClients = [];
      for (const iface of myIfaces) {
        const ifaceClients = clients.filter((c) => {
          // Find client connected to this interface via edges
          return edges.some(
            (e) => (e.from === iface.id && e.to === c.id) || (e.to === iface.id && e.from === c.id)
          );
        });
        myClients.push(...ifaceClients);
      }
      // Also find clients directly connected to router (no interface match)
      const directClients = clients.filter((c) => {
        return edges.some(
          (e) => (e.from === rId && e.to === c.id) || (e.to === rId && e.from === c.id)
        ) && !myClients.includes(c);
      });
      myClients.push(...directClients);
      return { router: r, ifaces: myIfaces, clients: myClients };
    });

    // Assign orphan clients (not linked to any router group)
    const assignedClientIds = new Set(routerGroups.flatMap((g) => g.clients.map((c) => c.id)));
    const orphanClients = clients.filter((c) => !assignedClientIds.has(c.id));
    if (orphanClients.length > 0 && routerGroups.length > 0) {
      routerGroups[0].clients.push(...orphanClients);
    }

    const pos = {};
    const colX = { router: 120, iface: 380, client: 680 };
    let y = 60;
    const ROW_H = 46;
    const GROUP_GAP = 30;

    for (const group of routerGroups) {
      const groupStartY = y;
      // Router node centered vertically in its group
      const groupRows = Math.max(1, group.ifaces.length, group.clients.length);
      const routerY = groupStartY + Math.floor((groupRows * ROW_H) / 2);
      pos[group.router.id] = { x: colX.router, y: routerY };

      // Interfaces
      for (let i = 0; i < group.ifaces.length; i++) {
        pos[group.ifaces[i].id] = { x: colX.iface, y: groupStartY + i * ROW_H };
      }

      // Clients
      for (let i = 0; i < group.clients.length; i++) {
        pos[group.clients[i].id] = { x: colX.client, y: groupStartY + i * ROW_H };
      }

      y = groupStartY + groupRows * ROW_H + GROUP_GAP;
    }

    // Position orphan interfaces (shouldn't happen but safety)
    for (const iface of ifaces) {
      if (!pos[iface.id]) {
        pos[iface.id] = { x: colX.iface, y };
        y += ROW_H;
      }
    }

    pos._canvasH = Math.max(650, y + 40);
    pos._routerGroups = routerGroups;
    return pos;
  }

  detailsHtml(node) {
    if (!node) return '<div class="hint">Node auswaehlen</div>';
    const a = node.attributes || {};
    const rows = [
      ["Name", node.label || node.id],
      ["Typ", node.type],
      ["Rolle", node.role],
      ["ID", node.id],
      ["IP", a.ip || a.host_ip || node.ip],
      ["Host-IP", a.host_ip],
      ["Status", node.status],
      ["Signal", a.signal !== null && a.signal !== undefined ? `${a.signal} dBm` : null],
      ["Bitrate", a.bitrate],
      ["SSID", a.ssid],
      ["Band", a.band],
      ["Channel", a.channel],
      ["Radio", a.radio],
      ["Hostname", a.hostname],
      ["MAC", a.mac],
      ["WAN Proto", a.wan_proto],
      ["WAN Connected", a.wan_connected !== undefined ? String(a.wan_connected) : null],
      ["Uplink", a.link_type],
      ["Firmware", a.firmware],
      ["Model", a.model],
      ["Inferred", node.inferred ? "ja" : "nein"],
      ["Source", node.source],
    ].filter(([, v]) => v !== null && v !== undefined && v !== "" && v !== "unknown");
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
    const layout = this.computeLayout(nodes, edges);
    const canvasH = layout._canvasH || 700;
    const selected = nodes.find((n) => n.id === this._selected) || null;

    const meta = snap?.meta || {};
    const routerCount = meta.router_count || nodes.filter((n) => n.type === "router").length;
    const stats = `${routerCount} Router  |  ${meta.client_count || 0} Clients  |  ${meta.interface_count || 0} Interfaces  |  ${meta.node_count || nodes.length} Nodes`;

    const edgeSvg = edges
      .map((e) => {
        const from = e.from || e.source;
        const to = e.to || e.target;
        const p1 = layout[from];
        const p2 = layout[to];
        if (!p1 || !p2) return "";
        const rel = String(e.relationship || "");
        const isUplink = rel.includes("uplink") || rel.includes("mesh");
        const isClient = rel.includes("client");
        const dashed = e.inferred ? "4,5" : isClient ? "6,4" : "";
        let color, w;
        if (isUplink) {
          color = rel.includes("wifi") ? "#7c3aed" : "#d97706";
          w = "3";
        } else {
          color = e.inferred ? "#475569" : "#334155";
          w = isClient ? "1.5" : "2";
        }
        return `<line x1="${p1.x}" y1="${p1.y}" x2="${p2.x}" y2="${p2.y}" stroke="${color}" stroke-width="${w}" ${dashed ? `stroke-dasharray="${dashed}"` : ""} />`;
      })
      .join("");

    const nodeHtml = nodes
      .map((n) => {
        const p = layout[n.id] || { x: 0, y: 0 };
        const cls = [
          "node",
          this.shapeClassFor(n),
          n.status === "inactive" || n.status === "offline" ? "inactive" : "",
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

    // Group separator lines
    const groups = layout._routerGroups || [];
    let groupLabelsHtml = "";
    if (groups.length > 1) {
      let gy = 60;
      const ROW_H = 46, GROUP_GAP = 30;
      for (const g of groups) {
        const rows = Math.max(1, g.ifaces.length, g.clients.length);
        const endY = gy + rows * ROW_H;
        const role = g.router.role === "gateway" ? "Gateway" : "AP";
        groupLabelsHtml += `<div class="group-label" style="top:${gy - 14}px">${esc(role)}: ${esc(g.router.label || g.router.id)}</div>`;
        if (g !== groups[groups.length - 1]) {
          groupLabelsHtml += `<div class="group-sep" style="top:${endY + GROUP_GAP / 2 - 1}px"></div>`;
        }
        gy = endY + GROUP_GAP;
      }
    }

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
        .col-label { position:absolute; top:10px; font-size:11px; color:#64748b; font-weight:600; text-transform:uppercase; letter-spacing:1px; }
        .col-0 { left:70px; } .col-1 { left:330px; } .col-2 { left:640px; }
        .group-label { position:absolute; left:10px; font-size:10px; color:#94a3b8; font-weight:600; text-transform:uppercase; letter-spacing:.5px; }
        .group-sep { position:absolute; left:10px; right:10px; height:1px; background:#334155; }
        .node { position:absolute; transform:translate(-50%,-50%); background:var(--node-bg,#64748b); color:#fff; border:2px solid rgba(255,255,255,.15); min-width:80px; min-height:32px; padding:4px 10px; cursor:pointer; font-size:12px; font-weight:500; transition:all .15s; }
        .node:hover { filter:brightness(1.2); z-index:10; }
        .shape-gateway { border-radius:10px; min-width:140px; font-size:14px; font-weight:700; border:3px solid rgba(255,255,255,.4); }
        .shape-router { border-radius:10px; min-width:120px; font-size:13px; font-weight:700; border:3px solid rgba(255,255,255,.25); }
        .shape-square { border-radius:8px; }
        .shape-pill { border-radius:16px; }
        .inactive { opacity:.35; }
        .invalid { border-color:#ef4444 !important; }
        .inferred { outline:2px dashed #fbbf24; outline-offset:3px; }
        .selected { box-shadow:0 0 0 3px #3b82f6,0 0 12px rgba(59,130,246,.4); z-index:20; }
        .side { border-left:1px solid #1e293b; padding:16px; overflow:auto; background:#1e293b; }
        .side h3 { margin:0 0 12px; font-size:14px; font-weight:600; color:#94a3b8; text-transform:uppercase; letter-spacing:1px; }
        .row { margin-bottom:5px; font-size:13px; display:flex; }
        .k { min-width:110px; color:#64748b; flex-shrink:0; }
        .v { color:#e2e8f0; word-break:break-all; }
        .hint { margin-top:12px; font-size:12px; padding:6px 8px; border-radius:6px; }
        .hint.inf { background:#1e3a5f; color:#93c5fd; }
        .hint.warn { background:#451a03; color:#fca5a5; }
        .error { color:#fca5a5; padding:20px; }
        .legend { margin-top:20px; border-top:1px solid #334155; padding-top:12px; }
        .legend h4 { margin:0 0 8px; font-size:12px; color:#64748b; text-transform:uppercase; }
        .legend-item { display:flex; align-items:center; gap:8px; margin-bottom:4px; font-size:12px; }
        .legend-dot { width:12px; height:12px; border-radius:3px; flex-shrink:0; }
        .legend-line { width:24px; height:0; flex-shrink:0; }
      </style>
      <div class="page">
        <div class="head">
          <div>
            <h2>OpenWrt Mesh Topology</h2>
            <div class="stats">${esc(stats)}</div>
          </div>
          <button id="reload">Neu laden</button>
        </div>
        <div class="canvas">
          ${this._error ? `<div class="error">Fehler: ${esc(this._error)}</div>` : ""}
          <div class="canvas-inner">
            <div class="col-label col-0">Router</div>
            <div class="col-label col-1">Interfaces</div>
            <div class="col-label col-2">Clients</div>
            ${groupLabelsHtml}
            <svg viewBox="0 0 900 ${canvasH}" preserveAspectRatio="none">${edgeSvg}</svg>
            ${nodeHtml}
          </div>
        </div>
        <div class="side">
          <h3>Details</h3>
          ${this.detailsHtml(selected)}
          <div class="legend">
            <h4>Legende</h4>
            <div class="legend-item"><div class="legend-dot" style="background:#d97706"></div> Gateway (WAN)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#1d4ed8"></div> AP Router</div>
            <div class="legend-item"><div class="legend-dot" style="background:#059669"></div> Interface 2.4 GHz</div>
            <div class="legend-item"><div class="legend-dot" style="background:#7c3aed"></div> Interface 5 GHz</div>
            <div class="legend-item"><div class="legend-dot" style="background:#059669"></div> Client (gut &gt;-50)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#0891b2"></div> Client (ok / ?)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#d97706"></div> Client (schwach)</div>
            <div class="legend-item"><div class="legend-dot" style="background:#dc2626"></div> Client (schlecht)</div>
            <div class="legend-item"><div class="legend-line" style="border-top:3px solid #d97706"></div> LAN Uplink</div>
            <div class="legend-item"><div class="legend-line" style="border-top:3px solid #7c3aed"></div> WiFi Uplink</div>
            <div class="legend-item"><div class="legend-line" style="border-top:2px dashed #fbbf24"></div> Inferred</div>
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
