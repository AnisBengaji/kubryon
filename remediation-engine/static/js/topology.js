/* ============================================================
   Kubernetes Security Console — Topology
   Real pod inventory / namespace topology

   Data source:
     GET /api/topology

   Important:
     This version does NOT invent network connections.
     Actual pod-to-pod traffic can be added later from Hubble.
   ============================================================ */

(() => {
  "use strict";

  const CONFIG = {
    refreshInterval: 8000,

    // Namespace layout
    namespaceGapX: 70,
    namespaceGapY: 70,

    // Pod layout
    podWidth: 155,
    podHeight: 42,
    podGapX: 18,
    podGapY: 18,

    // Namespace padding
    paddingTop: 46,
    paddingRight: 24,
    paddingBottom: 24,
    paddingLeft: 24,

    // Animation
    transition: 350,

    // Maximum label length displayed directly on graph
    labelLength: 21
  };

  const state = {
    data: {
      available: false,
      namespaces: [],
      nodes: []
    },

    nodes: [],
    visibleNodes: [],

    search: "",
    isolatedOnly: false,
    activeNamespaces: new Set(),

    svg: null,
    root: null,
    namespaceLayer: null,
    nodeLayer: null,

    zoom: null,

    selectedNode: null,

    width: 0,
    height: 0,

    refreshTimer: null,
    initialized: false
  };

  /* ==========================================================
     Helpers
     ========================================================== */

  function truncate(value, length = CONFIG.labelLength) {
    if (!value) return "";
    return value.length > length
      ? `${value.slice(0, length - 1)}…`
      : value;
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function statusClass(node) {
    if (node.isolated) return "isolated";

    const phase = String(node.phase || "").toLowerCase();

    if (phase === "running") return "running";
    if (phase === "succeeded" || phase === "completed") return "completed";

    return "unknown";
  }

  function statusColor(node) {
    switch (statusClass(node)) {
      case "running":
        return "#45c979";

      case "isolated":
        return "#ef6262";

      case "completed":
        return "#4c8dff";

      default:
        return "#89919d";
    }
  }

  function statusText(node) {
    if (node.isolated) return "ISOLATED";

    const phase = String(node.phase || "Unknown");

    return phase.toUpperCase();
  }

  function namespaceColor(namespace) {
    const colors = [
      "#4c8dff",
      "#45c979",
      "#d8c85a",
      "#ef7d7d",
      "#8c78d8",
      "#4fb6c6",
      "#d98c52",
      "#6f9fcf"
    ];

    let hash = 0;

    for (let i = 0; i < namespace.length; i++) {
      hash = ((hash << 5) - hash) + namespace.charCodeAt(i);
      hash |= 0;
    }

    return colors[Math.abs(hash) % colors.length];
  }

  function nodeMatchesSearch(node) {
    if (!state.search) return true;

    const query = state.search.toLowerCase();

    return [
      node.name,
      node.namespace,
      node.ip,
      node.owner_kind,
      node.phase
    ]
      .filter(Boolean)
      .some(value => String(value).toLowerCase().includes(query));
  }

  function nodeIsVisible(node) {
    if (!nodeMatchesSearch(node)) return false;

    if (state.isolatedOnly && !node.isolated) {
      return false;
    }

    if (
      state.activeNamespaces.size > 0 &&
      !state.activeNamespaces.has(node.namespace)
    ) {
      return false;
    }

    return true;
  }

  /* ==========================================================
     Metrics
     ========================================================== */

  function updateMetrics(nodes) {
    const podCount = nodes.length;

    const namespaces = new Set(
      nodes.map(node => node.namespace).filter(Boolean)
    );

    const running = nodes.filter(
      node =>
        !node.isolated &&
        String(node.phase || "").toLowerCase() === "running"
    ).length;

    const isolated = nodes.filter(node => node.isolated).length;

    setText("topology-pod-count", podCount);
    setText("topology-namespace-count", namespaces.size);
    setText("topology-running-count", running);
    setText("topology-isolated-count", isolated);
  }

  function setText(id, value) {
    const element = document.getElementById(id);

    if (element) {
      element.textContent = value;
    }
  }

  /* ==========================================================
     SVG setup
     ========================================================== */

  function setupSvg() {
    const svgElement = document.getElementById("topo-svg");

    if (!svgElement) {
      console.error("Topology: #topo-svg not found.");
      return false;
    }

    state.svg = d3.select(svgElement);

    state.svg.selectAll("*").remove();

    const defs = state.svg.append("defs");

    /*
     * Subtle grid.
     */
    const pattern = defs
      .append("pattern")
      .attr("id", "topology-grid")
      .attr("width", 32)
      .attr("height", 32)
      .attr("patternUnits", "userSpaceOnUse");

    pattern
      .append("path")
      .attr("d", "M 32 0 L 0 0 0 32")
      .attr("fill", "none")
      .attr("stroke", "#1a2028")
      .attr("stroke-width", 0.7)
      .attr("opacity", 0.45);

    state.svg
      .append("rect")
      .attr("class", "topology-background")
      .attr("width", "100%")
      .attr("height", "100%")
      .attr("fill", "url(#topology-grid)");

    state.root = state.svg
      .append("g")
      .attr("class", "topology-root");

    state.namespaceLayer = state.root
      .append("g")
      .attr("class", "namespace-layer");

    state.nodeLayer = state.root
      .append("g")
      .attr("class", "node-layer");

    setupZoom();

    return true;
  }

  function setupZoom() {
    state.zoom = d3.zoom()
      .scaleExtent([0.45, 2.5])
      .on("zoom", event => {
        state.root.attr("transform", event.transform);
      });

    state.svg.call(state.zoom);

    state.svg.on("dblclick.zoom", null);

    const zoomIn = document.getElementById("zoom-in");
    const zoomOut = document.getElementById("zoom-out");
    const zoomReset = document.getElementById("zoom-reset");

    zoomIn?.addEventListener("click", event => {
      event.stopPropagation();

      state.svg
        .transition()
        .duration(250)
        .call(state.zoom.scaleBy, 1.25);
    });

    zoomOut?.addEventListener("click", event => {
      event.stopPropagation();

      state.svg
        .transition()
        .duration(250)
        .call(state.zoom.scaleBy, 0.8);
    });

    zoomReset?.addEventListener("click", event => {
      event.stopPropagation();

      resetZoom();
    });
  }

  function resetZoom() {
    if (!state.svg || !state.zoom) return;

    state.svg
      .transition()
      .duration(350)
      .call(
        state.zoom.transform,
        d3.zoomIdentity
      );
  }

  /* ==========================================================
     Namespace layout
     ========================================================== */

  function calculateNamespaceLayout(nodes) {
    const grouped = d3.group(
      nodes,
      node => node.namespace || "default"
    );

    const namespaceData = [];

    for (const [namespace, namespaceNodes] of grouped) {
      const count = namespaceNodes.length;

      /*
       * Keep namespace cards reasonably wide.
       *
       * 1-2 pods   -> 2 columns
       * 3-4 pods   -> 2 columns
       * 5-6 pods   -> 3 columns
       * 7-9 pods   -> 3 columns
       * 10+ pods   -> 4 columns
       */
      let columns;

      if (count <= 2) {
        columns = 2;
      } else if (count <= 6) {
        columns = 3;
      } else if (count <= 12) {
        columns = 4;
      } else {
        columns = 5;
      }

      const rows = Math.ceil(count / columns);

      const width =
        CONFIG.paddingLeft +
        CONFIG.paddingRight +
        columns * CONFIG.podWidth +
        (columns - 1) * CONFIG.podGapX;

      const height =
        CONFIG.paddingTop +
        CONFIG.paddingBottom +
        rows * CONFIG.podHeight +
        (rows - 1) * CONFIG.podGapY;

      namespaceData.push({
        namespace,
        nodes: namespaceNodes,
        columns,
        rows,
        width,
        height,
        x: 0,
        y: 0
      });
    }

    /*
     * Arrange namespace cards into a clean responsive grid.
     */
    const availableWidth = Math.max(
      state.width - 80,
      700
    );

    let columns = 1;

    if (availableWidth >= 1500) {
      columns = 3;
    } else if (availableWidth >= 950) {
      columns = 2;
    }

    /*
     * If namespace cards are particularly wide,
     * reduce the number of columns.
     */
    const widest = d3.max(namespaceData, d => d.width) || 0;

    if (widest * columns + CONFIG.namespaceGapX * (columns - 1) > availableWidth) {
      columns = Math.max(
        1,
        Math.floor(
          (availableWidth + CONFIG.namespaceGapX) /
          (widest + CONFIG.namespaceGapX)
        )
      );
    }

    columns = Math.max(1, Math.min(columns, namespaceData.length));

    let currentX = 0;
    let currentY = 0;
    let rowHeight = 0;

    namespaceData.forEach((group, index) => {
      if (
        index > 0 &&
        currentX + group.width > availableWidth
      ) {
        currentX = 0;
        currentY += rowHeight + CONFIG.namespaceGapY;
        rowHeight = 0;
      }

      group.x = currentX;
      group.y = currentY;

      currentX += group.width + CONFIG.namespaceGapX;

      rowHeight = Math.max(
        rowHeight,
        group.height
      );
    });

    const totalWidth =
      d3.max(namespaceData, d => d.x + d.width) || 0;

    const totalHeight =
      d3.max(namespaceData, d => d.y + d.height) || 0;

    return {
      groups: namespaceData,
      width: totalWidth,
      height: totalHeight
    };
  }

  /* ==========================================================
     Assign pod positions
     ========================================================== */

  function positionPods(groups) {
    groups.forEach(group => {
      group.nodes.forEach((node, index) => {
        const column =
          index % group.columns;

        const row =
          Math.floor(index / group.columns);

        node.x =
          group.x +
          CONFIG.paddingLeft +
          column *
            (CONFIG.podWidth + CONFIG.podGapX) +
          CONFIG.podWidth / 2;

        node.y =
          group.y +
          CONFIG.paddingTop +
          row *
            (CONFIG.podHeight + CONFIG.podGapY) +
          CONFIG.podHeight / 2;
      });
    });
  }

  /* ==========================================================
     Render namespace cards
     ========================================================== */

  function renderNamespaces(groups) {
    const selection = state.namespaceLayer
      .selectAll(".namespace-group")
      .data(
        groups,
        d => d.namespace
      );

    const entering = selection
      .enter()
      .append("g")
      .attr("class", "namespace-group")
      .attr(
        "transform",
        d => `translate(${d.x},${d.y})`
      )
      .style("opacity", 0);

    /*
     * Card background
     */
    entering
      .append("rect")
      .attr("class", "namespace-card")
      .attr("rx", 6)
      .attr("fill", "#0d1117")
      .attr("stroke", "#29313b")
      .attr("stroke-width", 1);

    /*
     * Namespace accent.
     */
    entering
      .append("rect")
      .attr("class", "namespace-accent")
      .attr("height", 2)
      .attr("rx", 1)
      .attr("x", 0)
      .attr("y", 0);

    /*
     * Header separator.
     */
    entering
      .append("line")
      .attr("class", "namespace-divider")
      .attr("x1", 0)
      .attr("y1", CONFIG.paddingTop - 10)
      .attr("y2", CONFIG.paddingTop - 10);

    /*
     * Namespace name.
     */
    entering
      .append("text")
      .attr("class", "namespace-title")
      .attr("x", 14)
      .attr("y", 24)
      .attr("fill", "#dce2e9")
      .attr("font-family", "ui-monospace, SFMono-Regular, Menlo, monospace")
      .attr("font-size", 13)
      .attr("font-weight", 600)
      .text(d => d.namespace);

    /*
     * Pod count.
     */
    entering
      .append("text")
      .attr("class", "namespace-count")
      .attr("y", 24)
      .attr("text-anchor", "end")
      .attr("fill", "#6f7884")
      .attr("font-family", "ui-monospace, SFMono-Regular, Menlo, monospace")
      .attr("font-size", 10)
      .text(d => `${d.nodes.length} POD${d.nodes.length === 1 ? "" : "S"}`);

    const merged = entering.merge(selection);

    merged
      .transition()
      .duration(CONFIG.transition)
      .attr(
        "transform",
        d => `translate(${d.x},${d.y})`
      )
      .style("opacity", 1);

    merged
      .select(".namespace-card")
      .transition()
      .duration(CONFIG.transition)
      .attr("width", d => d.width)
      .attr("height", d => d.height);

    merged
      .select(".namespace-accent")
      .transition()
      .duration(CONFIG.transition)
      .attr("width", d => d.width)
      .attr(
        "fill",
        d => namespaceColor(d.namespace)
      )
      .attr(
        "opacity",
        0.8
      );

    merged
      .select(".namespace-divider")
      .transition()
      .duration(CONFIG.transition)
      .attr("x2", d => d.width);

    merged
      .select(".namespace-count")
      .transition()
      .duration(CONFIG.transition)
      .attr("x", d => d.width - 14);

    selection
      .exit()
      .transition()
      .duration(200)
      .style("opacity", 0)
      .remove();
  }

  /* ==========================================================
     Render pods
     ========================================================== */

  function renderNodes(nodes) {
    const selection = state.nodeLayer
      .selectAll(".pod-node")
      .data(
        nodes,
        d => d.id
      );

    const entering = selection
      .enter()
      .append("g")
      .attr("class", "pod-node")
      .attr(
        "transform",
        d => `translate(${d.x},${d.y})`
      )
      .style("cursor", "pointer")
      .style("opacity", 0);

    /*
     * Pod body.
     */
    entering
      .append("rect")
      .attr("class", "pod-body")
      .attr(
        "x",
        -CONFIG.podWidth / 2
      )
      .attr(
        "y",
        -CONFIG.podHeight / 2
      )
      .attr(
        "width",
        CONFIG.podWidth
      )
      .attr(
        "height",
        CONFIG.podHeight
      )
      .attr("rx", 5)
      .attr("fill", "#11161d")
      .attr("stroke", "#303844")
      .attr("stroke-width", 1);

    /*
     * Status indicator.
     */
    entering
      .append("circle")
      .attr("class", "pod-status")
      .attr("cx", -CONFIG.podWidth / 2 + 12)
      .attr("cy", 0)
      .attr("r", 4)
      .attr(
        "fill",
        d => statusColor(d)
      );

    /*
     * Isolated ring.
     */
    entering
      .append("circle")
      .attr("class", "pod-isolated-ring")
      .attr("cx", -CONFIG.podWidth / 2 + 12)
      .attr("cy", 0)
      .attr("r", 7)
      .attr("fill", "none")
      .attr("stroke", "#ef6262")
      .attr("stroke-width", 1)
      .attr("opacity", d => d.isolated ? 0.8 : 0);

    /*
     * Pod name.
     */
    entering
      .append("text")
      .attr("class", "pod-name")
      .attr(
        "x",
        -CONFIG.podWidth / 2 + 23
      )
      .attr("y", -5)
      .attr("fill", "#cdd4dc")
      .attr("font-family", "ui-monospace, SFMono-Regular, Menlo, monospace")
      .attr("font-size", 10)
      .attr("font-weight", 500)
      .text(d => truncate(d.name));

    /*
     * Namespace / status line.
     */
    entering
      .append("text")
      .attr("class", "pod-meta")
      .attr(
        "x",
        -CONFIG.podWidth / 2 + 23
      )
      .attr("y", 10)
      .attr("fill", "#68727e")
      .attr("font-family", "ui-monospace, SFMono-Regular, Menlo, monospace")
      .attr("font-size", 9)
      .text(d => `${d.ip || "no-ip"} · ${statusText(d)}`);

    /*
     * Hover.
     */
    entering
      .on("mouseenter", function(event, node) {
        showTooltip(event, node);

        d3.select(this)
          .select(".pod-body")
          .transition()
          .duration(120)
          .attr("stroke", statusColor(node))
          .attr("stroke-width", 1.5);
      })
      .on("mousemove", function(event, node) {
        moveTooltip(event);
      })
      .on("mouseleave", function() {
        hideTooltip();

        d3.select(this)
          .select(".pod-body")
          .transition()
          .duration(120)
          .attr("stroke", "#303844")
          .attr("stroke-width", 1);
      })
      .on("click", function(event, node) {
        event.stopPropagation();

        openDetailPanel(node);
      });

    const merged = entering.merge(selection);

    merged
      .transition()
      .duration(CONFIG.transition)
      .attr(
        "transform",
        d => `translate(${d.x},${d.y})`
      )
      .style("opacity", 1);

    merged
      .select(".pod-status")
      .attr(
        "fill",
        d => statusColor(d)
      );

    merged
      .select(".pod-isolated-ring")
      .transition()
      .duration(200)
      .attr(
        "opacity",
        d => d.isolated ? 0.85 : 0
      );

    merged
      .select(".pod-name")
      .text(d => truncate(d.name));

    merged
      .select(".pod-meta")
      .text(
        d =>
          `${d.ip || "no-ip"} · ${statusText(d)}`
      );

    selection
      .exit()
      .transition()
      .duration(200)
      .style("opacity", 0)
      .remove();
  }

  /* ==========================================================
     Main graph rendering
     ========================================================== */

  function renderGraph() {
    if (!state.svg) return;

    state.width =
      document.getElementById("topo-stage")?.clientWidth ||
      1200;

    state.height =
      document.getElementById("topo-stage")?.clientHeight ||
      700;

    state.visibleNodes =
      state.nodes.filter(node =>
        nodeIsVisible(node)
      );

    updateMetrics(state.nodes);

    const layout =
      calculateNamespaceLayout(
        state.visibleNodes
      );

    positionPods(layout.groups);

    renderNamespaces(layout.groups);

    renderNodes(state.visibleNodes);

    /*
     * Center the topology after the first render.
     */
    if (!state.initialized) {
      state.initialized = true;

      requestAnimationFrame(() => {
        fitTopology(layout.width, layout.height);
      });
    }
  }

  /* ==========================================================
     Fit topology
     * ========================================================== */

  function fitTopology(contentWidth, contentHeight) {
    if (!state.svg || !state.zoom) return;

    const stage =
      document.getElementById("topo-stage");

    if (!stage) return;

    const width = stage.clientWidth;
    const height = stage.clientHeight;

    if (!contentWidth || !contentHeight) {
      resetZoom();
      return;
    }

    const padding = 50;

    const scale = Math.min(
      (width - padding * 2) / contentWidth,
      (height - padding * 2) / contentHeight,
      1
    );

    const safeScale = Math.max(
      0.45,
      Math.min(scale, 1.15)
    );

    const x =
      (width - contentWidth * safeScale) / 2;

    const y =
      (height - contentHeight * safeScale) / 2;

    const transform =
      d3.zoomIdentity
        .translate(x, y)
        .scale(safeScale);

    state.svg
      .transition()
      .duration(450)
      .call(
        state.zoom.transform,
        transform
      );
  }

  /* ==========================================================
     Tooltip
     ========================================================== */

  function showTooltip(event, node) {
    const tooltip =
      document.getElementById(
        "topo-tooltip"
      );

    if (!tooltip) return;

    tooltip.innerHTML = `
      <div class="tooltip-title">
        ${escapeHtml(node.name)}
      </div>

      <div class="tooltip-row">
        <span>Namespace</span>
        <strong>${escapeHtml(node.namespace)}</strong>
      </div>

      <div class="tooltip-row">
        <span>IP</span>
        <strong>${escapeHtml(node.ip || "—")}</strong>
      </div>

      <div class="tooltip-row">
        <span>Status</span>
        <strong style="color:${statusColor(node)}">
          ${escapeHtml(statusText(node))}
        </strong>
      </div>

      <div class="tooltip-row">
        <span>Owner</span>
        <strong>${escapeHtml(node.owner_kind || "—")}</strong>
      </div>
    `;

    tooltip.style.display = "block";

    moveTooltip(event);
  }

  function moveTooltip(event) {
    const tooltip =
      document.getElementById(
        "topo-tooltip"
      );

    if (!tooltip) return;

    const stage =
      document.getElementById(
        "topo-stage"
      );

    if (!stage) return;

    const rect =
      stage.getBoundingClientRect();

    let x =
      event.clientX -
      rect.left +
      16;

    let y =
      event.clientY -
      rect.top +
      16;

    const tooltipWidth =
      tooltip.offsetWidth;

    const tooltipHeight =
      tooltip.offsetHeight;

    if (
      x + tooltipWidth >
      rect.width - 10
    ) {
      x =
        event.clientX -
        rect.left -
        tooltipWidth -
        16;
    }

    if (
      y + tooltipHeight >
      rect.height - 10
    ) {
      y =
        event.clientY -
        rect.top -
        tooltipHeight -
        16;
    }

    tooltip.style.left =
      `${Math.max(8, x)}px`;

    tooltip.style.top =
      `${Math.max(8, y)}px`;
  }

  function hideTooltip() {
    const tooltip =
      document.getElementById(
        "topo-tooltip"
      );

    if (tooltip) {
      tooltip.style.display = "none";
    }
  }

  /* ==========================================================
     Detail panel
     ========================================================== */

  function openDetailPanel(node) {
    state.selectedNode = node;

    const panel =
      document.getElementById(
        "detail-panel"
      );

    const body =
      document.getElementById(
        "dp-body"
      );

    if (!panel || !body) return;

    const color =
      statusColor(node);

    body.innerHTML = `
      <div class="dp-section">
        <div class="dp-kicker">
          POD
        </div>

        <div
          class="dp-title"
          title="${escapeHtml(node.name)}"
        >
          ${escapeHtml(node.name)}
        </div>

        <div
          class="dp-status"
          style="color:${color}"
        >
          <span
            class="dp-status-dot"
            style="background:${color}"
          ></span>

          ${escapeHtml(statusText(node))}
        </div>
      </div>

      <div class="dp-section">
        <div class="dp-label">
          Namespace
        </div>

        <div class="dp-value">
          ${escapeHtml(node.namespace || "—")}
        </div>
      </div>

      <div class="dp-section">
        <div class="dp-label">
          Pod IP
        </div>

        <div class="dp-value mono">
          ${escapeHtml(node.ip || "—")}
        </div>
      </div>

      <div class="dp-section">
        <div class="dp-label">
          Owner
        </div>

        <div class="dp-value">
          ${escapeHtml(node.owner_kind || "—")}
        </div>
      </div>

      <div class="dp-section">
        <div class="dp-label">
          Phase
        </div>

        <div class="dp-value">
          ${escapeHtml(node.phase || "—")}
        </div>
      </div>

      <div class="dp-section">
        <div class="dp-label">
          Security state
        </div>

        <div class="dp-value ${node.isolated ? "danger" : ""}">
          ${node.isolated ? "Network isolated" : "Normal"}
        </div>
      </div>

      <div class="dp-section dp-id">
        <div class="dp-label">
          Resource ID
        </div>

        <div class="dp-value mono">
          ${escapeHtml(node.id || "—")}
        </div>
      </div>
    `;

    panel.classList.remove(
      "translate-x-full"
    );

    panel.classList.add(
      "translate-x-0"
    );
  }

  function closeDetailPanel() {
    const panel =
      document.getElementById(
        "detail-panel"
      );

    if (!panel) return;

    panel.classList.remove(
      "translate-x-0"
    );

    panel.classList.add(
      "translate-x-full"
    );

    state.selectedNode = null;
  }

  /* ==========================================================
     Filters
     ========================================================== */

  function setupFilters() {
    const search =
      document.getElementById(
        "topology-search"
      );

    search?.addEventListener(
      "input",
      event => {
        state.search =
          event.target.value.trim();

        renderGraph();
      }
    );

    const isolated =
      document.getElementById(
        "topology-isolated-filter"
      );

    isolated?.addEventListener(
      "click",
      () => {
        state.isolatedOnly =
          !state.isolatedOnly;

        isolated.classList.toggle(
          "active",
          state.isolatedOnly
        );

        renderGraph();
      }
    );

    document
      .getElementById("dp-close")
      ?.addEventListener(
        "click",
        closeDetailPanel
      );

    /*
     * Close detail panel by clicking
     * the empty topology background.
     */
    document
      .getElementById("topo-svg")
      ?.addEventListener(
        "click",
        event => {
          if (
            event.target.tagName === "svg" ||
            event.target.classList.contains(
              "topology-background"
            )
          ) {
            closeDetailPanel();
          }
        }
      );
  }

  /* ==========================================================
     Namespace filter chips
     ========================================================== */

  function renderNamespaceFilters() {
    const container =
      document.getElementById(
        "topology-namespace-filters"
      );

    if (!container) return;

    const namespaces =
      [...new Set(
        state.nodes
          .map(node => node.namespace)
          .filter(Boolean)
      )].sort();

    container.innerHTML = "";

    namespaces.forEach(namespace => {
      const nodes =
        state.nodes.filter(
          node =>
            node.namespace === namespace
        );

      const button =
        document.createElement("button");

      button.type = "button";

      button.className =
        "topology-namespace-chip";

      if (
        state.activeNamespaces.has(
          namespace
        )
      ) {
        button.classList.add("active");
      }

      const dot =
        document.createElement("span");

      dot.className =
        "namespace-chip-dot";

      dot.style.background =
        namespaceColor(namespace);

      const label =
        document.createElement("span");

      label.textContent =
        truncate(namespace, 18);

      const count =
        document.createElement("span");

      count.className =
        "namespace-chip-count";

      count.textContent =
        nodes.length;

      button.appendChild(dot);
      button.appendChild(label);
      button.appendChild(count);

      button.addEventListener(
        "click",
        () => {
          if (
            state.activeNamespaces.has(
              namespace
            )
          ) {
            state.activeNamespaces.delete(
              namespace
            );
          } else {
            state.activeNamespaces.add(
              namespace
            );
          }

          renderNamespaceFilters();
          renderGraph();
        }
      );

      container.appendChild(button);
    });
  }

  /* ==========================================================
     API
     ========================================================== */

  async function loadTopology() {
    try {
      const response =
        await fetch(
          "/api/topology",
          {
            cache: "no-store"
          }
        );

      if (!response.ok) {
        throw new Error(
          `HTTP ${response.status}`
        );
      }

      const data =
        await response.json();

      if (!data || data.available === false) {
        state.data = {
          available: false,
          namespaces: [],
          nodes: []
        };

        state.nodes = [];

        renderGraph();

        return;
      }

      state.data = data;

      state.nodes =
        Array.isArray(data.nodes)
          ? data.nodes.map(node => ({
              ...node
            }))
          : [];

      renderNamespaceFilters();

      renderGraph();

    } catch (error) {
      console.error(
        "Topology API error:",
        error
      );

      state.nodes = [];

      renderGraph();
    }
  }

  /* ==========================================================
     Resize
     ========================================================== */

  function setupResize() {
    let timeout;

    window.addEventListener(
      "resize",
      () => {
        clearTimeout(timeout);

        timeout =
          setTimeout(() => {
            renderGraph();
          }, 120);
      }
    );
  }

  /* ==========================================================
     Polling
     ========================================================== */

  function startPolling() {
    if (state.refreshTimer) {
      clearInterval(
        state.refreshTimer
      );
    }

    state.refreshTimer =
      setInterval(
        loadTopology,
        CONFIG.refreshInterval
      );
  }

  /* ==========================================================
     Initialization
     ========================================================== */

  async function init() {
    if (state.initialized === "booting") {
      return;
    }

    state.initialized = "booting";

    if (
      typeof d3 === "undefined"
    ) {
      console.error(
        "Topology requires D3."
      );

      return;
    }

    if (!setupSvg()) {
      return;
    }

    setupFilters();
    setupResize();

    await loadTopology();

    state.initialized = true;

    startPolling();
  }

  /* ==========================================================
     Alpine compatibility
     ========================================================== */

  window.topologyApp = function() {
    return {
      init
    };
  };

  /*
   * Compatibility with any previous
   * code that called updateTopologyGraph().
   */
  window.updateTopologyGraph =
    function(data) {
      if (!data) return;

      state.data = data;

      state.nodes =
        Array.isArray(data.nodes)
          ? data.nodes.map(node => ({
              ...node
            }))
          : [];

      renderNamespaceFilters();
      renderGraph();
    };
})();
