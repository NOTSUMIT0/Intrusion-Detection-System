/* ===========================================================
   investigations.js  –  IDS Investigation Center
   =========================================================== */

const API_BASE = "http://127.0.0.1:8000";

let investigatingAlerts = [];
let resolvedAlerts = [];
let allAlerts = [];
let activeTab = "investigating";

/* ---------- ECharts Instances ---------- */
let pipelineChart;
let severityBreakdownChart;

function initCharts() {
  pipelineChart = echarts.init(document.getElementById("pipelineChart"));
  severityBreakdownChart = echarts.init(document.getElementById("severityBreakdown"));

  window.addEventListener("resize", () => {
    pipelineChart.resize();
    severityBreakdownChart.resize();
  });
}


/* ==========================================================
   DATA FETCHING
   ========================================================== */

async function loadInvestigationData() {
  try {
    const [allRes, invRes, resRes] = await Promise.all([
      fetch(`${API_BASE}/alerts`),
      fetch(`${API_BASE}/alerts/investigating`),
      fetch(`${API_BASE}/alerts/resolved`)
    ]);

    const allData = await allRes.json();
    const invData = await invRes.json();
    const resData = await resRes.json();

    allAlerts = allData.alerts || [];
    investigatingAlerts = invData.alerts || [];
    resolvedAlerts = resData.alerts || [];

    updateStats();
    updateCharts();
    renderActiveTab();

  } catch (err) {
    console.error("Failed to load investigation data", err);
  }
}


/* ==========================================================
   STATS CARDS
   ========================================================== */

function updateStats() {
  const totalManaged = investigatingAlerts.length + resolvedAlerts.length;

  document.getElementById("statTotal").innerText = allAlerts.length;
  document.getElementById("statInvestigating").innerText = investigatingAlerts.length;
  document.getElementById("statResolved").innerText = resolvedAlerts.length;

  const rate = totalManaged > 0
    ? Math.round((resolvedAlerts.length / totalManaged) * 100)
    : 0;
  document.getElementById("statRate").innerText = rate + "%";
}


/* ==========================================================
   ECHARTS  –  PIPELINE DONUT
   ========================================================== */

function updateCharts() {
  // --- Pipeline Donut ---
  pipelineChart.setOption({
    backgroundColor: "transparent",
    tooltip: {
      trigger: "item",
      backgroundColor: "#1e293b",
      borderColor: "#334155",
      textStyle: { color: "#e2e8f0" }
    },
    legend: {
      bottom: 10,
      textStyle: { color: "#9ca3af" }
    },
    series: [{
      type: "pie",
      radius: ["40%", "68%"],
      center: ["50%", "45%"],
      avoidLabelOverlap: true,
      itemStyle: {
        borderRadius: 6,
        borderColor: "#0b0f19",
        borderWidth: 3
      },
      label: {
        show: true,
        color: "#e2e8f0",
        formatter: "{b}\n{c} ({d}%)"
      },
      data: [
        {
          value: allAlerts.filter(a => !a.status || a.status === "new").length,
          name: "New",
          itemStyle: { color: "#3b82f6" }
        },
        {
          value: investigatingAlerts.length,
          name: "Investigating",
          itemStyle: { color: "#a855f7" }
        },
        {
          value: resolvedAlerts.length,
          name: "Resolved",
          itemStyle: { color: "#22c55e" }
        }
      ]
    }]
  });

  // --- Severity Breakdown (grouped bar) ---
  const invSeverity = { high: 0, medium: 0, low: 0 };
  const resSeverity = { high: 0, medium: 0, low: 0 };

  investigatingAlerts.forEach(a => {
    const s = a.severity || "low";
    invSeverity[s] = (invSeverity[s] || 0) + 1;
  });

  resolvedAlerts.forEach(a => {
    const s = a.severity || "low";
    resSeverity[s] = (resSeverity[s] || 0) + 1;
  });

  severityBreakdownChart.setOption({
    backgroundColor: "transparent",
    tooltip: {
      trigger: "axis",
      backgroundColor: "#1e293b",
      borderColor: "#334155",
      textStyle: { color: "#e2e8f0" }
    },
    legend: {
      bottom: 10,
      textStyle: { color: "#9ca3af" }
    },
    xAxis: {
      type: "category",
      data: ["High", "Medium", "Low"],
      axisLabel: { color: "#9ca3af" },
      axisLine: { lineStyle: { color: "#374151" } }
    },
    yAxis: {
      type: "value",
      axisLabel: { color: "#9ca3af" },
      splitLine: { lineStyle: { color: "#1f2937" } }
    },
    series: [
      {
        name: "Investigating",
        type: "bar",
        data: [invSeverity.high, invSeverity.medium, invSeverity.low],
        itemStyle: { color: "#a855f7", borderRadius: [4, 4, 0, 0] },
        barGap: "20%"
      },
      {
        name: "Resolved",
        type: "bar",
        data: [resSeverity.high, resSeverity.medium, resSeverity.low],
        itemStyle: { color: "#22c55e", borderRadius: [4, 4, 0, 0] }
      }
    ]
  });
}


/* ==========================================================
   TAB SWITCHING
   ========================================================== */

function switchTab(tab) {
  activeTab = tab;

  const btnInv = document.getElementById("tabInvestigating");
  const btnRes = document.getElementById("tabResolved");

  if (tab === "investigating") {
    btnInv.className = "px-6 py-3 text-sm font-semibold border-b-2 border-purple-500 text-purple-400 transition";
    btnRes.className = "px-6 py-3 text-sm font-semibold border-b-2 border-transparent text-gray-400 hover:text-gray-200 transition";
  } else {
    btnRes.className = "px-6 py-3 text-sm font-semibold border-b-2 border-green-500 text-green-400 transition";
    btnInv.className = "px-6 py-3 text-sm font-semibold border-b-2 border-transparent text-gray-400 hover:text-gray-200 transition";
  }

  renderActiveTab();
}

function renderActiveTab() {
  if (activeTab === "investigating") {
    renderInvestigatingCards();
  } else {
    renderResolvedCards();
  }
}


/* ==========================================================
   PACKET CARDS  –  INVESTIGATING
   ========================================================== */

function renderInvestigatingCards() {
  const container = document.getElementById("packetCards");
  container.innerHTML = "";

  if (!investigatingAlerts.length) {
    container.innerHTML = `
      <div class="bg-[#111827] border border-gray-800 rounded-lg p-8 text-center">
        <p class="text-gray-400 text-lg">No alerts under investigation.</p>
        <p class="text-gray-500 text-sm mt-2">
          Mark alerts as "Investigating" from the Dashboard to see them here.
        </p>
      </div>`;
    return;
  }

  investigatingAlerts.forEach(alert => {
    const severity = alert.severity || "low";
    const severityBadge =
      severity === "high" ? "bg-red-500/20 text-red-400" :
        severity === "medium" ? "bg-yellow-500/20 text-yellow-400" :
          "bg-green-500/20 text-green-400";

    const card = document.createElement("div");
    card.className = `
      bg-[#111827] border border-gray-800 rounded-lg p-5
      transition-all duration-300 hover:bg-[#1f2937]
    `;

    card.innerHTML = `
      <div class="flex justify-between items-start">
        <div class="flex-1">
          <div class="flex items-center gap-3 mb-2">
            <span class="px-2 py-1 rounded text-xs font-semibold bg-purple-500/20 text-purple-400">
              🔍 INVESTIGATING
            </span>
            <span class="px-2 py-1 rounded-full text-xs font-semibold ${severityBadge}">
              ${severity.toUpperCase()}
            </span>
          </div>

          <p class="font-semibold text-gray-100 text-lg">${alert.attack_name}</p>

          <div class="grid grid-cols-2 gap-4 mt-3 text-sm">
            <div>
              <p class="text-gray-500">Source</p>
              <p class="font-mono text-gray-300">${alert.source?.ip || "N/A"}:${alert.source?.port || "N/A"}</p>
            </div>
            <div>
              <p class="text-gray-500">Destination</p>
              <p class="font-mono text-gray-300">${alert.destination?.ip || "N/A"}:${alert.destination?.port || "N/A"}</p>
            </div>
            <div>
              <p class="text-gray-500">MITRE Technique</p>
              <p class="font-mono text-gray-300">${alert.mitre_technique || "N/A"}</p>
            </div>
            <div>
              <p class="text-gray-500">Timestamp</p>
              <p class="text-gray-300">${new Date(alert.timestamp).toLocaleString()}</p>
            </div>
          </div>

          ${alert.traffic ? `
          <div class="mt-3 grid grid-cols-3 gap-3 text-xs">
            <div class="bg-[#0b1220] rounded p-2">
              <p class="text-gray-500">Packet Size</p>
              <p class="text-gray-300 font-mono">${alert.traffic.packet_size} B</p>
            </div>
            <div class="bg-[#0b1220] rounded p-2">
              <p class="text-gray-500">Packet Rate</p>
              <p class="text-gray-300 font-mono">${alert.traffic.packet_rate?.toFixed(2)} pkt/s</p>
            </div>
            <div class="bg-[#0b1220] rounded p-2">
              <p class="text-gray-500">TCP Flags</p>
              <p class="text-gray-300 font-mono">${alert.traffic.tcp_flags || "N/A"}</p>
            </div>
          </div>
          ` : ""}
        </div>

        <div class="flex flex-col gap-2 ml-4 flex-shrink-0">
          <button
            onclick="event.stopPropagation(); markResolved('${alert.timestamp}')"
            class="px-4 py-2 rounded text-sm font-semibold
                   bg-green-500/20 text-green-400 hover:bg-green-500/30
                   transition whitespace-nowrap">
            ✅ Mark Resolved
          </button>

          <button
            onclick="event.stopPropagation(); openDetailModal(${JSON.stringify(alert).replace(/"/g, '&quot;')})"
            class="px-4 py-2 rounded text-sm font-semibold
                   bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30
                   transition whitespace-nowrap">
            📋 Full Details
          </button>
        </div>
      </div>
    `;

    container.appendChild(card);
  });
}


/* ==========================================================
   PACKET CARDS  –  RESOLVED
   ========================================================== */

function renderResolvedCards() {
  const container = document.getElementById("packetCards");
  container.innerHTML = "";

  if (!resolvedAlerts.length) {
    container.innerHTML = `
      <div class="bg-[#111827] border border-gray-800 rounded-lg p-8 text-center">
        <p class="text-gray-400 text-lg">No resolved alerts yet.</p>
        <p class="text-gray-500 text-sm mt-2">
          Resolve investigating alerts and they will appear here.
        </p>
      </div>`;
    return;
  }

  // Summary banner
  const highCount = resolvedAlerts.filter(a => a.severity === "high").length;
  const medCount = resolvedAlerts.filter(a => a.severity === "medium").length;
  const lowCount = resolvedAlerts.filter(a => a.severity === "low").length;

  const banner = document.createElement("div");
  banner.className = "bg-[#111827] border border-gray-800 rounded-lg p-5";
  banner.innerHTML = `
    <div class="flex items-center gap-3 mb-3">
      <span class="text-2xl">🛡️</span>
      <h3 class="text-lg font-semibold text-green-400">Resolution Summary</h3>
    </div>
    <div class="grid grid-cols-3 gap-4 text-center">
      <div class="bg-[#0b1220] rounded-lg p-3">
        <p class="text-3xl font-bold text-red-400">${highCount}</p>
        <p class="text-xs text-gray-400 mt-1">High Severity</p>
      </div>
      <div class="bg-[#0b1220] rounded-lg p-3">
        <p class="text-3xl font-bold text-yellow-400">${medCount}</p>
        <p class="text-xs text-gray-400 mt-1">Medium Severity</p>
      </div>
      <div class="bg-[#0b1220] rounded-lg p-3">
        <p class="text-3xl font-bold text-green-400">${lowCount}</p>
        <p class="text-xs text-gray-400 mt-1">Low Severity</p>
      </div>
    </div>
    <p class="text-gray-500 text-sm mt-3">
      Total of <span class="text-green-400 font-semibold">${resolvedAlerts.length}</span> threat(s)
      analyzed and resolved by the security team.
    </p>
  `;
  container.appendChild(banner);

  // Individual resolved alert cards
  resolvedAlerts.forEach(alert => {
    const severity = alert.severity || "low";
    const severityBadge =
      severity === "high" ? "bg-red-500/20 text-red-400" :
        severity === "medium" ? "bg-yellow-500/20 text-yellow-400" :
          "bg-green-500/20 text-green-400";

    const card = document.createElement("div");
    card.className = `
      bg-[#111827] border border-gray-800 rounded-lg p-5
      transition-all duration-300 hover:bg-[#1f2937] opacity-90
    `;

    card.innerHTML = `
      <div class="flex justify-between items-start">
        <div class="flex-1">
          <div class="flex items-center gap-3 mb-2">
            <span class="px-2 py-1 rounded text-xs font-semibold bg-green-500/20 text-green-400">
              ✅ RESOLVED
            </span>
            <span class="px-2 py-1 rounded-full text-xs font-semibold ${severityBadge}">
              ${severity.toUpperCase()}
            </span>
          </div>

          <p class="font-semibold text-gray-100 text-lg">${alert.attack_name}</p>

          <div class="grid grid-cols-2 gap-4 mt-3 text-sm">
            <div>
              <p class="text-gray-500">Source</p>
              <p class="font-mono text-gray-300">${alert.source?.ip || "N/A"}:${alert.source?.port || "N/A"}</p>
            </div>
            <div>
              <p class="text-gray-500">Destination</p>
              <p class="font-mono text-gray-300">${alert.destination?.ip || "N/A"}:${alert.destination?.port || "N/A"}</p>
            </div>
            <div>
              <p class="text-gray-500">MITRE Technique</p>
              <p class="font-mono text-gray-300">${alert.mitre_technique || "N/A"}</p>
            </div>
            <div>
              <p class="text-gray-500">Detected</p>
              <p class="text-gray-300">${new Date(alert.timestamp).toLocaleString()}</p>
            </div>
          </div>

          ${alert.traffic ? `
          <div class="mt-3 border border-gray-800 rounded-lg p-3 bg-[#0b1220]">
            <p class="text-cyan-400 text-xs font-semibold mb-2">Traffic Analysis</p>
            <div class="grid grid-cols-3 gap-3 text-xs">
              <div>
                <p class="text-gray-500">Packet Size</p>
                <p class="text-gray-300 font-mono">${alert.traffic.packet_size} bytes</p>
              </div>
              <div>
                <p class="text-gray-500">Packet Rate</p>
                <p class="text-gray-300 font-mono">${alert.traffic.packet_rate?.toFixed(2)} pkt/s</p>
              </div>
              <div>
                <p class="text-gray-500">Byte Rate</p>
                <p class="text-gray-300 font-mono">${alert.traffic.byte_rate?.toFixed(2)} B/s</p>
              </div>
              <div>
                <p class="text-gray-500">TCP Flags</p>
                <p class="text-gray-300 font-mono">${alert.traffic.tcp_flags || "N/A"}</p>
              </div>
              <div>
                <p class="text-gray-500">Flow Duration</p>
                <p class="text-gray-300 font-mono">${alert.traffic.flow_duration?.toFixed(2) || "N/A"}s</p>
              </div>
            </div>
          </div>
          ` : ""}
        </div>

        <div class="flex flex-col gap-2 ml-4 flex-shrink-0">
          <button
            onclick="event.stopPropagation(); openDetailModal(${JSON.stringify(alert).replace(/"/g, '&quot;')})"
            class="px-4 py-2 rounded text-sm font-semibold
                   bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30
                   transition whitespace-nowrap">
            📋 Full Details
          </button>
        </div>
      </div>
    `;

    container.appendChild(card);
  });
}


/* ==========================================================
   ACTIONS
   ========================================================== */

async function markResolved(timestamp) {
  try {
    await fetch(`${API_BASE}/alerts/${encodeURIComponent(timestamp)}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "resolved" })
    });
  } catch (err) {
    console.error("Failed to mark as resolved", err);
    return;
  }

  // Refresh data
  await loadInvestigationData();
}


/* ==========================================================
   DETAIL MODAL
   ========================================================== */

function openDetailModal(alert) {
  const modal = document.getElementById("detailModal");
  const content = document.getElementById("detailModalContent");

  const severityColor =
    alert.severity === "high" ? "text-red-400" :
      alert.severity === "medium" ? "text-yellow-400" :
        "text-green-400";

  content.innerHTML = `
    <div class="space-y-5">

      <div>
        <p class="text-gray-400">Attack</p>
        <p class="text-lg font-semibold">${alert.attack_name}</p>
      </div>

      <div class="flex gap-8">
        <div>
          <p class="text-gray-400">Severity</p>
          <p class="font-semibold ${severityColor}">
            ${(alert.severity || "low").toUpperCase()}
          </p>
        </div>
        <div>
          <p class="text-gray-400">Status</p>
          <p class="font-semibold ${alert.status === 'resolved' ? 'text-green-400' : 'text-purple-400'}">
            ${(alert.status || "new").toUpperCase()}
          </p>
        </div>
        <div>
          <p class="text-gray-400">Timestamp</p>
          <p>${new Date(alert.timestamp).toLocaleString()}</p>
        </div>
      </div>

      <div>
        <p class="text-gray-400">Source → Destination</p>
        <p class="font-mono">
          ${alert.source?.ip}:${alert.source?.port || "N/A"}
          →
          ${alert.destination?.ip}:${alert.destination?.port || "N/A"}
        </p>
      </div>

      <div>
        <p class="text-gray-400">MITRE Technique</p>
        <p class="font-mono">${alert.mitre_technique || "N/A"}</p>
      </div>

      ${alert.traffic ? `
      <div class="border border-gray-800 rounded-lg bg-[#111827] p-4">
        <p class="text-purple-400 font-semibold mb-2">
          Packet & Traffic Analysis
        </p>
        <div class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p class="text-gray-400">Packet Size</p>
            <p class="font-mono">${alert.traffic.packet_size} bytes</p>
          </div>
          <div>
            <p class="text-gray-400">TCP Flags</p>
            <p class="font-mono">${alert.traffic.tcp_flags ?? "N/A"}</p>
          </div>
          <div>
            <p class="text-gray-400">Packet Rate</p>
            <p>${alert.traffic.packet_rate?.toFixed(2)} packets/sec</p>
          </div>
          <div>
            <p class="text-gray-400">Byte Rate</p>
            <p>${alert.traffic.byte_rate?.toFixed(2)} bytes/sec</p>
          </div>
          <div>
            <p class="text-gray-400">Flow Duration</p>
            <p>${alert.traffic.flow_duration?.toFixed(2) || "N/A"} sec</p>
          </div>
        </div>
      </div>
      ` : ""}

    </div>
  `;

  modal.classList.remove("hidden");
}

function closeDetailModal() {
  document.getElementById("detailModal").classList.add("hidden");
}

// Close on backdrop click
document.getElementById("detailModal").addEventListener("click", (e) => {
  if (e.target.id === "detailModal") closeDetailModal();
});


/* ==========================================================
   INIT
   ========================================================== */

initCharts();
loadInvestigationData();
