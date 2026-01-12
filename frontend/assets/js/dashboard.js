const API_URL = "http://127.0.0.1:8000/alerts";

let severityChart = echarts.init(document.getElementById("severityChart"));
let timelineChart = echarts.init(document.getElementById("timelineChart"));
let sourceChart = echarts.init(document.getElementById("sourceChart"));

/* ---------- MITRE ATT&CK KNOWLEDGE BASE ---------- */
const MITRE_DB = {
  "T1046": {
    name: "Network Service Scanning",
    tactic: "Reconnaissance",
    description:
      "Adversaries scan networks to discover open ports and services, " +
      "which can later be exploited for initial access.",
    risk:
      "Allows attackers to map the attack surface and identify vulnerable services.",
    mitigation: [
      "Close unused ports and services",
      "Use firewall port filtering",
      "Enable IDS/IPS rules for scan detection",
      "Monitor repeated connection attempts"
    ]
  },
  "T1499": {
    name: "Endpoint Denial of Service",
    tactic: "Impact",
    description:
      "Adversaries attempt to disrupt availability by overwhelming systems " +
      "with excessive traffic.",
    risk:
      "Can cause service outages and resource exhaustion.",
    mitigation: [
      "Apply rate limiting",
      "Enable DDoS protection",
      "Monitor abnormal traffic spikes",
      "Use network segmentation"
    ]
  }
};
/* ---------- Fetch and Render Alerts ---------- */

async function loadAlerts() {
  try {
    const res = await fetch(API_URL);
    const data = await res.json();
    const alerts = data.alerts || [];

    document.getElementById("total").innerText = data.count;
    document.getElementById("lastUpdated").innerText =
      new Date().toLocaleTimeString();

    updateSeverityCounters(alerts);
    updateSeverityChart(alerts);
    updateTimelineChart(alerts);
    updateSourceChart(alerts);
    renderAlertsTable(alerts);

  } catch (err) {
    console.error("Failed to fetch alerts", err);
  }
}

/* ---------- Severity Counters ---------- */
function updateSeverityCounters(alerts) {
  let high = 0, medium = 0;

  alerts.forEach(a => {
    if (a.severity === "high") high++;
    if (a.severity === "medium") medium++;
  });

  document.getElementById("highCount").innerText = high;
  document.getElementById("mediumCount").innerText = medium;
}

/* ---------- Severity Donut ---------- */
function updateSeverityChart(alerts) {
  const counts = { high: 0, medium: 0, low: 0 };

  alerts.forEach(a => {
    counts[a.severity] = (counts[a.severity] || 0) + 1;
  });

  severityChart.setOption({
    backgroundColor: "transparent",
    tooltip: { trigger: "item" },
    series: [{
      type: "pie",
      radius: ["45%", "70%"],
      data: [
        { value: counts.high, name: "High", itemStyle: { color: "#ef4444" } },
        { value: counts.medium, name: "Medium", itemStyle: { color: "#f59e0b" } },
        { value: counts.low, name: "Low", itemStyle: { color: "#22c55e" } }
      ],
      label: { color: "#e5e7eb" }
    }]
  });
}

/* ---------- Alerts Timeline ---------- */
function updateTimelineChart(alerts) {
  const map = {};

  alerts.forEach(a => {
    const t = new Date(a.timestamp).toLocaleTimeString();
    map[t] = (map[t] || 0) + 1;
  });

  timelineChart.setOption({
    backgroundColor: "transparent",
    xAxis: {
      type: "category",
      data: Object.keys(map),
      axisLabel: { color: "#9ca3af" }
    },
    yAxis: {
      type: "value",
      axisLabel: { color: "#9ca3af" }
    },
    series: [{
      data: Object.values(map),
      type: "line",
      smooth: true,
      lineStyle: { color: "#38bdf8" },
      areaStyle: { color: "rgba(56,189,248,0.2)" }
    }]
  });
}

/* ---------- Top Source IPs ---------- */
function updateSourceChart(alerts) {
  const srcMap = {};

  alerts.forEach(a => {
    const ip = a.source?.ip || "unknown";
    srcMap[ip] = (srcMap[ip] || 0) + 1;
  });

  const entries = Object.entries(srcMap).slice(0, 5);

  sourceChart.setOption({
    backgroundColor: "transparent",
    xAxis: {
      type: "value",
      axisLabel: { color: "#9ca3af" }
    },
    yAxis: {
      type: "category",
      data: entries.map(e => e[0]),
      axisLabel: { color: "#9ca3af" }
    },
    series: [{
      type: "bar",
      data: entries.map(e => e[1]),
      itemStyle: { color: "#38bdf8" }
    }]
  });
}

/* ---------- Alerts Table ---------- */
function renderAlertsTable(alerts) {
  const container = document.getElementById("alertsTable");
  container.innerHTML = "";

  if (!alerts.length) {
    container.innerHTML = `
      <div class="bg-[#111827] p-4 rounded text-gray-400">
        No alerts detected yet.
      </div>`;
    return;
  }

  alerts.slice().reverse().forEach(alert => {
    const severity = alert.severity || "low";
    const glow =
      severity === "high" ? "glow-high" :
      severity === "medium" ? "glow-medium" :
      "glow-low";

    const row = document.createElement("div");
    row.className = `
      bg-[#111827] border border-gray-800 rounded-lg
      p-4 cursor-pointer transition-all duration-300
      hover:bg-[#1f2937] ${glow}
    `;

    row.innerHTML = `
      <div class="flex justify-between items-center">
        <div>
          <p class="font-semibold text-gray-200">${alert.attack_name}</p>
          <p class="text-sm text-gray-400">
            ${alert.source?.ip} → ${alert.destination?.ip}
          </p>
        </div>
        <span class="px-3 py-1 rounded-full text-xs font-semibold
          ${severity === "high" ? "bg-red-500/20 text-red-400" :
            severity === "medium" ? "bg-yellow-500/20 text-yellow-400" :
            "bg-green-500/20 text-green-400"}">
          ${severity.toUpperCase()}
        </span>
      </div>
    `;
    
    row.addEventListener("click", () => {
      openModal(alert);
    });


    container.appendChild(row);
  });
}

/// ---------- Alert Details Modal ----------
function openModal(alert) {
  const modal = document.getElementById("alertModal");
  const content = document.getElementById("modalContent");

  const severityColor =
    alert.severity === "high" ? "text-red-400" :
    alert.severity === "medium" ? "text-yellow-400" :
    "text-green-400";

  const mitre = MITRE_DB[alert.mitre_technique];

    content.innerHTML = `
      <div class="space-y-5">

        <!-- BASIC ALERT INFO -->
        <div>
          <p class="text-gray-400">Attack</p>
          <p class="text-lg font-semibold">${alert.attack_name}</p>
        </div>

        <div class="flex gap-8">
          <div>
            <p class="text-gray-400">Severity</p>
            <p class="font-semibold ${severityColor}">
              ${alert.severity.toUpperCase()}
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
            ${alert.source?.ip} → ${alert.destination?.ip}
          </p>
        </div>

        <!-- MITRE PANEL -->
        <div class="border border-gray-800 rounded-lg bg-[#111827] p-4">
          <p class="text-cyan-400 font-semibold mb-2">
            MITRE ATT&CK Intelligence
          </p>

          ${
            mitre
              ? `
            <p class="text-sm">
              <span class="text-gray-400">Technique:</span>
              <span class="font-mono">${alert.mitre_technique}</span> —
              ${mitre.name}
            </p>

            <p class="text-sm mt-1">
              <span class="text-gray-400">Tactic:</span>
              ${mitre.tactic}
            </p>

            <p class="text-sm mt-3 text-gray-400">
              ${mitre.description}
            </p>

            <div class="mt-3">
              <p class="text-yellow-400 font-semibold text-sm">
                Why this is dangerous
              </p>
              <p class="text-sm text-gray-400">
                ${mitre.risk}
              </p>
            </div>

            <div class="mt-3">
              <p class="text-green-400 font-semibold text-sm">
                Recommended Mitigations
              </p>
              <ul class="list-disc list-inside text-sm text-gray-400 space-y-1">
                ${mitre.mitigation.map(m => `<li>${m}</li>`).join("")}
              </ul>
            </div>
            `
              : `
            <p class="text-sm text-gray-400">
              No MITRE intelligence available for this alert.
            </p>
            `
          }
        </div>

      </div>
    `;


  modal.classList.remove("hidden");
}

function closeModal() {
  document.getElementById("alertModal").classList.add("hidden");
}


/* ---------- Live Alert Update ---------- */
function updateFromLiveAlert(alert) {
  // Update metrics
  const total = document.getElementById("total");
  total.innerText = parseInt(total.innerText) + 1;

  // Add alert to charts + table
  loadAlerts(); // safe re-sync
}


/* ---------- Live Alerts via WebSocket ---------- */
const WS_URL = "ws://127.0.0.1:8000/ws/alerts";

let socket = new WebSocket(WS_URL);

socket.onopen = () => {
  console.log("WebSocket connected");
};

socket.onmessage = (event) => {
  const alert = JSON.parse(event.data);

  // Append alert live
  updateFromLiveAlert(alert);
};

socket.onclose = () => {
  console.warn("WebSocket disconnected, fallback to polling");
  setInterval(loadAlerts, 5000);
};

/* ---------- Modal Event Listeners ---------- */
document.getElementById("alertModal").addEventListener("click", (e) => {
  if (e.target.id === "alertModal") closeModal();
});


loadAlerts();
