const API_URL = "http://127.0.0.1:8000/alerts";
let CURRENT_ALERTS = [];
window.currentAlerts = [];

/* ---------- MITRE ATT&CK CHAIN ---------- */
const MITRE_ATTACK_CHAIN = {
  T1499: {
    tactic: "Impact",
    chain: [
      "Reconnaissance",
      "Initial Access",
      "Execution",
      "Persistence",
      "Privilege Escalation",
      "Defense Evasion",
      "Command & Control",
      "Impact"
    ],
    description:
      "Denial-of-Service attack intended to disrupt availability by overwhelming resources."
  },
  T1046: {
    tactic: "Reconnaissance",
    chain: [
      "Reconnaissance",
      "Initial Access",
      "Execution",
      "Persistence",
      "Privilege Escalation",
      "Defense Evasion",
      "Command & Control",
      "Impact"
    ],
    description:
      "Scanning network services to discover open ports and attack surface."
  }
};




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

/* ---------- INCIDENT GROUPING ---------- */
function groupAlertsBySource(alerts) {
  const incidents = {};

  alerts.forEach(alert => {
    const src = alert.source?.ip || "unknown";

    if (!incidents[src]) {
      incidents[src] = {
        source_ip: src,
        alerts: [],
        highest_severity: "low",
        first_seen: alert.timestamp,
        last_seen: alert.timestamp
      };
    }

    incidents[src].alerts.push(alert);

    // Track severity escalation
    if (alert.severity === "high") {
      incidents[src].highest_severity = "high";
    } else if (
      alert.severity === "medium" &&
      incidents[src].highest_severity !== "high"
    ) {
      incidents[src].highest_severity = "medium";
    }

    incidents[src].last_seen = alert.timestamp;
  });

  return Object.values(incidents);
}


/* ---------- Fetch and Render Alerts ---------- */

async function loadAlerts() {
  try {
    const res = await fetch(API_URL);
    const data = await res.json();
    const alerts = data.alerts || [];

    alerts.forEach(a => {
    if (!a.status) a.status = "new";
    });

    CURRENT_ALERTS = alerts;

    // Update dashboard metrics

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
  window.currentAlerts = alerts;
  

  renderIncidents(alerts); // Update incidents on load (this is added by TAB)
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

/* ---------- Export Alerts as CSV ---------- */
function exportCSV() {
  if (!CURRENT_ALERTS.length) {
    alert("No alerts available to export.");
    return;
  }

  const headers = [
    "Timestamp",
    "Attack",
    "Severity",
    "MITRE",
    "Source IP",
    "Destination IP"
  ];

  const rows = CURRENT_ALERTS.map(a => [
    a.timestamp,
    a.attack_name,
    a.severity,
    a.mitre_technique || "",
    a.source?.ip || "",
    a.destination?.ip || ""
  ]);

  let csvContent =
    headers.join(",") + "\n" +
    rows.map(r => r.join(",")).join("\n");

  const blob = new Blob([csvContent], { type: "text/csv" });
  const url = URL.createObjectURL(blob);

  const link = document.createElement("a");
  link.href = url;
  link.download = "ids_incident_report.csv";
  link.click();

  URL.revokeObjectURL(url);
}


/* ---------- Export Alerts as PDF ---------- */
function exportPDF() {
  if (!CURRENT_ALERTS.length) {
    alert("No alerts available to export.");
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  doc.setFontSize(16);
  doc.text("Intrusion Detection System - Incident Report", 14, 20);

  doc.setFontSize(10);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 28);

  let y = 38;

  CURRENT_ALERTS.forEach((a, index) => {
    if (y > 270) {
      doc.addPage();
      y = 20;
    }

    doc.setFontSize(11);
    doc.text(`Alert ${index + 1}`, 14, y);
    y += 6;

    doc.setFontSize(9);
    doc.text(`Attack: ${a.attack_name}`, 16, y); y += 5;
    doc.text(`Severity: ${a.severity}`, 16, y); y += 5;
    doc.text(`MITRE: ${a.mitre_technique || "N/A"}`, 16, y); y += 5;
    doc.text(`Source: ${a.source?.ip}`, 16, y); y += 5;
    doc.text(`Destination: ${a.destination?.ip}`, 16, y); y += 8;
  });

  doc.save("ids_incident_report.pdf");
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
        <div class="flex gap-2 items-center">
          <span class="px-3 py-1 rounded-full text-xs font-semibold
            ${severity === "high" ? "bg-red-500/20 text-red-400" :
              severity === "medium" ? "bg-yellow-500/20 text-yellow-400" :
              "bg-green-500/20 text-green-400"}">
            ${severity.toUpperCase()}
          </span>

          <span class="px-2 py-1 rounded text-xs font-semibold
            ${alert.status === "new" ? "bg-blue-500/20 text-blue-400" :
              alert.status === "investigating" ? "bg-purple-500/20 text-purple-400" :
              "bg-green-500/20 text-green-400"}">
            ${alert.status.toUpperCase()}
          </span>
        </div>
      </div>
    `;
    
    row.addEventListener("click", () => {
      openModal(alert);
    });


    container.appendChild(row);
  });
}


/* ---------- Incidents Table ---------- */
function renderIncidents(alerts) {
  const container = document.getElementById("incidentsTable");
  container.innerHTML = "";

  const incidents = groupAlertsBySource(alerts);

  if (!incidents.length) {
    container.innerHTML = `
      <div class="bg-[#111827] p-4 rounded text-gray-400">
        No active incidents detected.
      </div>`;
    return;
  }

  incidents.forEach(incident => {
    const sev = incident.highest_severity;
    const glow =
      sev === "high" ? "glow-high" :
      sev === "medium" ? "glow-medium" :
      "glow-low";

    const card = document.createElement("div");
    card.className = `
      bg-[#111827] border border-gray-800 rounded-lg p-4
      transition hover:bg-[#1f2937] ${glow}
    `;

    card.innerHTML = `
      <div class="flex justify-between items-center">
        <div>
          <p class="font-semibold text-gray-200">
            Source IP: ${incident.source_ip}
          </p>
          <p class="text-sm text-gray-400">
            Alerts: ${incident.alerts.length}
          </p>
        </div>

        <span class="px-3 py-1 rounded-full text-xs font-semibold
          ${sev === "high" ? "bg-red-500/20 text-red-400" :
            sev === "medium" ? "bg-yellow-500/20 text-yellow-400" :
            "bg-green-500/20 text-green-400"}">
          ${sev.toUpperCase()}
        </span>
      </div>

      <div class="text-xs text-gray-500 mt-2">
        First seen: ${new Date(incident.first_seen).toLocaleString()}<br/>
        Last seen: ${new Date(incident.last_seen).toLocaleString()}
      </div>
    `;

    card.addEventListener("click", () => {
      openIncidentModal(incident);
    });

    container.appendChild(card);
  });
}



/// ---------- Alert Details Modal ----------
function openModal(alert) {
  // Reset tactic panel
  document.getElementById("tacticPanel")?.classList.add("hidden");

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

                    <!-- PACKET & TRAFFIC DETAILS -->
          <div class="border border-gray-800 rounded-lg bg-[#111827] p-4">
            <p class="text-purple-400 font-semibold mb-2">
              Packet & Traffic Analysis
            </p>

            ${
              alert.traffic
                ? `
              <div class="grid grid-cols-2 gap-4 text-sm">

                <div>
                  <p class="text-gray-400">Source Port</p>
                  <p class="font-mono">${alert.source?.port ?? "N/A"}</p>
                </div>

                <div>
                  <p class="text-gray-400">Destination Port</p>
                  <p class="font-mono">${alert.destination?.port ?? "N/A"}</p>
                </div>

                <div>
                  <p class="text-gray-400">Packet Size</p>
                  <p>${alert.traffic.packet_size} bytes</p>
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

              </div>

              <div class="mt-3 text-sm text-gray-400">
                These packet-level characteristics indicate abnormal traffic behavior
                that triggered the IDS detection logic.
              </div>
              `
                : `
              <p class="text-sm text-gray-400">
                Packet-level details are not available for this alert.
              </p>
              `
            }
          </div>


          <!-- ALERT LIFECYCLE ACTIONS -->
          <div class="border border-gray-800 rounded-lg bg-[#111827] p-4">
            <p class="text-cyan-400 font-semibold mb-2">
              Alert Lifecycle
            </p>

            <div class="flex gap-3">
              <button
                class="px-3 py-2 rounded bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 transition"
                onclick="setAlertStatus('${alert.timestamp}', 'investigating')">
                Mark Investigating
              </button>

              <button
                class="px-3 py-2 rounded bg-green-500/20 text-green-400 hover:bg-green-500/30 transition"
                onclick="setAlertStatus('${alert.timestamp}', 'resolved')">
                Mark Resolved
              </button>
            </div>
          </div>


      </div>
    `;

  
  // Render MITRE attack chain
  if (alert.mitre_technique) {
    renderAttackChain(alert.mitre_technique);
  }

  modal.classList.remove("hidden");
}

/* ---------- MITRE ATT&CK CHAIN RENDERING ---------- */
function renderAttackChain(mitreId) {
  const container = document.getElementById("attackChain");
  const desc = document.getElementById("attackChainDesc");

  container.innerHTML = "";
  desc.innerText = "";

  if (!MITRE_ATTACK_CHAIN[mitreId]) {
    desc.innerText = "No attack chain data available.";
    return;
  }

  const { chain, tactic, description } = MITRE_ATTACK_CHAIN[mitreId];

  chain.forEach(stage => {
    const isActive = stage === tactic;

    const box = document.createElement("div");
    box.className = `
      px-3 py-2 rounded-lg border
      ${isActive
        ? "bg-red-500/20 border-red-500 text-red-400 font-semibold"
        : "bg-[#0b1220] border-gray-700 text-gray-400"}
    `;
    box.innerText = stage;

    box.addEventListener("click", () => {
      showTacticDetails(stage);
    });

    container.appendChild(box);
  });

  desc.innerText = description;
}

/* ---------- MITRE TACTIC DETAILS PANEL ---------- */
function showTacticDetails(tactic) {
  const panel = document.getElementById("tacticPanel");
  const content = document.getElementById("tacticContent");

  content.innerHTML = "";

  if (!MITRE_TACTIC_DETAILS[tactic]) {
    content.innerHTML =
      "<p class='text-gray-400'>No details available.</p>";
    panel.classList.remove("hidden");
    return;
  }

  const data = MITRE_TACTIC_DETAILS[tactic];

  content.innerHTML = `
    <div>
      <p class="text-gray-400">Objective</p>
      <p class="font-semibold text-gray-200">${data.goal}</p>
    </div>

    <div>
      <p class="text-gray-400">Common Attacker Actions</p>
      <ul class="list-disc list-inside text-gray-300">
        ${data.actions.map(a => `<li>${a}</li>`).join("")}
      </ul>
    </div>

    <div>
      <p class="text-gray-400">Defensive Measures</p>
      <ul class="list-disc list-inside text-green-400">
        ${data.defenses.map(d => `<li>${d}</li>`).join("")}
      </ul>
    </div>
  `;

  panel.classList.remove("hidden");
}


/* ---------- MITRE TACTIC DETAILS ---------- */
const MITRE_TACTIC_DETAILS = {
  "Reconnaissance": {
    goal: "Gather information about the target environment",
    actions: [
      "Network scanning",
      "Service enumeration",
      "IP range discovery"
    ],
    defenses: [
      "Monitor scanning activity",
      "Limit exposed services",
      "Enable IDS/IPS alerts"
    ]
  },

  "Initial Access": {
    goal: "Gain a foothold into the target system",
    actions: [
      "Exploiting exposed services",
      "Credential abuse",
      "Phishing attacks"
    ],
    defenses: [
      "Patch exposed services",
      "Strong authentication",
      "Access control policies"
    ]
  },

  "Execution": {
    goal: "Run malicious code on the target",
    actions: [
      "Script execution",
      "Malware deployment",
      "Command execution"
    ],
    defenses: [
      "Application whitelisting",
      "Behavioral monitoring",
      "Endpoint protection"
    ]
  },

  "Command & Control": {
    goal: "Maintain communication with compromised systems",
    actions: [
      "Beaconing",
      "C2 channels",
      "Encrypted traffic abuse"
    ],
    defenses: [
      "Traffic inspection",
      "DNS monitoring",
      "Outbound filtering"
    ]
  },

  "Impact": {
    goal: "Disrupt availability or integrity",
    actions: [
      "Denial of Service",
      "Data destruction",
      "Resource exhaustion"
    ],
    defenses: [
      "Rate limiting",
      "DDoS protection",
      "Traffic anomaly detection"
    ]
  }
};



/* ---------- Incident Details Modal ---------- */
function openIncidentModal(incident) {
  const modal = document.getElementById("alertModal");
  const content = document.getElementById("modalContent");

  content.innerHTML = `
    <div class="space-y-4">

      <div>
        <p class="text-gray-400">Incident Source IP</p>
        <p class="text-lg font-semibold">${incident.source_ip}</p>
      </div>

      <div>
        <p class="text-gray-400">Total Alerts</p>
        <p>${incident.alerts.length}</p>
      </div>

      <div>
        <p class="text-gray-400">Highest Severity</p>
        <p class="font-semibold">${incident.highest_severity.toUpperCase()}</p>
      </div>

      <div class="border border-gray-800 rounded bg-[#111827] p-3">
        <p class="text-cyan-400 font-semibold mb-2">
          Alerts in this Incident
        </p>
        <ul class="list-disc list-inside text-sm text-gray-400 space-y-1">
          ${incident.alerts.map(a => `
            <li>
              ${new Date(a.timestamp).toLocaleTimeString()} —
              ${a.attack_name} (${a.severity})
            </li>
          `).join("")}
        </ul>
      </div>

      <div class="text-sm text-gray-400">
        This incident groups multiple related alerts originating from the same
        source IP, indicating a coordinated or repeated attack attempt.
      </div>

    </div>
  `;

  modal.classList.remove("hidden");
}



function closeModal() {
  document.getElementById("alertModal").classList.add("hidden");
}

/* ---------- Set Alert Status ---------- */
function setAlertStatus(timestamp, status) {
  const alerts = window.currentAlerts || [];

  alerts.forEach(a => {
    if (a.timestamp === timestamp) {
      a.status = status;
    }
  });

  closeModal();
  renderAlertsTable(alerts);
  renderIncidents(alerts);
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
renderIncidents(alerts);
