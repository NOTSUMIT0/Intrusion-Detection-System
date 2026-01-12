const API_URL = "http://127.0.0.1:8000/alerts";

/* ================= MITRE DATABASE ================= */
const MITRE = {
  T1046: {
    name: "Network Service Scanning",
    tactic: "Reconnaissance",
    description: "Scanning ports and services to identify attack surface.",
    risk: "Helps attackers plan exploitation.",
    mitigation: ["Firewall rules", "Scan detection", "Limit exposed services"]
  },
  T1499: {
    name: "Endpoint Denial of Service",
    tactic: "Impact",
    description: "Flooding targets to exhaust resources.",
    risk: "Service disruption and downtime.",
    mitigation: ["Rate limiting", "DDoS protection", "Traffic shaping"]
  }
};

const KILL_CHAIN = [
  "Reconnaissance",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Command & Control",
  "Impact"
];

const techniqueChart = echarts.init(document.getElementById("techniqueChart"));
const tacticSeverityChart = echarts.init(document.getElementById("tacticSeverityChart"));

/* ================= LOAD ================= */
async function loadMITRE() {
  const res = await fetch(API_URL);
  const data = await res.json();
  const alerts = data.alerts || [];

  renderKillChain(alerts);
  renderTechniqueChart(alerts);
  renderTacticSeverity(alerts);
  renderTechniqueList(alerts);
}

/* ================= KILL CHAIN ================= */
function renderKillChain(alerts) {
  const container = document.getElementById("killChain");
  container.innerHTML = "";

  const activeTactics = new Set(
    alerts.map(a => MITRE[a.mitre_technique]?.tactic).filter(Boolean)
  );

  KILL_CHAIN.forEach(stage => {
    const active = activeTactics.has(stage);

    const div = document.createElement("div");
    div.className = `
      px-2 py-2 rounded border
      ${active
        ? "bg-red-500/20 border-red-500 text-red-400 font-semibold"
        : "bg-[#0b1220] border-gray-700 text-gray-400"}
    `;
    div.innerText = stage;
    container.appendChild(div);
  });
}

/* ================= CHARTS ================= */
function renderTechniqueChart(alerts) {
  const map = {};

  alerts.forEach(a => {
    if (a.mitre_technique)
      map[a.mitre_technique] = (map[a.mitre_technique] || 0) + 1;
  });

  techniqueChart.setOption({
    xAxis: { type: "category", data: Object.keys(map), axisLabel: { color: "#9ca3af" }},
    yAxis: { type: "value", axisLabel: { color: "#9ca3af" }},
    series: [{
      type: "bar",
      data: Object.values(map),
      itemStyle: { color: "#38bdf8" }
    }]
  });
}

function renderTacticSeverity(alerts) {
  const map = {};

  alerts.forEach(a => {
    const tactic = MITRE[a.mitre_technique]?.tactic;
    if (!tactic) return;
    map[tactic] = (map[tactic] || 0) + 1;
  });

  tacticSeverityChart.setOption({
    tooltip: {},
    series: [{
      type: "pie",
      radius: "65%",
      data: Object.entries(map).map(([k, v]) => ({ name: k, value: v })),
      label: { color: "#e5e7eb" }
    }]
  });
}

/* ================= LIST ================= */
function renderTechniqueList(alerts) {
  const container = document.getElementById("techniqueList");
  container.innerHTML = "";

  const used = new Set(alerts.map(a => a.mitre_technique).filter(Boolean));

  used.forEach(id => {
    const t = MITRE[id];
    if (!t) return;

    const card = document.createElement("div");
    card.className = "bg-[#111827] border border-gray-800 rounded-lg p-4 hover:bg-[#1f2937] transition cursor-pointer";

    card.innerHTML = `
      <p class="font-semibold text-cyan-400">${id} — ${t.name}</p>
      <p class="text-sm text-gray-400 mt-1">${t.tactic}</p>
    `;

    card.onclick = () => openModal(id);
    container.appendChild(card);
  });
}

/* ================= MODAL ================= */
function openModal(id) {
  const t = MITRE[id];
  document.getElementById("modalTitle").innerText = `${id} — ${t.name}`;

  document.getElementById("modalContent").innerHTML = `
    <p><strong>Description:</strong> ${t.description}</p>
    <p><strong>Why dangerous:</strong> ${t.risk}</p>
    <p><strong>Tactic:</strong> ${t.tactic}</p>
    <p><strong>Mitigations:</strong></p>
    <ul class="list-disc list-inside">
      ${t.mitigation.map(m => `<li>${m}</li>`).join("")}
    </ul>
  `;

  document.getElementById("mitreModal").classList.remove("hidden");
}

function closeModal() {
  document.getElementById("mitreModal").classList.add("hidden");
}

loadMITRE();
