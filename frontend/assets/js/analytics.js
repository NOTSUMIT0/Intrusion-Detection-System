const API_URL = "http://127.0.0.1:8000/alerts";

const severityChart = echarts.init(document.getElementById("severityChart"));
const timelineChart = echarts.init(document.getElementById("timelineChart"));
const sourceChart = echarts.init(document.getElementById("sourceChart"));
const attackTypeChart = echarts.init(document.getElementById("attackTypeChart"));

async function loadAnalytics() {
  const res = await fetch(API_URL);
  const data = await res.json();
  const alerts = data.alerts || [];

  renderSeverity(alerts);
  renderTimeline(alerts);
  renderSources(alerts);
  renderAttackTypes(alerts);
  renderInsights(alerts);
}

/* ---------- Severity Distribution ---------- */
function renderSeverity(alerts) {
  const count = { high: 0, medium: 0, low: 0 };

  alerts.forEach(a => count[a.severity]++);

  severityChart.setOption({
    tooltip: { trigger: "item" },
    series: [{
      type: "pie",
      radius: ["45%", "70%"],
      label: { color: "#e5e7eb" },
      data: [
        { value: count.high, name: "High", itemStyle: { color: "#ef4444" }},
        { value: count.medium, name: "Medium", itemStyle: { color: "#f59e0b" }},
        { value: count.low, name: "Low", itemStyle: { color: "#22c55e" }}
      ]
    }]
  });
}

/* ---------- Timeline ---------- */
function renderTimeline(alerts) {
  const map = {};

  alerts.forEach(a => {
    const t = new Date(a.timestamp).toLocaleTimeString();
    map[t] = (map[t] || 0) + 1;
  });

  timelineChart.setOption({
    xAxis: { type: "category", data: Object.keys(map), axisLabel: { color: "#9ca3af" }},
    yAxis: { type: "value", axisLabel: { color: "#9ca3af" }},
    series: [{
      type: "line",
      smooth: true,
      data: Object.values(map),
      lineStyle: { color: "#38bdf8" },
      areaStyle: { color: "rgba(56,189,248,0.2)" }
    }]
  });
}

/* ---------- Source IPs ---------- */
function renderSources(alerts) {
  const map = {};

  alerts.forEach(a => {
    const ip = a.source?.ip || "unknown";
    map[ip] = (map[ip] || 0) + 1;
  });

  const entries = Object.entries(map).slice(0, 6);

  sourceChart.setOption({
    xAxis: { type: "value", axisLabel: { color: "#9ca3af" }},
    yAxis: { type: "category", data: entries.map(e => e[0]), axisLabel: { color: "#9ca3af" }},
    series: [{
      type: "bar",
      data: entries.map(e => e[1]),
      itemStyle: { color: "#38bdf8" }
    }]
  });
}

/* ---------- Attack Types ---------- */
function renderAttackTypes(alerts) {
  const map = {};

  alerts.forEach(a => {
    map[a.attack_name] = (map[a.attack_name] || 0) + 1;
  });

  attackTypeChart.setOption({
    tooltip: {},
    xAxis: { type: "category", data: Object.keys(map), axisLabel: { color: "#9ca3af", rotate: 20 }},
    yAxis: { type: "value", axisLabel: { color: "#9ca3af" }},
    series: [{
      type: "bar",
      data: Object.values(map),
      itemStyle: { color: "#a855f7" }
    }]
  });
}

/* ---------- Insights ---------- */
function renderInsights(alerts) {
  const container = document.getElementById("insights");
  container.innerHTML = "";

  const high = alerts.filter(a => a.severity === "high").length;

  container.innerHTML += `<li>${alerts.length} total alerts detected.</li>`;
  container.innerHTML += `<li>${high} high-severity alerts indicate potential active threats.</li>`;
  container.innerHTML += `<li>Repeated alerts from same IPs suggest coordinated attacks.</li>`;
  container.innerHTML += `<li>Timeline spikes may indicate attack bursts or scans.</li>`;
}

loadAnalytics();
