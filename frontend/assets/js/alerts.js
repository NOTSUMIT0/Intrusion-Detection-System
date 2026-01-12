const API_URL = "http://127.0.0.1:8000/alerts";

async function loadAlertsOnly() {
  const res = await fetch(API_URL);
  const data = await res.json();
  renderAlerts(data.alerts || []);
}

function renderAlerts(alerts) {
  const container = document.getElementById("alertsTable");
  container.innerHTML = "";

  if (!alerts.length) {
    container.innerHTML = `
      <div class="bg-[#111827] p-4 rounded text-gray-400">
        No alerts detected.
      </div>`;
    return;
  }

  alerts.slice().reverse().forEach(alert => {
    const sev = alert.severity;
    const color =
      sev === "high" ? "text-red-400" :
      sev === "medium" ? "text-yellow-400" :
      "text-green-400";

    container.innerHTML += `
      <div class="bg-[#111827] border border-gray-800 p-4 rounded-lg">
        <div class="flex justify-between">
          <div>
            <p class="font-semibold">${alert.attack_name}</p>
            <p class="text-sm text-gray-400">
              ${alert.source?.ip} → ${alert.destination?.ip}
            </p>
          </div>
          <span class="${color} font-semibold">
            ${sev.toUpperCase()}
          </span>
        </div>
      </div>`;
  });
}

loadAlertsOnly();
