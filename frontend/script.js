const state = {
    logs: [],
    alerts: [],
    timeline: [],
    attackChains: [],
    monitoringActive: false,
    scanMode: "live",
};

const elements = {
    monitoringStatus: document.getElementById("monitoringStatus"),
    alertCount: document.getElementById("alertCount"),
    chainCount: document.getElementById("chainCount"),
    scanModeStatus: document.getElementById("scanModeStatus"),
    logsContainer: document.getElementById("logsContainer"),
    alertsContainer: document.getElementById("alertsContainer"),
    timelineContainer: document.getElementById("timelineContainer"),
    chainsContainer: document.getElementById("chainsContainer"),
    logSearch: document.getElementById("logSearch"),
    severityFilter: document.getElementById("severityFilter"),
    scanModeSelect: document.getElementById("scanModeSelect"),
    startBtn: document.getElementById("startBtn"),
    stopBtn: document.getElementById("stopBtn"),
    downloadBtn: document.getElementById("downloadBtn"),
};

let refreshIntervalId = null;

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function formatTimestamp(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function highlightIp(text) {
    return String(text).replace(/(\b\d{1,3}(?:\.\d{1,3}){3}\b)/g, '<span class="highlight-ip">$1</span>');
}

function renderLogs() {
    const query = elements.logSearch.value.trim().toLowerCase();
    const filtered = state.logs.slice().reverse().filter((item) => {
        if (!query) {
            return true;
        }
        const combined = `${item.raw} ${JSON.stringify(item.parsed)}`.toLowerCase();
        return combined.includes(query);
    });

    elements.logsContainer.innerHTML = filtered.length
        ? filtered.map((item) => `
            <div class="item">
                <div class="item-head">
                    <span class="item-title">${escapeHtml(item.source)}</span>
                    <span class="item-time">${escapeHtml(formatTimestamp(item.timestamp))}</span>
                </div>
                <div class="item-meta">${highlightIp(escapeHtml(item.raw))}</div>
            </div>
        `).join("")
        : '<div class="item"><div class="item-meta">No logs received yet.</div></div>';
}

function renderAlerts() {
    const severity = elements.severityFilter.value;
    const filtered = state.alerts.slice().reverse().filter((item) => severity === "ALL" || item.severity === severity);

    elements.alertCount.textContent = String(state.alerts.length);
    elements.alertsContainer.innerHTML = filtered.length
        ? filtered.map((item) => `
            <div class="item alert-${item.severity.toLowerCase()}">
                <div class="item-head">
                    <span class="item-title">${escapeHtml(item.category)}</span>
                    <span class="item-time">${escapeHtml(formatTimestamp(item.timestamp))}</span>
                </div>
                <div class="item-meta">${escapeHtml(item.message)}</div>
                <div class="item-meta">Severity: ${escapeHtml(item.severity)} | Rule: ${escapeHtml(item.rule_id)} | IP: ${highlightIp(escapeHtml(item.ip_address || "N/A"))}</div>
            </div>
        `).join("")
        : '<div class="item"><div class="item-meta">No alerts triggered.</div></div>';
}

function renderTimeline() {
    const items = state.timeline.slice().reverse();
    elements.timelineContainer.innerHTML = items.length
        ? items.map((item) => `
            <div class="item">
                <div class="item-head">
                    <span class="item-title">${escapeHtml(item.title)}</span>
                    <span class="item-time">${escapeHtml(formatTimestamp(item.timestamp))}</span>
                </div>
                <div class="item-meta">Type: ${escapeHtml(item.event_type)}</div>
            </div>
        `).join("")
        : '<div class="item"><div class="item-meta">Timeline is empty.</div></div>';
}

function renderChains() {
    elements.chainCount.textContent = String(state.attackChains.length);
    const items = state.attackChains.slice().reverse();
    elements.chainsContainer.innerHTML = items.length
        ? items.map((item) => `
            <div class="item">
                <div class="item-head">
                    <span class="item-title">${escapeHtml(item.title)}</span>
                    <span class="item-time">${escapeHtml(formatTimestamp(item.created_at))}</span>
                </div>
                <div class="item-meta">Chain: ${escapeHtml(item.chain_id)} | Severity: ${escapeHtml(item.severity)} | Source IP: ${highlightIp(escapeHtml(item.source_ip || "Unknown"))}</div>
                <div class="item-meta">Steps: ${item.steps.map((step) => escapeHtml(step.rule_id)).join(" -> ")}</div>
            </div>
        `).join("")
        : '<div class="item"><div class="item-meta">No correlated attack chains yet.</div></div>';
}

function updateStatus() {
    elements.monitoringStatus.textContent = state.monitoringActive ? "Running" : "Stopped";
    elements.scanModeStatus.textContent = state.scanMode === "historical" ? "Historical" : "Live";
}

function renderAll() {
    updateStatus();
    renderLogs();
    renderAlerts();
    renderTimeline();
    renderChains();
}

async function fetchInitialData() {
    const [logsResponse, alertsResponse, timelineResponse, chainResponse, statusResponse] = await Promise.all([
        fetch("/logs"),
        fetch("/alerts"),
        fetch("/timeline"),
        fetch("/attack-chains"),
        fetch("/status"),
    ]);

    state.logs = (await logsResponse.json()).items;
    state.alerts = (await alertsResponse.json()).items;
    state.timeline = (await timelineResponse.json()).items;
    state.attackChains = (await chainResponse.json()).items;
    const statusPayload = await statusResponse.json();
    state.monitoringActive = statusPayload.monitoring_active;
    if (state.monitoringActive) {
        state.scanMode = statusPayload.scan_mode || "live";
        elements.scanModeSelect.value = state.scanMode;
    } else {
        state.scanMode = elements.scanModeSelect.value;
    }
    renderAll();
}

async function startMonitoring() {
    const selectedScanMode = elements.scanModeSelect.value;
    const response = await fetch("/monitoring/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: "auto", scan_mode: selectedScanMode }),
    });
    if (!response.ok) {
        alert("Unable to start monitoring.");
        return;
    }
    state.scanMode = selectedScanMode;
    await fetchInitialData();
}

async function stopMonitoring() {
    const response = await fetch("/monitoring/stop", { method: "POST" });
    if (!response.ok) {
        alert("Unable to stop monitoring.");
        return;
    }
    await fetchInitialData();
}

async function downloadReport() {
    const response = await fetch("/report/download");
    if (!response.ok) {
        const errorPayload = await response.json();
        alert(errorPayload.detail || "Report is not ready yet.");
        return;
    }

    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = downloadUrl;
    anchor.download = "ids_final_report.pdf";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.URL.revokeObjectURL(downloadUrl);
}

function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${protocol}://${window.location.host}/ws/live`);

    socket.addEventListener("message", (event) => {
        const payload = JSON.parse(event.data);
        if (payload.type === "snapshot") {
            state.monitoringActive = payload.data.monitoring_active;
            state.logs = payload.data.logs || [];
            state.alerts = payload.data.alerts || [];
            state.timeline = payload.data.timeline || [];
            state.attackChains = payload.data.attack_chains || [];
            if (state.monitoringActive) {
                state.scanMode = payload.data.scan_mode || "live";
                elements.scanModeSelect.value = state.scanMode;
            } else {
                state.scanMode = elements.scanModeSelect.value;
            }
            renderAll();
            return;
        }

        if (payload.type === "log") {
            state.logs.push(payload.data);
        }
        if (payload.type === "alert") {
            state.alerts.push(payload.data);
        }
        if (payload.type === "timeline") {
            state.timeline.push(payload.data);
            if (payload.data.event_type === "monitoring") {
                state.monitoringActive = payload.data.title.toLowerCase().includes("started");
            }
        }
        if (payload.type === "attack_chain") {
            state.attackChains.push(payload.data);
        }
        renderAll();
    });

    socket.addEventListener("close", () => {
        setTimeout(connectWebSocket, 1500);
    });
}

elements.startBtn.addEventListener("click", startMonitoring);
elements.stopBtn.addEventListener("click", stopMonitoring);
elements.downloadBtn.addEventListener("click", downloadReport);
elements.logSearch.addEventListener("input", renderLogs);
elements.severityFilter.addEventListener("change", renderAlerts);

fetchInitialData();
connectWebSocket();
refreshIntervalId = window.setInterval(fetchInitialData, 2000);
