const state = {
    logs: [],
    alerts: [],
    timeline: [],
    attackChains: [],
    monitoringActive: false,
    scanMode: "live",
    sourceMode: "auto",
    selectedScanMode: "live",
};

const elements = {
    monitoringStatus: document.getElementById("monitoringStatus"),
    monitoringDot: document.getElementById("monitoringDot"),
    alertCount: document.getElementById("alertCount"),
    chainCount: document.getElementById("chainCount"),
    scanModeStatus: document.getElementById("scanModeStatus"),
    sourceModeStatus: document.getElementById("sourceModeStatus"),
    recentAlertStatus: document.getElementById("recentAlertStatus"),
    suspiciousIpCount: document.getElementById("suspiciousIpCount"),
    visibleAlertCount: document.getElementById("visibleAlertCount"),
    logsCount: document.getElementById("logsCount"),
    highCount: document.getElementById("highCount"),
    mediumCount: document.getElementById("mediumCount"),
    lowCount: document.getElementById("lowCount"),
    highBar: document.getElementById("highBar"),
    mediumBar: document.getElementById("mediumBar"),
    lowBar: document.getElementById("lowBar"),
    logsRing: document.getElementById("logsRing"),
    alertsRing: document.getElementById("alertsRing"),
    chainsRing: document.getElementById("chainsRing"),
    topIpsContainer: document.getElementById("topIpsContainer"),
    logsContainer: document.getElementById("logsContainer"),
    alertsContainer: document.getElementById("alertsContainer"),
    timelineContainer: document.getElementById("timelineContainer"),
    chainsContainer: document.getElementById("chainsContainer"),
    logSearch: document.getElementById("logSearch"),
    severityFilter: document.getElementById("severityFilter"),
    liveModeBtn: document.getElementById("liveModeBtn"),
    historicalModeBtn: document.getElementById("historicalModeBtn"),
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

function normalizedSourceLabel(mode) {
    if (!mode) {
        return "Auto";
    }
    const labels = {
        windows_events: "Windows Events",
        file: "System Logs",
        demo: "Demo Logs",
        auto: "Auto",
    };
    return labels[mode] || mode.replaceAll("_", " ");
}

function setRingProgress(element, value, cap) {
    const safeCap = Math.max(cap, 1);
    const progress = Math.max(8, Math.min(100, (value / safeCap) * 100));
    element.style.setProperty("--progress", `${progress}%`);
}

function setSelectedScanMode(mode) {
    state.selectedScanMode = mode;
    elements.liveModeBtn.classList.toggle("active", mode === "live");
    elements.historicalModeBtn.classList.toggle("active", mode === "historical");
}

function getSeverityCounts() {
    return state.alerts.reduce(
        (counts, alert) => {
            const severity = (alert.severity || "").toLowerCase();
            if (severity === "high") {
                counts.high += 1;
            } else if (severity === "medium") {
                counts.medium += 1;
            } else if (severity === "low") {
                counts.low += 1;
            }
            return counts;
        },
        { high: 0, medium: 0, low: 0 }
    );
}

function getVisibleAlerts() {
    const severity = elements.severityFilter.value;
    return state.alerts.filter((item) => severity === "ALL" || item.severity === severity);
}

function renderTopIps() {
    const ipCounter = new Map();
    state.alerts.forEach((alert) => {
        if (alert.ip_address) {
            ipCounter.set(alert.ip_address, (ipCounter.get(alert.ip_address) || 0) + 1);
        }
    });

    const topIps = Array.from(ipCounter.entries())
        .sort((left, right) => right[1] - left[1])
        .slice(0, 5);

    elements.suspiciousIpCount.textContent = String(ipCounter.size);
    elements.topIpsContainer.innerHTML = topIps.length
        ? topIps.map(([ip, count]) => `<span class="chip">${escapeHtml(ip)} · ${count}</span>`).join("")
        : '<span class="chip">No suspicious IPs yet</span>';
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
                <span class="item-kicker">Parsed Event</span>
            </div>
        `).join("")
        : '<div class="item"><div class="item-meta">No logs received yet.</div></div>';
}

function renderAlerts() {
    const filtered = getVisibleAlerts().slice().reverse();
    elements.visibleAlertCount.textContent = String(filtered.length);

    elements.alertsContainer.innerHTML = filtered.length
        ? filtered.map((item) => `
            <div class="item alert-${item.severity.toLowerCase()}">
                <div class="item-head">
                    <span class="item-title">${escapeHtml(item.category)}</span>
                    <span class="item-time">${escapeHtml(formatTimestamp(item.timestamp))}</span>
                </div>
                <div class="item-meta">${escapeHtml(item.message)}</div>
                <div class="item-meta">Severity: ${escapeHtml(item.severity)} | Rule: ${escapeHtml(item.rule_id)} | IP: ${highlightIp(escapeHtml(item.ip_address || "N/A"))}</div>
                <span class="item-kicker">${escapeHtml(item.severity)} Priority</span>
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
                <span class="item-kicker">Timeline Entry</span>
            </div>
        `).join("")
        : '<div class="item"><div class="item-meta">Timeline is empty.</div></div>';
}

function renderChains() {
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
                <span class="item-kicker">Correlated Sequence</span>
            </div>
        `).join("")
        : '<div class="item"><div class="item-meta">No correlated attack chains yet.</div></div>';
}

function updateStatus() {
    const severityCounts = getSeverityCounts();
    const totalAlerts = state.alerts.length;
    const recentAlert = state.alerts.length ? state.alerts[state.alerts.length - 1] : null;

    elements.monitoringStatus.textContent = state.monitoringActive ? "Running" : "Stopped";
    elements.scanModeStatus.textContent = state.scanMode === "historical" ? "Historical" : "Live";
    elements.sourceModeStatus.textContent = normalizedSourceLabel(state.sourceMode);
    elements.recentAlertStatus.textContent = recentAlert ? recentAlert.category : "No active alerts";
    elements.monitoringDot.classList.toggle("active", state.monitoringActive);

    elements.logsCount.textContent = String(state.logs.length);
    elements.alertCount.textContent = String(totalAlerts);
    elements.chainCount.textContent = String(state.attackChains.length);
    elements.highCount.textContent = String(severityCounts.high);
    elements.mediumCount.textContent = String(severityCounts.medium);
    elements.lowCount.textContent = String(severityCounts.low);

    const totalSeverity = Math.max(totalAlerts, 1);
    elements.highBar.style.width = `${(severityCounts.high / totalSeverity) * 100}%`;
    elements.mediumBar.style.width = `${(severityCounts.medium / totalSeverity) * 100}%`;
    elements.lowBar.style.width = `${(severityCounts.low / totalSeverity) * 100}%`;

    setRingProgress(elements.logsRing, state.logs.length, 120);
    setRingProgress(elements.alertsRing, totalAlerts, 40);
    setRingProgress(elements.chainsRing, state.attackChains.length, 15);
    renderTopIps();
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
    state.sourceMode = statusPayload.source_mode || "auto";
    if (state.monitoringActive) {
        state.scanMode = statusPayload.scan_mode || "live";
        setSelectedScanMode(state.scanMode);
    } else {
        state.scanMode = state.selectedScanMode;
    }
    renderAll();
}

async function startMonitoring() {
    const response = await fetch("/monitoring/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: "auto", scan_mode: state.selectedScanMode }),
    });
    if (!response.ok) {
        alert("Unable to start monitoring.");
        return;
    }
    state.scanMode = state.selectedScanMode;
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
            state.sourceMode = payload.data.source_mode || "auto";
            if (state.monitoringActive) {
                state.scanMode = payload.data.scan_mode || "live";
                setSelectedScanMode(state.scanMode);
            } else {
                state.scanMode = state.selectedScanMode;
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

elements.liveModeBtn.addEventListener("click", () => {
    setSelectedScanMode("live");
    if (!state.monitoringActive) {
        state.scanMode = "live";
        renderAll();
    }
});

elements.historicalModeBtn.addEventListener("click", () => {
    setSelectedScanMode("historical");
    if (!state.monitoringActive) {
        state.scanMode = "historical";
        renderAll();
    }
});

elements.startBtn.addEventListener("click", startMonitoring);
elements.stopBtn.addEventListener("click", stopMonitoring);
elements.downloadBtn.addEventListener("click", downloadReport);
elements.logSearch.addEventListener("input", renderLogs);
elements.severityFilter.addEventListener("change", renderAlerts);

setSelectedScanMode("live");
fetchInitialData();
connectWebSocket();
refreshIntervalId = window.setInterval(fetchInitialData, 2000);
