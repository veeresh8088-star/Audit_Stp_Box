// ── ADMIN AUDIT LOGS & WARNING MODALS MODULE ──

function closeUnreviewedWarningModal() {
    const modalEl = document.getElementById("unreviewed-warning-modal");
    if (modalEl) modalEl.style.display = "none";
}

async function forceCommitSessionToShaktiDB() {
    if (typeof commitSessionToShaktiDB === "function") {
        await commitSessionToShaktiDB(true);
    }
}

async function loadAdminAuditLogs() {
    const modalEl = document.getElementById("admin-log-modal");
    const tbody = document.getElementById("admin-log-table-body");
    if (!modalEl || !tbody) return;

    modalEl.style.display = "flex";
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:16px; color:#94a3b8;">Loading Admin Audit Log trail...</td></tr>`;

    try {
        const response = await fetch(`${API_BASE}/audit/admin-logs`);
        const data = await response.json();
        if (data.success && data.logs && data.logs.length > 0) {
            tbody.innerHTML = data.logs.map(log => `
                <tr style="border-bottom: 1px solid rgba(148, 163, 184, 0.15);">
                    <td style="padding: 10px; font-family: monospace; font-size: 0.78rem;">${escapeHtml(log.timestamp)}</td>
                    <td style="padding: 10px; font-weight: 600; color: #60a5fa;">${escapeHtml(log.auditor_user)}</td>
                    <td style="padding: 10px;"><span style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.74rem;">${escapeHtml(log.action)}</span></td>
                    <td style="padding: 10px; font-family: monospace; color: #fbbf24;">${escapeHtml(log.unreviewed_controls || 'N/A')}</td>
                    <td style="padding: 10px; font-size: 0.78rem; color: #cbd5e1;">${escapeHtml(log.details)}</td>
                </tr>
            `).join("");
        } else {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:16px; color:#94a3b8;">No administrative overrides recorded yet.</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:16px; color:#ef4444;">Failed to load logs: ${err.message}</td></tr>`;
    }
}

function closeAdminLogModal() {
    const modalEl = document.getElementById("admin-log-modal");
    if (modalEl) modalEl.style.display = "none";
}

// ── EXPORT DOWNLOAD HANDLERS ──────────────────────────────────────────────────

/**
 * Download System Audit Event Logs as Excel (.xlsx) or PDF (.pdf).
 * Reads the #admin-log-auditor-filter input for optional per-user filtering.
 * Routes to /api/logs/system/export-excel or /api/logs/system/export-pdf.
 */
function downloadAdminLogsExport(format) {
    const auditorFilter = (document.getElementById("admin-log-auditor-filter")?.value || "").trim();
    const ext = format === "excel" ? "xlsx" : "pdf";
    let url = `${API_BASE}/logs/system/export-${format}`;
    if (auditorFilter) {
        url += `?auditor_user=${encodeURIComponent(auditorFilter)}`;
    }
    const btn = document.getElementById(format === "excel" ? "btn-download-logs-excel" : "btn-download-logs-pdf");
    if (btn) { btn.disabled = true; btn.textContent = "⏳ Generating..."; }
    const a = document.createElement("a");
    a.href = url;
    a.download = `System_Event_Logs_${auditorFilter || "all"}.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => {
        if (btn) {
            btn.disabled = false;
            btn.textContent = format === "excel" ? "📥 Download Logs (.xlsx)" : "📄 Download Logs (.pdf)";
        }
    }, 2500);
}

/**
 * Download Telemetry Benchmark Report as Excel (.xlsx) or PDF (.pdf).
 * Reads the #admin-log-auditor-filter input for optional per-user filtering.
 * Routes to /api/logs/benchmark/export-excel or /api/logs/benchmark/export-pdf.
 */
function downloadBenchmarkExport(format) {
    const auditorFilter = (document.getElementById("admin-log-auditor-filter")?.value || "").trim();
    const ext = format === "excel" ? "xlsx" : "pdf";
    let url = `${API_BASE}/logs/benchmark/export-${format}`;
    if (auditorFilter) {
        url += `?auditor_user=${encodeURIComponent(auditorFilter)}`;
    }
    const btn = document.getElementById(format === "excel" ? "btn-download-telemetry-excel" : "btn-download-telemetry-pdf");
    if (btn) { btn.disabled = true; btn.textContent = "⏳ Generating..."; }
    const a = document.createElement("a");
    a.href = url;
    a.download = `Executive_Telemetry_Report_${auditorFilter || "all"}.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => {
        if (btn) {
            btn.disabled = false;
            btn.textContent = format === "excel" ? "📥 Download Telemetry (.xlsx)" : "📄 Download Telemetry (.pdf)";
        }
    }, 2500);
}


// ── REDIS LIVE METRICS POLLING ────────────────────────────────────────────────
// Powers the "Live Server Metrics (Redis Stream)" KPI panel in the admin tab.
// Polls /api/logs/live-metrics every 3s and updates KPI cards + session table.
// ─────────────────────────────────────────────────────────────────────────────

let _liveMetricsInterval = null;

/**
 * Start polling Redis live metrics every 3 seconds.
 * Injects the KPI panel + Active Sessions table into #live-metrics-container.
 * Call this when the admin-logs tab is opened.
 */
function startLiveMetricsPolling() {
    stopLiveMetricsPolling(); // clear any previous interval
    _fetchAndRenderLiveMetrics(); // immediate first fetch
    _liveMetricsInterval = setInterval(_fetchAndRenderLiveMetrics, 3000);
}

function stopLiveMetricsPolling() {
    if (_liveMetricsInterval) {
        clearInterval(_liveMetricsInterval);
        _liveMetricsInterval = null;
    }
}

async function _fetchAndRenderLiveMetrics() {
    const container = document.getElementById("live-metrics-container");
    if (!container) return;
    try {
        const res = await fetch(`${API_BASE}/logs/live-metrics`);
        if (!res.ok) return;
        const d = await res.json();

        const redisOk = d.redis_available !== false;
        const tokens  = redisOk ? (d.global_tokens || 0).toLocaleString() : "---";
        const latency = redisOk ? (d.avg_latency_per_ctrl_str || "0m 0.0s") : "---";
        const files   = redisOk ? (d.global_files || 0) : "---";
        const errors  = redisOk ? (d.global_errors || 0) : "---";
        const sessions = redisOk ? (d.active_sessions || []) : [];

        const statusDot = redisOk
            ? `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;margin-right:5px;"></span>Redis Connected`
            : `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#ef4444;margin-right:5px;"></span>Redis Offline`;

        container.innerHTML = `
            <!-- Status bar -->
            <div style="display:flex; align-items:center; gap:8px; font-size:0.74rem; color:#94a3b8; margin-bottom:12px;">
                ${statusDot}
                <span style="margin-left:auto; font-size:0.7rem; color:#475569;">Updated: ${new Date().toLocaleTimeString()}</span>
            </div>

            <!-- KPI Cards -->
            <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:14px;">
                ${_kpiCard("Tokens Consumed", tokens + " Tokens", "#22c55e", "↑")}
                ${_kpiCard("Avg Latency/Ctrl", latency, "#fbbf24", "⚡")}
                ${_kpiCard("Total Files/Size", files + " Files", "#38bdf8", "📁")}
                ${_kpiCard("Error Log", errors + " Errors", errors > 0 ? "#ef4444" : "#22c55e", errors > 0 ? "⚠" : "✓")}
            </div>

            <!-- Active Auditor Sessions -->
            <div style="background:rgba(15,23,42,0.5); border:1px solid rgba(148,163,184,0.15); border-radius:10px; overflow:hidden;">
                <div style="padding:10px 14px; font-size:0.8rem; font-weight:700; color:#f8fafc; background:rgba(15,23,42,0.4); border-bottom:1px solid rgba(148,163,184,0.1);">
                    Active Auditor Sessions Live Stream
                    <span style="float:right; font-size:0.7rem; color:#94a3b8;">${sessions.filter(s=>s.status==='running').length} Running</span>
                </div>
                ${sessions.length > 0 ? `
                    <table style="width:100%; border-collapse:collapse; font-size:0.78rem; color:#e2e8f0;">
                        <thead>
                            <tr style="background:rgba(15,23,42,0.3); border-bottom:1px solid rgba(148,163,184,0.1);">
                                <th style="padding:8px 12px; text-align:left; font-weight:700; color:#94a3b8;">Auditor</th>
                                <th style="padding:8px 12px; text-align:left; font-weight:700; color:#94a3b8;">Files / Size</th>
                                <th style="padding:8px 12px; text-align:left; font-weight:700; color:#94a3b8;">Tokens Used</th>
                                <th style="padding:8px 12px; text-align:left; font-weight:700; color:#94a3b8;">Latency</th>
                                <th style="padding:8px 12px; text-align:left; font-weight:700; color:#94a3b8;">Controls</th>
                                <th style="padding:8px 12px; text-align:center; font-weight:700; color:#94a3b8;">Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${sessions.map(s => `
                                <tr style="border-bottom:1px solid rgba(148,163,184,0.08);">
                                    <td style="padding:9px 12px; font-weight:600; color:#60a5fa;">${s.auditor || 'SYSTEM'}</td>
                                    <td style="padding:9px 12px; color:#94a3b8;">${s.files} Files / ${s.file_mb} MB</td>
                                    <td style="padding:9px 12px; color:#a5b4fc; font-weight:700;">${(s.tokens||0).toLocaleString()} Tokens</td>
                                    <td style="padding:9px 12px; color:#fbbf24;">${s.latency_str || '0m 0s'}</td>
                                    <td style="padding:9px 12px; color:#94a3b8;">${s.controls}</td>
                                    <td style="padding:9px 12px; text-align:center;">
                                        ${s.status === 'running'
                                            ? '<span style="color:#38bdf8; font-size:1rem;">🔄</span>'
                                            : s.status === 'done'
                                                ? '<span style="color:#22c55e; font-size:1rem;">✅</span>'
                                                : '<span style="color:#ef4444; font-size:1rem;">❌</span>'}
                                    </td>
                                </tr>`).join('')}
                        </tbody>
                    </table>` : `
                    <div style="padding:20px; text-align:center; color:#475569; font-size:0.8rem;">
                        No active audit sessions right now. Start an audit to see live metrics.
                    </div>`}
            </div>`;
    } catch (err) {
        // Silently fail — Redis may be starting up
    }
}

function _kpiCard(label, value, color, icon) {
    return `
        <div style="background:rgba(15,23,42,0.6); border:1px solid rgba(148,163,184,0.15); border-radius:10px; padding:12px;">
            <div style="font-size:0.7rem; color:#94a3b8; margin-bottom:4px;">${label}</div>
            <div style="font-size:1.35rem; font-weight:800; color:${color}; display:flex; align-items:center; gap:6px;">
                ${value}
                <span style="font-size:1rem;">${icon}</span>
            </div>
        </div>`;
}

// Auto-hook: start polling when admin-logs tab is switched to
// and stop polling when navigating away.
// Integrates with the existing switchTab() in app.js.
if (typeof window !== 'undefined') {
    const _origSwitchTab = window.switchTab;
    window.switchTab = function(tabId) {
        if (typeof _origSwitchTab === 'function') _origSwitchTab(tabId);
        if (tabId === 'tab-admin-logs' || tabId === 'admin-logs') {
            startLiveMetricsPolling();
        } else {
            stopLiveMetricsPolling();
        }
    };

    document.addEventListener("DOMContentLoaded", () => {
        const adminTab = document.getElementById("tab-admin-logs");
        if (adminTab && (adminTab.classList.contains("active") || adminTab.style.display !== "none")) {
            startLiveMetricsPolling();
        } else if (document.getElementById("live-metrics-container")) {
            // Also start polling if container exists
            startLiveMetricsPolling();
        }
    });
}

