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
