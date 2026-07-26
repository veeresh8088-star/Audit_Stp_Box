// ── GLOBAL STATE & UTILITY HELPERS ──
var API_BASE = window.location.origin + "/api";

var activeSessionId = localStorage.getItem("shakti_active_session") || null;
var currentUser = JSON.parse(localStorage.getItem("shakti_user") || "null");
var selectedRole = localStorage.getItem("shakti_role") || "auditor";
var selectedAnalysisMode = "Deep";
var selectedScopeControlIds = [];
var findingsList = [];

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function showToast(msg, type = "info") {
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.style.cssText = `
        position: fixed; bottom: 24px; right: 24px; z-index: 99999;
        background: ${type === 'error' ? '#ef4444' : (type === 'warning' ? '#f59e0b' : '#10b981')};
        color: #fff; padding: 12px 20px; border-radius: 10px; font-weight: 600;
        font-size: 0.88rem; box-shadow: 0 10px 25px rgba(0,0,0,0.3); transition: all 0.3s ease;
    `;
    toast.innerText = msg;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

function isFindingCompliant(f) {
    const s = (f.status || "").toUpperCase();
    return s === "COMPLIANT" || s === "ACCEPTED" || s === "PASS" || s === "SUCCESS";
}
