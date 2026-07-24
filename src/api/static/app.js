// ── AICyberAuditBox Client Application ──

const API_BASE = "http://127.0.0.1:8000/api";

let currentUser = null;
let selectedRole = "auditor";
let activeTab = "";
let activeSessionId = "";
let activeSessionTitle = "";
let findingsList = [];
let activeSeverityFilter = "";
let activeStatusFilter = "All";
let logsPage = 0;
let logsTotalPages = 1;
let customEvidenceMappings = null;
let customControlDocuments = null;

// --- EMOJIS & ICONS FOR FRAMEWORK CONTROLS ---
const DEFAULT_FRAMEWORK_CONTROLS = [
    { sl: 5, use_case: "5.1 Policies for information security", label: "5.1 Security Policies", category: "Organizational" },
    { sl: 6, use_case: "5.2 Information security roles and responsibilities", label: "5.2 Security Roles", category: "Organizational" },
    { sl: 8, use_case: "5.15 Access control", label: "5.15 Access Control", category: "Organizational" },
    { sl: 12, use_case: "5.16 Identity management", label: "5.16 Identity Management", category: "Organizational" },
    { sl: 15, use_case: "8.15.1 Access restriction", label: "8.15.1 Access Restriction", category: "Technical" },
    { sl: 22, use_case: "8.24 Use of cryptography", label: "8.24 Cryptography", category: "Technical" }
];

// --- INITIAL EVENT LISTENERS ---
document.addEventListener("DOMContentLoaded", () => {
    // Clock setup
    setInterval(updateHeaderClock, 30000);
    updateHeaderClock();
    
    // Default render tabs & framework controls on page load so they are never blank
    setupTabs(selectedRole || "auditor");
    loadFrameworkControls();
    
    // Auth selectors
    const loginForm = document.getElementById("login-form");
    if (loginForm) loginForm.addEventListener("submit", handleLoginSubmit);
    
    const otpForm = document.getElementById("otp-form");
    if (otpForm) otpForm.addEventListener("submit", handleOTPSubmit);
    
    // Setup File Upload drop zone
    setupFileDropZone();
    
    // Setup Custom Control form
    const createControlForm = document.getElementById("create-control-form");
    if (createControlForm) {
        createControlForm.addEventListener("submit", handleCreateControlSubmit);
    }
    
    // Setup Edit Finding Modal form
    const editForm = document.getElementById("edit-finding-form");
    if (editForm) editForm.addEventListener("submit", handleEditFindingSubmit);
});

function updateHeaderClock() {
    const timeLabel = document.getElementById("current-time-label");
    if (timeLabel) {
        const now = new Date();
        const options = { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' };
        timeLabel.innerText = now.toLocaleDateString('en-GB', options).replace(/,/g, '');
    }
}

// ── AUTHENTICATION CONTROLLERS ──

function selectRole(role) {
    selectedRole = role;
    
    // Update button visual styles
    document.querySelectorAll(".role-btn").forEach(btn => btn.classList.remove("active"));
    document.getElementById(`role-${role}-btn`).classList.add("active");
    
    // Update descriptions
    const descEl = document.getElementById("role-desc");
    if (role === "admin") {
        descEl.innerText = "SYSTEM ADMINISTRATOR • Full access to settings, analyses, and records";
    } else if (role === "auditor") {
        descEl.innerText = "COMPLIANCE AUDITOR • Upload compliance documents and run guided audits";
    } else {
        descEl.innerText = "AUDITEE • Upload audit evidence documents for the auditor to review";
    }
    
    // Hide register option for Admin (seeded default is login only)
    const toggleRow = document.getElementById("toggle-auth-row");
    if (role === "admin") {
        toggleRow.style.display = "none";
        resetAuthActionToLogin();
    } else {
        toggleRow.style.display = "flex";
    }
    showError("");
}

function resetAuthActionToLogin() {
    const submitBtn = document.getElementById("auth-submit-btn");
    const toggleActionBtn = document.getElementById("toggle-action-btn");
    const toggleLabel = document.getElementById("toggle-label");
    
    submitBtn.innerText = "Secure Sign In";
    toggleActionBtn.innerText = "Create Account";
    toggleLabel.innerText = "NEW USER?";
}

function toggleAuthAction() {
    const submitBtn = document.getElementById("auth-submit-btn");
    const toggleActionBtn = document.getElementById("toggle-action-btn");
    const toggleLabel = document.getElementById("toggle-label");
    
    if (submitBtn.innerText === "Secure Sign In") {
        submitBtn.innerText = "Create Secure Account";
        toggleActionBtn.innerText = "Back to Login";
        toggleLabel.innerText = "ALREADY REGISTERED?";
    } else {
        resetAuthActionToLogin();
    }
    showError("");
}

async function handleLoginSubmit(e) {
    e.preventDefault();
    showError("");
    
    const username = document.getElementById("username-input").value.trim();
    const password = document.getElementById("password-input").value;
    const submitBtn = document.getElementById("auth-submit-btn");
    
    const isRegister = submitBtn.innerText.includes("Create");
    
    try {
        if (isRegister) {
            // Register Action
            const response = await fetch(`${API_BASE}/auth/register`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password, role: selectedRole })
            });
            
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || "Registration failed.");
            
            // Show QR Setup
            document.getElementById("login-form").style.display = "none";
            document.getElementById("register-setup-form").style.display = "block";
            document.getElementById("register-qr-img").src = data.qr_code_base64;
            document.getElementById("register-qr-secret").innerText = data.totp_secret;
        } else {
            // Login Action
            const response = await fetch(`${API_BASE}/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || "Authentication failed.");
            
            // Switch to OTP verify
            document.getElementById("login-form").style.display = "none";
            document.getElementById("otp-form").style.display = "block";
            document.getElementById("otp-input").value = "";
            document.getElementById("otp-input").focus();
            
            // If admin, show the seeded OTP QR code
            if (data.username === "admin" && data.qr_code_base64) {
                document.getElementById("admin-qr-container").style.display = "block";
                document.getElementById("admin-qr-img").src = data.qr_code_base64;
                document.getElementById("admin-qr-secret").innerText = data.totp_secret_preview;
            } else {
                document.getElementById("admin-qr-container").style.display = "none";
            }
            
            // Stash user detail temporarily
            currentUser = { username: data.username, role: data.role };
        }
    } catch (err) {
        showError(err.message);
    }
}

async function handleOTPSubmit(e) {
    e.preventDefault();
    showError("");
    
    const otpCode = document.getElementById("otp-input").value.trim();
    if (!currentUser) return;
    
    try {
        const response = await fetch(`${API_BASE}/auth/verify-otp`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: currentUser.username, otp_code: otpCode })
        });
        
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Invalid code.");
        
        currentUser.token = data.token;
        
        // Login Successful
        document.getElementById("auth-overlay").classList.remove("active");
        document.getElementById("app-shell").style.display = "grid";
        
        initializeDashboard(currentUser);
    } catch (err) {
        showError(err.message);
    }
}

function resetOTPForm() {
    document.getElementById("otp-form").style.display = "none";
    document.getElementById("login-form").style.display = "block";
    showError("");
}

function proceedToSignInAfterRegister() {
    document.getElementById("register-setup-form").style.display = "none";
    document.getElementById("login-form").style.display = "block";
    resetAuthActionToLogin();
    showError("");
}

function showError(msg) {
    const errorEl = document.getElementById("auth-error");
    if (msg) {
        errorEl.innerText = msg;
        errorEl.style.display = "block";
    } else {
        errorEl.style.display = "none";
    }
}

function logout() {
    currentUser = null;
    document.getElementById("app-shell").style.display = "none";
    document.getElementById("auth-overlay").classList.add("active");
    document.getElementById("login-form").style.display = "block";
    document.getElementById("otp-form").style.display = "none";
    document.getElementById("register-setup-form").style.display = "none";
    document.getElementById("username-input").value = "";
    document.getElementById("password-input").value = "";
    showError("");
}

// ── DASHBOARD INITIALIZATION ──

async function initializeDashboard(user) {
    // Set Profile Info
    document.getElementById("profile-name").innerText = user.username;
    document.getElementById("profile-role").innerText = user.role.toUpperCase();
    document.getElementById("profile-initials").innerText = user.username.slice(0,2).toUpperCase();
    
    // Role permissions toggle
    const isAdmin = user.role === "admin";
    const isAuditor = user.role === "auditor";
    
    // Hide/show sidebar panels (safe null-check in case some panels are absent)
    const setDisplay = (id, val) => { const el = document.getElementById(id); if (el) el.style.display = val; };
    setDisplay("sidebar-ai-setup", isAdmin ? "block" : "none");
    setDisplay("sidebar-framework-setup", (isAdmin || isAuditor) ? "block" : "none");
    setDisplay("sidebar-branding-setup", (isAdmin || isAuditor) ? "block" : "none");
    setDisplay("sidebar-mode-setup", (isAdmin || isAuditor) ? "block" : "none");
    setDisplay("sidebar-checklist-setup", (isAdmin || isAuditor) ? "block" : "none");
    setDisplay("sidebar-action-setup", (isAdmin || isAuditor) ? "block" : "none");
    
    // Setup Tabs Bar
    setupTabs(user.role);
    
    // Initialize standard checklist
    if (isAdmin || isAuditor) {
        loadFrameworkControls();
    }
    
    // Resolve Active Audit Session ID
    await loadOrCreateSession(user);
    
    // Load Chat History list
    if (user.role !== "auditee") {
        loadChatSessions();
    }
}

function setupTabs(role) {
    const tabsBar = document.getElementById("tabs-bar");
    if (!tabsBar) return;
    tabsBar.innerHTML = "";
    
    let tabs = [];
    if (role === "auditee") {
        tabs = [
            { id: "tab-upload-evidence", label: "Upload Evidence" },
            { id: "tab-submitted-reports", label: "Submitted" }
        ];
    } else if (role === "admin") {
        tabs = [
            { id: "tab-scan-workspace", label: "Scan workspace" },
            { id: "tab-audit-records", label: "Audit Records" },
            { id: "tab-audit-report", label: "Report" },
            { id: "tab-manage-controls", label: "Controls" },
            { id: "tab-admin-logs", label: "Admin Logs" }
        ];
    } else {
        // Auditor Role
        tabs = [
            { id: "tab-scan-workspace", label: "Scan workspace" },
            { id: "tab-audit-records", label: "Audit Records" },
            { id: "tab-auditee-docs", label: "Auditee docs" },
            { id: "tab-audit-report", label: "Report" },
            { id: "tab-submitted-reports", label: "Submitted" },
            { id: "tab-manage-controls", label: "Controls" }
        ];
    }
    
    tabs.forEach((tab, index) => {
        const btn = document.createElement("button");
        btn.className = `tab-link ${index === 0 ? 'active' : ''}`;
        btn.innerText = tab.label;
        btn.onclick = () => switchTab(tab.id, btn);
        tabsBar.appendChild(btn);
    });
    
    if (tabsBar.firstChild) {
        switchTab(tabs[0].id, tabsBar.firstChild);
    }
}

function switchTab(tabId, tabBtn) {
    activeTab = tabId;
    
    // Active tabs navigation state
    document.querySelectorAll(".tab-link").forEach(btn => btn.classList.remove("active"));
    if (tabBtn) tabBtn.classList.add("active");
    
    // Show active tab panel
    document.querySelectorAll(".tab-panel").forEach(panel => panel.classList.remove("active"));
    const targetPanel = document.getElementById(tabId);
    if (targetPanel) targetPanel.classList.add("active");
    
    // Update workspace title header based on active tab
    const wsTitle = document.getElementById("workspace-title");
    if (wsTitle) {
        if (tabId === "tab-scan-workspace") wsTitle.innerText = "Audit Scan Workspace";
        else if (tabId === "tab-audit-records") wsTitle.innerText = "Audit Records & Compliance Gaps Workspace";
        else if (tabId === "tab-auditee-docs") wsTitle.innerText = "Auditee Evidence Documents";
        else if (tabId === "tab-audit-report") wsTitle.innerText = "Audit Report & Delivery Center";
        else if (tabId === "tab-submitted-reports") wsTitle.innerText = "Submitted Audit Reports";
        else if (tabId === "tab-manage-controls") wsTitle.innerText = "Manage ISO 27001 / VAPT Framework Controls";
        else if (tabId === "tab-admin-logs") wsTitle.innerText = "System Event & Developer Logs";
    }

    // Perform tab-specific loading
    if (tabId === "tab-scan-workspace") {
        loadEvidenceFileList();
    } else if (tabId === "tab-audit-records") {
        loadFindings();
    } else if (tabId === "tab-admin-logs") {
        loadSystemEvents();
        loadDeveloperLogs();
    } else if (tabId === "tab-manage-controls") {
        loadCustomControlsTable();
    } else if (tabId === "tab-submitted-reports") {
        loadSubmittedReports();
    } else if (tabId === "tab-auditee-docs") {
        loadAuditeeSessionsList();
    } else if (tabId === "tab-ai-chat") {
        loadChatSessions();
    }
}

function toggleCollapsible(contentId) {
    const el = document.getElementById(contentId);
    if (!el) return;
    const parent = el.parentElement;
    if (parent) parent.classList.toggle("open");
    
    if (el.style.display === "none" || !el.style.display) {
        el.style.display = "block";
    } else {
        el.style.display = "none";
    }
}

// ── SESSION MANAGEMENT ──

async function loadOrCreateSession(user) {
    try {
        const response = await fetch(`${API_BASE}/audit/sessions?role=${user.role}&username=${user.username}`);
        const data = await response.json();
        
        if (data.success && data.sessions.length > 0) {
            // Re-use most recent draft session
            activeSessionId = data.sessions[0].session_id;
            activeSessionTitle = data.sessions[0].session_title;
        } else {
            // Create fresh session
            const body = new FormData();
            body.append("session_title", "ISO 27001 Local Compliance Audit");
            body.append("framework", "ISO 27001");
            body.append("username", user.username);
            
            const createRes = await fetch(`${API_BASE}/audit/sessions`, {
                method: "POST",
                body: body
            });
            const createData = await createRes.json();
            if (createData.success) {
                activeSessionId = createData.session_id;
                activeSessionTitle = createData.session_title;
            }
        }
        
        document.getElementById("active-session-badge").innerText = `Session ID: ${activeSessionId}`;
        document.getElementById("workspace-title").innerText = activeSessionTitle;
        
        // Refresh evidence files list
        loadEvidenceFileList();
        
        // Populate Target Auditee selector
        if (user.role !== "auditee") {
            populateAuditeeSelector();
        }
    } catch (err) {
        console.error("Session resolution error:", err);
    }
}

async function populateAuditeeSelector() {
    const select = document.getElementById("report-target-auditee");
    if (!select) return;
    select.innerHTML = "";
    
    try {
        // Quick list sessions associated with auditee role to choose
        const response = await fetch(`${API_BASE}/audit/sessions`);
        const data = await response.json();
        
        if (data.success) {
            data.sessions.forEach(s => {
                const opt = document.createElement("option");
                opt.value = s.id;
                opt.innerText = `${s.session_title} (${s.session_id.slice(0,6)})`;
                select.appendChild(opt);
            });
        }
    } catch (err) {
        console.error(err);
    }
}

// ── SIDEBAR FRAMEWORK CHECKLIST ──

// ── SIDEBAR FRAMEWORK CHECKLIST & SEGMENTED CONTROLS ──

function setAnalysisMode(mode) {
    const deepBtn = document.getElementById("btn-mode-deep");
    const quickBtn = document.getElementById("btn-mode-quick");
    const radioDeep = document.getElementById("radio-mode-deep");
    const radioQuick = document.getElementById("radio-mode-quick");

    if (mode === "Deep") {
        if (deepBtn) deepBtn.classList.add("active");
        if (quickBtn) quickBtn.classList.remove("active");
        if (radioDeep) radioDeep.checked = true;
    } else {
        if (quickBtn) quickBtn.classList.add("active");
        if (deepBtn) deepBtn.classList.remove("active");
        if (radioQuick) radioQuick.checked = true;
    }
}

function setScopingMode(mode) {
    const aiBtn = document.getElementById("btn-scoping-ai");
    const chkBtn = document.getElementById("btn-scoping-checklist");
    const radioAi = document.getElementById("radio-scoping-ai");
    const radioChk = document.getElementById("radio-scoping-chk");
    const checklistBox = document.getElementById("sidebar-checklist-setup");
    const fileContainer = document.getElementById("scoping-file-container");

    if (mode.includes("AI")) {
        if (aiBtn) aiBtn.classList.add("active");
        if (chkBtn) chkBtn.classList.remove("active");
        if (radioAi) radioAi.checked = true;
        if (checklistBox) checklistBox.style.display = "none";
        if (fileContainer) fileContainer.style.display = "none";
    } else {
        if (chkBtn) chkBtn.classList.add("active");
        if (aiBtn) aiBtn.classList.remove("active");
        if (radioChk) radioChk.checked = true;
        if (checklistBox) checklistBox.style.display = "block";
        if (fileContainer) fileContainer.style.display = "block";
    }
}

function toggleScopeChecklistModal() {
    const checklistBox = document.getElementById("sidebar-checklist-setup");
    if (!checklistBox) return;
    if (checklistBox.style.display === "none" || !checklistBox.style.display) {
        setScopingMode("Audit Scope Checklist");
    } else {
        checklistBox.style.display = "none";
    }
}

function toggleClauseAccordion(contentId, headerEl) {
    const body = document.getElementById(contentId);
    if (!body) return;
    const arrow = headerEl.querySelector(".clause-arrow");
    if (body.style.display === "none") {
        body.style.display = "block";
        if (arrow) arrow.innerText = "v";
    } else {
        body.style.display = "none";
        if (arrow) arrow.innerText = "›";
    }
}

async function loadFrameworkControls() {
    const select = document.getElementById("framework-select");
    const container = document.getElementById("controls-checkbox-container");
    if (!container) return;
    container.innerHTML = "<div style='font-size:11px;color:var(--text-muted);padding:8px;'>Loading controls checklist...</div>";
    
    try {
        const response = await fetch(`${API_BASE}/controls/framework`);
        const data = await response.json();
        
        let controlsToRender = DEFAULT_FRAMEWORK_CONTROLS;
        if (data.success && data.controls && data.controls.length > 0) {
            controlsToRender = data.controls;
        }
        
        container.innerHTML = "";
        const selectedStd = select ? select.value : "All Standards";
        
        const filtered = controlsToRender.filter(c => {
            if (selectedStd === "All Standards") return true;
            const isVapt = (c.category || "").toUpperCase().includes("VAPT") || (c.use_case || "").toUpperCase().includes("VAPT");
            if (selectedStd === "ISO 27001") return !isVapt;
            return isVapt;
        });

        // Group into 5 Clause Categories matching Streamlit UI
        const clauseMap = {
            "Clause 5 — Organizational Controls": [],
            "Clause 6 — People Controls": [],
            "Clause 7 — Physical Controls": [],
            "Clause 8 — Technological Controls": [],
            "VAPT Framework Controls": []
        };

        filtered.forEach(c => {
            const cid = (c.control_id || c.sl || "").toString();
            const cat = (c.category || "").toUpperCase();
            
            if (cid.startsWith("5.") || cat.includes("ORGANIZATIONAL")) {
                clauseMap["Clause 5 — Organizational Controls"].push(c);
            } else if (cid.startsWith("6.") || cat.includes("PEOPLE")) {
                clauseMap["Clause 6 — People Controls"].push(c);
            } else if (cid.startsWith("7.") || cat.includes("PHYSICAL")) {
                clauseMap["Clause 7 — Physical Controls"].push(c);
            } else if (cid.startsWith("8.") || cat.includes("TECH") || cat.includes("IT SECURITY")) {
                clauseMap["Clause 8 — Technological Controls"].push(c);
            } else {
                clauseMap["VAPT Framework Controls"].push(c);
            }
        });

        // Render each Clause Accordion
        Object.keys(clauseMap).forEach((clauseTitle, idx) => {
            const controls = clauseMap[clauseTitle];
            if (controls.length === 0) return;

            const accordionCard = document.createElement("div");
            accordionCard.className = "clause-accordion-card";
            accordionCard.style.cssText = "margin-bottom: 8px; border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 10px; background: rgba(30, 41, 59, 0.6); overflow: hidden;";

            const contentId = `clause_body_${idx}`;
            
            const header = document.createElement("div");
            header.className = "clause-header";
            header.style.cssText = "padding: 10px 12px; background: rgba(30, 41, 59, 0.8); font-size: 0.82rem; font-weight: 700; color: #f1f5f9; display: flex; align-items: center; justify-content: space-between; cursor: pointer; user-select: none;";
            header.onclick = () => toggleClauseAccordion(contentId, header);
            header.innerHTML = `
                <div style="display: flex; align-items: center; gap: 8px; min-width: 0; flex: 1;">
                    <span class="clause-arrow" style="color: #60a5fa; font-weight: 700; font-size: 0.85rem; width: 14px; text-align: center;">›</span>
                    <span style="font-weight: 700; color: #f1f5f9; font-size: 0.8rem; text-transform: none; white-space: normal; line-height: 1.2;">${clauseTitle}</span>
                </div>
                <span class="clause-count-badge" style="font-size: 0.7rem; color: #60a5fa; font-weight: 700; background: rgba(37, 99, 235, 0.2); padding: 2px 6px; border-radius: 6px; border: 1px solid rgba(59, 130, 246, 0.3); white-space: nowrap; margin-left: 6px;">[All]</span>
            `;

            const body = document.createElement("div");
            body.id = contentId;
            body.className = "clause-body";
            body.style.cssText = "display: none; padding: 10px 12px 12px 12px; border-top: 1px solid rgba(148, 163, 184, 0.15); background: rgba(15, 23, 42, 0.6); max-height: 280px; overflow-y: auto; scrollbar-width: thin;";

            controls.forEach(c => {
                const itemDiv = document.createElement("div");
                itemDiv.className = "checkbox-item ctrl-checkbox-item";
                itemDiv.style.cssText = "display: flex; align-items: flex-start; gap: 10px; padding: 6px 4px; border-radius: 6px;";

                const input = document.createElement("input");
                input.type = "checkbox";
                input.value = c.sl;
                input.id = `ctrl_chk_${c.sl}`;
                input.checked = true;
                input.style.cssText = "width: 16px; height: 16px; min-width: 16px; margin-top: 2px; cursor: pointer;";
                input.onchange = updateSelectedScopeCount;

                const label = document.createElement("label");
                label.htmlFor = `ctrl_chk_${c.sl}`;
                label.style.cssText = "cursor: pointer; font-size: 0.78rem; color: #cbd5e1; font-weight: 500; text-transform: none; white-space: normal; word-break: break-word; line-height: 1.35; margin: 0; max-width: none;";
                
                const ctrlId = c.control_id || c.sl;
                const ctrlName = c.label || c.control_name || "";
                label.innerText = `${ctrlName} (${ctrlId})`;
                label.title = `${ctrlId}: ${ctrlName}`;

                itemDiv.appendChild(input);
                itemDiv.appendChild(label);
                body.appendChild(itemDiv);
            });

            accordionCard.appendChild(header);
            accordionCard.appendChild(body);
            container.appendChild(accordionCard);
        });

        updateSelectedScopeCount();
    } catch (err) {
        container.innerHTML = `<div style='font-size:11px;color:var(--error);padding:8px;'>Loaded fallback controls.</div>`;
    }
}

function updateSelectedScopeCount() {
    const checkboxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
    const selected = Array.from(checkboxes).filter(cb => cb.checked);
    
    const countBadge = document.getElementById("sidebar-scope-count-badge");
    if (countBadge) countBadge.innerText = `${selected.length}/${checkboxes.length} · Edit`;

    const totalBadge = document.getElementById("total-scope-badge");
    if (totalBadge) totalBadge.innerText = `${selected.length} / ${checkboxes.length} selected`;
}

function selectAllCheckboxes(checked) {
    const checkboxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
    checkboxes.forEach(cb => cb.checked = checked);
    updateSelectedScopeCount();
}

function filterCheckboxList() {
    const input = document.getElementById("controls-search-input");
    if (!input) return;
    const query = input.value.toLowerCase().trim();
    
    const accordions = document.querySelectorAll(".clause-accordion-card");
    accordions.forEach(acc => {
        let hasMatch = false;
        const items = acc.querySelectorAll(".ctrl-checkbox-item");
        items.forEach(item => {
            const text = item.innerText.toLowerCase();
            if (!query || text.includes(query)) {
                item.style.display = "flex";
                hasMatch = true;
            } else {
                item.style.display = "none";
            }
        });
        
        if (query) {
            acc.style.display = hasMatch ? "block" : "none";
            const body = acc.querySelector(".clause-body");
            if (body && hasMatch) body.style.display = "block";
        } else {
            acc.style.display = "block";
        }
    });
}

async function handleExcelScopeUpload(e) {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    const file = files[0];
    
    const badge = document.getElementById("scoping-file-name");
    if (badge) {
        badge.innerText = `📄 ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        badge.style.display = "block";
    }

    const formData = new FormData();
    formData.append("file", file);
    
    try {
        const response = await fetch(`${API_BASE}/controls/parse-scope-excel`, {
            method: "POST",
            body: formData
        });
        
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Failed to parse Excel file.");
        
        customEvidenceMappings = data.custom_evidence || null;
        customControlDocuments = data.custom_documents || null;
        const matchedSls = new Set(data.matched_sls || []);
        
        // Auto-check mapped controls in checklist, uncheck unmapped
        const checkboxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
        checkboxes.forEach(cb => {
            const slNum = parseInt(cb.value);
            cb.checked = matchedSls.has(slNum);
        });
        
        updateSelectedScopeCount();
        alert(`✅ ${data.message || 'Loaded checklist items successfully!'}`);
    } catch (err) {
        alert(`❌ Error parsing Excel: ${err.message}`);
    }
}

function filterCheckboxList() {
    const q = document.getElementById("controls-search-input").value.toLowerCase();
    const rows = document.querySelectorAll("#controls-checkbox-container .checkbox-item");
    rows.forEach(row => {
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(q) ? "flex" : "none";
    });
}

function selectAllCheckboxes(checked) {
    const rows = document.querySelectorAll("#controls-checkbox-container .checkbox-item");
    rows.forEach(row => {
        if (row.style.display !== "none") {
            const cb = row.querySelector("input[type='checkbox']");
            if (cb) cb.checked = checked;
        }
    });
    updateSelectedScopeCount();
}

// ── EVIDENCE FILE UPLOAD ──

function setupFileDropZone() {
    const dropZone = document.getElementById("drop-zone");
    if (!dropZone) return;
    
    dropZone.addEventListener("dragover", e => {
        e.preventDefault();
        dropZone.style.borderColor = "var(--primary)";
    });
    
    dropZone.addEventListener("dragleave", () => {
        dropZone.style.borderColor = "rgba(148, 163, 184, 0.25)";
    });
    
    dropZone.addEventListener("drop", e => {
        e.preventDefault();
        dropZone.style.borderColor = "rgba(148, 163, 184, 0.25)";
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            uploadFiles(files);
        }
    });
}

function handleEvidenceUpload(e) {
    const files = e.target.files;
    if (files.length > 0) {
        uploadFiles(files);
    }
}

async function uploadFiles(files) {
    const progressContainer = document.getElementById("upload-progress-container");
    const progressBar = document.getElementById("upload-progress-bar");
    const progressText = document.getElementById("upload-progress-text");
    
    if (progressContainer) progressContainer.style.display = "block";
    if (progressBar) progressBar.style.width = "0%";
    
    if (!activeSessionId && currentUser) {
        await loadOrCreateSession(currentUser);
    }
    
    if (!activeSessionId) {
        if (progressText) progressText.innerText = "❌ Error: Active session missing. Please start a session first.";
        alert("⚠️ Active session missing. Please create or select an audit session first.");
        return;
    }
    
    const isAuditor = currentUser ? currentUser.role !== "auditee" : true;
    const body = new FormData();
    body.append("session_id", activeSessionId);
    body.append("is_auditor_uploaded", isAuditor ? "true" : "false");
    
    for (let i = 0; i < files.length; i++) {
        body.append("files", files[i]);
    }
    
    try {
        if (progressText) progressText.innerText = "Processing RAG security check & text extraction...";
        if (progressBar) progressBar.style.width = "50%";
        
        const response = await fetch(`${API_BASE}/audit/upload`, {
            method: "POST",
            body: body
        });
        
        const data = await response.json();
        if (!response.ok) throw new Error(formatApiError(data.detail, "Upload failed."));
        
        if (progressBar) progressBar.style.width = "100%";
        if (progressText) progressText.innerText = `Successfully processed ${files.length} evidence file(s)!`;
        
        setTimeout(() => {
            if (progressContainer) progressContainer.style.display = "none";
        }, 3000);
        
        loadEvidenceFileList();
    } catch (err) {
        if (progressText) progressText.innerText = `❌ Error: ${err.message}`;
        alert(`❌ Upload Error: ${err.message}`);
    }
}

async function loadEvidenceFileList() {
    const registries = document.querySelectorAll("#uploaded-files-registry, #auditee-files-registry");
    const countBadge = document.getElementById("evidence-count-badge");
    if (!registries || registries.length === 0) return;
    
    if (!activeSessionId && currentUser) {
        await loadOrCreateSession(currentUser);
    }
    
    if (!activeSessionId) return;

    try {
        const response = await fetch(`${API_BASE}/audit/evidence?session_id=${activeSessionId}`);
        const data = await response.json();
        
        const files = (data.success && data.files) ? data.files : [];
        if (countBadge) countBadge.innerText = `${files.length} files`;
        
        registries.forEach(registry => {
            registry.innerHTML = "";
            if (files.length === 0) {
                registry.innerHTML = `<div class="empty-state">No files uploaded yet. Drag files to begin audit.</div>`;
            } else {
                files.forEach(f => {
                    const fn = f.filename;
                    const ext = fn.split('.').pop().toLowerCase();
                    let fileClass = "file-type-xml";
                    let fileIconText = "XML";
                    
                    if (ext === "pdf") { fileClass = "file-type-pdf"; fileIconText = "PDF"; }
                    else if (["doc", "docx"].includes(ext)) { fileClass = "file-type-doc"; fileIconText = "DOC"; }
                    else if (["xls", "xlsx", "csv"].includes(ext)) { fileClass = "file-type-xls"; fileIconText = "XLS"; }
                    
                    const card = document.createElement("div");
                    card.className = "modern-file-card";
                    card.innerHTML = `
                        <div class="file-icon-badge ${fileClass}">${fileIconText}</div>
                        <div class="file-details">
                            <span class="file-title" title="${fn}">${fn}</span>
                            <span class="file-meta">${f.size_str || 'Ready'}</span>
                        </div>
                    `;
                    registry.appendChild(card);
                });
            }
        });
    } catch (err) {
        console.error("Error loading evidence file list:", err);
    }
}

// ── RUN LOCAL AUDIT ANALYSIS ──

let progressInterval = null;

async function triggerAuditAnalysis() {
    const btn = document.getElementById("run-analysis-btn");
    const stopBtn = document.getElementById("stop-analysis-btn");
    btn.disabled = true;
    btn.innerText = "⏳ Running Scan (0%)...";
    if (stopBtn) stopBtn.style.display = "block";
    
    const checkboxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
    const selectedSls = Array.from(checkboxes).filter(cb => cb.checked).map(cb => parseInt(cb.value));
    
    if (selectedSls.length === 0) {
        alert("⚠️ Please select at least one control to analyze.");
        btn.disabled = false;
        btn.innerText = "▶ Run RAG Scan";
        if (stopBtn) stopBtn.style.display = "none";
        return;
    }
    
    const frameworkSelect = document.getElementById("framework-select");
    const isVaptFramework = frameworkSelect ? frameworkSelect.value.toUpperCase().includes("VAPT") : false;
    const model = document.getElementById("llm-model-select").value;
    const mode = isVaptFramework ? "VAPT validation" : document.querySelector("input[name='audit-mode']:checked").value;
    
    try {
        const response = await fetch(`${API_BASE}/audit/start`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: activeSessionId,
                selected_sls: selectedSls,
                model_choice: model,
                audit_mode: mode,
                custom_evidence: customEvidenceMappings,
                custom_documents: customControlDocuments
            })
        });
        
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Failed to trigger scan.");
        
        // Start high-frequency progress polling (every 1 second)
        if (progressInterval) clearInterval(progressInterval);
        progressInterval = setInterval(pollAuditProgress, 1000);
    } catch (err) {
        btn.disabled = false;
        btn.innerText = "▶ Run RAG Scan";
        if (stopBtn) stopBtn.style.display = "none";
        alert(`Failed to start scan: ${err.message}`);
    }
}

async function pollAuditProgress() {
    const btn = document.getElementById("run-analysis-btn");
    const stopBtn = document.getElementById("stop-analysis-btn");
    const progressBar = document.getElementById("pipeline-progress-fill");
    const progressPercent = document.getElementById("pipeline-progress-percent");
    const progressStatus = document.getElementById("pipeline-status-text");

    try {
        const response = await fetch(`${API_BASE}/audit/status/${activeSessionId}`);
        const data = await response.json();
        
        if (data.status === "running") {
            const p = data.progress || {};
            const pct = typeof p.percent === "number" ? Math.min(100, Math.max(0, p.percent)) : 0;
            const txt = p.text || 'Scanning...';
            
            if (txt && (txt.includes("Scanning") || txt.includes("evaluating"))) {
                btn.innerText = `⏳ ${pct}% • ${txt}`;
            } else {
                btn.innerText = `⏳ Running Scan (${pct}%)...`;
            }
            
            if (progressBar) progressBar.style.width = `${pct}%`;
            if (progressPercent) progressPercent.innerText = `${pct}%`;
            if (progressStatus) progressStatus.innerText = `${txt} (${pct}%)`;
        } else if (data.status === "completed") {
            clearInterval(progressInterval);
            btn.disabled = false;
            btn.innerText = "▶ Step 3: Run RAG Scan";
            if (stopBtn) stopBtn.style.display = "none";
            if (progressBar) progressBar.style.width = `100%`;
            if (progressPercent) progressPercent.innerText = `100%`;
            if (progressStatus) progressStatus.innerText = `Scan completed successfully`;
            
            // Auto-load audit records findings and switch to records view
            await loadFindings();
            
            // Switch to Audit Records tab if not already open
            if (typeof activeTab !== "undefined" && activeTab !== "tab-audit-records") {
                const recordsTabBtn = Array.from(document.querySelectorAll("#tabs-bar button")).find(b => b.innerText.includes("Records") || b.innerText.includes("Scan workspace"));
                if (recordsTabBtn) switchTab("tab-audit-records", recordsTabBtn);
            }
            
            alert("✅ Local audit RAG scan completed successfully! Review records below and click 'Save to Shakthi DB' to commit.");
        } else if (data.status === "idle" && data.checkpoint && data.checkpoint.status === "failed") {
            clearInterval(progressInterval);
            btn.disabled = false;
            btn.innerText = "▶ Step 3: Run RAG Scan";
            if (stopBtn) stopBtn.style.display = "none";
            if (progressStatus) progressStatus.innerText = `Scan failed`;
            alert("❌ Analysis failed. Verify Ollama or local llama-server is running.");
        } else if (data.status === "idle") {
            clearInterval(progressInterval);
            btn.disabled = false;
            btn.innerText = "▶ Step 3: Run RAG Scan";
            if (stopBtn) stopBtn.style.display = "none";
        }
    } catch (err) {
        console.error("Progress polling error:", err);
    }
}

async function stopAuditAnalysis() {
    const stopBtn = document.getElementById("stop-analysis-btn");
    const btn = document.getElementById("run-analysis-btn");
    if (!activeSessionId) return;
    stopBtn.disabled = true;
    stopBtn.innerText = "⏳ Stopping...";
    try {
        const res = await fetch(`${API_BASE}/audit/stop/${activeSessionId}`, { method: "POST" });
        const data = await res.json();
        if (data.success) {
            btn.innerText = "⏳ Stopping after current control...";
            showToast("⛔ Stop signal sent — scan will stop after the current control.", "warning");
        } else {
            alert(data.message || "No active scan to stop.");
            stopBtn.disabled = false;
            stopBtn.innerText = "⛔ Stop Analysis";
        }
    } catch (err) {
        alert(`Failed to stop scan: ${err.message}`);
        stopBtn.disabled = false;
        stopBtn.innerText = "⛔ Stop Analysis";
    }
}

// ── AUDIT FINDINGS FEED & CRUD ──

async function loadFindings() {
    if (!activeSessionId) return;
    const container = document.getElementById("findings-container");
    if (!container) return;
    container.innerHTML = `<div class="empty-state">Loading findings from Shakthi DB...</div>`;
    
    const userRole = currentUser ? currentUser.role : (selectedRole || "auditor");
    
    try {
        const response = await fetch(`${API_BASE}/audit/findings?session_id=${activeSessionId}&role=${userRole}`);
        const data = await response.json();
        
        const banner = document.getElementById("shakti-commit-banner");
        const bannerText = document.getElementById("shakti-banner-text");
        if (banner) {
            banner.style.display = "flex";
            if (data.success && data.findings && data.findings.length > 0) {
                findingsList = data.findings;
                renderFindingsList();
                calculateSeverityStats();

                if (data.session_title && data.session_title.includes("Finalized")) {
                    banner.style.background = "rgba(16, 185, 129, 0.12)";
                    banner.style.borderColor = "rgba(52, 211, 153, 0.35)";
                    if (bannerText) bannerText.innerHTML = `✅ <b>Committed to Shakthi DB:</b> ${data.findings.length} audit record(s) finalized and locked.`;
                } else {
                    banner.style.background = "rgba(245, 158, 11, 0.12)";
                    banner.style.borderColor = "rgba(245, 158, 11, 0.35)";
                    if (bannerText) bannerText.innerHTML = `⚠️ <b>Notice:</b> ${data.findings.length} finding(s) loaded. Review records below and click "Save to Shakthi DB" to commit.`;
                }
            } else {
                banner.style.background = "rgba(245, 158, 11, 0.12)";
                banner.style.borderColor = "rgba(245, 158, 11, 0.35)";
                if (bannerText) bannerText.innerHTML = `⚠️ <b>Notice:</b> No findings recorded yet. Go to <b>Scan workspace</b> tab, upload evidence, and click <b>"▶ Step 3: Run RAG Scan"</b>.`;
                container.innerHTML = `<div class="empty-state">No compliance gaps recorded for session ${activeSessionId.slice(0, 8) || 'draft'}. Switch to <b>Scan workspace</b> tab to upload evidence and run RAG scan!</div>`;
            }
        }
    } catch (err) {
        container.innerHTML = `<div class="error-msg">Failed to query findings: ${err.message}</div>`;
    }
}

async function commitSessionToShaktiDB() {
    if (!activeSessionId) return;
    try {
        const response = await fetch(`${API_BASE}/audit/findings/commit-session/${activeSessionId}`, {
            method: "PUT"
        });
        const data = await response.json();
        if (data.success) {
            alert(`✅ ${data.message}`);
            loadFindings();
        } else {
            alert(`Failed to commit: ${data.message || 'Unknown error'}`);
        }
    } catch (err) {
        alert(`Failed to commit findings to Shakthi DB: ${err.message}`);
    }
}

function calculateSeverityStats() {
    let p1 = 0, p2 = 0, p3 = 0, p4 = 0;
    let compliant = 0, nonCompliant = 0;
    findingsList.forEach(f => {
        const sev = (f.severity || "").toLowerCase();
        if (sev.includes("p1") || sev.includes("critical")) p1++;
        else if (sev.includes("p2") || sev.includes("high")) p2++;
        else if (sev.includes("p3") || sev.includes("medium")) p3++;
        else if (sev.includes("p4") || sev.includes("low")) p4++;

        const st = (f.status || "").toUpperCase();
        if ((st.includes("COMPLIANT") && !st.includes("NON") && !st.includes("NOT") && !st.includes("PARTIAL")) || st.includes("ACCEPTED")) {
            compliant++;
        } else {
            nonCompliant++;
        }
    });
    
    if (document.getElementById("count-p1")) document.getElementById("count-p1").innerText = p1;
    if (document.getElementById("count-p2")) document.getElementById("count-p2").innerText = p2;
    if (document.getElementById("count-p3")) document.getElementById("count-p3").innerText = p3;
    if (document.getElementById("count-p4")) document.getElementById("count-p4").innerText = p4;
    if (document.getElementById("count-compliant")) document.getElementById("count-compliant").innerText = compliant;
    if (document.getElementById("count-noncompliant")) document.getElementById("count-noncompliant").innerText = nonCompliant;
}

function toggleComplianceFilter(statusType) {
    const select = document.getElementById("status-filter");
    if (select) {
        select.value = statusType;
        renderFindingsList();
    }
}

function toggleSeverityFilter(sev) {
    if (activeSeverityFilter === sev) {
        activeSeverityFilter = ""; // Clear filter
        document.querySelectorAll(".sev-card").forEach(c => c.classList.remove("active"));
    } else {
        activeSeverityFilter = sev;
        document.querySelectorAll(".sev-card").forEach(c => c.classList.remove("active"));
        if (sev === "P1 Critical") document.querySelector(".sev-card.p1")?.classList.add("active");
        else if (sev === "P2 High") document.querySelector(".sev-card.p2")?.classList.add("active");
        else if (sev === "P3 Medium") document.querySelector(".sev-card.p3")?.classList.add("active");
        else if (sev === "P4 Low") document.querySelector(".sev-card.p4")?.classList.add("active");
    }
    renderFindingsList();
}

function renderFindingsList() {
    const container = document.getElementById("findings-container");
    if (!container) return;
    container.innerHTML = "";
    
    const filterStatusElement = document.getElementById("status-filter");
    const filterStatus = filterStatusElement ? filterStatusElement.value : "All";
    
    const filtered = findingsList.filter(f => {
        const st = (f.status || "").toUpperCase();
        const isCompliant = (st.includes("COMPLIANT") && !st.includes("NON") && !st.includes("NOT") && !st.includes("PARTIAL")) || st.includes("ACCEPTED");

        // Workflow status filter
        if (filterStatus === "Compliant" && !isCompliant) return false;
        if (filterStatus === "Non-Compliant" && isCompliant) return false;
        if (filterStatus === "Open" && isCompliant) return false;
        if (filterStatus === "Accepted" && f.status !== "Accepted" && !isCompliant) return false;
        if (filterStatus === "Rejected" && f.status !== "Rejected") return false;
        
        // Severity level filter
        if (activeSeverityFilter) {
            const f_sev = (f.severity || "").toLowerCase();
            const filter_sev = activeSeverityFilter.toLowerCase();
            if (!f_sev.includes(filter_sev.slice(0,2))) return false;
        }
        return true;
    });
    
    if (filtered.length === 0) {
        container.innerHTML = `<div class="empty-state">No matching findings found in this filter range.</div>`;
        return;
    }
    
    filtered.forEach(f => {
        const card = document.createElement("div");
        let sevClass = "p3";
        const f_sev = (f.severity || "").toLowerCase();
        if (f_sev.includes("p1") || f_sev.includes("critical")) sevClass = "p1";
        else if (f_sev.includes("p2") || f_sev.includes("high")) sevClass = "p2";
        else if (f_sev.includes("p4") || f_sev.includes("low")) sevClass = "p4";
        
        card.className = `finding-card ${sevClass}`;
        
        let statusBadgeClass = "non-compliant";
        const st = (f.status || "").toUpperCase();
        if ((st.includes("COMPLIANT") && !st.includes("NON") && !st.includes("NOT") && !st.includes("PARTIAL")) || st === "ACCEPTED") {
            statusBadgeClass = "compliant";
        } else if (st.includes("PARTIAL")) {
            statusBadgeClass = "partial";
        } else {
            statusBadgeClass = "non-compliant";
        }
        
        const ctrlTitle = (f.control_name && f.control_name !== "null") ? f.control_name : ((f.control && f.control !== "null") ? f.control : "");
        const displayTitle = ctrlTitle ? `${f.control_id} - ${ctrlTitle}` : f.control_id;
        const findingJsonStr = JSON.stringify(f).replace(/'/g, "&#39;").replace(/"/g, "&quot;");

        card.innerHTML = `
            <div class="finding-card-header">
                <div class="finding-card-title">
                    <h3>${displayTitle}</h3>
                </div>
                <div class="finding-badges">
                    <span class="badge-status ${statusBadgeClass}">${f.status}</span>
                    <span class="badge-pill">${f.severity || 'P3 Medium'}</span>
                </div>
            </div>
            
            <div class="finding-detail-row">
                <label>Finding Description</label>
                <p>${f.description || 'No detailed description logged.'}</p>
            </div>
            
            ${f.evidence_snippet ? `
            <div class="finding-detail-row">
                <label>Evidence Snippet</label>
                <pre class="finding-snippet">"${f.evidence_snippet}"</pre>
            </div>` : ''}

            <div class="finding-detail-row">
                <label>Lead Auditor Recommendations</label>
                <p style="color: #60a5fa;">${f.recommendation || 'No recommendation logged.'}</p>
            </div>

            <div class="finding-actions" style="display: flex; justify-content: space-between; align-items: center; margin-top: 14px; padding-top: 10px; border-top: 1px solid rgba(148, 163, 184, 0.15);">
                <div class="auditor-notes" style="font-size: 0.78rem; color: var(--text-muted);">
                    <span>Reasoning: <i>${f.reasoning || 'Semantic similarity evaluation.'}</i></span>
                </div>
                <div class="btn-card-group" style="display: flex; gap: 8px;">
                    <button class="btn-secondary" style="color: #10b981; font-weight: 700; border-color: rgba(16, 185, 129, 0.4);" onclick="updateFindingWorkflowStatus(${f.id}, 'Accepted')">✓ Accept</button>
                    <button class="btn-secondary" style="color: #3b82f6; font-weight: 700; border-color: rgba(59, 130, 246, 0.4);" onclick='openEditFindingModal(${findingJsonStr})'>✏️ Modify</button>
                    <button class="btn-danger" style="font-weight: 700;" onclick="updateFindingWorkflowStatus(${f.id}, 'Rejected')">✕ Reject</button>
                </div>
            </div>
        `;
        container.appendChild(card);
    });
}

async function updateFindingWorkflowStatus(id, status) {
    try {
        const response = await fetch(`${API_BASE}/audit/findings/${id}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status })
        });
        const data = await response.json();
        if (data.success) {
            // Hot reload local list
            const idx = findingsList.findIndex(f => f.id === id);
            if (idx !== -1) findingsList[idx].status = status;
            renderFindingsList();
            calculateSeverityStats();
        }
    } catch (err) {
        alert(err.message);
    }
}

// ── MODAL EDIT FINDING FORM ──

function openEditFindingModal(finding) {
    document.getElementById("edit-finding-id").value = finding.id;
    document.getElementById("edit-finding-status").value = finding.status;
    document.getElementById("edit-finding-policy").value = finding.policy_present || "No";
    document.getElementById("edit-finding-evidence").value = finding.evidence_present || "No";
    document.getElementById("edit-finding-severity").value = finding.severity || "P3 Medium";
    document.getElementById("edit-finding-desc").value = finding.description;
    document.getElementById("edit-finding-snippet").value = finding.evidence_snippet || "";
    document.getElementById("edit-finding-recommendation").value = finding.recommendation || "";
    document.getElementById("edit-finding-reasoning").value = finding.reasoning || "";
    
    document.getElementById("edit-finding-modal").classList.add("active");
}

function closeEditFindingModal() {
    document.getElementById("edit-finding-modal").classList.remove("active");
}

async function handleEditFindingSubmit(e) {
    e.preventDefault();
    const id = document.getElementById("edit-finding-id").value;
    
    const body = {
        status: document.getElementById("edit-finding-status").value,
        policy_present: document.getElementById("edit-finding-policy").value,
        evidence_present: document.getElementById("edit-finding-evidence").value,
        severity: document.getElementById("edit-finding-severity").value,
        description: document.getElementById("edit-finding-desc").value,
        evidence_snippet: document.getElementById("edit-finding-snippet").value,
        recommendation: document.getElementById("edit-finding-recommendation").value,
        reasoning: document.getElementById("edit-finding-reasoning").value
    };
    
    try {
        const response = await fetch(`${API_BASE}/audit/findings/${id}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });
        const data = await response.json();
        
        if (data.success) {
            closeEditFindingModal();
            loadFindings(); // Reload list
        }
    } catch (err) {
        alert(`Update failed: ${err.message}`);
    }
}

// ── AI ASSISTANT CHAT ENGINE ──

async function sendChatMessage() {
    const input = document.getElementById("chat-input");
    const msg = input.value.trim();
    if (!msg) return;
    
    input.value = "";
    
    const feed = document.getElementById("chat-feed-box");
    
    // Append User Message
    const userDiv = document.createElement("div");
    userDiv.className = "chat-bubble user";
    userDiv.innerHTML = `<p>${msg}</p>`;
    feed.appendChild(userDiv);
    feed.scrollTop = feed.scrollHeight;
    
    // Show Thinking indicator
    const indicator = document.getElementById("chat-generating-indicator");
    indicator.style.display = "block";
    
    const model = document.getElementById("llm-model-select").value;
    
    try {
        const response = await fetch(`${API_BASE}/audit/chats/send`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: activeSessionId,
                message: msg,
                model_choice: model,
                username: currentUser.username
            })
        });
        
        const data = await response.json();
        indicator.style.display = "none";
        
        if (data.success) {
            const aiDiv = document.createElement("div");
            aiDiv.className = "chat-bubble assistant";
            aiDiv.innerHTML = `<p>${data.response}</p>`;
            feed.appendChild(aiDiv);
            feed.scrollTop = feed.scrollHeight;
        } else {
            throw new Error(data.detail);
        }
    } catch (err) {
        indicator.style.display = "none";
        const errDiv = document.createElement("div");
        errDiv.className = "chat-bubble assistant error-msg";
        errDiv.innerHTML = `<p>Error: ${err.message}. Ollama server might be offline.</p>`;
        feed.appendChild(errDiv);
    }
}

// ── MANAGE CUSTOM CONTROLS Framework ──

async function loadCustomControlsTable() {
    const tbody = document.getElementById("custom-controls-table-body");
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;">Loading custom controls from ShaktiDB...</td></tr>`;
    
    try {
        const response = await fetch(`${API_BASE}/controls?active_only=false`);
        const data = await response.json();
        
        if (data.success && data.controls.length > 0) {
            tbody.innerHTML = "";
            data.controls.forEach(c => {
                const tr = document.createElement("tr");
                const kws = c.keywords.join(", ");
                tr.innerHTML = `
                    <td><b>${c.control_id}</b></td>
                    <td>${c.control_name}</td>
                    <td><span class="badge-pill">${c.category}</span></td>
                    <td><code style="color:#60a5fa;">${kws || 'None'}</code></td>
                    <td>
                        <button class="btn-danger" style="padding: 4px 8px; font-size:11px;" onclick="deleteCustomControl(${c.id})">Delete</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);">No custom controls registered. Create one on the left!</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--error);">Failed to load controls: ${err.message}</td></tr>`;
    }
}

async function handleCreateControlSubmit(e) {
    e.preventDefault();
    
    const body = {
        control_id: document.getElementById("new-ctrl-id").value.trim(),
        control_name: document.getElementById("new-ctrl-name").value.trim(),
        category: document.getElementById("new-ctrl-cat").value,
        keywords: document.getElementById("new-ctrl-kws").value.split(",").map(k => k.trim()).filter(k => k),
        description: document.getElementById("new-ctrl-desc").value.trim()
    };
    
    try {
        const response = await fetch(`${API_BASE}/controls`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });
        
        const data = await response.json();
        if (data.success) {
            // Reset form
            document.getElementById("create-control-form").reset();
            loadCustomControlsTable();
            loadFrameworkControls(); // Reload sidebar checklist
            alert("✅ Custom control saved successfully!");
        }
    } catch (err) {
        alert(err.message);
    }
}

async function autogenerateKeywords() {
    const name = document.getElementById("new-ctrl-name").value.trim();
    const desc = document.getElementById("new-ctrl-desc").value.trim();
    
    if (!name) {
        alert("⚠️ Please enter a Control Name first.");
        return;
    }
    
    const kwField = document.getElementById("new-ctrl-kws");
    kwField.placeholder = "🧠 AI is generating regex keywords...";
    
    try {
        const response = await fetch(`${API_BASE}/controls/autogen-keywords`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, description: desc })
        });
        const data = await response.json();
        if (data.success) {
            kwField.value = data.keywords.join(", ");
        }
    } catch (err) {
        kwField.placeholder = "Failed to auto-generate keywords.";
        alert(err.message);
    }
}

async function deleteCustomControl(id) {
    if (!confirm("Are you sure you want to deactivate and remove this custom control?")) return;
    try {
        const response = await fetch(`${API_BASE}/controls/${id}?soft=false`, {
            method: "DELETE"
        });
        const data = await response.json();
        if (data.success) {
            loadCustomControlsTable();
            loadFrameworkControls();
        }
    } catch (err) {
        alert(err.message);
    }
}

// ── ADMIN SYSTEM LOGS & CONSOLE ──

async function loadSystemEvents() {
    const tbody = document.getElementById("system-events-table-body");
    const indicator = document.getElementById("logs-page-indicator");
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;">Loading logs...</td></tr>`;
    
    const severity = document.getElementById("log-severity-filter").value;
    
    try {
        const response = await fetch(`${API_BASE}/logs/system?severity=${severity}&page=${logsPage}&page_size=15`);
        const data = await response.json();
        
        if (data.success && data.events.length > 0) {
            tbody.innerHTML = "";
            logsTotalPages = data.total_pages;
            indicator.innerText = `Page ${logsPage + 1} of ${logsTotalPages}`;
            
            data.events.forEach(e => {
                const tr = document.createElement("tr");
                let color = "#aaa";
                if (e.severity === "ERROR") color = "var(--error)";
                else if (e.severity === "WARNING") color = "var(--warning)";
                else if (e.severity === "CRITICAL") color = "#f43f5e";
                
                tr.innerHTML = `
                    <td style="color:#64748b; font-family:var(--font-mono);">${e.created_at.slice(0,19)}</td>
                    <td><b>${e.event_type}</b></td>
                    <td>${e.actor}</td>
                    <td><span style="color:${color}; font-weight:700;">${e.severity}</span></td>
                    <td style="color:#94a3b8; font-size:0.75rem;">${e.meta || '—'}</td>
                `;
                tbody.appendChild(tr);
            });
            
            // Toggle paginator buttons
            document.getElementById("logs-prev-btn").disabled = logsPage === 0;
            document.getElementById("logs-next-btn").disabled = logsPage >= logsTotalPages - 1;
        } else {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);">No matching log events recorded.</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--error);">Failed: ${err.message}</td></tr>`;
    }
}

function prevLogsPage() {
    if (logsPage > 0) {
        logsPage--;
        loadSystemEvents();
    }
}

function nextLogsPage() {
    if (logsPage < logsTotalPages - 1) {
        logsPage++;
        loadSystemEvents();
    }
}

async function purgeLogs() {
    if (!confirm("Are you sure you want to delete all log entries older than 90 days?")) return;
    try {
        const response = await fetch(`${API_BASE}/logs/purge?days=90`, { method: "POST" });
        const data = await response.json();
        if (data.success) {
            alert(data.message);
            logsPage = 0;
            loadSystemEvents();
        }
    } catch (err) {
        alert(err.message);
    }
}

async function loadDeveloperLogs() {
    const terminal = document.getElementById("developer-terminal");
    try {
        const response = await fetch(`${API_BASE}/logs/developer`);
        const data = await response.json();
        if (data.success) {
            terminal.value = data.logs || "No server latency logs recorded yet.";
            terminal.scrollTop = terminal.scrollHeight;
        }
    } catch (err) {
        terminal.value = `Failed to stream logs: ${err.message}`;
    }
}

async function clearDeveloperLogs() {
    if (!confirm("Clear developer latency log file?")) return;
    try {
        const response = await fetch(`${API_BASE}/logs/developer`, { method: "DELETE" });
        const data = await response.json();
        if (data.success) {
            loadDeveloperLogs();
        }
    } catch (err) {
        alert(err.message);
    }
}

// ── AUDIT REPORT & DELIVERY ──

async function exportFindingsCSV() {
    // Queries findings and generates CSV download on client side
    try {
        const response = await fetch(`${API_BASE}/audit/findings?session_id=${activeSessionId}&role=${currentUser.role}`);
        const data = await response.json();
        if (data.success && data.findings.length > 0) {
            let csv = "Control ID,Name,Severity,Status,Description,Recommendation,Reasoning,Files\n";
            data.findings.forEach(f => {
                // escape commas and quotes in CSV
                const desc = `"${(f.description || '').replace(/"/g, '""')}"`;
                const rec = `"${(f.recommendation || '').replace(/"/g, '""')}"`;
                const reason = `"${(f.reasoning || '').replace(/"/g, '""')}"`;
                csv += `${f.control_id},"${f.control_name}",${f.severity},${f.status},${desc},${rec},${reason},"${f.source_files}"\n`;
            });
            
            const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.setAttribute("download", `audit_report_${activeSessionId.slice(0,6)}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        } else {
            alert("No findings records to export. Try running a scan first.");
        }
    } catch (err) {
        alert(err.message);
    }
}

async function triggerDeleteAllRecords() {
    if (!currentUser || currentUser.role !== "admin") {
        alert("⚠️ Access Denied: Only system administrators can clear database records.");
        return;
    }
    
    if (!confirm("🚨 WARNING: Wiping all database records is irreversible and clears everything. Continue?")) return;
    
    try {
        const response = await fetch(`${API_BASE}/audit/clear-records`, {
            method: "DELETE"
        });
        const data = await response.json();
        if (data.success) {
            alert("✅ Entire database records successfully cleared!");
            location.reload();
        } else {
            alert(`Error: ${data.detail || "Wipe failed"}`);
        }
    } catch (err) {
        alert(err.message);
    }
}

async function loadAuditeeSessionsList() {
    const select = document.getElementById("auditee-session-selector");
    if (!select) return;
    select.innerHTML = `<option value="">Choose session...</option>`;
    
    try {
        const response = await fetch(`${API_BASE}/audit/sessions`);
        const data = await response.json();
        
        if (data.success) {
            data.sessions.forEach(s => {
                const opt = document.createElement("option");
                opt.value = s.session_id;
                opt.innerText = `${s.session_title} (${s.session_id.slice(0,6)})`;
                select.appendChild(opt);
            });
        }
    } catch (err) {
        console.error(err);
    }
}

async function loadAuditeeEvidenceDocs() {
    const selector = document.getElementById("auditee-session-selector");
    const container = document.getElementById("auditee-evidence-files-box");
    if (!selector || !container) return;
    
    const sessId = selector.value;
    if (!sessId) {
        container.innerHTML = `<div class="empty-state">Select an auditee session above to inspect evidence documents.</div>`;
        return;
    }
    
    container.innerHTML = `<div class="empty-state">Loading evidence documents...</div>`;
    
    try {
        const response = await fetch(`${API_BASE}/audit/evidence?session_id=${sessId}`);
        const data = await response.json();
        
        const files = (data.success && data.files) ? data.files : [];
        if (files.length === 0) {
            container.innerHTML = `<div class="empty-state">No uploaded evidence documents found for session ${sessId.slice(0, 8)}.</div>`;
            return;
        }
        
        container.innerHTML = "";
        files.forEach((f, idx) => {
            const fn = f.filename;
            const ext = fn.split('.').pop().toLowerCase();
            let fileClass = "file-type-xml";
            let fileIconText = "XML";
            
            if (ext === "pdf") { fileClass = "file-type-pdf"; fileIconText = "PDF"; }
            else if (["doc", "docx"].includes(ext)) { fileClass = "file-type-doc"; fileIconText = "DOC"; }
            else if (["xls", "xlsx", "csv"].includes(ext)) { fileClass = "file-type-xls"; fileIconText = "XLS"; }
            
            const card = document.createElement("div");
            card.className = "modern-file-card";
            card.style.cssText = "display: flex; align-items: center; gap: 12px; padding: 12px; background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 12px;";
            card.innerHTML = `
                <input type="checkbox" class="auditee-doc-checkbox" value="${fn}" id="auditee_doc_${idx}" checked style="width: 18px; height: 18px; cursor: pointer;">
                <div class="file-icon-badge ${fileClass}">${fileIconText}</div>
                <div class="file-details" style="flex: 1; min-width: 0;">
                    <label for="auditee_doc_${idx}" class="file-title" style="cursor: pointer; display: block; font-weight: 600; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;" title="${fn}">${fn}</label>
                    <span class="file-meta" style="font-size: 0.72rem; color: var(--text-muted);">${f.size_str || 'Submitted Evidence'}</span>
                </div>
                <span class="badge-pill" style="color:var(--success); border-color:rgba(34,197,94,0.3); font-size: 0.7rem;">SUBMITTED</span>
            `;
            container.appendChild(card);
        });
    } catch (err) {
        container.innerHTML = `<div class="error-msg">Error: ${err.message}</div>`;
    }
}

function selectAllAuditeeDocs(checked) {
    const checkboxes = document.querySelectorAll(".auditee-doc-checkbox");
    checkboxes.forEach(cb => cb.checked = checked);
}

async function runAnalysisOnSelectedAuditeeDocs() {
    const selector = document.getElementById("auditee-session-selector");
    if (!selector || !selector.value) {
        alert("⚠️ Please select an auditee session first.");
        return;
    }
    
    const checkedDocs = Array.from(document.querySelectorAll(".auditee-doc-checkbox:checked")).map(cb => cb.value);
    if (checkedDocs.length === 0) {
        alert("⚠️ Please select at least one document to analyze.");
        return;
    }
    
    // Set active session to target auditee session
    activeSessionId = selector.value;
    document.getElementById("active-session-badge").innerText = `Session ID: ${activeSessionId}`;
    
    // Refresh evidence files list in main workspace
    await loadEvidenceFileList();
    
    // Switch to Scan workspace tab
    const scanTabBtn = Array.from(document.querySelectorAll("#tabs-bar button")).find(b => b.innerText.includes("Scan workspace"));
    if (scanTabBtn) switchTab("tab-scan-workspace", scanTabBtn);
    
    // Trigger RAG Audit Scan
    alert(`🚀 Starting RAG analysis on ${checkedDocs.length} selected document(s) for session ${activeSessionId.slice(0, 8)}...`);
    triggerAuditAnalysis();
}

async function handleScopingUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const fileBadge = document.getElementById("scoping-file-name");
    fileBadge.innerText = "Parsing excel checklist...";
    fileBadge.style.display = "block";
    
    const body = new FormData();
    body.append("file", file);
    
    try {
        const response = await fetch(`${API_BASE}/audit/upload-scope-excel`, {
            method: "POST",
            body: body
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Failed to parse checklist.");
        
        fileBadge.innerText = `Checked: ${file.name}`;
        
        // Save mappings globally
        customEvidenceMappings = data.custom_evidence;
        customControlDocuments = data.custom_documents;
        
        // Auto select matched checkboxes in UI checklist
        const matchedSet = new Set(data.matched_sls);
        const checkboxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
        checkboxes.forEach(cb => {
            cb.checked = matchedSet.has(parseInt(cb.value));
        });
        
        updateSelectedScopeCount();
        alert(`✅ Loaded checklist items across ${data.matched_sls.length} unique standard controls!`);
    } catch (err) {
        fileBadge.innerText = "Error parsing file";
        alert(`Scoping Error: ${err.message}`);
    }
}

function formatApiError(detail, fallbackMsg = "Operation failed.") {
    if (!detail) return fallbackMsg;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
        return detail.map(d => (typeof d === "string" ? d : (d.msg || JSON.stringify(d)))).join("; ");
    }
    if (typeof detail === "object") {
        return detail.message || detail.msg || JSON.stringify(detail);
    }
    return String(detail);
}

async function handleSidebarUpload(event) {
    const files = event.target.files;
    if (!files || files.length === 0) return;
    
    const statusDiv = document.getElementById("sidebar-upload-status");
    if (statusDiv) statusDiv.innerText = "⏳ Uploading files...";
    
    // Ensure active session is loaded
    if (!activeSessionId && currentUser) {
        await loadOrCreateSession(currentUser);
    }
    
    if (!activeSessionId) {
        if (statusDiv) statusDiv.innerText = "❌ Error: Active session missing. Please start a session first.";
        alert("⚠️ Active session missing. Please create or select an audit session first.");
        return;
    }
    
    const body = new FormData();
    body.append("session_id", activeSessionId);
    body.append("is_auditor_uploaded", "true");
    
    for (let i = 0; i < files.length; i++) {
        body.append("files", files[i]);
    }
    
    try {
        const response = await fetch(`${API_BASE}/audit/upload`, {
            method: "POST",
            body: body
        });
        const data = await response.json();
        if (!response.ok) throw new Error(formatApiError(data.detail, "Upload failed."));
        
        if (statusDiv) statusDiv.innerText = `Successfully uploaded ${files.length} file(s)!`;
        loadEvidenceFileList();
        setTimeout(() => { if (statusDiv) statusDiv.innerText = ""; }, 4000);
    } catch (err) {
        if (statusDiv) statusDiv.innerText = `❌ Error: ${err.message}`;
    }
}

async function deliverReportToAuditee() {
    const select = document.getElementById("report-target-auditee");
    if (!select) return;
    const auditeeId = select.value;
    if (!auditeeId) {
        alert("⚠️ Please select a target auditee account first.");
        return;
    }
    
    if (!confirm("Are you sure you want to finalize and send these audit findings to the auditee?")) return;
    
    const body = new FormData();
    body.append("session_id", activeSessionId);
    body.append("auditee_id", auditeeId);
    body.append("username", currentUser ? currentUser.username : "auditor@24");
    
    try {
        const response = await fetch(`${API_BASE}/audit/deliver`, {
            method: "POST",
            body: body
        });
        const data = await response.json();
        if (data.success) {
            alert("✅ Report successfully published and recorded in the Submitted tab!");
            
            // Switch to Submitted Reports tab and refresh list
            const submittedTabBtn = Array.from(document.querySelectorAll("#tabs-bar button")).find(b => b.innerText.includes("Submitted"));
            if (submittedTabBtn) switchTab("tab-submitted-reports", submittedTabBtn);
            else loadSubmittedReports();
        } else {
            alert(`Error: ${data.detail || "Delivery failed"}`);
        }
    } catch (err) {
        alert(err.message);
    }
}

async function loadSubmittedReports() {
    const container = document.getElementById("submitted-reports-container");
    if (!container) return;
    container.innerHTML = `<div class="empty-state">Loading submitted reports from Shakthi DB...</div>`;
    
    try {
        let url = `${API_BASE}/audit/sessions`;
        if (currentUser && currentUser.role === "auditee") {
            url += `?role=auditee&username=${currentUser.username}`;
        }
        
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.success && data.sessions.length > 0) {
            container.innerHTML = "";
            const seen = new Set();
            const reports = data.sessions.filter(s => {
                if (!s.session_id || seen.has(s.session_id)) return false;
                
                const title = (s.session_title || "").toLowerCase();
                const st = (s.status || "Draft").toLowerCase();
                
                // Exclude chat sessions and error logs
                if (title.includes("chat") || title.includes("error")) return false;
                
                // For auditee, only show sent/delivered/completed reports
                if (currentUser && currentUser.role === "auditee") {
                    return st.includes("sent") || st.includes("deliver") || st.includes("complet") || st.includes("submit");
                }
                
                // For auditor/admin, show non-draft submitted/delivered or finalized reports
                const isSubmitted = st.includes("sent") || st.includes("deliver") || st.includes("complet") || st.includes("submit") || st.includes("pending") || title.includes("finalized");
                if (isSubmitted) {
                    seen.add(s.session_id);
                    return true;
                }
                return false;
            });
            
            if (reports.length === 0) {
                container.innerHTML = `<div class="empty-state">No submitted audit reports available yet. Publish a report from the <b>Report</b> tab to view it here.</div>`;
                return;
            }
            
            reports.forEach(r => {
                const card = document.createElement("div");
                card.className = "report-card";
                card.style.cssText = "background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 12px; padding: 16px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;";
                
                let badgeColor = "var(--text-muted)";
                let badgeBorder = "rgba(148, 163, 184, 0.2)";
                const statusStr = (r.status || "Submitted").toUpperCase();
                if (statusStr.includes("SENT") || statusStr.includes("DELIVER") || statusStr.includes("COMPLET")) {
                    badgeColor = "#10b981";
                    badgeBorder = "rgba(16, 185, 129, 0.4)";
                } else if (statusStr.includes("PENDING") || statusStr.includes("REVIEW")) {
                    badgeColor = "#f59e0b";
                    badgeBorder = "rgba(245, 158, 11, 0.4)";
                }
                
                card.innerHTML = `
                    <div>
                        <h4 style="margin: 0 0 6px 0; color: var(--text-main); font-size: 1.05rem; font-weight: 700;">${r.session_title}</h4>
                        <div style="font-size: 0.8rem; color: var(--text-muted); display: flex; gap: 16px; align-items: center;">
                            <span>Standard: <b style="color: #60a5fa;">${r.framework || 'ISO 27001'}</b></span>
                            <span>Date: <b>${(r.created_at || '').slice(0, 10) || 'Recent'}</b></span>
                            <span>Compliance Score: <b style="color: #10b981;">${r.score_percent || 0}%</b></span>
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span class="badge-pill" style="color: ${badgeColor}; border-color: ${badgeBorder}; font-weight: 700;">${statusStr}</span>
                        <button class="btn-secondary" style="padding: 6px 14px; font-size: 0.78rem;" onclick="exportReportCSV('${r.session_id}')">📥 Export CSV</button>
                    </div>
                `;
                container.appendChild(card);
            });
        } else {
            container.innerHTML = `<div class="empty-state">No submitted audit reports available yet. Publish a report from the <b>Report</b> tab to view it here.</div>`;
        }
    } catch (err) {
        container.innerHTML = `<div class="error-msg">Error loading submitted reports: ${err.message}</div>`;
    }
}

async function exportReportCSV(sessId) {
    try {
        const response = await fetch(`${API_BASE}/audit/findings?session_id=${sessId}`);
        const data = await response.json();
        if (data.success && data.findings.length > 0) {
            let csv = "Control ID,Name,Severity,Status,Description,Recommendation,Reasoning,Files\n";
            data.findings.forEach(f => {
                const desc = `"${(f.description || '').replace(/"/g, '""')}"`;
                const rec = `"${(f.recommendation || '').replace(/"/g, '""')}"`;
                const reason = `"${(f.reasoning || '').replace(/"/g, '""')}"`;
                csv += `${f.control_id},"${f.control_name}",${f.severity},${f.status},${desc},${rec},${reason},"${f.source_files}"\n`;
            });
            
            const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.setAttribute("download", `audit_report_${sessId.slice(0,6)}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        } else {
            alert("No findings records to export. Try running a scan first.");
        }
    } catch (err) {
        alert(err.message);
    }
}

async function exportFeedbackBackup() {
    try {
        const response = await fetch(`${API_BASE}/audit/feedback/export`);
        const data = await response.json();
        
        if (response.ok) {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.setAttribute("download", `auditor_feedback_memory_backup.json`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        } else {
            alert("Failed to export feedback data.");
        }
    } catch (err) {
        alert(err.message);
    }
}

async function importFeedbackBackup(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    if (!confirm(`Are you sure you want to import feedback records from ${file.name}?`)) return;
    
    const body = new FormData();
    body.append("file", file);
    
    try {
        const response = await fetch(`${API_BASE}/audit/feedback/import`, {
            method: "POST",
            body: body
        });
        const data = await response.json();
        if (data.success) {
            alert(`✅ ${data.message}`);
        } else {
            alert(`Import failed: ${data.detail || "Unknown error"}`);
        }
    } catch (err) {
        alert(`Error: ${err.message}`);
    }
}

async function loadChatSessions() {
    const sidebar = document.getElementById("chat-history-sidebar");
    if (!sidebar) return;
    sidebar.innerHTML = "<div style='font-size:11px;color:var(--text-muted);padding:8px;'>Loading history...</div>";
    
    try {
        const response = await fetch(`${API_BASE}/audit/chats/sessions?role=${currentUser.role}&username=${encodeURIComponent(currentUser.username || '')}`);
        const data = await response.json();
        
        if (data.success) {
            sidebar.innerHTML = "";
            if (data.sessions.length === 0) {
                sidebar.innerHTML = "<div style='font-size:11px;color:var(--text-muted);padding:8px;text-align:center;'>No conversations yet.</div>";
                return;
            }
            
            data.sessions.forEach(s => {
                const item = document.createElement("div");
                item.className = `chat-session-item ${s.session_id === activeSessionId ? 'active' : ''}`;
                item.onclick = () => selectChatSession(s.session_id);
                
                item.innerHTML = `
                    <div style="display:flex; align-items:center; gap:8px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1;">
                        <span>💬</span>
                        <span title="${s.session_title}">${s.session_title.slice(0, 18)}${s.session_title.length > 18 ? '...' : ''}</span>
                    </div>
                    <button style="background:none; border:none; color:var(--text-muted); font-size:0.75rem; cursor:pointer;" onclick="clearChatSession('${s.session_id}', event)">🗑️</button>
                `;
                sidebar.appendChild(item);
            });
        } else {
            sidebar.innerHTML = "<div style='font-size:11px;color:var(--error);padding:8px;'>Failed to load history.</div>";
        }
    } catch (err) {
        sidebar.innerHTML = `<div style='font-size:11px;color:var(--error);padding:8px;'>Error: ${err.message}</div>`;
    }
}

async function selectChatSession(sessionId) {
    activeSessionId = sessionId;
    
    // Refresh active session badge and workspace details
    document.getElementById("active-session-badge").innerText = `Session ID: ${activeSessionId}`;
    
    // Highlight active chat session card
    document.querySelectorAll(".chat-session-item").forEach(item => item.classList.remove("active"));
    loadChatSessions(); // will refresh active class list
    
    // Reload relevant evidence files & findings for the selected conversation context
    loadEvidenceFileList();
    loadFindings();
    
    const feed = document.getElementById("chat-feed-box");
    feed.innerHTML = "<div class='empty-state'>Loading conversation...</div>";
    
    try {
        const response = await fetch(`${API_BASE}/audit/chats/history?session_id=${sessionId}&username=${encodeURIComponent(currentUser.username || '')}`);
        const data = await response.json();
        
        if (data.success) {
            feed.innerHTML = "";
            if (data.messages.length === 0) {
                feed.innerHTML = `
                    <div class="chat-bubble assistant">
                        <p>Hello! I am your lead auditor AI assistant. Ask me anything about the uploaded evidence policies against standard compliance controls.</p>
                    </div>
                `;
                return;
            }
            
            data.messages.forEach(m => {
                if (m.role === "findings_snapshot") return; // skip internal snapshots
                const bubble = document.createElement("div");
                bubble.className = `chat-bubble ${m.role === 'user' ? 'user' : 'assistant'}`;
                bubble.innerHTML = `<p>${m.content}</p>`;
                feed.appendChild(bubble);
            });
            feed.scrollTop = feed.scrollHeight;
        }
    } catch (err) {
        feed.innerHTML = `<div class="error-msg">Error loading messages: ${err.message}</div>`;
    }
}

async function startNewChatSession() {
    // Generate a fresh session ID
    const newSessionId = 'chat_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    
    // Post to register audit report session on backend
    const body = new FormData();
    body.append("session_title", "Custom AI Chat Conversation");
    body.append("framework", "ISO 27001");
    body.append("username", currentUser.username);
    
    try {
        const response = await fetch(`${API_BASE}/audit/sessions`, {
            method: "POST",
            body: body
        });
        const data = await response.json();
        if (data.success) {
            // Override report session ID
            activeSessionId = data.session_id;
            
            // Reload sidebar list and select the new blank session
            await selectChatSession(activeSessionId);
            alert("✅ Switched to a fresh new AI conversation session!");
        }
    } catch (err) {
        alert(`Failed to initialize new session: ${err.message}`);
    }
}

async function clearChatSession(sessionId, event) {
    if (event) event.stopPropagation(); // prevent clicking session activation
    
    if (!confirm("Are you sure you want to clear conversation messages and checkpoints for this session?")) return;
    
    const body = new FormData();
    body.append("session_id", sessionId);
    if (currentUser && currentUser.username) body.append("username", currentUser.username);
    
    try {
        const response = await fetch(`${API_BASE}/audit/chats/clear`, {
            method: "POST",
            body: body
        });
        const data = await response.json();
        if (data.success) {
            if (sessionId === activeSessionId) {
                // If currently active chat deleted, start a new one
                startNewChatSession();
            } else {
                loadChatSessions();
            }
        }
    } catch (err) {
        alert(err.message);
    }
}

function getBrandingQueryParams() {
    const firm = encodeURIComponent(document.getElementById("brand-firm")?.value || "");
    const auditor = encodeURIComponent(document.getElementById("brand-auditor")?.value || "");
    const reviewer = encodeURIComponent(document.getElementById("brand-reviewer")?.value || "");
    const approver = encodeURIComponent(document.getElementById("brand-approver")?.value || "");
    const docid = encodeURIComponent(document.getElementById("brand-docid")?.value || "");
    const client = encodeURIComponent(document.getElementById("brand-client")?.value || "");
    const email = encodeURIComponent(document.getElementById("brand-email")?.value || "");
    return `&auditor_firm=${firm}&auditor_lead=${auditor}&auditor_reviewer=${reviewer}&auditor_approver=${approver}&document_id=${docid}&client_contact=${client}&client_email=${email}`;
}

async function exportFindingsDOCX() {
    try {
        const brandingParams = getBrandingQueryParams();
        const link = document.createElement("a");
        link.href = `${API_BASE}/audit/export/docx?session_id=${activeSessionId}${brandingParams}`;
        link.setAttribute("download", `audit_report_${activeSessionId.slice(0,6)}.docx`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    } catch (err) {
        alert("Error exporting Word report: " + err.message);
    }
}

async function exportFindingsPDF() {
    try {
        const brandingParams = getBrandingQueryParams();
        const link = document.createElement("a");
        link.href = `${API_BASE}/audit/export/pdf?session_id=${activeSessionId}${brandingParams}`;
        link.setAttribute("download", `audit_report_${activeSessionId.slice(0,6)}.pdf`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    } catch (err) {
        alert("Error exporting PDF report: " + err.message);
    }
}

async function commitSessionToShaktiDB() {
    if (!activeSessionId) {
        alert("⚠️ No active audit session selected.");
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/audit/findings/commit-session/${activeSessionId}`, {
            method: "PUT"
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Failed to commit session to ShaktiDB.");
        
        // Hide unreviewed warning banner
        const banner = document.getElementById("shakti-commit-banner");
        if (banner) banner.style.display = "none";
        
        // Real-time update recent sessions list in sidebar
        loadRecentSessionsList();
        loadFindings();
        
        alert(`💾 Session ${activeSessionId.slice(0, 8)}... successfully committed to Shakthi DB!`);
    } catch (err) {
        alert(`Failed to commit session: ${err.message}`);
    }
}

function toggleChatSidebar() {
    const sidebar = document.querySelector(".chat-sidebar");
    const toggleText = document.getElementById("toggle-sidebar-text");
    const container = document.querySelector(".chat-container");
    
    if (sidebar.style.display === "none") {
        sidebar.style.display = "flex";
        container.style.gridTemplateColumns = "240px 1fr";
        toggleText.innerText = "Hide Recents";
    } else {
        sidebar.style.display = "none";
        container.style.gridTemplateColumns = "1fr";
        toggleText.innerText = "Show Recents";
    }
}

/* ── INSTANT THEME SWITCHER (DARK / LIGHT) ── */
function toggleAppTheme() {
    const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
    const newTheme = currentTheme === "dark" ? "light" : "dark";
    
    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem("aicyber_theme", newTheme);
    
    updateThemeToggleUI(newTheme);
}

function updateThemeToggleUI(theme) {
    const icon = document.getElementById("theme-toggle-icon");
    const text = document.getElementById("theme-toggle-text");
    const btn = document.getElementById("theme-toggle-btn");
    
    if (icon && text) {
        if (theme === "light") {
            icon.innerText = "☀️";
            text.innerText = "Light Mode";
            if (btn) btn.style.background = "rgba(0,0,0,0.06)";
        } else {
            icon.innerText = "🌙";
            text.innerText = "Dark Mode";
            if (btn) btn.style.background = "rgba(255,255,255,0.08)";
        }
    }
}

// Restore user theme preference instantly on page load
(function initAppTheme() {
    const savedTheme = localStorage.getItem("aicyber_theme") || "dark";
    document.documentElement.setAttribute("data-theme", savedTheme);
    document.addEventListener("DOMContentLoaded", () => {
        updateThemeToggleUI(savedTheme);
    });
})();

/* ── FLOATING AI COPILOT WIDGET (GEMINI STYLE) ── */
function toggleCopilotDrawer() {
    const drawer = document.getElementById("ai-copilot-drawer");
    if (!drawer) return;
    
    if (drawer.style.display === "none" || !drawer.style.display) {
        drawer.style.display = "flex";
        updateCopilotContextBadge();
    } else {
        drawer.style.display = "none";
    }
}

function updateCopilotContextBadge() {
    const badge = document.getElementById("copilot-page-context");
    if (!badge) return;
    
    let tabName = "Audit Workspace";
    if (activeTab === "tab-audit-records") tabName = "Audit Records Findings";
    else if (activeTab === "tab-upload-evidence") tabName = "Auditee Document Uploads";
    else if (activeTab === "tab-audit-report") tabName = "Audit Delivery Report";
    else if (activeTab === "tab-manage-controls") tabName = "Controls Management";
    else if (activeTab === "tab-ai-chat") tabName = "Full AI Chat Assistant";
    
    badge.innerText = `📍 Active Context: ${tabName}`;
}

function handleCopilotKeyPress(event) {
    if (event.key === "Enter") {
        sendCopilotMessage();
    }
}

function sendQuickCopilotPrompt(text) {
    const input = document.getElementById("copilot-input");
    if (input) {
        input.value = text;
        sendCopilotMessage();
    }
}

async function sendCopilotMessage() {
    const input = document.getElementById("copilot-input");
    const feed = document.getElementById("copilot-chat-feed");
    const indicator = document.getElementById("copilot-thinking-indicator");
    
    if (!input || !feed) return;
    const msgText = input.value.trim();
    if (!msgText) return;
    
    input.value = "";
    
    // Render user message bubble
    const userBubble = document.createElement("div");
    userBubble.className = "chat-bubble user";
    userBubble.innerHTML = `<p>${escapeHtml(msgText)}</p>`;
    feed.appendChild(userBubble);
    feed.scrollTop = feed.scrollHeight;
    
    if (indicator) indicator.style.display = "block";
    
    const selectedModel = document.getElementById("llm-model-select")?.value || "Gemma 4 (e4b)";
    const uName = currentUser ? currentUser.username : "auditor";
    
    try {
        let activeContext = `[Context: Active Tab = ${activeTab}, Session = ${activeSessionId}]`;
        const response = await fetch(`${API_BASE}/audit/chats/send`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: activeSessionId,
                message: `${activeContext}\n${msgText}`,
                username: uName,
                model_choice: selectedModel
            })
        });
        
        const data = await response.json();
        if (indicator) indicator.style.display = "none";
        
        if (!response.ok) throw new Error(data.detail || "Copilot failed to respond.");
        
        const replyText = data.response || data.reply || "No response received from local AI model.";
        
        const aiBubble = document.createElement("div");
        aiBubble.className = "chat-bubble assistant";
        aiBubble.innerHTML = `<p>${escapeHtml(replyText).replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')}</p>`;
        feed.appendChild(aiBubble);
        feed.scrollTop = feed.scrollHeight;
    } catch (err) {
        if (indicator) indicator.style.display = "none";
        const errBubble = document.createElement("div");
        errBubble.className = "chat-bubble assistant";
        errBubble.innerHTML = `<p style="color: var(--error);">⚠️ Error: ${err.message}</p>`;
        feed.appendChild(errBubble);
        feed.scrollTop = feed.scrollHeight;
    }
}

/* ── SIDEBAR COLLAPSE TOGGLE (◀ / ▶) ── */
function toggleSidebarCollapse() {
    const sidebar = document.getElementById("main-sidebar");
    const toggleBtn = document.getElementById("sidebar-toggle-btn");
    if (!sidebar || !toggleBtn) return;
    
    if (sidebar.classList.contains("collapsed")) {
        sidebar.classList.remove("collapsed");
        sidebar.style.width = "300px";
        sidebar.style.minWidth = "300px";
        toggleBtn.innerText = "◀";
        toggleBtn.title = "Collapse Sidebar";
    } else {
        sidebar.classList.add("collapsed");
        sidebar.style.width = "64px";
        sidebar.style.minWidth = "64px";
        toggleBtn.innerText = "▶";
        toggleBtn.title = "Expand Sidebar";
    }
}

function generateUUID() {
    if (typeof crypto !== "undefined" && crypto.randomUUID) {
        return crypto.randomUUID().replace(/-/g, "");
    }
    return 'xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

/* ── AUDIT SESSION MANAGER (+ New Session & Recent Sessions) ── */
async function startNewAuditSession() {
    activeSessionId = generateUUID();
    findingsList = [];
    
    // Register fresh session in Shakthi DB
    try {
        const username = currentUser ? currentUser.username : "auditor@24";
        const body = new FormData();
        body.append("session_title", `Local Compliance Audit (${activeSessionId.slice(0, 6)})`);
        body.append("framework", "ISO 27001");
        body.append("username", username);
        
        const res = await fetch(`${API_BASE}/audit/sessions`, { method: "POST", body });
        const data = await res.json();
        if (data.success && data.session_id) {
            activeSessionId = data.session_id;
        }
    } catch (e) {
        console.warn("Session creation API fallback:", e);
    }

    const badge = document.getElementById("active-session-badge");
    if (badge) badge.innerText = `Session ID: ${activeSessionId}`;
    const wsTitle = document.getElementById("workspace-title");
    if (wsTitle) wsTitle.innerText = "Audit Records Workspace";
    
    // Clear evidence files display immediately
    const evidenceRegistry = document.getElementById("uploaded-files-registry");
    const auditeeRegistry = document.getElementById("auditee-files-registry");
    const countBadge = document.getElementById("evidence-count-badge");
    const emptyMsg = `<div class="empty-state">No files uploaded yet. Drag files to begin audit.</div>`;
    if (evidenceRegistry) evidenceRegistry.innerHTML = emptyMsg;
    if (auditeeRegistry) auditeeRegistry.innerHTML = emptyMsg;
    if (countBadge) countBadge.innerText = "0 files";
    
    // Clear findings panel
    const findingsContainer = document.getElementById("findings-container");
    if (findingsContainer) {
        findingsContainer.innerHTML = `<div class="empty-state">New session started. Upload evidence files and click "▶ Step 3: Run RAG Scan".</div>`;
    }

    // Clear KPI counters
    ["count-compliant","count-noncompliant","count-p1","count-p2","count-p3","count-p4"].forEach(id => {
        const el = document.getElementById(id); if (el) el.innerText = "0";
    });
    
    // Hide Shakthi DB banner
    const banner = document.getElementById("shakti-commit-banner");
    if (banner) banner.style.display = "none";
    
    // Reset upload status label
    const uploadStatus = document.getElementById("sidebar-upload-status");
    if (uploadStatus) uploadStatus.innerText = "No files selected";
    
    loadRecentSessionsList();
    alert(`✨ New Audit Session initialized!\nSession ID: ${activeSessionId.slice(0, 8)}...`);
}

async function loadRecentSessionsList() {
    const container = document.getElementById("recent-sessions-list");
    if (!container) return;
    
    try {
        const response = await fetch(`${API_BASE}/audit/sessions`);
        const data = await response.json();
        
        if (data.success && data.sessions.length > 0) {
            container.innerHTML = "";
            data.sessions.slice(0, 8).forEach(sess => {
                const item = document.createElement("div");
                item.className = "recent-session-item";
                item.style.cssText = "display: flex; align-items: center; justify-content: space-between; padding: 6px 8px; background: rgba(255,255,255,0.05); border-radius: 6px; cursor: pointer; font-size: 0.73rem; transition: background 0.2s;";
                item.onclick = () => switchActiveAuditSession(sess.session_id);
                
                const isCurrent = sess.session_id === activeSessionId;
                item.innerHTML = `
                    <div style="text-overflow: ellipsis; overflow: hidden; white-space: nowrap; max-width: 140px;">
                        <span style="font-weight: 600; color: ${isCurrent ? '#60a5fa' : 'var(--text-main)'};">${sess.session_id.slice(0, 8)}...</span>
                        <div style="font-size: 0.65rem; color: var(--text-muted);">${sess.findings_count || 0} findings</div>
                    </div>
                    <span class="badge-pill" style="font-size: 0.62rem; padding: 2px 4px; border-color: ${sess.status === 'Reviewed & Finalized' ? 'rgba(52,211,153,0.4)' : 'rgba(245,158,11,0.4)'}; color: ${sess.status === 'Reviewed & Finalized' ? '#34d399' : '#fbbf24'};">${sess.status === 'Reviewed & Finalized' ? 'FINAL' : 'OPEN'}</span>
                `;
                container.appendChild(item);
            });
        } else {
            container.innerHTML = `<div style="font-size: 0.72rem; color: var(--text-muted); text-align: center; padding: 6px;">No recent sessions found</div>`;
        }
    } catch (err) {
        container.innerHTML = `<div style="font-size: 0.72rem; color: var(--text-muted); text-align: center; padding: 6px;">Ready</div>`;
    }
}

function switchActiveAuditSession(sessionId) {
    activeSessionId = sessionId;
    document.getElementById("active-session-badge").innerText = `Session: ${activeSessionId.slice(0, 8)}...`;
    loadFindings();
    loadRecentSessionsList();
    alert(`📂 Switched to Audit Session: ${sessionId.slice(0, 8)}...`);
}

// Load recent sessions on page load
window.addEventListener("DOMContentLoaded", () => {
    setTimeout(loadRecentSessionsList, 1500);
});



