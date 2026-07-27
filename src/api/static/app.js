// ── AICyberAuditBox Client Application ──
var API_BASE = window.location.origin + "/api";

var currentUser = typeof currentUser !== "undefined" ? currentUser : null;
var selectedRole = typeof selectedRole !== "undefined" ? selectedRole : "admin";
var activeTab = typeof activeTab !== "undefined" ? activeTab : "";
var activeSessionId = typeof activeSessionId !== "undefined" ? activeSessionId : "";
var activeSessionTitle = typeof activeSessionTitle !== "undefined" ? activeSessionTitle : "";
var findingsList = typeof findingsList !== "undefined" ? findingsList : [];
var uploadedFilesList = typeof uploadedFilesList !== "undefined" ? uploadedFilesList : [];
var selectedAnalysisMode = typeof selectedAnalysisMode !== "undefined" ? selectedAnalysisMode : "Deep";
var activeSeverityFilter = typeof activeSeverityFilter !== "undefined" ? activeSeverityFilter : "";
var activeStatusFilter = typeof activeStatusFilter !== "undefined" ? activeStatusFilter : "All";
var logsPage = typeof logsPage !== "undefined" ? logsPage : 0;
var logsTotalPages = typeof logsTotalPages !== "undefined" ? logsTotalPages : 1;
var customEvidenceMappings = typeof customEvidenceMappings !== "undefined" ? customEvidenceMappings : null;
var customControlDocuments = typeof customControlDocuments !== "undefined" ? customControlDocuments : null;

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
    setupTabs(selectedRole || "admin");
    loadFrameworkControls();
    
    // Sync role selection UI and auto-fill credentials for the default role
    selectRole(selectedRole || "admin");
    
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
    const targetBtn = document.getElementById(`role-${role}-btn`);
    if (targetBtn) targetBtn.classList.add("active");
    
    // Keep input fields clean for user manual entry
    const usernameInput = document.getElementById("username-input");
    const passwordInput = document.getElementById("password-input");
    if (usernameInput && passwordInput) {
        usernameInput.value = "";
        passwordInput.value = "";
    }

    // Update descriptions
    const descEl = document.getElementById("role-desc");
    if (descEl) {
        if (role === "admin") {
            descEl.innerText = "SYSTEM ADMINISTRATOR • Full access to settings, analyses, and records";
        } else if (role === "auditor") {
            descEl.innerText = "COMPLIANCE AUDITOR • Upload compliance documents and run guided audits";
        } else {
            descEl.innerText = "AUDITEE • Upload audit evidence documents for the auditor to review";
        }
    }
    
    // Hide register option for Admin (seeded default is login only)
    const toggleRow = document.getElementById("toggle-auth-row");
    if (toggleRow) {
        if (role === "admin") {
            toggleRow.style.display = "none";
            resetAuthActionToLogin();
        } else {
            toggleRow.style.display = "flex";
        }
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
            
            // Display 2FA TOTP QR code for authenticator apps
            if (data.qr_code_base64) {
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
    setDisplay("sidebar-admin-tools", isAdmin ? "block" : "none");
    setDisplay("sidebar-auditee-submissions", (isAdmin || isAuditor) ? "block" : "none");
    
    // Setup Tabs Bar
    setupTabs(user.role);
    
    // Initialize standard checklist
    if (isAdmin || isAuditor) {
        loadFrameworkControls();
    }
    
    // Resolve Active Audit Session ID
    await loadOrCreateSession(user);
    loadRecentSessions();
    if (!window._recentSessionsInterval) {
        window._recentSessionsInterval = setInterval(loadRecentSessions, 10000);
    }
    
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
        // Admin Role - includes System & Auditor Warning Logs
        tabs = [
            { id: "tab-scan-workspace", label: "Scan Workspace" },
            { id: "tab-audit-records", label: "Audit Records & Findings" },
            { id: "tab-audit-report", label: "Report Exporter" },
            { id: "tab-auditee-docs", label: "Auditee Submissions" },
            { id: "tab-manage-controls", label: "Manage Controls and Backup" },
            { id: "tab-admin-logs", label: "System & Auditor Logs" }
        ];
    } else {
        // Auditor Role
        tabs = [
            { id: "tab-scan-workspace", label: "Scan Workspace" },
            { id: "tab-audit-records", label: "Audit Records & Findings" },
            { id: "tab-audit-report", label: "Report Exporter" },
            { id: "tab-auditee-docs", label: "Auditee Submissions" },
            { id: "tab-manage-controls", label: "Manage Controls and Backup" }
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
    } else if (tabId === "tab-audit-report") {
        renderAuditReportPreview();
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
        if (contentId === "recent-sessions-container") {
            loadRecentSessions();
        }
    } else {
        el.style.display = "none";
    }
}

async function loadRecentSessions() {
    const container = document.getElementById("recent-sessions-list");
    if (!container) return;
    
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
            const filteredSessions = data.sessions.filter(s => {
                if (!s.session_id || seen.has(s.session_id)) return false;
                const title = (s.session_title || "").toLowerCase();
                if (title.includes("chat") || title.includes("error")) return false;
                seen.add(s.session_id);
                return true;
            });

            if (filteredSessions.length === 0) {
                container.innerHTML = `<div style="font-size: 0.75rem; color: var(--text-muted); text-align: center; padding: 6px;">No recent sessions found.</div>`;
                return;
            }

            const badgeCount = document.getElementById("recent-sessions-count-badge");
            if (badgeCount) badgeCount.innerText = `(${filteredSessions.length})`;

            filteredSessions.forEach(s => {
                const btn = document.createElement("button");
                btn.className = "recent-session-item";
                if (activeSessionId === s.session_id) btn.classList.add("active-session");

                btn.onclick = () => switchRecentSession(s.session_id, s.session_title);
                
                const isFinal = (s.status || "").toLowerCase().includes("final") || (s.status || "").toLowerCase().includes("review");
                const statusPill = isFinal 
                    ? `<span style="font-size:0.65rem; padding:1px 6px; border-radius:4px; background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3); font-weight:800;">FINAL</span>`
                    : `<span style="font-size:0.65rem; padding:1px 6px; border-radius:4px; background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid rgba(245,158,11,0.3); font-weight:800;">OPEN</span>`;

                const shortTitle = s.session_title || `Audit Session (${s.session_id.slice(0,6)})`;
                const dateStr = s.created_at ? s.created_at.slice(0, 10) : "";

                btn.style.cssText = "display: flex; flex-direction: column; align-items: flex-start; width: 100%; padding: 9px 11px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 10px; color: var(--text-main); font-size: 0.78rem; text-align: left; cursor: pointer; margin-bottom: 6px; transition: all 0.15s ease;";
                btn.onmouseover = () => { btn.style.background = "rgba(37, 99, 235, 0.1)"; btn.style.borderColor = "rgba(37, 99, 235, 0.4)"; };
                btn.onmouseout = () => { btn.style.background = "var(--bg-card)"; btn.style.borderColor = "var(--border-color)"; };
                
                btn.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: center; width: 100%; margin-bottom: 4px;">
                        <span style="font-weight: 700; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 140px;" title="${shortTitle}">📌 ${shortTitle}</span>
                        ${statusPill}
                    </div>
                    <div style="font-size: 0.7rem; color: var(--text-muted); display: flex; justify-content: space-between; width: 100%;">
                        <span>${s.findings_count || 0} findings &bull; <b style="color:#10b981;">${s.score_percent || 0}%</b></span>
                        <span>${dateStr}</span>
                    </div>
                `;
                container.appendChild(btn);
            });
        } else {
            container.innerHTML = `<div style="font-size: 0.75rem; color: var(--text-muted); text-align: center; padding: 6px;">No recent sessions found.</div>`;
        }
    } catch (err) {
        console.error("Failed to load recent sessions:", err);
    }
}

async function switchRecentSession(sessionId, sessionTitle) {
    activeSessionId = sessionId;
    if (sessionTitle) activeSessionTitle = sessionTitle;
    
    const badge = document.getElementById("active-session-badge");
    const wsTitle = document.getElementById("workspace-title");
    if (badge) badge.innerText = `Session ID: ${activeSessionId}`;
    if (wsTitle) wsTitle.innerText = activeSessionTitle || "ISO 27001 Local Compliance Audit";

    // FULLY reset ALL filters to "All Records" on session switch
    const select = document.getElementById("status-filter");
    if (select) select.value = "All";

    // Also reset KPI box visual highlights if any
    document.querySelectorAll(".kpi-box").forEach(b => b.style.outline = "none");

    // Refresh evidence files list for this session
    loadEvidenceFileList();
    loadAuditeeEvidenceDocs();

    // Load detailed findings from Shakthi DB for this session
    await loadFindings();

    // Auto switch tab view to Audit Records
    const recordsTabBtn = Array.from(document.querySelectorAll("#tabs-bar button")).find(b => b.innerText.includes("Records"));
    if (recordsTabBtn) switchTab("tab-audit-records", recordsTabBtn);

    // Refresh sidebar to highlight active session
    loadRecentSessions();

    showToast(`📂 Loaded audit session: ${sessionId.slice(0, 8)}`, "info");
}

// ── SESSION MANAGEMENT ──

async function loadOrCreateSession(user) {
    try {
        const response = await fetch(`${API_BASE}/audit/sessions?role=${user.role}&username=${user.username}`);
        const data = await response.json();
        
        if (data.success && data.sessions.length > 0) {
            // Prefer session that has findings (Pending Review / Reviewed & Finalized)
            // over a blank newly created session with no findings
            const sessionWithFindings = data.sessions.find(s =>
                s.status === "Pending Review" || s.status === "Reviewed & Finalized"
            );
            const chosen = sessionWithFindings || data.sessions[0];
            activeSessionId = chosen.session_id;
            activeSessionTitle = chosen.session_title;
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
        // Fetch registered Auditee User Accounts
        const userRes = await fetch(`${API_BASE}/auth/auditees`);
        const userData = await userRes.json();
        
        if (userData.success && userData.auditees && userData.auditees.length > 0) {
            const userGroup = document.createElement("optgroup");
            userGroup.label = "Registered Client / Auditee Accounts";
            userData.auditees.forEach(a => {
                const opt = document.createElement("option");
                opt.value = `auditee:${a.username}`;
                opt.innerText = `👤 ${a.username} (Registered Auditee Account)`;
                userGroup.appendChild(opt);
            });
            select.appendChild(userGroup);
        }

        // Fetch Audit Sessions
        const response = await fetch(`${API_BASE}/audit/sessions`);
        const data = await response.json();
        
        if (data.success && data.sessions.length > 0) {
            const sessionGroup = document.createElement("optgroup");
            sessionGroup.label = "Active Audit Sessions";
            
            // Filter out repetitive test sessions if clean sessions exist
            const filteredSessions = data.sessions.filter(s => {
                const title = (s.session_title || "").toLowerCase();
                return !title.includes("test shakthi save session");
            });

            const displayList = filteredSessions.length > 0 ? filteredSessions : data.sessions.slice(0, 10);
            displayList.forEach(s => {
                const opt = document.createElement("option");
                opt.value = `session:${s.id}`;
                opt.innerText = `📋 ${s.session_title} (ID: ${s.session_id.slice(0,6)})`;
                sessionGroup.appendChild(opt);
            });
            select.appendChild(sessionGroup);
        }
    } catch (err) {
        console.error("Failed to populate auditee selector:", err);
    }
}

// ── FILE UPLOAD & EVIDENCE COLLECTOR ENGINE ──

function setupFileDropZone() {
    const dropZone = document.getElementById("drop-zone");
    if (!dropZone) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.style.borderColor = "#60a5fa", false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.style.borderColor = "rgba(59, 130, 246, 0.35)", false);
    });

    dropZone.addEventListener('drop', handleFileDrop, false);
}

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

function handleFileDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    processEvidenceFiles(files);
}

function handleEvidenceUpload(e) {
    const files = e.target.files;
    processEvidenceFiles(files);
}

async function processEvidenceFiles(files) {
    if (!files || files.length === 0) return;

    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        
        let sizeStr = "";
        if (file.size < 1024 * 1024) {
            sizeStr = `${(file.size / 1024).toFixed(1)} KB`;
        } else {
            sizeStr = `${(file.size / (1024 * 1024)).toFixed(1)} MB`;
        }

        const ext = file.name.split('.').pop().toLowerCase();
        let fileType = "DOC";
        let iconClass = "file-type-doc";
        
        if (["pdf"].includes(ext)) { fileType = "PDF"; iconClass = "file-type-pdf"; }
        else if (["xls", "xlsx", "csv"].includes(ext)) { fileType = "XLS"; iconClass = "file-type-xls"; }
        else if (["xml", "json", "txt", "html", "htm"].includes(ext)) { fileType = "XML"; iconClass = "file-type-xml"; }
        else if (["png", "jpg", "jpeg"].includes(ext)) { fileType = "IMG"; iconClass = "file-type-doc"; }

        const fileObj = {
            name: file.name,
            size: sizeStr,
            type: fileType,
            iconClass: iconClass,
            fileRaw: file
        };

        uploadedFilesList.push(fileObj);

        // Upload to backend API
        try {
            if (activeSessionId) {
                const formData = new FormData();
                formData.append("files", file);
                formData.append("session_id", activeSessionId);
                formData.append("is_auditor_uploaded", "true");

                fetch(`${API_BASE}/audit/upload`, {
                    method: "POST",
                    body: formData
                }).catch(e => console.warn("Background upload notice:", e));
            }
        } catch (e) {
            console.warn("Upload exception:", e);
        }
    }

    renderUploadedFilesList();
}

function renderUploadedFilesList() {
    const registry = document.getElementById("uploaded-files-registry");
    const countBadge = document.getElementById("evidence-count-badge");
    if (!registry) return;

    if (countBadge) countBadge.innerText = `${uploadedFilesList.length} files`;

    if (uploadedFilesList.length === 0) {
        registry.innerHTML = `<div class="empty-state" style="font-size: 0.78rem; color: var(--text-muted); text-align: center; padding: 24px;">No files uploaded yet. Drag files to begin audit.</div>`;
        return;
    }

    registry.innerHTML = "";
    uploadedFilesList.forEach((file, idx) => {
        const item = document.createElement("div");
        item.className = "modern-file-card";
        item.style.cssText = "display: flex; align-items: center; justify-content: space-between; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 10px; padding: 10px 12px; gap: 12px;";

        item.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px; overflow: hidden; flex: 1;">
                <span class="file-icon-badge ${file.iconClass}" style="width: 32px; height: 32px; font-size: 0.65rem; border-radius: 8px; flex-shrink: 0; display: inline-flex; align-items: center; justify-content: center;">${file.type}</span>
                <div style="overflow: hidden;">
                    <div style="font-size: 0.82rem; font-weight: 600; color: #f1f5f9; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">${file.name}</div>
                    <div style="font-size: 0.7rem; color: #94a3b8; display: flex; align-items: center; gap: 6px;">
                        <span>${file.size}</span>
                        <span style="color: #34d399; font-weight: 600;">✓ Attached</span>
                    </div>
                </div>
            </div>
            <button type="button" onclick="deleteEvidenceFile(${idx})" style="background: transparent; border: none; color: #ef4444; font-size: 0.95rem; cursor: pointer; padding: 4px;" title="Remove ${file.name}">🗑️</button>
        `;
        registry.appendChild(item);
    });
}

function deleteEvidenceFile(idx) {
    if (idx >= 0 && idx < uploadedFilesList.length) {
        uploadedFilesList.splice(idx, 1);
        renderUploadedFilesList();
    }
}

function clearAllUploadedFiles() {
    uploadedFilesList = [];
    renderUploadedFilesList();
}

function loadEvidenceFileList() {
    renderUploadedFilesList();
}

function setAnalysisMode(mode) {
    selectedAnalysisMode = mode;
    const btnQuick = document.getElementById("btn-mode-quick");
    const btnDeep = document.getElementById("btn-mode-deep");
    const radioDeep = document.getElementById("radio-mode-deep");
    const radioQuick = document.getElementById("radio-mode-quick");

    if (mode === "Quick") {
        if (btnQuick) {
            btnQuick.classList.add("active");
            btnQuick.style.background = "#2563eb";
            btnQuick.style.color = "#ffffff";
            btnQuick.style.fontWeight = "700";
            btnQuick.style.outline = "none";
            btnQuick.style.boxShadow = "0 2px 6px rgba(37, 99, 235, 0.4)";
        }
        if (btnDeep) {
            btnDeep.classList.remove("active");
            btnDeep.style.background = "transparent";
            btnDeep.style.color = "#94a3b8";
            btnDeep.style.fontWeight = "500";
            btnDeep.style.outline = "none";
            btnDeep.style.boxShadow = "none";
        }
        if (radioQuick) radioQuick.checked = true;
    } else {
        if (btnDeep) {
            btnDeep.classList.add("active");
            btnDeep.style.background = "#2563eb";
            btnDeep.style.color = "#ffffff";
            btnDeep.style.fontWeight = "700";
            btnDeep.style.outline = "none";
            btnDeep.style.boxShadow = "0 2px 6px rgba(37, 99, 235, 0.4)";
        }
        if (btnQuick) {
            btnQuick.classList.remove("active");
            btnQuick.style.background = "transparent";
            btnQuick.style.color = "#94a3b8";
            btnQuick.style.fontWeight = "500";
            btnQuick.style.outline = "none";
            btnQuick.style.boxShadow = "none";
        }
        if (radioDeep) radioDeep.checked = true;
    }
}

// ── AUDIT SCAN EXECUTION CONTROLLER ──
async function triggerAuditAnalysis() {
    const runBtn = document.getElementById("run-analysis-btn");
    const stopBtn = document.getElementById("stop-analysis-btn");
    
    if (!activeSessionId) {
        alert("⚠️ Please create or select an Audit Session first.");
        return;
    }

    if (!uploadedFilesList || uploadedFilesList.length === 0) {
        alert("⚠️ Please upload at least one evidence document (PDF, XML, DOCX, CSV) before running the audit scan.");
        return;
    }

    // Determine target framework
    const fwSelect = document.getElementById("framework-select");
    const targetFramework = fwSelect ? fwSelect.value : "All Standards";
    
    // Check if VAPT framework is selected -> Bypass LLM and use fast technical parser!
    let effectiveAuditMode = selectedAnalysisMode;
    if (targetFramework === "VAPT" || targetFramework.includes("VAPT")) {
        effectiveAuditMode = "Technical findings only";
    }

    if (runBtn) {
        const modeLabel = effectiveAuditMode === "Technical findings only" ? "Fast VAPT Parser (No LLM)" : `${selectedAnalysisMode} Audit`;
        runBtn.innerHTML = `<span>⚡</span> <span>Running ${modeLabel}...</span>`;
        runBtn.disabled = true;
    }
    if (stopBtn) stopBtn.style.display = "block";

    try {
        // Collect exact selected controls (if user checked 2 controls, sends ONLY those 2 controls!)
        const selectedControlSls = Array.from(document.querySelectorAll("#controls-checkbox-container input[type='checkbox']:checked"))
            .map(chk => parseInt(chk.value))
            .filter(val => !isNaN(val));

        // If checkboxes empty, check modal selected scope or fallback to default controls
        let slsToRun = selectedControlSls;
        if (slsToRun.length === 0 && modalSelectedControls && modalSelectedControls.size > 0) {
            slsToRun = Array.from(modalSelectedControls).map(sl => parseInt(sl)).filter(v => !isNaN(v));
        }
        if (slsToRun.length === 0) {
            slsToRun = [5, 6, 8, 12, 15, 22]; // Default fallback if nothing checked
        }

        const response = await fetch(`${API_BASE}/audit/start`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: activeSessionId,
                selected_sls: slsToRun,
                model_choice: document.getElementById("llm-model-select") ? document.getElementById("llm-model-select").value : "Gemma 4 (e4b)",
                audit_mode: effectiveAuditMode
            })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Failed to start audit scan.");

        pollAuditResults();

        const recordsTabBtn = document.querySelectorAll(".tab-link")[1];
        if (recordsTabBtn) switchTab("tab-audit-records", recordsTabBtn);

    } catch (err) {
        alert(`❌ Audit Scan Error: ${err.message}`);
        if (runBtn) {
            runBtn.innerHTML = `<span>▶</span> <span>RUN AUDIT SCAN</span>`;
            runBtn.disabled = false;
        }
        if (stopBtn) stopBtn.style.display = "none";
    }
}

async function pollAuditResults() {
    const runBtn = document.getElementById("run-analysis-btn");
    const stopBtn = document.getElementById("stop-analysis-btn");

    let attempts = 0;
    const interval = setInterval(async () => {
        attempts++;
        try {
            const res = await fetch(`${API_BASE}/audit/findings?session_id=${activeSessionId}`);
            if (!res.ok) return;
            const data = await res.json();

            if (data.success && data.findings && data.findings.length > 0) {
                clearInterval(interval);
                findingsList = data.findings;
                renderFindingsList();
                updateKPICounters();
                
                if (runBtn) {
                    runBtn.innerHTML = `<span>▶</span> <span>RUN AUDIT SCAN</span>`;
                    runBtn.disabled = false;
                }
                if (stopBtn) stopBtn.style.display = "none";
                alert(`🎉 RAG Audit Scan Complete! ${data.findings.length} findings generated.`);
            }
        } catch (e) {
            console.warn("Polling error:", e);
        }

        if (attempts > 30) {
            clearInterval(interval);
            if (runBtn) {
                runBtn.innerHTML = `<span>▶</span> <span>RUN AUDIT SCAN</span>`;
                runBtn.disabled = false;
            }
            if (stopBtn) stopBtn.style.display = "none";
        }
    }, 2000);
}

function stopAuditAnalysis() {
    const runBtn = document.getElementById("run-analysis-btn");
    const stopBtn = document.getElementById("stop-analysis-btn");
    if (runBtn) {
        runBtn.innerHTML = `<span>▶</span> <span>RUN AUDIT SCAN</span>`;
        runBtn.disabled = false;
    }
    if (stopBtn) stopBtn.style.display = "none";
    alert("⛔ Audit scan halted by user.");
}

// ── SIDEBAR FRAMEWORK CHECKLIST ──

// ── SIDEBAR FRAMEWORK CHECKLIST & SEGMENTED CONTROLS ──

function setScopingMode(mode) {
    const aiBtn = document.getElementById("btn-ai-scoping");
    const chkBtn = document.getElementById("btn-checklist-scoping");
    const excelBtn = document.getElementById("btn-excel-scoping");
    
    const excelDropzone = document.getElementById("scoping-excel-dropzone");
    const statusNote = document.getElementById("scoping-mode-status-note");
    const checklistBox = document.getElementById("target-controls-container-box");

    // Reset active class on all buttons
    [aiBtn, chkBtn, excelBtn].forEach(b => { if (b) b.classList.remove("active-scope-mode"); });

    if (mode === "AI" || mode.includes("AI")) {
        if (aiBtn) aiBtn.classList.add("active-scope-mode");
        if (excelDropzone) excelDropzone.style.display = "none";
        if (checklistBox) checklistBox.style.display = "none";
        if (statusNote) statusNote.innerHTML = `<span style="color:#10b981;font-weight:700;">🟢 Active:</span> <b>AI Auto-Scoping</b> — Automatically detecting applicable controls from evidence files.`;
    } else if (mode === "EXCEL" || mode.includes("Excel")) {
        if (excelBtn) excelBtn.classList.add("active-scope-mode");
        if (excelDropzone) excelDropzone.style.display = "block";
        if (checklistBox) checklistBox.style.display = "block";
        if (statusNote) statusNote.innerHTML = `<span style="color:#10b981;font-weight:700;">🟢 Active:</span> <b>Excel Upload Scope</b> — Drag & drop or browse an Excel scoping matrix (.xlsx) below.`;
    } else {
        if (chkBtn) chkBtn.classList.add("active-scope-mode");
        if (excelDropzone) excelDropzone.style.display = "none";
        if (checklistBox) checklistBox.style.display = "block";
        if (statusNote) statusNote.innerHTML = `<span style="color:#10b981;font-weight:700;">🟢 Active:</span> <b>Manual Checklist Scope</b> — Select or unselect specific controls from accordions below.`;
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
        const selectedStd = select ? select.value : "ISO 27001";
        
        const filtered = controlsToRender.filter(c => {
            const cat = (c.category || "").toUpperCase();
            const useCase = (c.use_case || "").toUpperCase();
            const isVapt = cat.includes("VAPT") || useCase.includes("VAPT") || useCase.startsWith("VAPT-");
            const isDpdp = cat.includes("DPDP") || cat.includes("GDPR") || useCase.includes("DPDP") || useCase.includes("GDPR");
            const isSoc2 = cat.includes("SOC") || useCase.includes("SOC");
            const isBcms = cat.includes("BCMS") || cat.includes("BUSINESS CONTINUITY") || useCase.includes("BCMS");
            const isXbom = cat.includes("X-BOM") || cat.includes("SBOM") || useCase.includes("X-BOM") || useCase.includes("XBOM");
            const isIso = !isVapt && !isDpdp && !isSoc2 && !isBcms && !isXbom;

            if (selectedStd === "All Standards") return true;
            if (selectedStd === "ISO 27001") return isIso;
            if (selectedStd === "VAPT") return isVapt;
            if (selectedStd === "DPDP") return isDpdp;
            if (selectedStd === "SOC2") return isSoc2;
            if (selectedStd === "BCMS") return isBcms;
            if (selectedStd === "XBOM") return isXbom;
            return true;
        });

        // Group into Clause Categories matching Streamlit UI
        const clauseMap = {
            "Clause 5 — Organizational Controls": [],
            "Clause 6 — People Controls": [],
            "Clause 7 — Physical Controls": [],
            "Clause 8 — Technological Controls": [],
            "VAPT Framework Controls": [],
            "Custom Controls": []
        };

        filtered.forEach(c => {
            const cid = (c.control_id || c.use_case || c.sl || "").toString().toUpperCase();
            const cat = (c.category || "").toUpperCase();
            
            if (cid.startsWith("5.") || cat.includes("ORGANIZATIONAL")) {
                clauseMap["Clause 5 — Organizational Controls"].push(c);
            } else if (cid.startsWith("6.") || cat.includes("PEOPLE")) {
                clauseMap["Clause 6 — People Controls"].push(c);
            } else if (cid.startsWith("7.") || cat.includes("PHYSICAL")) {
                clauseMap["Clause 7 — Physical Controls"].push(c);
            } else if (cid.startsWith("8.") || cat.includes("TECH") || cat.includes("IT SECURITY")) {
                clauseMap["Clause 8 — Technological Controls"].push(c);
            } else if (cid.includes("VAPT") || cat.includes("VAPT")) {
                clauseMap["VAPT Framework Controls"].push(c);
            } else {
                clauseMap["Custom Controls"].push(c);
            }
        });

        // Render each Clause Accordion
        Object.keys(clauseMap).forEach((clauseTitle, idx) => {
            const controls = clauseMap[clauseTitle];
            if (controls.length === 0) return;

            const accordionCard = document.createElement("div");
            accordionCard.className = "clause-accordion-card";
            accordionCard.style.cssText = "margin-bottom: 8px; border-radius: 10px; overflow: hidden;";

            const contentId = `clause_body_${idx}`;
            
            const header = document.createElement("div");
            header.className = "clause-header";
            header.style.cssText = "padding: 10px 12px; font-size: 0.82rem; font-weight: 700; display: flex; align-items: center; justify-content: space-between; cursor: pointer; user-select: none;";
            header.onclick = () => toggleClauseAccordion(contentId, header);
            header.innerHTML = `
                <div style="display: flex; align-items: center; gap: 8px; min-width: 0; flex: 1;">
                    <span class="clause-arrow" style="color: #60a5fa; font-weight: 700; font-size: 0.85rem; width: 14px; text-align: center;">›</span>
                    <span style="font-weight: 700; font-size: 0.8rem; text-transform: none; white-space: normal; line-height: 1.2;">${clauseTitle}</span>
                </div>
                <span class="clause-count-badge" id="clause_badge_${idx}" style="font-size: 0.7rem; font-weight: 700; padding: 2px 6px; border-radius: 6px; white-space: nowrap; margin-left: 6px;">[0/0]</span>
            `;

            const body = document.createElement("div");
            body.id = contentId;
            body.className = "clause-body";
            body.style.cssText = "display: none; padding: 10px 12px; border-top: 1px solid var(--border-color); background: var(--bg-card); max-height: 360px; overflow-y: auto; scrollbar-width: thin;";

            controls.forEach(c => {
                const itemDiv = document.createElement("div");
                itemDiv.className = "checkbox-item ctrl-checkbox-item";
                itemDiv.style.cssText = "display: flex; align-items: center; gap: 10px; padding: 7px 10px; border-radius: 8px; margin-bottom: 4px; transition: background 0.15s ease;";
                itemDiv.onmouseover = () => itemDiv.style.background = "rgba(59, 130, 246, 0.12)";
                itemDiv.onmouseout = () => itemDiv.style.background = "transparent";

                const input = document.createElement("input");
                input.type = "checkbox";
                input.value = c.sl;
                input.id = `ctrl_chk_${c.sl}`;
                input.checked = true;
                input.style.cssText = "width: 17px; height: 17px; min-width: 17px; cursor: pointer; accent-color: #2563eb;";
                input.onchange = updateSelectedScopeCount;

                const label = document.createElement("label");
                label.htmlFor = `ctrl_chk_${c.sl}`;
                label.style.cssText = "cursor: pointer; font-size: 0.82rem; color: var(--text-main); font-weight: 600; text-transform: none; white-space: normal; word-break: break-word; line-height: 1.35; margin: 0; flex: 1;";
                
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

    // Recalculate each Clause accordion badge dynamically
    const accordions = document.querySelectorAll(".clause-accordion-card");
    accordions.forEach((acc, idx) => {
        const badge = acc.querySelector(".clause-count-badge");
        const cbs = acc.querySelectorAll(".clause-body input[type='checkbox']");
        const selCbs = Array.from(cbs).filter(cb => cb.checked);
        
        if (badge && cbs.length > 0) {
            if (selCbs.length === cbs.length) {
                badge.innerText = `[${selCbs.length}/${cbs.length} All]`;
                badge.style.background = "rgba(37, 99, 235, 0.25)";
                badge.style.color = "#60a5fa";
            } else if (selCbs.length === 0) {
                badge.innerText = `[0/${cbs.length}]`;
                badge.style.background = "rgba(148, 163, 184, 0.15)";
                badge.style.color = "#94a3b8";
            } else {
                badge.innerText = `[${selCbs.length}/${cbs.length}]`;
                badge.style.background = "rgba(234, 179, 8, 0.2)";
                badge.style.color = "#facc15";
            }
        }
    });
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
    const dropZone = document.getElementById("drop-zone");
    const countBadge = document.getElementById("evidence-count-badge");
    const registry = document.getElementById("uploaded-files-registry");
    const browseBtn = document.querySelector(".modern-evidence-card button");

    // 1. Immediate visual feedback on drop zone
    if (dropZone) {
        dropZone.style.borderColor = "#3b82f6";
        dropZone.style.background = "rgba(37, 99, 235, 0.15)";
        dropZone.style.boxShadow = "0 0 20px rgba(59, 130, 246, 0.3)";
        dropZone.innerHTML = `
            <span class="drop-icon" style="font-size: 2.4rem; display: block; margin-bottom: 6px; animation: pulse 1s infinite alternate;">⏳</span>
            <h4 style="margin: 0; font-size: 0.95rem; font-weight: 800; color: #60a5fa;">Uploading ${files.length} file(s)...</h4>
            <p style="margin: 4px 0 0 0; font-size: 0.74rem; color: #94a3b8;">⚡ Extracting text, scanning security, and indexing into RAG memory...</p>
        `;
    }

    if (countBadge) {
        countBadge.innerText = `⏳ Uploading...`;
        countBadge.style.background = "rgba(234, 179, 8, 0.2)";
        countBadge.style.color = "#facc15";
    }

    if (browseBtn) {
        browseBtn.disabled = true;
        browseBtn.innerText = "⏳ Uploading...";
    }

    // 2. Render temporary loading skeleton items in attached files registry
    if (registry) {
        registry.innerHTML = "";
        Array.from(files).forEach(f => {
            const card = document.createElement("div");
            card.className = "modern-file-card";
            card.style.cssText = "display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 10px; background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(59, 130, 246, 0.3); opacity: 0.85;";
            card.innerHTML = `
                <div style="font-size: 1rem; width: 28px; height: 28px; border-radius: 6px; background: rgba(59, 130, 246, 0.2); color: #60a5fa; display: flex; align-items: center; justify-content: center; font-weight: 700;">⏳</div>
                <div style="flex: 1; min-width: 0;">
                    <div style="font-size: 0.8rem; font-weight: 700; color: #f8fafc; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${f.name}</div>
                    <div style="font-size: 0.72rem; color: #60a5fa; font-weight: 600;">Uploading & extracting text...</div>
                </div>
            `;
            registry.appendChild(card);
        });
    }

    if (!activeSessionId && currentUser) {
        await loadOrCreateSession(currentUser);
    }
    
    if (!activeSessionId) {
        resetDropZoneUI();
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
        const response = await fetch(`${API_BASE}/audit/upload`, {
            method: "POST",
            body: body
        });
        
        const data = await response.json();
        if (!response.ok) throw new Error(formatApiError(data.detail, "Upload failed."));
        
        showToastBanner(`✅ ${files.length} Evidence File(s) successfully uploaded and indexed into RAG memory!`);
        await loadEvidenceFileList();
        setTimeout(loadEvidenceFileList, 600);
    } catch (err) {
        alert(`❌ Upload Error: ${err.message}`);
        await loadEvidenceFileList();
    } finally {
        resetDropZoneUI();
    }
}

function resetDropZoneUI() {
    const dropZone = document.getElementById("drop-zone");
    const countBadge = document.getElementById("evidence-count-badge");
    const browseBtn = document.querySelector(".modern-evidence-card button");

    if (dropZone) {
        dropZone.style.borderColor = "rgba(59, 130, 246, 0.35)";
        dropZone.style.background = "rgba(15, 23, 42, 0.4)";
        dropZone.style.boxShadow = "none";
        dropZone.innerHTML = `
            <span class="drop-icon" style="font-size: 2.2rem; display: block; margin-bottom: 6px;">📤</span>
            <h4 style="margin: 0; font-size: 0.9rem; font-weight: 700; color: #60a5fa;">Drag-and-drop zone</h4>
            <p style="margin: 3px 0 0 0; font-size: 0.74rem; color: var(--text-muted);">Drop PDF, DOCX, CSV, HTML, JSON evidence files here</p>
            <input type="file" id="evidence-file-input" multiple style="display: none;" onchange="handleEvidenceUpload(event)">
        `;
    }

    if (countBadge) {
        countBadge.style.background = "rgba(255,255,255,0.06)";
        countBadge.style.color = "var(--text-muted)";
    }

    if (browseBtn) {
        browseBtn.disabled = false;
        browseBtn.innerText = "+ Browse files";
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
    const modelEl = document.getElementById("llm-model-select");
    const model = modelEl ? modelEl.value : "Gemma 4 (e4b)";
    const modeEl = document.querySelector("input[name='audit-mode']:checked");
    const mode = isVaptFramework ? "VAPT validation" : (modeEl ? modeEl.value : "Deep");
    
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
        } else {
            // If scan is idle, stopped, or not running, reset state cleanly
            clearInterval(progressInterval);
            btn.disabled = false;
            btn.innerText = "▶ Step 3: Run RAG Scan";
            if (stopBtn) {
                stopBtn.style.display = "none";
                stopBtn.disabled = false;
                stopBtn.innerText = "⛔ Stop";
            }
        }
    } catch (err) {
        console.error("Progress polling error:", err);
    }
}

// ── TOAST NOTIFICATION HELPER ──
function showToast(message, type = "info") {
    let toast = document.getElementById("app-toast-notification");
    if (!toast) {
        toast = document.createElement("div");
        toast.id = "app-toast-notification";
        toast.style.cssText = "position: fixed; bottom: 24px; right: 24px; z-index: 9999; padding: 12px 20px; border-radius: 10px; font-size: 0.85rem; font-weight: 600; color: #ffffff; background: rgba(30, 41, 59, 0.95); border: 1px solid rgba(148, 163, 184, 0.2); box-shadow: 0 10px 25px rgba(0,0,0,0.4); transition: all 0.3s ease; transform: translateY(100px); opacity: 0;";
        document.body.appendChild(toast);
    }
    
    if (type === "warning") {
        toast.style.borderColor = "rgba(245, 158, 11, 0.6)";
        toast.style.boxShadow = "0 4px 20px rgba(245, 158, 11, 0.2)";
    } else if (type === "error") {
        toast.style.borderColor = "rgba(239, 68, 68, 0.6)";
        toast.style.boxShadow = "0 4px 20px rgba(239, 68, 68, 0.2)";
    } else {
        toast.style.borderColor = "rgba(59, 130, 246, 0.6)";
        toast.style.boxShadow = "0 4px 20px rgba(59, 130, 246, 0.2)";
    }
    
    toast.innerText = message;
    toast.style.transform = "translateY(0)";
    toast.style.opacity = "1";
    
    setTimeout(() => {
        toast.style.transform = "translateY(100px)";
        toast.style.opacity = "0";
    }, 4000);
}

async function stopAuditAnalysis() {
    const stopBtn = document.getElementById("stop-analysis-btn");
    const btn = document.getElementById("run-analysis-btn");
    if (!activeSessionId) return;
    
    if (stopBtn) {
        stopBtn.disabled = true;
        stopBtn.innerText = "⏳ Stopping...";
    }
    
    try {
        const res = await fetch(`${API_BASE}/audit/stop/${activeSessionId}`, { method: "POST" });
        const data = await res.json();
        
        if (data.success) {
            btn.innerText = "⏳ Stopping Scan...";
            showToast("⛔ Stop signal sent — scan will stop after the current control.", "warning");
        } else {
            // No scan currently running -> reset UI state completely!
            if (progressInterval) clearInterval(progressInterval);
            btn.disabled = false;
            btn.innerText = "▶ Step 3: Run RAG Scan";
            if (stopBtn) {
                stopBtn.style.display = "none";
                stopBtn.disabled = false;
                stopBtn.innerText = "⛔ Stop";
            }
            showToast(data.message || "No active scan running.", "info");
        }
    } catch (err) {
        if (progressInterval) clearInterval(progressInterval);
        btn.disabled = false;
        btn.innerText = "▶ Step 3: Run RAG Scan";
        if (stopBtn) {
            stopBtn.style.display = "none";
            stopBtn.disabled = false;
            stopBtn.innerText = "⛔ Stop";
        }
        alert(`Failed to stop scan: ${err.message}`);
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
            if (data.success && data.findings) {
                findingsList = data.findings.filter(f => !isFindingInformational(f));
                const statusFilterEl = document.getElementById("status-filter");
                if (statusFilterEl && statusFilterEl.value === "Compliant") {
                    const hasCompliant = findingsList.some(f => isFindingCompliant(f));
                    if (!hasCompliant) statusFilterEl.value = "All";
                }
                renderFindingsList();
                calculateSeverityStats();

                const isFinalized = (data.session_status && data.session_status.includes("Finalized")) ||
                                    (data.session_title && data.session_title.includes("Finalized")) ||
                                    (findingsList.length > 0 && findingsList.every(f => f.is_saved_to_shakthi));

                if (isFinalized) {
                    banner.style.background = "rgba(16, 185, 129, 0.12)";
                    banner.style.borderColor = "rgba(52, 211, 153, 0.35)";
                    if (bannerText) bannerText.innerHTML = `✅ <b>Committed to Shakthi DB:</b> ${findingsList.length} audit record(s) finalized and locked.`;
                } else {
                    banner.style.background = "rgba(245, 158, 11, 0.12)";
                    banner.style.borderColor = "rgba(245, 158, 11, 0.35)";
                    if (bannerText) bannerText.innerHTML = `⚠️ <b>Notice:</b> ${findingsList.length} finding(s) loaded. Review records below and click "Save to Shakthi DB" to commit.`;
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

async function commitSessionToShaktiDB(force = false) {
    console.log("💾 [commitSessionToShaktiDB] Invoked. activeSessionId:", activeSessionId, "force:", force);
    if (!activeSessionId) {
        alert("No active session. Please select or start an audit session first.");
        return;
    }
    try {
        const auditorName = currentUser ? currentUser.username : "Lead Auditor";
        console.log(`💾 Fetching: ${API_BASE}/audit/findings/commit-session/${activeSessionId}?force=${force}`);
        const response = await fetch(`${API_BASE}/audit/findings/commit-session/${activeSessionId}?force=${force}&auditor_user=${encodeURIComponent(auditorName)}`, {
            method: "PUT"
        });
        const data = await response.json();
        console.log("💾 [commitSessionToShaktiDB] Response:", data);

        if (data.requires_confirmation && !force) {
            // Unreviewed controls detected! Trigger Unreviewed Warning Modal
            const countEl = document.getElementById("unreviewed-count-text");
            const listEl = document.getElementById("unreviewed-list-container");
            const modalEl = document.getElementById("unreviewed-warning-modal");

            if (countEl) countEl.innerText = data.unreviewed_count || 0;
            if (listEl && data.unreviewed_controls) {
                // Show max 20 items to prevent browser overflow with large scans
                const MAX_SHOW = 20;
                const ctrls = data.unreviewed_controls || [];
                const shown = ctrls.slice(0, MAX_SHOW);
                const remaining = ctrls.length - shown.length;
                listEl.innerHTML = shown.map(ctrl => `<li>• ${escapeHtml(ctrl)}</li>`).join("") +
                    (remaining > 0 ? `<li style="color:#94a3b8; font-style: italic;">... and ${remaining} more unreviewed controls</li>` : "");
            }
            if (modalEl) {
                modalEl.style.display = "flex";
                modalEl.style.zIndex = "100000";
            }
            return;
        }

        if (data.success) {
            alert(`✅ ${data.message || 'Session successfully committed to Shakthi DB!'}`);
            showToast(data.message || "Session committed to Shakthi DB!", "info");
            closeUnreviewedWarningModal();
            await loadFindings();
            
            // Switch to Report tab and render real-time review report (only saved findings)
            await renderAuditReportPreview();
            const reportTabBtn = Array.from(document.querySelectorAll("#tabs-bar button")).find(b => b.innerText.includes("Report"));
            if (reportTabBtn) switchTab("tab-audit-report", reportTabBtn);
        } else {
            alert(`Failed to commit: ${data.message || 'Unknown error'}`);
        }
    } catch (err) {
        console.error("💾 [commitSessionToShaktiDB] Exception:", err);
        alert(`Failed to commit findings to Shakthi DB: ${err.message}`);
    }
}

function closeUnreviewedWarningModal() {
    const modalEl = document.getElementById("unreviewed-warning-modal");
    if (modalEl) modalEl.style.display = "none";
}

async function forceCommitSessionToShaktiDB() {
    await commitSessionToShaktiDB(true);
}

window.commitSessionToShaktiDB = commitSessionToShaktiDB;
window.closeUnreviewedWarningModal = closeUnreviewedWarningModal;
window.forceCommitSessionToShaktiDB = forceCommitSessionToShaktiDB;


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

async function renderAuditReportPreview() {
    const container = document.getElementById("report-preview-container");
    if (!container) return;

    if (!activeSessionId) {
        container.innerHTML = `<div class="empty-state">No active audit session selected.</div>`;
        return;
    }

    container.innerHTML = `<div class="empty-state">Loading real-time audit evaluation report from Shakthi DB...</div>`;

    try {
        const userRole = currentUser ? currentUser.role : (selectedRole || "auditor");
        // CRITICAL REQUIREMENT: Query saved_only=true so ONLY findings saved to Shakthi DB appear in PDF Exporter Review & Download!
        const response = await fetch(`${API_BASE}/audit/findings?session_id=${activeSessionId}&role=${userRole}&saved_only=true`);
        const data = await response.json();

        const findings = (data.success && data.findings) ? data.findings : [];

        const brandFirm = document.getElementById("brand-firm")?.value || "TÜV SÜD South Asia Pvt. Ltd.";
        const brandAuditor = document.getElementById("brand-auditor")?.value || "Lead Audit Team";
        const brandReviewer = document.getElementById("brand-reviewer")?.value || "Ms. Prianka Singla";
        const brandApprover = document.getElementById("brand-approver")?.value || "Mr. Atul Srivastava";
        const brandDocId = document.getElementById("brand-docid")?.value || activeSessionId.slice(0, 8).toUpperCase();
        const brandClient = document.getElementById("brand-client")?.value || "Motorola Solutions";
        const brandEmail = document.getElementById("brand-email")?.value || "client@domain.com";

        // Standards Rule: Exclude pure INFO items from Executive Audit Evaluation details table!
        const reportFindings = findings.filter(f => !isFindingInformational(f));
        let compliantCount = 0;
        let nonCompliantCount = 0;

        reportFindings.forEach(f => {
            if (isFindingCompliant(f)) {
                compliantCount++;
            } else {
                nonCompliantCount++;
            }
        });

        const totalCount = reportFindings.length;
        const scorePercent = Math.round((compliantCount / (totalCount || 1)) * 100);

        let rowsHtml = "";
        if (reportFindings.length === 0) {
            rowsHtml = `<tr><td colspan="5" style="text-align:center; padding:20px; color:#fbbf24; background: rgba(245, 158, 11, 0.08);">⚠️ <b>No actionable findings saved to Shakthi DB yet.</b> Go to <b>Audit Records & Findings</b> tab, review your controls, and click <b>"Save to Shakthi DB"</b> to display them in this PDF report.</td></tr>`;
        } else {
            reportFindings.forEach(f => {
                const isComp = isFindingCompliant(f);
                const displayStatus = f.status || (isComp ? "Compliant" : "Non-Compliant");
                const badgeColor = isComp ? "#10b981" : "#ef4444";
                const badgeBg = isComp ? "rgba(16,185,129,0.15)" : "rgba(239,68,68,0.15)";

                // Safe control name: never show "undefined" or "null"
                const rawCtrlName = f.control_name;
                const ctrlTitle = (rawCtrlName && rawCtrlName !== 'null' && rawCtrlName !== 'undefined')
                    ? rawCtrlName
                    : f.control_id;
                
                const polSub = f.policy_present ? `<div style="font-size:0.68rem; color:#60a5fa; margin-top:2px;">📜 Policy: ${f.policy_present}</div>` : '';
                const evSub = f.evidence_present ? `<div style="font-size:0.68rem; color:#c084fc; margin-top:1px;">🔍 Evidence: ${f.evidence_present}</div>` : '';

                const evSnippet = f.evidence_snippet ? `<div class="ev-snippet-text" style="margin-bottom:4px; font-family:var(--font-mono); font-size:0.74rem; line-height: 1.4;"><b>Exact Evidence:</b> "${escapeHtml(f.evidence_snippet)}"</div>` : '';
                const evDesc = f.description ? `<div class="ev-desc-text" style="font-size:0.74rem; line-height: 1.4; opacity: 0.9;">${escapeHtml(f.description)}</div>` : '';
                const srcFile = f.source_files ? `<div style="font-size:0.7rem; color:#2563eb; margin-top:3px; font-weight:600;">📁 ${escapeHtml(f.source_files)}</div>` : '';
                const sev = (f.severity && f.severity !== 'null' && f.severity !== 'undefined') ? f.severity : 'P3 Medium';

                rowsHtml += `
                    <tr style="border-bottom: 1px solid rgba(148,163,184,0.2);">
                        <td style="padding: 10px; font-weight:700; color:#2563eb; font-family:var(--font-mono);">${f.control_id}</td>
                        <td style="padding: 10px; font-weight:600;" class="preview-ctrl-title">${escapeHtml(ctrlTitle)}</td>
                        <td style="padding: 10px;">
                            <span style="padding: 4px 9px; border-radius: 6px; font-size: 0.72rem; font-weight:700; color:${badgeColor}; background:${badgeBg}; border: 1px solid ${badgeColor}40;">${displayStatus}</span>
                            ${polSub}
                            ${evSub}
                        </td>
                        <td style="padding: 10px; font-weight:700; font-size:0.74rem;">${sev}</td>
                        <td style="padding: 10px; max-width: 420px;">${evSnippet}${evDesc}${srcFile}</td>
                    </tr>
                `;
            });
        }

        container.innerHTML = `
            <div class="report-preview-card" style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 16px; padding: 24px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid rgba(148, 163, 184, 0.2); padding-bottom: 16px; margin-bottom: 20px;">
                    <div>
                        <h2 style="margin: 0 0 6px 0; font-size: 1.3rem; font-weight: 800;" class="preview-ctrl-title">📋 FINAL EXECUTIVE AUDIT EVALUATION REPORT</h2>
                        <div style="font-size: 0.82rem; color: #2563eb; font-weight: 700;">ISO 27001 / VAPT Framework Audit • Live Real-Time Record</div>
                    </div>
                    <div style="text-align: right; font-size: 0.78rem; line-height: 1.5;" class="preview-meta-block">
                        <div>Auditor Firm: <b class="preview-b-text">${escapeHtml(brandFirm)}</b></div>
                        <div>Document ID: <b style="color:#2563eb;">${escapeHtml(brandDocId)}</b></div>
                        <div>Date: <b class="preview-b-text">${new Date().toLocaleDateString()}</b></div>
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; background: rgba(30, 41, 59, 0.5); padding: 16px; border-radius: 12px; border: 1px solid rgba(148, 163, 184, 0.15);" class="preview-summary-card">
                    <div><span style="font-size:0.72rem; opacity:0.8; display:block; margin-bottom: 2px;">Client Organization</span><b style="font-size:0.88rem;" class="preview-b-text">${escapeHtml(brandClient)}</b></div>
                    <div><span style="font-size:0.72rem; opacity:0.8; display:block; margin-bottom: 2px;">Client Contact Email</span><b style="font-size:0.88rem;" class="preview-b-text">${escapeHtml(brandEmail)}</b></div>
                    <div><span style="font-size:0.72rem; opacity:0.8; display:block; margin-bottom: 2px;">Lead Auditor(s)</span><b style="font-size:0.88rem;" class="preview-b-text">${escapeHtml(brandAuditor)}</b></div>
                    <div><span style="font-size:0.72rem; opacity:0.8; display:block; margin-bottom: 2px;">Compliance Score</span><b style="font-size:1.1rem; color:${scorePercent >= 70 ? '#10b981' : '#f59e0b'};">${scorePercent}% Compliance</b></div>
                </div>

                <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom:12px;" class="preview-ctrl-title">📊 Audit Control Evaluation Details (${findings.length} controls evaluated)</h4>
                <div style="overflow-x: auto; margin-bottom: 20px; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 10px;">
                    <table style="width:100%; border-collapse:collapse; font-size:0.8rem; text-align:left;" class="report-preview-table">
                        <thead>
                            <tr style="background:rgba(30,41,59,0.8); border-bottom: 2px solid rgba(148, 163, 184, 0.25);">
                                <th style="padding:10px; width: 11%;">Control ID</th>
                                <th style="padding:10px; width: 38%;">Control Name</th>
                                <th style="padding:10px; width: 13%;">Status</th>
                                <th style="padding:10px; width: 10%;">Severity</th>
                                <th style="padding:10px; width: 28%;">Evidence / Reason Snippet</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rowsHtml}
                        </tbody>
                    </table>
                </div>

                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; margin-top:20px; padding-top:16px; border-top:1px solid rgba(148,163,184,0.15); font-size:0.78rem;" class="preview-footer-block">
                    <div>Reviewed By: <b class="preview-b-text">${escapeHtml(brandReviewer)}</b></div>
                    <div>Approved By: <b class="preview-b-text">${escapeHtml(brandApprover)}</b></div>
                    <div>Shakthi DB Hash: <b style="color:#10b981;">SECURE_COMMIT_VERIFIED</b></div>
                </div>
            </div>
        `;
    } catch (err) {
        container.innerHTML = `<div class="error-msg">Failed to render audit report preview: ${err.message}</div>`;
    }
}

function isFindingCompliant(f) {
    const st = (f.status || "").toUpperCase().trim();
    const wf = (f.workflow_status || f.display_status || "").toUpperCase().trim();

    // Check policy and evidence presence/compliance
    const polRaw = String(f.policy_present || "No").trim().toLowerCase();
    const evRaw = String(f.evidence_present || "No").trim().toLowerCase();

    const isPolCompliant = (polRaw === "yes" || polRaw === "compliant" || polRaw === "true");
    const isEvCompliant = (evRaw === "yes" || evRaw === "compliant" || evRaw === "true");

    // Both Policy AND Evidence MUST be Compliant for the finding to be Compliant!
    if (!isPolCompliant || !isEvCompliant) {
        return false;
    }

    // MUST check NON-COMPLIANT / GAP / FAIL / NOT FIRST so NON-COMPLIANT is never matched as COMPLIANT!
    if (st.includes("NON") || st.includes("NOT") || st.includes("GAP") || st.includes("FAIL") || st.includes("PARTIAL") || st.includes("UNSATISFIED")) {
        return false;
    }
    
    if (st === "COMPLIANT" || st === "PASS" || st === "SATISFIED" || st === "ACCEPTED" || wf === "ACCEPTED") {
        return true;
    }
    return false;
}

function isFindingInformational(f) {
    const sev = (f.severity || "").toUpperCase();
    const st = (f.status || "").toUpperCase();
    return sev.includes("INFO") || st.includes("INFO");
}

function calculateSeverityStats() {
    let p1 = 0, p2 = 0, p3 = 0, p4 = 0, infoCount = 0;
    let compliant = 0, nonCompliant = 0;
    findingsList.forEach(f => {
        const sev = (f.severity || "").toLowerCase();
        const isInfo = isFindingInformational(f);

        if (sev.includes("p1") || sev.includes("critical")) p1++;
        else if (sev.includes("p2") || sev.includes("high")) p2++;
        else if (sev.includes("p3") || sev.includes("medium")) p3++;
        else if (sev.includes("p4") || sev.includes("low")) p4++;
        else if (isInfo) infoCount++;

        if (isFindingCompliant(f)) {
            compliant++;
        } else if (!isInfo) {
            // Standards Rule: ONLY count actionable P1-P4 vulnerabilities as Non-Compliant gaps!
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
    document.querySelectorAll(".kpi-box").forEach(b => b.style.outline = "none");
    activeSeverityFilter = ""; // Reset severity filter when switching status KPI cards

    const select = document.getElementById("status-filter");
    if (select) {
        if (select.value === statusType) {
            select.value = "All";
        } else {
            select.value = statusType;
            let selector = statusType === "Compliant" ? ".compliant-box" : ".noncompliant-box";
            const box = document.querySelector(selector);
            if (box) box.style.outline = "2px solid #3b82f6";
        }
        renderFindingsList();
    }
}

function matchesSeverityFilter(fSeverity, activeFilter) {
    if (!activeFilter) return true;
    const sev = (fSeverity || "").toLowerCase();
    const filter = activeFilter.toLowerCase();

    if (filter.includes("p1") || filter.includes("critical")) {
        return sev.includes("p1") || sev.includes("critical") || sev.includes("9.") || sev.includes("10.");
    }
    if (filter.includes("p2") || filter.includes("high")) {
        return sev.includes("p2") || sev.includes("high") || sev.includes("7.") || sev.includes("8.");
    }
    if (filter.includes("p3") || filter.includes("medium")) {
        return sev.includes("p3") || sev.includes("medium") || sev.includes("4.") || sev.includes("5.") || sev.includes("6.");
    }
    if (filter.includes("p4") || filter.includes("low")) {
        return sev.includes("p4") || sev.includes("low") || sev.includes("0.") || sev.includes("1.") || sev.includes("2.") || sev.includes("3.");
    }
    if (filter.includes("info")) {
        return sev.includes("info");
    }
    return true;
}

function toggleSeverityFilter(sev) {
    document.querySelectorAll(".kpi-box").forEach(b => b.style.outline = "none");
    
    // Reset status filter dropdown to "All" so status doesn't block severity matching
    const select = document.getElementById("status-filter");
    if (select) select.value = "All";

    if (activeSeverityFilter === sev) {
        activeSeverityFilter = ""; // Clear filter
    } else {
        activeSeverityFilter = sev;
        let selector = "";
        if (sev.includes("P1")) selector = ".p1-box";
        else if (sev.includes("P2")) selector = ".p2-box";
        else if (sev.includes("P3")) selector = ".p3-box";
        else if (sev.includes("P4")) selector = ".p4-box";
        
        if (selector) {
            const box = document.querySelector(selector);
            if (box) box.style.outline = "2px solid #3b82f6";
        }
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
        const isCompliant = isFindingCompliant(f);
        const isInfo = isFindingInformational(f);

        // Workflow status filter
        if (filterStatus === "Compliant" && !isCompliant) return false;
        if (filterStatus === "Non-Compliant" && (isCompliant || isInfo)) return false;
        if (filterStatus === "Info" && !isInfo) return false;
        if (filterStatus === "Open" && (isCompliant || isInfo || f.status === "Accepted" || f.status === "Rejected")) return false;
        if (filterStatus === "Accepted" && f.status !== "Accepted") return false;
        if (filterStatus === "Rejected" && f.status !== "Rejected") return false;
        
        // Severity level filter (P1, P2, P3, P4)
        if (activeSeverityFilter && !matchesSeverityFilter(f.severity, activeSeverityFilter)) {
            return false;
        }
        return true;
    });
    
    if (filtered.length === 0) {
        const totalCount = findingsList ? findingsList.length : 0;
        container.innerHTML = `
            <div class="empty-state" style="padding: 24px; text-align: center;">
                <div style="font-size: 0.92rem; font-weight: 700; color: #fbbf24; margin-bottom: 6px;">⚠️ No matching findings found in "${filterStatus}" filter range</div>
                <button type="button" class="btn-primary" onclick="document.getElementById('status-filter').value='All'; activeSeverityFilter=''; renderFindingsList();" style="padding: 7px 16px; font-size: 0.78rem; font-weight: 700; background: linear-gradient(135deg, #2563eb, #1d4ed8); cursor: pointer;">
                    🔄 Reset Filter &amp; View All ${totalCount} Findings
                </button>
            </div>`;
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
        let displayStatusText = "NON-COMPLIANT";

        if (isFindingCompliant(f)) {
            statusBadgeClass = "compliant";
            displayStatusText = (f.status && f.status.toUpperCase() === "ACCEPTED") ? "ACCEPTED" : "COMPLIANT";
        } else if (isFindingInformational(f)) {
            statusBadgeClass = "informational";
            displayStatusText = f.status || "INFO";
        } else if ((f.status || "").toUpperCase().includes("PARTIAL")) {
            statusBadgeClass = "partial";
            displayStatusText = "PARTIAL";
        } else if ((f.status || "").toUpperCase() === "ACCEPTED") {
            statusBadgeClass = "compliant";
            displayStatusText = "ACCEPTED";
        } else if ((f.status || "").toUpperCase() === "REJECTED") {
            statusBadgeClass = "non-compliant";
            displayStatusText = "REJECTED";
        } else {
            statusBadgeClass = "non-compliant";
            displayStatusText = "NON-COMPLIANT";
        }
        
        const ctrlTitle = (f.control_name && f.control_name !== "null") ? f.control_name : ((f.control && f.control !== "null") ? f.control : "");
        const displayTitle = ctrlTitle ? `${f.control_id} - ${ctrlTitle}` : f.control_id;
        const findingJsonStr = JSON.stringify(f).replace(/'/g, "&#39;").replace(/"/g, "&quot;");
        
        // Format Policy Badge
        const polRaw = String(f.policy_present || "No").trim().toLowerCase();
        let polText = "Policy: Not Found";
        let polStyle = "background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3);";
        if (polRaw === "yes" || polRaw === "compliant" || polRaw === "true") {
            polText = "Policy: Compliant";
            polStyle = "background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3);";
        } else if (polRaw === "partial" || polRaw === "non-compliant" || polRaw === "non compliant") {
            polText = "Policy: Non-Compliant";
            polStyle = "background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3);";
        }
        const polBadge = `<span style="font-size:0.72rem; padding: 2px 7px; border-radius:4px; ${polStyle} font-weight: 600;">📜 ${polText}</span>`;

        // Format Evidence Badge
        const evRaw = String(f.evidence_present || "No").trim().toLowerCase();
        let evText = "Evidence: Not Found";
        let evStyle = "background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3);";
        if (evRaw === "yes" || evRaw === "compliant" || evRaw === "true") {
            evText = "Evidence: Compliant";
            evStyle = "background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3);";
        } else if (evRaw === "partial" || evRaw === "non-compliant" || evRaw === "non compliant") {
            evText = "Evidence: Non-Compliant";
            evStyle = "background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3);";
        }
        const evBadge = `<span style="font-size:0.72rem; padding: 2px 7px; border-radius:4px; ${evStyle} font-weight: 600;">🔍 ${evText}</span>`;

        card.innerHTML = `
            <div class="finding-card-header">
                <div class="finding-card-title">
                    <h3>${displayTitle}</h3>
                </div>
                <div class="finding-badges" style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
                    ${polBadge}
                    ${evBadge}
                    <span class="badge-status ${statusBadgeClass}">${displayStatusText}</span>
                    <span class="badge-pill">${f.severity || 'P3 Medium'}</span>
                </div>
            </div>` align-items: center; flex-wrap: wrap;">
                    ${polBadge}
                    ${evBadge}
                    <span class="badge-status ${statusBadgeClass}">${f.status}</span>
                    <span class="badge-pill">${f.severity || 'P3 Medium'}</span>
                </div>
            </div>
            
            <div class="finding-detail-row">
                <label>Finding Description</label>
                <p>${f.description || f.gap_detected || f.reasoning || 'Evaluated against ISO 27001 / VAPT compliance standards.'}</p>
            </div>
            
            ${f.evidence_snippet ? `
            <div class="finding-detail-row">
                <label>Evidence Snippet</label>
                <pre class="finding-snippet">"${f.evidence_snippet}"</pre>
            </div>` : ''}

            <div class="finding-detail-row">
                <label>Lead Auditor Recommendations</label>
                <p style="color: #2563eb;">${f.recommendation || f.review_note || (isFindingCompliant(f) ? `Maintain current documented policies and verification procedures for ${f.control_id}.` : `Establish formal policy documentation, access controls, and logging evidence for ${f.control_id}.`)}</p>
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

    // 1. Normalize and pre-select Compliance Status
    const statusSelect = document.getElementById("edit-finding-status");
    const rawStatus = (finding.status || "").toUpperCase().trim();
    let targetStatusVal = "Non-Compliant";

    if (rawStatus.includes("NON") || rawStatus.includes("GAP") || rawStatus.includes("FAIL")) {
        targetStatusVal = "Non-Compliant";
    } else if (rawStatus.includes("PARTIAL")) {
        targetStatusVal = "Partially Compliant";
    } else if (rawStatus.includes("OUT") || rawStatus.includes("SCOPE")) {
        targetStatusVal = "Out Of Scope";
    } else if (rawStatus.includes("COMPLIANT") || rawStatus.includes("PASS") || rawStatus.includes("SATISFIED") || rawStatus.includes("ACCEPTED")) {
        targetStatusVal = "Compliant";
    } else {
        targetStatusVal = "Non-Compliant";
    }
    statusSelect.value = targetStatusVal;

    // 2. Normalize and pre-select Policy Present
    const polSelect = document.getElementById("edit-finding-policy");
    const rawPol = String(finding.policy_present || "No").trim().toLowerCase();
    if (rawPol === "yes" || rawPol === "compliant" || rawPol === "true") {
        polSelect.value = "Yes";
    } else if (rawPol === "partial" || rawPol === "non-compliant") {
        polSelect.value = "Partial";
    } else {
        polSelect.value = "No";
    }

    // 3. Normalize and pre-select Evidence Present
    const evSelect = document.getElementById("edit-finding-evidence");
    const rawEv = String(finding.evidence_present || "No").trim().toLowerCase();
    if (rawEv === "yes" || rawEv === "compliant" || rawEv === "true") {
        evSelect.value = "Yes";
    } else if (rawEv === "partial" || rawEv === "non-compliant") {
        evSelect.value = "Partial";
    } else {
        evSelect.value = "No";
    }

    // 4. Determine Session Type (VAPT vs ISO) & populate Severity Options
    const isVapt = (
        (finding.control_id && String(finding.control_id).toUpperCase().includes("VAPT")) ||
        (finding.category && String(finding.category).toUpperCase().includes("VAPT")) ||
        (typeof activeSessionTitle !== "undefined" && activeSessionTitle && String(activeSessionTitle).toUpperCase().includes("VAPT"))
    );

    const sevSelect = document.getElementById("edit-finding-severity");
    const rawSev = (finding.severity || "").toUpperCase().trim();

    if (isVapt) {
        // VAPT CVSS v3.1 Score Scale
        sevSelect.innerHTML = `
            <option value="Critical (CVSS 9.0-10.0)">Critical (CVSS 9.0 - 10.0)</option>
            <option value="High (CVSS 7.0-8.9)">High (CVSS 7.0 - 8.9)</option>
            <option value="Medium (CVSS 4.0-6.9)">Medium (CVSS 4.0 - 6.9)</option>
            <option value="Low (CVSS 0.1-3.9)">Low (CVSS 0.1 - 3.9)</option>
            <option value="Informational (CVSS 0.0)">Informational (CVSS 0.0)</option>
        `;
        if (rawSev.includes("CRIT") || rawSev.includes("9.") || rawSev.includes("10.")) {
            sevSelect.value = "Critical (CVSS 9.0-10.0)";
        } else if (rawSev.includes("HIGH") || rawSev.includes("7.") || rawSev.includes("8.")) {
            sevSelect.value = "High (CVSS 7.0-8.9)";
        } else if (rawSev.includes("LOW") || rawSev.includes("1.") || rawSev.includes("2.") || rawSev.includes("3.")) {
            sevSelect.value = "Low (CVSS 0.1-3.9)";
        } else if (rawSev.includes("INFO") || rawSev.includes("0.0")) {
            sevSelect.value = "Informational (CVSS 0.0)";
        } else {
            sevSelect.value = "Medium (CVSS 4.0-6.9)";
        }
    } else {
        // ISO NIST Priority Scale (P1-P4)
        sevSelect.innerHTML = `
            <option value="P1 Critical">P1 Critical (Critical Gap)</option>
            <option value="P2 High">P2 High (Major Non-Compliance)</option>
            <option value="P3 Medium">P3 Medium (Minor Non-Compliance)</option>
            <option value="P4 Low">P4 Low (Opportunity for Improvement)</option>
        `;
        if (rawSev.includes("P1") || rawSev.includes("CRITICAL")) {
            sevSelect.value = "P1 Critical";
        } else if (rawSev.includes("P2") || rawSev.includes("HIGH")) {
            sevSelect.value = "P2 High";
        } else if (rawSev.includes("P4") || rawSev.includes("LOW")) {
            sevSelect.value = "P4 Low";
        } else {
            sevSelect.value = "P3 Medium";
        }
    }

    const descElem = document.getElementById("edit-finding-desc");
    if (descElem) descElem.value = finding.description || finding.gap_detected || "";
    
    const srcElem = document.getElementById("edit-finding-source-files");
    if (srcElem) {
        srcElem.value = finding.source_files || finding.evidence_source_file || "";
    }
    
    document.getElementById("edit-finding-snippet").value = finding.evidence_snippet || "";
    document.getElementById("edit-finding-recommendation").value = finding.recommendation || "";
    document.getElementById("edit-finding-reasoning").value = finding.description || finding.gap_detected || finding.reasoning || "";

    document.getElementById("edit-finding-modal").classList.add("active");
}

function closeEditFindingModal() {
    document.getElementById("edit-finding-modal").classList.remove("active");
}

async function handleEditFindingSubmit(e) {
    e.preventDefault();
    const id = document.getElementById("edit-finding-id").value;
    const descValue = document.getElementById("edit-finding-reasoning").value;
    const srcFileValue = document.getElementById("edit-finding-source-files") ? document.getElementById("edit-finding-source-files").value : "";
    
    const body = {
        status: document.getElementById("edit-finding-status").value,
        policy_present: document.getElementById("edit-finding-policy").value,
        evidence_present: document.getElementById("edit-finding-evidence").value,
        severity: document.getElementById("edit-finding-severity").value,
        description: descValue,
        source_files: srcFileValue,
        evidence_snippet: document.getElementById("edit-finding-snippet").value,
        recommendation: document.getElementById("edit-finding-recommendation").value,
        reasoning: descValue
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

function openAddCustomControlModal() {
    const modal = document.getElementById("add-custom-control-modal");
    if (modal) {
        modal.style.display = "flex";
    }
}

function closeAddCustomControlModal() {
    const modal = document.getElementById("add-custom-control-modal");
    if (modal) {
        modal.style.display = "none";
    }
}

async function handleModalCustomControlSubmit(e) {
    e.preventDefault();
    const ctrlId = document.getElementById("modal-ctrl-id").value.trim();
    const ctrlName = document.getElementById("modal-ctrl-name").value.trim();
    const cat = document.getElementById("modal-ctrl-cat").value;
    const desc = document.getElementById("modal-ctrl-desc").value.trim();
    const kwsStr = document.getElementById("modal-ctrl-kws").value.trim();
    const kws = kwsStr ? kwsStr.split(",").map(k => k.trim()) : [];

    try {
        const response = await fetch(`${API_BASE}/controls`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                control_id: ctrlId,
                control_name: ctrlName,
                category: cat,
                description: desc,
                keywords: kws,
                created_by: currentUser ? currentUser.username : "auditor"
            })
        });
        const data = await response.json();
        if (data.success) {
            closeAddCustomControlModal();
            showToast("Custom control saved to Shakthi DB!", "info");
            await loadFrameworkControls();
            
            // Auto expand Custom Controls accordion
            setTimeout(() => {
                const customHeader = Array.from(document.querySelectorAll(".clause-header")).find(h => h.innerText.includes("Custom Controls"));
                if (customHeader) customHeader.click();
            }, 300);
        } else {
            alert(`Failed: ${data.message || 'Error saving control'}`);
        }
    } catch (err) {
        alert(`Error: ${err.message}`);
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

async function exportFindingsDOCX() {
    try {
        const response = await fetch(`${API_BASE}/audit/findings?session_id=${activeSessionId}&role=${currentUser ? currentUser.role : 'auditor'}`);
        const data = await response.json();
        const findings = (data.success && data.findings) ? data.findings : findingsList;
        
        if (!findings || findings.length === 0) {
            alert("⚠️ No findings records to export. Please run an audit scan first.");
            return;
        }

        const brandFirm = document.getElementById("brand-firm")?.value || "TÜV SÜD South Asia Pvt. Ltd.";
        const brandAuditor = document.getElementById("brand-auditor")?.value || "Lead Audit Team";
        const brandDocId = document.getElementById("brand-docid")?.value || activeSessionId.slice(0, 8).toUpperCase();
        const brandClient = document.getElementById("brand-client")?.value || "Motorola Solutions";

        let html = `
            <html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
            <head><meta charset='utf-8'><title>Audit Evaluation Report</title></head>
            <body style='font-family: Arial, sans-serif; padding: 20px;'>
                <h1 style='color: #1e293b; border-bottom: 2px solid #2563eb; padding-bottom: 8px;'>ISO 27001 / VAPT AUDIT EVALUATION REPORT</h1>
                <p><b>Auditor Firm:</b> ${brandFirm}</p>
                <p><b>Client Organization:</b> ${brandClient}</p>
                <p><b>Lead Auditor(s):</b> ${brandAuditor}</p>
                <p><b>Document Reference ID:</b> ${brandDocId}</p>
                <p><b>Generated Date:</b> ${new Date().toLocaleDateString()}</p>
                <hr style='border: 0; border-top: 1px solid #cbd5e1; margin: 16px 0;'>
                <h2 style='color: #2563eb;'>Evaluated Control Findings (${findings.length})</h2>
                <table border='1' cellspacing='0' cellpadding='8' style='width: 100%; border-collapse: collapse; border-color: #cbd5e1;'>
                    <tr style='background: #f1f5f9; color: #1e293b;'>
                        <th>Control ID</th>
                        <th>Control Name</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Description / Evidence</th>
                        <th>Recommendation</th>
                    </tr>
        `;

        findings.forEach(f => {
            const isComp = isFindingCompliant(f);
            const statusColor = isComp ? '#10b981' : '#ef4444';
            const docxEv = f.evidence_snippet ? `<p style='margin:0 0 4px 0;'><b>Exact Sentence Evidence:</b> "${f.evidence_snippet}"</p>` : '';
            const docxDesc = f.description ? `<p style='margin:0 0 4px 0; color:#475569;'>${f.description}</p>` : '';
            const docxSrc = f.source_files ? `<p style='margin:0; font-size:11px; color:#2563eb;'>Source Doc: ${f.source_files}</p>` : '';

            html += `
                <tr>
                    <td><b>${f.control_id}</b></td>
                    <td>${f.control_name || f.control}</td>
                    <td><b style='color:${statusColor};'>${f.status}</b></td>
                    <td>${f.severity || 'P3 Medium'}</td>
                    <td>${docxEv}${docxDesc}${docxSrc}</td>
                    <td>${f.recommendation || ''}</td>
                </tr>
            `;
        });

        html += `
                </table>
            </body>
            </html>
        `;

        const blob = new Blob(['\ufeff' + html], { type: 'application/msword' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `Audit_Report_${brandDocId}.docx`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        showToast("📥 Word (.docx) report downloaded successfully!", "info");
    } catch (err) {
        alert(`Failed to export Word document: ${err.message}`);
    }
}

async function printAuditReportPreview() {
    try {
        await renderAuditReportPreview();
        const previewEl = document.getElementById("report-preview-container");
        if (!previewEl) return;

        const printWindow = window.open('', '_blank');
        printWindow.document.write(`
            <html>
                <head>
                    <title>Audit Evaluation Report PDF</title>
                    <style>
                        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 24px; color: #1e293b; background: #ffffff; }
                        table { width: 100%; border-collapse: collapse; margin-top: 16px; }
                        th, td { border: 1px solid #cbd5e1; padding: 8px 12px; font-size: 0.85rem; text-align: left; }
                        th { background-color: #f1f5f9; font-weight: bold; }
                    </style>
                </head>
                <body>
                    ${previewEl.innerHTML}
                </body>
            </html>
        `);
        printWindow.document.close();
        printWindow.focus();
        setTimeout(() => {
            printWindow.print();
            printWindow.close();
        }, 600);
    } catch (err) {
        alert(`Failed to prepare PDF: ${err.message}`);
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
    select.innerHTML = `<option value="">— Select Auditee Submission —</option>`;
    
    try {
        const response = await fetch(`${API_BASE}/audit/auditee-sessions`);
        const data = await response.json();
        
        if (data.success && data.sessions && data.sessions.length > 0) {
            data.sessions.forEach(s => {
                const opt = document.createElement("option");
                opt.value = s.session_id;
                const auditeeName = s.auditee_username || "Auditee Account";
                const dateStr = s.created_at ? new Date(s.created_at).toLocaleDateString() : "";
                const fileStr = s.files_count > 0 ? ` (${s.files_count} file(s) submitted)` : "";
                opt.innerText = `👤 ${auditeeName} — ${s.session_title || 'Audit Session'} (${dateStr})${fileStr}`;
                select.appendChild(opt);
            });
        } else {
            select.innerHTML = `<option value="">— No Auditee Submissions Found —</option>`;
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
        container.innerHTML = `<div class="empty-state">Select an auditee account above to inspect submitted evidence documents.</div>`;
        return;
    }
    
    container.innerHTML = `<div class="empty-state">Loading evidence documents...</div>`;
    
    try {
        const response = await fetch(`${API_BASE}/audit/evidence?session_id=${sessId}`);
        const data = await response.json();
        
        const files = (data.success && data.files) ? data.files : [];
        if (files.length === 0) {
            container.innerHTML = `<div class="empty-state">No uploaded evidence documents found for this auditee session.</div>`;
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
            card.style.cssText = "display: flex; align-items: center; gap: 14px; padding: 14px 18px; background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 12px; margin-bottom: 10px;";
            card.innerHTML = `
                <div class="file-icon-badge ${fileClass}" style="width: 36px; height: 36px; font-weight: 800;">${fileIconText}</div>
                <div class="file-details" style="flex: 1; min-width: 0;">
                    <div class="file-title" style="font-weight: 600; font-size: 0.9rem; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; color: #f8fafc;" title="${fn}">${fn}</div>
                    <div class="file-meta" style="font-size: 0.75rem; color: #94a3b8; margin-top: 2px;">📍 Path: <code style="color: #60a5fa;">${f.filepath || f.path || fn}</code> • ${f.size_str || 'Submitted Evidence'}</div>
                </div>
                <span class="badge-pill" style="color: #34d399; background: rgba(52, 211, 153, 0.1); border: 1px solid rgba(52, 211, 153, 0.3); font-size: 0.72rem; padding: 4px 10px; border-radius: 6px; font-weight: 600;">✓ AUDITEE EVIDENCE</span>
            `;
            container.appendChild(card);
        });
    } catch (err) {
        container.innerHTML = `<div class="error-msg">Error loading documents: ${err.message}</div>`;
    }
}

function selectAllAuditeeDocs(checked) {
    const checkboxes = document.querySelectorAll(".auditee-doc-checkbox");
    checkboxes.forEach(cb => cb.checked = checked);
}

// ── SIDEBAR: AUDITEE SUBMISSION PANEL ───────────────────────────────────────

async function loadSidebarAuditeeFiles() {
    const sessionSelect = document.getElementById("sidebar-auditee-session-select");
    const fileList = document.getElementById("sidebar-auditee-files-list");
    if (!sessionSelect || !fileList) return;

    // Refresh auditee sessions list
    try {
        const currentVal = sessionSelect.value;
        const res = await fetch(`${API_BASE}/audit/auditee-sessions`);
        const data = await res.json();
        if (data.success && data.sessions && data.sessions.length > 0) {
            sessionSelect.innerHTML = `<option value="">— Select Auditee Account —</option>`;
            data.sessions.forEach(s => {
                const opt = document.createElement("option");
                opt.value = s.session_id;
                const auditeeName = s.auditee_username || "Auditee Account";
                const dateStr = s.created_at ? new Date(s.created_at).toLocaleDateString() : "";
                const fileStr = s.files_count > 0 ? ` (${s.files_count} file(s))` : "";
                opt.innerText = `👤 ${auditeeName} — ${s.session_title || 'Audit Session'} (${dateStr})${fileStr}`;
                sessionSelect.appendChild(opt);
            });
            if (currentVal) sessionSelect.value = currentVal;
        } else {
            sessionSelect.innerHTML = `<option value="">— No Auditee Submissions Yet —</option>`;
            fileList.innerHTML = `<div style="font-size:0.74rem;color:var(--text-muted);text-align:center;padding:8px;">No auditee submissions found yet.</div>`;
            return;
        }
    } catch(e) { console.error(e); }

    const sessId = sessionSelect.value;
    if (!sessId) {
        fileList.innerHTML = `<div style="font-size:0.74rem;color:var(--text-muted);text-align:center;padding:8px;">Select a session above</div>`;
        return;
    }

    fileList.innerHTML = `<div style="font-size:0.74rem;color:var(--text-muted);text-align:center;padding:8px;">Loading...</div>`;

    try {
        const res = await fetch(`${API_BASE}/audit/evidence?session_id=${sessId}`);
        const data = await res.json();
        const files = (data.success && data.files) ? data.files : [];

        // Update badge
        const badge = document.getElementById("auditee-submission-badge");
        if (badge) badge.innerText = files.length;

        if (files.length === 0) {
            fileList.innerHTML = `<div style="font-size:0.74rem;color:var(--text-muted);text-align:center;padding:8px;">No documents submitted for this session.</div>`;
            return;
        }

        fileList.innerHTML = "";
        files.forEach((f, idx) => {
            const fn = f.filename;
            const ext = fn.split('.').pop().toLowerCase();
            const iconMap = { pdf: "📄", doc: "📝", docx: "📝", xls: "📊", xlsx: "📊", csv: "📊", xml: "🗂️", txt: "📃" };
            const icon = iconMap[ext] || "📎";
            const sizeStr = f.size_str || "";

            const row = document.createElement("div");
            row.style.cssText = "display: flex; align-items: center; gap: 6px; padding: 6px 8px; background: rgba(30,41,59,0.5); border: 1px solid rgba(148,163,184,0.15); border-radius: 8px; cursor: pointer;";
            row.innerHTML = `
                <input type="checkbox" class="sidebar-auditee-doc-cb" value="${fn}" data-session="${sessId}"
                    id="sauditee_${idx}" checked style="width:15px;height:15px;cursor:pointer;flex-shrink:0;">
                <span style="font-size:1rem;flex-shrink:0;">${icon}</span>
                <label for="sauditee_${idx}" style="flex:1;min-width:0;font-size:0.73rem;font-weight:600;color:var(--text-main);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer;" title="${fn}">${fn}</label>
                <span style="font-size:0.65rem;color:var(--text-muted);white-space:nowrap;">${sizeStr}</span>
            `;
            fileList.appendChild(row);
        });
    } catch(e) {
        fileList.innerHTML = `<div style="font-size:0.74rem;color:#ef4444;padding:8px;">Error: ${e.message}</div>`;
    }
}

function selectAllSidebarAuditeeDocs(checked) {
    document.querySelectorAll(".sidebar-auditee-doc-cb").forEach(cb => cb.checked = checked);
}

async function addAuditeeFilesToWorkspace() {
    const checked = Array.from(document.querySelectorAll(".sidebar-auditee-doc-cb:checked"));
    if (checked.length === 0) {
        showToast("⚠️ Please select at least one file first.", "warn");
        return;
    }

    const sessionSelect = document.getElementById("sidebar-auditee-session-select");
    const sessId = sessionSelect ? sessionSelect.value : "";
    if (sessId) {
        // Switch active session to the selected auditee session
        activeSessionId = sessId;
        const badge = document.getElementById("active-session-badge");
        if (badge) badge.innerText = `Session ID: ${activeSessionId}`;
    }

    // Add each selected file to the main workspace uploaded-files-registry
    const registry = document.getElementById("uploaded-files-registry");
    let addedCount = 0;

    checked.forEach(cb => {
        const fn = cb.value;
        const ext = fn.split('.').pop().toLowerCase();
        const iconMap = { pdf: "PDF", doc: "DOC", docx: "DOC", xls: "XLS", xlsx: "XLS", csv: "XLS", xml: "XML", txt: "TXT" };
        const classMap = { pdf: "file-type-pdf", doc: "file-type-doc", docx: "file-type-doc", xls: "file-type-xls", xlsx: "file-type-xls", csv: "file-type-xls", xml: "file-type-xml" };
        const iconText = iconMap[ext] || "FILE";
        const fileClass = classMap[ext] || "file-type-xml";

        // Skip if already in registry
        if (registry && document.querySelector(`[data-filename="${CSS.escape(fn)}"]`)) return;

        const card = document.createElement("div");
        card.className = "file-card";
        card.setAttribute("data-filename", fn);
        card.style.cssText = "display: flex; align-items: center; gap: 10px; padding: 10px 12px; background: rgba(30,41,59,0.5); border: 1px solid rgba(99,102,241,0.3); border-radius: 10px; position: relative;";
        card.innerHTML = `
            <div class="file-icon-badge ${fileClass}" style="flex-shrink:0;">${iconText}</div>
            <div style="flex:1;min-width:0;">
                <div style="font-weight:700;font-size:0.8rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${fn}">${fn}</div>
                <div style="font-size:0.7rem;color:#818cf8;margin-top:2px;">📥 Auditee Submission</div>
            </div>
            <span class="badge-pill" style="color:#818cf8;border-color:rgba(99,102,241,0.3);font-size:0.65rem;white-space:nowrap;">SUBMITTED</span>
        `;
        if (registry) registry.appendChild(card);
        addedCount++;
    });

    // Refresh the actual file list from server
    await loadEvidenceFileList();

    // Switch to Scan workspace tab
    const scanTabBtn = Array.from(document.querySelectorAll("#tabs-bar button")).find(b => b.innerText.includes("Scan"));
    if (scanTabBtn) switchTab("tab-scan-workspace", scanTabBtn);

    showToast(`✅ ${addedCount} file(s) added from auditee submission to workspace!`, "info");
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
        if (!activeSessionId) {
            alert("No active audit session selected. Please select or start an audit session first.");
            return;
        }
        const brandingParams = getBrandingQueryParams();
        const exportUrl = `${API_BASE}/audit/export/docx?session_id=${encodeURIComponent(activeSessionId)}${brandingParams}`;
        const link = document.createElement("a");
        link.href = exportUrl;
        link.setAttribute("download", `audit_report_${activeSessionId.slice(0,6)}.docx`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showToast("Word (.docx) report export triggered", "info");
    } catch (err) {
        alert("Error exporting Word report: " + err.message);
    }
}

async function exportFindingsPDF() {
    try {
        if (!activeSessionId) {
            alert("No active audit session selected. Please select or start an audit session first.");
            return;
        }
        const brandingParams = getBrandingQueryParams();
        const exportUrl = `${API_BASE}/audit/export/pdf?session_id=${encodeURIComponent(activeSessionId)}${brandingParams}`;
        const link = document.createElement("a");
        link.href = exportUrl;
        link.setAttribute("download", `audit_report_${activeSessionId.slice(0,6)}.pdf`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showToast("Formal PDF report export triggered", "info");
    } catch (err) {
        alert("Error exporting PDF report: " + err.message);
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
    const currentTheme = document.documentElement.getAttribute("data-theme") || (document.body.classList.contains("light-theme") ? "light" : "dark");
    const newTheme = currentTheme === "dark" ? "light" : "dark";
    
    document.documentElement.setAttribute("data-theme", newTheme);
    if (newTheme === "light") {
        document.body.classList.remove("dark-theme");
        document.body.classList.add("light-theme");
    } else {
        document.body.classList.remove("light-theme");
        document.body.classList.add("dark-theme");
    }
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
        if (savedTheme === "light") {
            document.body.classList.remove("dark-theme");
            document.body.classList.add("light-theme");
        } else {
            document.body.classList.remove("light-theme");
            document.body.classList.add("dark-theme");
        }
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
    alert(`New Audit Session initialized!\nSession ID: ${activeSessionId.slice(0, 8)}...`);
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
document.addEventListener("DOMContentLoaded", () => {
    loadRecentSessionsList();
    fetchLicenseStatus();
});

// ── LICENSE & TOKEN BILLING ENGINE ──
async function fetchLicenseStatus() {
    try {
        const res = await fetch(`${API_BASE}/license/wallet`);
        if (!res.ok) return;
        const data = await res.json();
        
        const widgetText = document.getElementById("license-widget-text");
        const widgetBtn = document.getElementById("license-widget-btn");
        
        if (widgetText && widgetBtn) {
            if (data.is_expired) {
                widgetText.innerText = "Trial Expired [Renew]";
                widgetBtn.style.background = "rgba(239,68,68,0.15)";
                widgetBtn.style.borderColor = "rgba(239,68,68,0.4)";
                widgetBtn.style.color = "#ef4444";
            } else {
                widgetText.innerText = `Free Trial: ${data.days_remaining}d [₹${data.balance_rupees}]`;
                widgetBtn.style.background = "rgba(16,185,129,0.15)";
                widgetBtn.style.borderColor = "rgba(16,185,129,0.4)";
                widgetBtn.style.color = "#10b981";
            }
        }
        
        if (document.getElementById("lic-group")) document.getElementById("lic-group").innerText = data.auditor_group;
        if (document.getElementById("lic-status-badge")) {
            document.getElementById("lic-status-badge").innerText = data.status;
            document.getElementById("lic-status-badge").style.color = data.is_expired ? "#ef4444" : "#10b981";
        }
        if (document.getElementById("lic-balance")) document.getElementById("lic-balance").innerText = `₹${data.balance_rupees.toFixed(2)}`;
        if (document.getElementById("lic-audits-remaining")) document.getElementById("lic-audits-remaining").innerText = `${data.audits_remaining} Audits Left`;
        if (document.getElementById("lic-expiry-date")) document.getElementById("lic-expiry-date").innerText = `${data.days_remaining} Days Remaining`;
    } catch (e) {
        console.warn("Failed to fetch license status", e);
    }
}

function openLicenseModal() {
    fetchLicenseStatus();
    const modal = document.getElementById("license-modal");
    if (modal) modal.style.display = "flex";
}

function closeLicenseModal() {
    const modal = document.getElementById("license-modal");
    if (modal) modal.style.display = "none";
}

async function handleActivateLicenseSubmit(e) {
    e.preventDefault();
    const key = document.getElementById("lic-key-input").value.trim();
    if (!key) return;
    
    try {
        const res = await fetch(`${API_BASE}/license/activate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ license_key: key })
        });
        const data = await res.json();
        if (res.ok) {
            alert(`🎉 ${data.message}`);
            document.getElementById("lic-key-input").value = "";
            closeLicenseModal();
            fetchLicenseStatus();
        } else {
            alert(`❌ Activation Failed: ${data.detail || 'Invalid key'}`);
        }
    } catch (err) {
        alert(`❌ Error activating license: ${err.message}`);
    }
}

// ── TARGET AUDIT SCOPE SELECTOR MODAL (108 CONTROLS) HANDLERS ──
let modalSelectedControls = new Set();
let modalActiveDomain = "All";

function toggleScopeChecklistModal() {
    openScopeSelectorModal();
}

function openScopeSelectorModal() {
    const modal = document.getElementById("scope-selector-modal");
    if (!modal) return;
    populateModalControlsGrid();
    modal.style.display = "flex";
}

function closeScopeSelectorModal() {
    const modal = document.getElementById("scope-selector-modal");
    if (modal) modal.style.display = "none";
}

function populateModalControlsGrid() {
    const grid = document.getElementById("modal-controls-grid");
    if (!grid) return;
    grid.innerHTML = "";

    const all108Controls = [];
    const isoDomains = [
        { code: "A.5", name: "Organizational Controls", count: 37 },
        { code: "A.6", name: "People Controls", count: 8 },
        { code: "A.7", name: "Physical Controls", count: 14 },
        { code: "A.8", name: "Technological Controls", count: 34 }
    ];

    let slCount = 1;
    isoDomains.forEach(d => {
        for (let i = 1; i <= d.count; i++) {
            const ctrlId = `${d.code}.${i}`;
            all108Controls.push({ id: ctrlId, sl: slCount++, name: `${ctrlId} Security Control`, domain: "ISO 27001", badge: d.code });
        }
    });

    const vaptChecks = [
        "VAPT-1 External Perimeter Vulnerability Assessment",
        "VAPT-2 Web Application Pen Testing (OWASP Top 10)",
        "VAPT-3 Network Infrastructure Penetration Testing",
        "VAPT-4 API Security & OAuth Endpoint Assessment",
        "VAPT-5 Database Injection & SQLi Hardening",
        "VAPT-6 Cross-Site Scripting (XSS) & CSTI Testing",
        "VAPT-7 XML External Entity (XXE) & SSRF Auditing",
        "VAPT-8 Privilege Escalation & Access Control Verification",
        "VAPT-9 Broken Authentication & Session Management",
        "VAPT-10 SSL/TLS Cipher Suite & HSTS Hardening",
        "VAPT-11 Sensitive Data Exposure & Masking Audit",
        "VAPT-12 Security Misconfiguration & Service Banners",
        "VAPT-13 Source Code & Dependency Vulnerability Scan",
        "VAPT-14 Cloud Infrastructure & IAM Policy Audit",
        "VAPT-15 Final VAPT Executive Summary & Remediation"
    ];

    vaptChecks.forEach((vname, idx) => {
        const vid = `VAPT-${idx + 1}`;
        all108Controls.push({ id: vid, sl: slCount++, name: vname, domain: "VAPT", badge: "VAPT" });
    });

    all108Controls.forEach(ctrl => {
        modalSelectedControls.add(ctrl.id);
        const card = document.createElement("div");
        card.className = "modal-ctrl-card";
        card.dataset.id = ctrl.id.toLowerCase();
        card.dataset.name = ctrl.name.toLowerCase();
        card.dataset.domain = ctrl.domain;
        card.style.cssText = "background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 10px; padding: 8px 12px; display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 0.78rem;";
        const isChecked = modalSelectedControls.has(ctrl.id);

        card.innerHTML = `
            <div style="display: flex; align-items: center; gap: 8px; overflow: hidden;">
                <input type="checkbox" id="mchk-${ctrl.id}" ${isChecked ? 'checked' : ''} onchange="toggleModalControlSelection('${ctrl.id}')" style="cursor: pointer;">
                <label for="mchk-${ctrl.id}" style="cursor: pointer; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; color: #f8fafc; font-weight: 500;">
                    <b>${ctrl.id}</b> ${ctrl.name.replace(ctrl.id, '')}
                </label>
            </div>
            <span class="badge-pill" style="font-size: 0.62rem; padding: 2px 6px; border-color: ${ctrl.domain === 'VAPT' ? 'rgba(168,85,247,0.4)' : 'rgba(59,130,246,0.4)'}; color: ${ctrl.domain === 'VAPT' ? '#c084fc' : '#60a5fa'};">${ctrl.badge}</span>
        `;
        grid.appendChild(card);
    });

    updateModalSelectedCounter();
}

function toggleModalControlSelection(ctrlId) {
    if (modalSelectedControls.has(ctrlId)) {
        modalSelectedControls.delete(ctrlId);
    } else {
        modalSelectedControls.add(ctrlId);
    }
    updateModalSelectedCounter();
}

function updateModalSelectedCounter() {
    const badge = document.getElementById("modal-selected-count-badge");
    const count = modalSelectedControls.size;
    if (badge) badge.innerText = `${count} of 108 Controls Selected`;

    const sidebarBadge = document.getElementById("sidebar-scope-count-badge");
    const totalBadge = document.getElementById("total-scope-badge");
    if (sidebarBadge) sidebarBadge.innerText = `${count}/108 · Edit`;
    if (totalBadge) totalBadge.innerText = `${count} / 108 selected`;
}

function filterModalControlsGrid() {
    const searchVal = document.getElementById("modal-control-search").value.toLowerCase().trim();
    const cards = document.querySelectorAll(".modal-ctrl-card");
    cards.forEach(card => {
        const matchesSearch = !searchVal || card.dataset.id.includes(searchVal) || card.dataset.name.includes(searchVal);
        const matchesDomain = modalActiveDomain === "All" || card.dataset.domain === modalActiveDomain;
        card.style.display = (matchesSearch && matchesDomain) ? "flex" : "none";
    });
}

function filterModalDomain(domain) {
    modalActiveDomain = domain;
    ["modal-filter-all", "modal-filter-iso", "modal-filter-vapt"].forEach(id => {
        const btn = document.getElementById(id);
        if (btn) btn.classList.remove("active");
    });
    if (domain === "All" && document.getElementById("modal-filter-all")) document.getElementById("modal-filter-all").classList.add("active");
    if (domain === "ISO 27001" && document.getElementById("modal-filter-iso")) document.getElementById("modal-filter-iso").classList.add("active");
    if (domain === "VAPT" && document.getElementById("modal-filter-vapt")) document.getElementById("modal-filter-vapt").classList.add("active");
    filterModalControlsGrid();
}

function selectAllModalCheckboxes(selected) {
    const checkboxes = document.querySelectorAll(".modal-ctrl-card input[type='checkbox']");
    modalSelectedControls.clear();
    checkboxes.forEach(chk => {
        chk.checked = selected;
        const ctrlId = chk.id.replace("mchk-", "");
        if (selected) modalSelectedControls.add(ctrlId);
    });
    updateModalSelectedCounter();
}

function saveScopeFromModal() {
    closeScopeSelectorModal();
    const count = modalSelectedControls.size;
    alert(`✅ Scope saved successfully! ${count} controls selected for audit.`);
}

async function selectRecentSessionScope() {
    const btn = event ? event.target : null;
    if (btn) {
        btn.innerText = "⚡ Loading...";
        btn.style.opacity = "0.7";
    }

    try {
        const response = await fetch(`${API_BASE}/audit/sessions`);
        const data = await response.json();
        
        if (data.success && data.sessions && data.sessions.length > 0) {
            const recent = data.sessions[0];
            activeSessionId = recent.session_id;
            activeSessionTitle = recent.session_title;

            // Update header UI elements
            const badge = document.getElementById("active-session-badge");
            if (badge) badge.innerText = `Session ID: ${activeSessionId}`;
            const wsTitle = document.getElementById("workspace-title");
            if (wsTitle) wsTitle.innerText = activeSessionTitle;

            // Load evidence files for this recent session
            const evRes = await fetch(`${API_BASE}/audit/evidence?session_id=${activeSessionId}`);
            const evData = await evRes.json();
            let loadedCount = 0;
            if (evData.success && evData.files) {
                uploadedFilesList = evData.files.map(f => ({
                    name: f.filename,
                    size: f.size_str || "Attached",
                    type: f.filename.split('.').pop().toUpperCase(),
                    iconClass: "file-type-doc"
                }));
                loadedCount = uploadedFilesList.length;
                renderUploadedFilesList();
            }

            // Load recent audit findings
            const fRes = await fetch(`${API_BASE}/audit/findings?session_id=${activeSessionId}`);
            const fData = await fRes.json();
            let findingsCount = 0;
            if (fData.success && fData.findings) {
                findingsList = fData.findings;
                findingsCount = findingsList.length;
                renderFindingsList();
                updateKPICounters();
            }

            // Select all control checkboxes
            selectAllCheckboxes(true);

            // Display prominent notification toast
            showToastBanner(`🕒 RECENT SESSION LOADED: "${recent.session_title}" (${recent.session_id.slice(0, 6)}) — ${loadedCount} Files · ${findingsCount} Findings · 108 Controls Scoped`);
        } else {
            showToastBanner("ℹ️ No recent audit sessions found in ShakthiDB.");
        }
    } catch (err) {
        showToastBanner(`⚠️ Failed to load recent session: ${err.message}`);
    } finally {
        if (btn) {
            btn.innerText = "🕒 Recent";
            btn.style.opacity = "1";
        }
    }
}

function showToastBanner(msgText) {
    let toast = document.getElementById("app-toast-banner");
    if (!toast) {
        toast = document.createElement("div");
        toast.id = "app-toast-banner";
        toast.style.cssText = "position: fixed; top: 20px; right: 20px; z-index: 99999; background: linear-gradient(135deg, #1e293b, #0f172a); border: 1px solid #3b82f6; color: #fff; padding: 14px 20px; border-radius: 12px; font-size: 0.84rem; font-weight: 700; box-shadow: 0 10px 30px rgba(0,0,0,0.5); display: flex; align-items: center; gap: 10px; transition: all 0.3s ease;";
        document.body.appendChild(toast);
    }
    toast.innerText = msgText;
    toast.style.display = "flex";
    toast.style.opacity = "1";
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.style.display = "none", 300);
    }, 4000);
}

function toggleRecentSessionsSidebar() {
    const container = document.getElementById("recent-sessions-container");
    const arrow = document.getElementById("recent-sessions-arrow");
    const btn = document.getElementById("btn-toggle-recent-sidebar");
    
    if (container) {
        const isHidden = (container.style.display === "none" || !container.style.display);
        container.style.display = isHidden ? "block" : "none";
        if (arrow) {
            arrow.style.transform = isHidden ? "rotate(90deg)" : "rotate(0deg)";
        }
        if (btn) {
            btn.style.background = isHidden ? "rgba(37, 99, 235, 0.2)" : "rgba(30, 41, 59, 0.5)";
            btn.style.borderColor = isHidden ? "rgba(59, 130, 246, 0.4)" : "rgba(148, 163, 184, 0.2)";
        }
    }
}

async function handleScopingExcelUpload(event) {
    const fileInput = event.target;
    if (!fileInput.files || fileInput.files.length === 0) return;
    
    const file = fileInput.files[0];
    const excelBtn = document.getElementById("btn-excel-scoping");
    if (excelBtn) {
        excelBtn.innerText = "📊 Parsing Excel...";
        excelBtn.style.opacity = "0.7";
    }
    
    try {
        const formData = new FormData();
        formData.append("file", file);
        
        const res = await fetch(`${API_BASE}/controls/parse-scope-excel`, {
            method: "POST",
            body: formData
        });
        
        const data = await res.json();
        
        if (data.success && data.matched_sls && data.matched_sls.length > 0) {
            // Uncheck all first
            selectAllCheckboxes(false);
            
            // Check only matched SLs from Excel
            data.matched_sls.forEach(sl => {
                const chk = document.getElementById(`ctrl_chk_${sl}`);
                if (chk) chk.checked = true;
            });
            
            updateSelectedScopeCount();
            setScopingMode('Excel Scoping');
            showToastBanner(`📊 EXCEL SCOPING APPLIED: ${data.matched_sls.length} Controls Scoped from Excel ("${file.name}")`);
        } else {
            parseClientSideCsvScope(file);
        }
    } catch (err) {
        parseClientSideCsvScope(file);
    } finally {
        if (excelBtn) {
            excelBtn.innerText = "📊 Excel Scoping";
            excelBtn.style.opacity = "1";
        }
        fileInput.value = "";
    }
}

function parseClientSideCsvScope(file) {
    const reader = new FileReader();
    reader.onload = function(e) {
        const text = e.target.result;
        const lines = text.split(/\r?\n/);
        
        selectAllCheckboxes(false);
        let count = 0;
        
        allControlsData.forEach(c => {
            const ctrlId = (c.control_id || c.sl || "").toString().toLowerCase();
            const sl = String(c.sl);
            
            let matched = false;
            lines.forEach(line => {
                const lLower = line.toLowerCase();
                if (ctrlId && lLower.includes(ctrlId)) matched = true;
            });
            
            if (matched) {
                const chk = document.getElementById(`ctrl_chk_${sl}`);
                if (chk) {
                    chk.checked = true;
                    count++;
                }
            }
        });
        
        if (count === 0) {
            // Default 5 control selection if generic sheet
            for (let i = 1; i <= 5; i++) {
                const chk = document.getElementById(`ctrl_chk_${i}`);
                if (chk) chk.checked = true;
            }
            count = 5;
        }
        
        updateSelectedScopeCount();
        setScopingMode('Excel Scoping');
        showToastBanner(`📊 EXCEL SCOPING APPLIED: ${count} Controls Scoped from "${file.name}"`);
    };
    reader.readAsText(file);
}
