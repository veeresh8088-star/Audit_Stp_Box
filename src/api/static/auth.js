// ── AICyberAuditBox Authentication Module ──

const API_BASE = window.API_BASE || "http://127.0.0.1:8000/api";

let currentUser = null;
let selectedRole = "auditor";

function selectRole(role) {
    selectedRole = role;
    
    // Update button visual styles
    document.querySelectorAll(".role-btn").forEach(btn => btn.classList.remove("active"));
    const roleBtn = document.getElementById(`role-${role}-btn`);
    if (roleBtn) roleBtn.classList.add("active");
    
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
    
    if (submitBtn) submitBtn.innerText = "Secure Sign In";
    if (toggleActionBtn) toggleActionBtn.innerText = "Create Account";
    if (toggleLabel) toggleLabel.innerText = "NEW USER?";
}

function toggleAuthAction() {
    const submitBtn = document.getElementById("auth-submit-btn");
    const toggleActionBtn = document.getElementById("toggle-action-btn");
    const toggleLabel = document.getElementById("toggle-label");
    
    if (submitBtn && submitBtn.innerText.includes("Sign In")) {
        submitBtn.innerText = "Create Secure Account";
        if (toggleActionBtn) toggleActionBtn.innerText = "Back to Login";
        if (toggleLabel) toggleLabel.innerText = "ALREADY REGISTERED?";
    } else {
        resetAuthActionToLogin();
    }
    showError("");
}

async function handleLoginSubmit(e) {
    if (e) e.preventDefault();
    showError("");
    
    const usernameEl = document.getElementById("username-input");
    const passwordEl = document.getElementById("password-input");
    const submitBtn = document.getElementById("auth-submit-btn");
    if (!usernameEl || !passwordEl || !submitBtn) return;

    const username = usernameEl.value.trim();
    const password = passwordEl.value;
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
    if (e) e.preventDefault();
    showError("");
    
    const otpInput = document.getElementById("otp-input");
    if (!otpInput) return;

    const otpCode = otpInput.value.trim();
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
        
        if (typeof initializeDashboard === "function") {
            initializeDashboard(currentUser);
        }
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
    if (errorEl) {
        if (msg) {
            errorEl.innerText = msg;
            errorEl.style.display = "block";
        } else {
            errorEl.style.display = "none";
        }
    }
}

function logout() {
    currentUser = null;
    document.getElementById("app-shell").style.display = "none";
    document.getElementById("auth-overlay").classList.add("active");
    document.getElementById("login-form").style.display = "block";
    document.getElementById("otp-form").style.display = "none";
    document.getElementById("register-setup-form").style.display = "none";
    const uInput = document.getElementById("username-input");
    const pInput = document.getElementById("password-input");
    if (uInput) uInput.value = "";
    if (pInput) pInput.value = "";
    showError("");
}
