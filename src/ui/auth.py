import streamlit as st
import hashlib
import pyotp
import qrcode
from io import BytesIO
from src.db.database import SessionLocal, User, engine, force_master

def _hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def seed_default_admin():
    with force_master():
        db = SessionLocal()
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            db.add(User(username="admin", password_hash=_hash_pw("admin123"), role="admin", totp_secret="ADMI2FASHRDSECRT"))
            db.commit()
        elif not admin.totp_secret:
            admin.totp_secret = "ADMI2FASHRDSECRT"
            db.commit()
        db.close()

def authenticate_user(username, password):
    with force_master():
        db = SessionLocal()
        user = db.query(User).filter(User.username == username, User.password_hash == _hash_pw(password)).first()
        db.close()
        if user:
            return {"username": user.username, "role": user.role, "totp_secret": user.totp_secret}
        return None

def register_user(username, password, role):
    with force_master():
        db = SessionLocal()
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            db.close()
            return False, "Username already exists.", None
        secret = pyotp.random_base32()
        db.add(User(username=username, password_hash=_hash_pw(password), role=role, totp_secret=secret))
        db.commit()
        db.close()
        return True, "Account created successfully!", secret

def select_role_admin():
    st.session_state.selected_role = "admin"
    st.session_state.login_error = None

def select_role_auditor():
    st.session_state.selected_role = "auditor"
    st.session_state.login_error = None

def select_role_auditee():
    st.session_state.selected_role = "auditee"
    st.session_state.login_error = None

def set_auth_action_register():
    st.session_state.auth_action = "Register"
    st.session_state.login_error = None

def set_auth_action_login():
    st.session_state.auth_action = "Login"
    st.session_state.login_error = None

def go_back_to_login():
    st.session_state.otp_sent = False
    st.session_state.otp_pending_user = None
    st.session_state.login_error = None

def proceed_to_signin():
    st.session_state.signup_success_user = None
    st.session_state.signup_success_secret = None
    st.session_state.auth_action = "Login"
    st.session_state.login_error = None

def handle_login_submit_callback():
    username = st.session_state.get("login_username_input", "").strip()
    password = st.session_state.get("login_password_input", "")
    selected_role = st.session_state.selected_role
    auth_action = st.session_state.get("auth_action", "Login")

    if not username or not password:
        st.session_state.login_error = "Please enter both username and password."
        return

    if auth_action == "Login":
        user = authenticate_user(username, password)
        if user:
            st.session_state.selected_role = user["role"]
            st.session_state.otp_pending_user = user
            st.session_state.otp_sent = True
            st.session_state.login_error = None
        else:
            st.session_state.login_error = "Invalid username or password."
    else:
        # Register
        if len(password) < 4:
            st.session_state.login_error = "Password must be at least 4 characters."
        else:
            ok, msg, secret = register_user(username, password, selected_role)
            if ok:
                st.session_state.signup_success_user = username
                st.session_state.signup_success_secret = secret
                st.session_state.login_error = None
                st.session_state.signup_success_msg = msg
            else:
                st.session_state.login_error = msg

def verify_otp_callback():
    otp_input = st.session_state.get("otp_input_field", "").strip()
    pending_user = st.session_state.otp_pending_user
    if not pending_user:
        st.session_state.login_error = "Session expired. Please log in again."
        return

    totp_secret = pending_user["totp_secret"]
    totp = pyotp.totp.TOTP(totp_secret)
    if totp.verify(otp_input, valid_window=3):
        st.session_state.authenticated = True
        st.session_state.user_role = pending_user["role"]
        st.session_state.username = pending_user["username"]
        st.session_state.otp_sent = False
        st.session_state.otp_pending_user = None
        st.session_state.login_error = None
    else:
        st.session_state.login_error = "Invalid security code. Please check your Authenticator app."

def render_login_gate():
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.user_role = None
        st.session_state.username = None
        st.session_state.selected_role = "admin"
    if "otp_sent" not in st.session_state:
        st.session_state.otp_sent = False
        st.session_state.otp_code = None
        st.session_state.otp_pending_user = None
    if "signup_success_user" not in st.session_state:
        st.session_state.signup_success_user = None
        st.session_state.signup_success_secret = None
    if "login_error" not in st.session_state:
        st.session_state.login_error = None

    if not st.session_state.authenticated:
        # We ensure default admin is there
        seed_default_admin()
        
        # Inject styling specific for auth
        st.markdown("""
        <style>
        div[data-testid="column"]:has(div[data-testid="stForm"]) {
            background: rgba(15, 23, 42, 0.4) !important;
            border: 1px solid rgba(148, 163, 184, 0.1) !important;
            border-radius: 24px !important;
            padding: 24px 28px !important;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.1) !important;
            backdrop-filter: blur(20px) !important;
            margin-top: 2vh !important;
        }
        [data-testid="stForm"] {
            border: none !important;
            background: transparent !important;
            padding: 0 !important;
        }
        div[data-baseweb="input"] {
            background-color: rgba(15, 23, 42, 0.8) !important;
            border: 1px solid rgba(148, 163, 184, 0.2) !important;
            border-radius: 12px !important;
        }
        div[data-baseweb="input"]:focus-within {
            border-color: #3b82f6 !important;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2) !important;
        }
        
        /* Input fields left-aligned icons via SVG backgrounds */
        input[placeholder="Enter your username"] {
            padding-left: 40px !important;
            background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="%2364748b" viewBox="0 0 16 16"><path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0zm4 8c0 1-1 1-1 1H3s-1 0-1-1 1-4 6-4 6 3 6 4zm-1-.004c-.001-.246-.154-.986-.832-1.664C11.516 10.68 10.289 10 8 10c-2.29 0-3.516.68-4.168 1.332-.678.678-.83 1.418-.832 1.664h10z"/></svg>') !important;
            background-repeat: no-repeat !important;
            background-position: 14px center !important;
        }
        input[placeholder="Enter your password"] {
            padding-left: 40px !important;
            background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="%2364748b" viewBox="0 0 16 16"><path d="M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2zm3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2z"/></svg>') !important;
            background-repeat: no-repeat !important;
            background-position: 14px center !important;
        }
        input[placeholder="Enter 6-digit OTP"] {
            padding-left: 40px !important;
            background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="%2364748b" viewBox="0 0 16 16"><path d="M3.5 11.5a.5.5 0 0 1 .5-.5h5.793L8.146 9.354a.5.5 0 1 1 .708-.708l3 3a.5.5 0 0 1 0 .708l-3 3a.5.5 0 0 1-.708-.708L9.793 13H4a.5.5 0 0 1-.5-.5z"/><path d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1z"/></svg>') !important;
            background-repeat: no-repeat !important;
            background-position: 14px center !important;
        }

        /* Style for nested role selection buttons inside columns */
        div[data-testid="column"] div[data-testid="column"] button {
            height: 76px !important;
            border-radius: 12px !important;
            font-size: 13px !important;
            font-weight: 600 !important;
            display: flex !important;
            flex-direction: column !important;
            justify-content: center !important;
            align-items: center !important;
            gap: 4px !important;
            transition: all 0.3s ease !important;
        }

        /* Active role button (primary) */
        div[data-testid="column"] div[data-testid="column"] button[data-testid="stBaseButton-primary"] {
            background: rgba(37, 99, 235, 0.15) !important;
            border: 2px solid #2563eb !important;
            color: white !important;
            box-shadow: 0 0 20px rgba(37, 99, 235, 0.3) !important;
        }
        div[data-testid="column"] div[data-testid="column"] button[data-testid="stBaseButton-primary"]:hover {
            background: rgba(37, 99, 235, 0.25) !important;
            border-color: #2563eb !important;
        }

        /* Inactive role buttons (secondary) */
        div[data-testid="column"] div[data-testid="column"] button[data-testid="stBaseButton-secondary"] {
            background: rgba(15, 23, 42, 0.5) !important;
            border: 1px solid rgba(255, 255, 255, 0.05) !important;
            color: #94a3b8 !important;
        }
        div[data-testid="column"] div[data-testid="column"] button[data-testid="stBaseButton-secondary"]:hover {
            background: rgba(30, 41, 59, 0.6) !important;
            border-color: rgba(255, 255, 255, 0.15) !important;
            color: #f8fafc !important;
        }

        /* Emoji / Text spacing inside role buttons */
        div[data-testid="column"] div[data-testid="column"] button div[data-testid="stMarkdownContainer"] p {
            font-size: 13px !important;
            line-height: 1.4 !important;
            text-align: center !important;
        }

        /* Form labels styled in uppercase grey */
        div[data-testid="stForm"] label {
            font-size: 11px !important;
            font-weight: 700 !important;
            letter-spacing: 1.5px !important;
            color: #475569 !important;
            text-transform: uppercase !important;
            margin-bottom: 6px !important;
        }

        /* Checkbox label styling */
        div[data-testid="stCheckbox"] label {
            color: #64748b !important;
            font-size: 14px !important;
        }

        /* Sign In Submit Button */
        div[data-testid="stFormSubmitButton"] button {
            border-radius: 12px !important;
            font-size: 1.05rem !important;
            font-weight: 700 !important;
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%) !important;
            color: white !important;
            border: none !important;
            box-shadow: 0 8px 16px rgba(37, 99, 235, 0.3) !important;
            transition: all 0.2s ease !important;
            margin-top: 6px !important;
            height: 44px !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
        }
        div[data-testid="stFormSubmitButton"] button:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 24px rgba(37, 99, 235, 0.5) !important;
        }

        /* Role Pill Badge styling */
        .role-badge-pill {
            background: rgba(37, 99, 235, 0.08) !important;
            border: 1px solid rgba(37, 99, 235, 0.3) !important;
            color: #3b82f6 !important;
            font-family: monospace;
            font-weight: 700;
            font-size: 11px;
            letter-spacing: 1.5px;
            padding: 6px 14px;
            border-radius: 20px;
            display: inline-block;
            text-transform: uppercase;
        }

        /* Toggle Signin/Signup Buttons style override */
        button[key*="toggle"] {
            background: transparent !important;
            border: 1px solid rgba(59, 130, 246, 0.35) !important;
            color: #60a5fa !important;
            border-radius: 12px !important;
            font-size: 14px !important;
            font-weight: 600 !important;
            height: 48px !important;
            transition: all 0.2s ease !important;
            box-shadow: none !important;
            margin-top: 8px !important;
        }
        button[key*="toggle"]:hover {
            background: rgba(59, 130, 246, 0.08) !important;
            border-color: rgba(59, 130, 246, 0.8) !important;
            color: white !important;
            box-shadow: 0 0 15px rgba(59, 130, 246, 0.25) !important;
        }
        </style>
        """, unsafe_allow_html=True)

        # Center the main login card
        _, col_main, _ = st.columns([1, 1.2, 1])

        with col_main:
            
            # Header Logo with Shield SVG
            st.markdown("""
            <div class="login-logo" style="text-align: center; margin-bottom: 16px;">
                <div style="display: inline-flex; justify-content: center; align-items: center; background: linear-gradient(135deg, #2563eb, #1d4ed8); width: 52px; height: 52px; border-radius: 14px; box-shadow: 0 0 15px rgba(37, 99, 235, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); margin-bottom: 8px;">
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="white">
                        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
                    </svg>
                </div>
                <div style="font-size: 1.6rem; font-weight: 800; color: #f8fafc; letter-spacing: -0.5px;">AICyberAuditBox</div>
                <div style="font-size: 0.8rem; color: #64748b; font-family: monospace; letter-spacing: 0.5px; margin-top: 2px;">Agentic RAG &nbsp;&middot;&nbsp; Cyber Security Audit Intelligence</div>
            </div>
            """, unsafe_allow_html=True)

            if st.session_state.signup_success_secret:
                st.markdown("""
                <div style='text-align: center; margin: 16px 0 28px 0;'>
                    <div class="role-badge-pill">● Setup Two-Factor Authentication</div>
                    <div style='color: #64748b; font-size: 0.82rem; margin-top: 8px; font-weight: 500;'>
                        Scan this QR code with your Authenticator app to add your account
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                totp_obj = pyotp.totp.TOTP(st.session_state.signup_success_secret)
                uri = totp_obj.provisioning_uri(
                    name=st.session_state.signup_success_user, 
                    issuer_name="AICyberAuditBox"
                )
                img = qrcode.make(uri)
                buf = BytesIO()
                img.save(buf, format="PNG")
                qr_bytes = buf.getvalue()
                
                st.markdown("<div style='text-align: center; margin-bottom: 16px;'>", unsafe_allow_html=True)
                st.image(qr_bytes, width=200, caption="Scan with Google/Microsoft Authenticator")
                st.markdown(f"<p style='color: #64748b; font-size: 0.85rem;'>Secret Key: <code style='color: #60a5fa;'>{st.session_state.signup_success_secret}</code></p>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)
                
                st.button("🔑 Proceed to Sign In", key="signup_complete_btn", use_container_width=True, type="primary", on_click=proceed_to_signin)

            elif st.session_state.otp_sent:
                st.markdown("""
                <div style='text-align: center; margin: 16px 0 16px 0;'>
                    <div class="role-badge-pill">● Two-Factor Authentication</div>
                    <div style='color: #64748b; font-size: 0.82rem; margin-top: 8px; font-weight: 500;'>
                        Enter the security verification code from your Authenticator app
                    </div>
                </div>
                """, unsafe_allow_html=True)

                pending_user = st.session_state.otp_pending_user
                totp_secret = pending_user["totp_secret"]

                # For the seeded admin account, show the QR code directly on-screen to scan
                if pending_user["username"] == "admin":
                    totp_obj = pyotp.totp.TOTP(totp_secret)
                    uri = totp_obj.provisioning_uri(name="admin", issuer_name="AICyberAuditBox")
                    img = qrcode.make(uri)
                    buf = BytesIO()
                    img.save(buf, format="PNG")
                    qr_bytes = buf.getvalue()
                    
                    st.markdown("<div style='text-align: center; margin-bottom: 12px;'>", unsafe_allow_html=True)
                    st.image(qr_bytes, width=160, caption="Scan to add Admin 2FA")
                    st.markdown(f"<p style='color: #64748b; font-size: 0.8rem; margin-top: -8px;'>Secret Key: <code style='color: #60a5fa;'>{totp_secret}</code></p>", unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)

                with st.form("otp_form", clear_on_submit=False):
                    otp_input = st.text_input("Enter Code", placeholder="Enter 6-digit OTP", key="otp_input_field")
                    st.form_submit_button("🔑 Verify & Authenticate", use_container_width=True, on_click=verify_otp_callback)

                if st.session_state.login_error:
                    st.error(st.session_state.login_error)

                st.markdown("<p style='text-align: center; font-size: 11px; color: #475569; margin: 8px 0;'>Codes regenerate every 30 seconds. Ensure your device clock is correct.</p>", unsafe_allow_html=True)

                st.button("Back to Login", key="otp_back", use_container_width=True, on_click=go_back_to_login)
            else:
                # Horizontal Role Grid Buttons
                role_c1, role_c2, role_c3 = st.columns(3)
                with role_c1:
                    admin_active = st.session_state.selected_role == "admin"
                    st.button("🔐\n\nAdmin", key="role_btn_admin", use_container_width=True, type="primary" if admin_active else "secondary", on_click=select_role_admin)
                with role_c2:
                    auditor_active = st.session_state.selected_role == "auditor"
                    st.button("📋\n\nAuditor", key="role_btn_auditor", use_container_width=True, type="primary" if auditor_active else "secondary", on_click=select_role_auditor)
                with role_c3:
                    auditee_active = st.session_state.selected_role == "auditee"
                    st.button("🗂️\n\nAuditee", key="role_btn_auditee", use_container_width=True, type="primary" if auditee_active else "secondary", on_click=select_role_auditee)

                selected_role = st.session_state.selected_role

                # Role pill badges and descriptions
                badge_map = {
                    "admin": ("SYSTEM ADMINISTRATOR", "Full access to settings, analyses, and records"),
                    "auditor": ("COMPLIANCE AUDITOR", "Upload compliance documents and run guided audits"),
                    "auditee": ("AUDITEE", "Upload audit evidence documents for the auditor to review")
                }
                badge_title, badge_desc = badge_map[selected_role]
                
                st.markdown(f"""
                <div style='text-align: center; margin: 8px 0 12px 0;'>
                    <div class="role-badge-pill">● {badge_title}</div>
                    <div style='color: #64748b; font-size: 0.8rem; margin-top: 4px; font-weight: 500;'>{badge_desc}</div>
                </div>
                """, unsafe_allow_html=True)

                # Compute active auth_action
                if selected_role != "admin":
                    if "auth_action" not in st.session_state:
                        st.session_state.auth_action = "Login"
                    auth_action = st.session_state.auth_action
                else:
                    auth_action = "Login"

                with st.form("login_form", clear_on_submit=False):
                    username = st.text_input("Username", placeholder="Enter your username", key="login_username_input")
                    password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_password_input")
                    
                    col_rem, col_forgot = st.columns([1, 1])
                    with col_rem:
                        remember_me = st.checkbox("Remember me", key="login_remember")
                    with col_forgot:
                        st.markdown("<div style='text-align:right; padding-top: 4px;'><a href='#' style='color:#3b82f6; text-decoration:none; font-size:14px; font-weight:500;'>Forgot password?</a></div>", unsafe_allow_html=True)
                    
                    st.form_submit_button(
                        "🔒 Secure Sign In" if auth_action == "Login" else "📝 Create Secure Account",
                        use_container_width=True,
                        on_click=handle_login_submit_callback
                    )

                if st.session_state.get("signup_success_msg") and st.session_state.signup_success_secret:
                    st.success(st.session_state.signup_success_msg)
                    st.session_state.signup_success_msg = None

                if st.session_state.login_error:
                    st.error(st.session_state.login_error)

                # Signup/Back to Login Toggle placement below the form
                if selected_role != "admin":
                    divider_label = "new user?" if auth_action == "Login" else "already registered?"
                    st.markdown(f"""
                    <div style="text-align: center; margin: 12px 0 8px 0; display: flex; align-items: center; justify-content: center; gap: 10px;">
                        <div style="flex: 1; height: 1px; background: rgba(255, 255, 255, 0.08);"></div>
                        <span style="font-size: 11px; text-transform: uppercase; color: #475569; font-weight: 700; letter-spacing: 1.5px;">
                            {divider_label}
                        </span>
                        <div style="flex: 1; height: 1px; background: rgba(255, 255, 255, 0.08);"></div>
                    </div>
                    """, unsafe_allow_html=True)

                    if auth_action == "Login":
                        st.button("＋  Create Account", key="toggle_signup_btn", use_container_width=True, on_click=set_auth_action_register)
                    else:
                        st.button("🔑  Back to Login", key="toggle_login_btn", use_container_width=True, on_click=set_auth_action_login)

            # Footer
            st.markdown("""
            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:16px; border-top:1px solid rgba(255,255,255,0.05); padding-top:8px; font-size:11px; color:#475569;">
                <div style="display:flex; gap:8px; align-items:center;">
                    <span style="color:#22c55e;">●</span> Secure
                    <span style="color:#475569; font-size: 8px;">&nbsp;&middot;&nbsp;</span> Offline
                    <span style="color:#475569; font-size: 8px;">&nbsp;&middot;&nbsp;</span> Encrypted
                </div>
                <div style="display:flex; gap:12px;">
                    <a href="#" style="color:#475569; text-decoration:none;">Privacy</a>
                    <a href="#" style="color:#475569; text-decoration:none;">Audit Policy</a>
                    <a href="#" style="color:#475569; text-decoration:none;">Help</a>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
        st.stop()
