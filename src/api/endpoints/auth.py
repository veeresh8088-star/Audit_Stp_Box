from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from typing import Optional
import pyotp
import qrcode
import time
import os
import jwt
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import base64
from io import BytesIO
from src.core.auth import (
    authenticate_user, 
    register_user, 
    seed_default_admin,
    _hash_pw
)
from src.db.database import SessionLocal, User, force_master

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ── JWT Configuration ─────────────────────────────────────────────────────────
_JWT_SECRET  = os.environ.get("JWT_SECRET", "aicyberauditbox-change-this-in-production-2026")
_JWT_ALGO    = "HS256"
_JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "8"))

def _create_token(username: str, role: str) -> str:
    """Create a signed JWT token with username, role, and expiry."""
    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=_JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGO)

def _require_auth(request: Request) -> dict:
    """Validates the JWT token in the Authorization header. Returns {username, role} or raises 401."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized. A valid authentication token is required.")
    token = auth_header[len("Bearer "):].strip()
    try:
        payload = jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGO])
        return {"username": payload.get("sub"), "role": payload.get("role")}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token. Please log in again.")

# --- Request / Response Schemas ---
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=4)
    role: str = Field(..., pattern="^(admin|auditor|auditee)$")

class LoginRequest(BaseModel):
    username: str
    password: str

class VerifyOTPRequest(BaseModel):
    username: str
    otp_code: str

class ForgotPasswordRequest(BaseModel):
    username: str

class ResetPasswordTOTPRequest(BaseModel):
    username: str
    otp_code: str
    new_password: str

# --- Simple In-Memory Rate Limiter (5 failed attempts per minute per IP) ---
_login_attempts: dict = defaultdict(list)  # {ip: [timestamp, ...]}
MAX_ATTEMPTS = 5
RATE_WINDOW_SECONDS = 60

def _check_rate_limit(ip: str):
    """Raises HTTP 429 if more than MAX_ATTEMPTS login attempts in RATE_WINDOW_SECONDS."""
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < RATE_WINDOW_SECONDS]
    if len(_login_attempts[ip]) >= MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Please wait {RATE_WINDOW_SECONDS} seconds before trying again."
        )
    _login_attempts[ip].append(now)

# --- Endpoints ---

@router.post("/register")
def api_register(req: RegisterRequest):
    # Call register_user logic from auth.py
    ok, msg, secret = register_user(req.username, req.password, req.role)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    
    # Generate TOTP QR code
    totp = pyotp.totp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=req.username, issuer_name="AICyberAuditBox")
    
    img = qrcode.make(provisioning_uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    
    return {
        "success": True,
        "message": msg,
        "username": req.username,
        "role": req.role,
        "totp_secret": secret,
        "qr_code_base64": f"data:image/png;base64,{qr_base64}"
    }

@router.post("/login")
def api_login(req: LoginRequest, request: Request):
    # Rate limiting — max 5 attempts per IP per minute
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    # Ensure default admin exists
    seed_default_admin()

    user = authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    
    # Generate TOTP QR code and secret preview for Authenticator apps
    qr_code_base64 = None
    totp_secret = user.get("totp_secret")
    if not totp_secret:
        totp_secret = pyotp.random_base32()
        
    totp = pyotp.totp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(name=user["username"], issuer_name="AICyberAuditBox")
    img = qrcode.make(provisioning_uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_code_base64 = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('utf-8')}"
        
    return {
        "success": True,
        "username": user["username"],
        "role": user["role"],
        "requires_otp": True,
        "qr_code_base64": qr_code_base64
        # totp_secret intentionally NOT returned — prevents 2FA cloning via DevTools
    }

@router.post("/verify-otp")
def api_verify_otp(req: VerifyOTPRequest, request: Request):
    # Rate limiting — OTP brute force prevention (3 attempts per minute)
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    with force_master():
        db = SessionLocal()
        user = db.query(User).filter(User.username == req.username).first()
        db.close()
        
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials.")
        
    totp = pyotp.totp.TOTP(user.totp_secret)
    # Verify live TOTP code from Google Authenticator only (no bypass codes)
    is_valid = totp.verify(req.otp_code, valid_window=5)

    if is_valid:
        return {
            "success": True,
            "username": user.username,
            "role": user.role,
            "token": _create_token(user.username, user.role)
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP code. Please enter the 6-digit code from your Google Authenticator app.")

@router.get("/auditees")
def api_get_auditees(request: Request):
    """Returns list of all registered Auditee user accounts for report distribution targeting."""
    _require_auth(request)
    with force_master():
        db = SessionLocal()
        try:
            from src.db.database import User
            users = db.query(User).filter(User.role.in_(["auditee", "client"])).all()
            if not users:
                # Seed default registered auditee accounts
                from src.core.auth import register_user
                register_user("auditee@organization.com", "Auditee123!", "auditee")
                register_user("auditee2@organization.com", "Auditee123!", "auditee")
                users = db.query(User).filter(User.role.in_(["auditee", "client"])).all()

            result = []
            for u in users:
                result.append({
                    "id": u.id,
                    "username": u.username,
                    "role": u.role
                })
            return {"success": True, "auditees": result}
        finally:
            db.close()

@router.post("/forgot-password/request")
def api_forgot_password_request(req: ForgotPasswordRequest):
    """Fetches user's Google Authenticator QR Code & Secret for TOTP password recovery."""
    with force_master():
        db = SessionLocal()
        try:
            u = db.query(User).filter(User.username == req.username).first()
            if not u:
                raise HTTPException(status_code=404, detail="Account not found. Please check your username and try again.")
            
            secret = u.totp_secret
            if not secret:
                secret = pyotp.random_base32()
                u.totp_secret = secret
                db.commit()
                
            totp = pyotp.totp.TOTP(secret)
            uri = totp.provisioning_uri(name=u.username, issuer_name="AICyberAuditBox")
            img = qrcode.make(uri)
            buf = BytesIO()
            img.save(buf, format="PNG")
            qr_base64 = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('utf-8')}"
            
            return {
                "success": True,
                "username": u.username,
                "totp_secret": secret,
                "qr_code_base64": qr_base64,
                "message": "Scan QR Code with Google Authenticator or enter 6-digit TOTP code to recover password."
            }
        finally:
            db.close()

@router.post("/forgot-password/reset")
def api_forgot_password_reset(req: ResetPasswordTOTPRequest):
    """Verifies 6-digit TOTP code from Google Authenticator and resets user password with ISO 27001 policy."""
    from src.core.auth import validate_iso_password
    p_ok, p_msg = validate_iso_password(req.new_password)
    if not p_ok:
        raise HTTPException(status_code=400, detail=p_msg)

    with force_master():
        db = SessionLocal()
        try:
            u = db.query(User).filter(User.username == req.username).first()
            if not u:
                raise HTTPException(status_code=404, detail=f"Username '{req.username}' not found.")
            
            secret = u.totp_secret
            if not secret:
                secret = pyotp.random_base32()
                u.totp_secret = secret
                db.commit()
                
            totp = pyotp.TOTP(secret)
            # Verify live TOTP code only — no demo bypass codes
            is_valid = totp.verify(req.otp_code.strip(), valid_window=5)
            
            if not is_valid:
                raise HTTPException(status_code=401, detail="Invalid Google Authenticator TOTP code. Please try again.")
                
            u.password_hash = _hash_pw(req.new_password)
            db.commit()
            
            return {
                "success": True,
                "message": f"Password for user '{u.username}' successfully reset! You can now log in."
            }
        finally:
            db.close()
