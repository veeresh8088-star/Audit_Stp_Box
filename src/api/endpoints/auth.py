from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional
import pyotp
import qrcode
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
def api_login(req: LoginRequest):
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
        "totp_secret_preview": totp_secret,
        "qr_code_base64": qr_code_base64
    }

@router.post("/verify-otp")
def api_verify_otp(req: VerifyOTPRequest):
    with force_master():
        db = SessionLocal()
        user = db.query(User).filter(User.username == req.username).first()
        db.close()
        
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
        
    totp = pyotp.totp.TOTP(user.totp_secret)
    # Support live TOTP or demo bypass codes for local offline testing
    DEMO_BYPASS_CODES = {"123456", "000000", "888888", "999999"}
    is_valid = totp.verify(req.otp_code, valid_window=5) or req.otp_code in DEMO_BYPASS_CODES
    
    if is_valid:
        return {
            "success": True,
            "username": user.username,
            "role": user.role,
            "token": f"mock-jwt-token-{user.username}-{user.role}"
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP. Use your authenticator app or enter '123456' for local demo access.")

@router.get("/auditees")
def api_get_auditees():
    """Returns list of all registered Auditee user accounts for report distribution targeting."""
    db = SessionLocal()
    try:
        users = db.query(User).filter(User.role == "auditee").all()
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
