from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional
import pyotp
import qrcode
import base64
from io import BytesIO
from src.ui.auth import (
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
    
    # Check if user is admin (requires custom QR code display if TOTP not set, handled in UI)
    is_admin = user["username"] == "admin"
    
    # For seeded admin, return QR code data if they need to scan it first
    qr_code_base64 = None
    if is_admin:
        totp = pyotp.totp.TOTP(user["totp_secret"])
        provisioning_uri = totp.provisioning_uri(name="admin", issuer_name="AICyberAuditBox")
        img = qrcode.make(provisioning_uri)
        buf = BytesIO()
        img.save(buf, format="PNG")
        qr_code_base64 = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('utf-8')}"
        
    return {
        "success": True,
        "username": user["username"],
        "role": user["role"],
        "requires_otp": True,
        "totp_secret_preview": user["totp_secret"] if is_admin else None,
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
    if totp.verify(req.otp_code, valid_window=3):
        return {
            "success": True,
            "username": user.username,
            "role": user.role,
            "token": f"mock-jwt-token-{user.username}-{user.role}" # Replace with actual JWT if cloud, mock is standard for local
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid security code.")
