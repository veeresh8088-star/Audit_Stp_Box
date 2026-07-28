# -*- coding: utf-8 -*-
"""
Core Authentication Module
Pure Python module for user authentication, password hashing, and user registration.
Decoupled from Streamlit UI.
"""

import hashlib
import re
import pyotp
from src.db.database import SessionLocal, User, force_master

def _hash_pw(pw: str) -> str:
    """Returns SHA256 hash of a plain text password."""
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def validate_username(username: str) -> tuple[bool, str]:
    """
    Enforces Gmail address rule:
    Usernames must be a valid @gmail.com email address (e.g. user@gmail.com).
    Admin account ('admin') and legacy test accounts are explicitly exempt.
    """
    uname = (username or "").strip().lower()
    if uname in ("admin", "auditor@24", "auditee2@organization.com"):
        return True, ""
    
    if not uname.endswith("@gmail.com") or len(uname) <= 10 or "@" not in uname:
        return False, "Username must be a valid Gmail address (e.g., user@gmail.com)."
    return True, ""

def validate_iso_password(password: str) -> tuple[bool, str]:
    """
    Enforces ISO 27001 / ISO 27002 A.5.17 password security policy:
    - Minimum 8 characters long
    - At least 1 uppercase letter (A-Z)
    - At least 1 lowercase letter (a-z)
    - At least 1 number (0-9)
    - At least 1 special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
    """
    pw = password or ""
    if len(pw) < 8:
        return False, "Password must be at least 8 characters long under ISO 27001 policy."
    if not re.search(r"[A-Z]", pw):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", pw):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", pw):
        return False, "Password must contain at least one digit (0-9)."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", pw):
        return False, "Password must contain at least one special character (e.g. @, #, $, !)."
    return True, ""

def seed_default_admin():
    """Ensures a default admin user exists in database."""
    with force_master():
        db = SessionLocal()
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            db.add(User(
                username="admin",
                password_hash=_hash_pw("admin123"),
                role="admin",
                totp_secret="ADMI2FASHRDSECRT"
            ))
            db.commit()
        elif not admin.totp_secret:
            admin.totp_secret = "ADMI2FASHRDSECRT"
            db.commit()
        db.close()

def authenticate_user(username: str, password: str):
    """Authenticates user credentials and returns user details if valid."""
    with force_master():
        db = SessionLocal()
        user = db.query(User).filter(
            User.username == username,
            User.password_hash == _hash_pw(password)
        ).first()
        db.close()
        if user:
            return {
                "username": user.username,
                "role": user.role,
                "totp_secret": user.totp_secret
            }
        return None

def register_user(username: str, password: str, role: str):
    """Registers a new user in database with Gmail username and ISO 27001 password verification."""
    # 1. Username Gmail validation
    u_ok, u_msg = validate_username(username)
    if not u_ok:
        return False, u_msg, None

    # 2. ISO 27001 password policy validation
    p_ok, p_msg = validate_iso_password(password)
    if not p_ok:
        return False, p_msg, None

    with force_master():
        db = SessionLocal()
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            db.close()
            return False, "Username already exists.", None
        secret = pyotp.random_base32()
        db.add(User(
            username=username,
            password_hash=_hash_pw(password),
            role=role,
            totp_secret=secret
        ))
        db.commit()
        db.close()
        return True, "Account created successfully!", secret
