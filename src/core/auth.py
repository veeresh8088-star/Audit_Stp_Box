# -*- coding: utf-8 -*-
"""
Core Authentication Module
Pure Python module for user authentication, password hashing, and user registration.
Decoupled from Streamlit UI.
"""

import hashlib
import pyotp
from src.db.database import SessionLocal, User, force_master

def _hash_pw(pw: str) -> str:
    """Returns SHA256 hash of a plain text password."""
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

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
    """Registers a new user in database and returns TOTP secret."""
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
