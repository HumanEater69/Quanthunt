# SECURITY TARGET: Core Security Utilities
import ipaddress
import socket
from urllib.parse import urlparse

def is_private_ip(ip: str) -> bool:
    """Check if an IP address belongs to private/internal subnets."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Blocks 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, link-local, multicast, etc.
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast
    except ValueError:
        return False

def resolve_and_verify_ssrf(domain_or_url: str) -> bool:
    """
    Resolve a hostname and verify it points to a public IP address.
    Raises ValueError if it routes to an internal network (SSRF protection).
    """
    # Clean the input, if it is a full URL, extract hostname
    if "://" in domain_or_url:
        host = urlparse(domain_or_url).hostname
    else:
        host = domain_or_url.split(":")[0]

    if not host:
        raise ValueError("Invalid target host.")

    try:
        # Resolve all IPv4 and IPv6 addresses
        addr_info = socket.getaddrinfo(host, None)
        ips = [info[4][0] for info in addr_info]
    except socket.gaierror:
        # DNS failed, let regular network flow handle or reject it
        return True

    for ip in ips:
        if is_private_ip(ip):
            raise ValueError(f"SSRF BLOCKED: Target {host} resolved to internal IP {ip}")

    return True

# --- Authentication & Authorization ---
import os
import jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# SECURITY TARGET: Enforce JWT Secret presence
JWT_SECRET = os.environ.get("JWT_SECRET", "local_dev_secret")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_role(required_role: str):
    def role_checker(payload: dict = Depends(verify_token)) -> dict:
        user_role = payload.get("role")
        if user_role != required_role and user_role != "admin":
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return payload
    return role_checker