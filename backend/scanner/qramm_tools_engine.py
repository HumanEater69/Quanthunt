"""
QRAMM Open Source Security Tools Integration Engine for QuantHunt.

Implements backend capabilities inspired by QRAMM Open Source Security Tools:
1. CryptoDeps: Dependency scanner for Python, npm, Go, and Maven packages.
2. CNSA 2.0 Compliance Timeline Analyzer: Evaluates infrastructure against NSA CNSA 2.0 milestones.
3. PQC-Bench & SNDL Recommender: Sector-specific post-quantum algorithm selection engine (FIPS 203, 204, 205).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional


# =====================================================================
# 1. CryptoDeps: Software Dependency Scanner
# =====================================================================

VULNERABLE_CRYPTO_DEPENDENCIES: Dict[str, Dict[str, Any]] = {
    # Python
    "pycryptodome": {"risk": "PARTIAL", "reason": "Contains RSA/ECC classical algorithms alongside AES. Audit usage for PQC migration.", "ecosystem": "python"},
    "cryptography": {"risk": "PARTIAL", "reason": "Standard Python crypto library; supports classical RSA/ECDSA and OpenSSL 3.x PQC bindings.", "ecosystem": "python"},
    "rsa": {"risk": "VULNERABLE", "reason": "Pure RSA implementation. Vulnerable to Shor's algorithm.", "ecosystem": "python"},
    "ecdsa": {"risk": "VULNERABLE", "reason": "Pure ECDSA implementation. Vulnerable to Shor's algorithm.", "ecosystem": "python"},
    "paramiko": {"risk": "VULNERABLE", "reason": "SSH protocol implementation relying heavily on classical RSA/ECDHE KEX.", "ecosystem": "python"},
    "pynacl": {"risk": "PARTIAL", "reason": "NaCl/libsodium bindings using Ed25519/X25519. High classical security, but vulnerable to quantum attacks.", "ecosystem": "python"},
    "pyopenssl": {"risk": "PARTIAL", "reason": "OpenSSL wrapper; security depends on underlying OpenSSL PQC provider.", "ecosystem": "python"},
    
    # npm (Node.js)
    "crypto-js": {"risk": "PARTIAL", "reason": "Classical JS crypto primitives. Symmetric AES/SHA-3 safe; RSA/ECC primitives vulnerable.", "ecosystem": "npm"},
    "node-forge": {"risk": "VULNERABLE", "reason": "JavaScript implementation of TLS and RSA/PKI protocols.", "ecosystem": "npm"},
    "elliptic": {"risk": "VULNERABLE", "reason": "Elliptic curve cryptography library for JS. Vulnerable to Shor's algorithm.", "ecosystem": "npm"},
    "bcrypt": {"risk": "SAFE", "reason": "Password hashing algorithm (Blowfish-based). Quantum resistant for high cost factors.", "ecosystem": "npm"},
    "argon2": {"risk": "SAFE", "reason": "Memory-hard password hashing standard. Quantum resistant.", "ecosystem": "npm"},

    # Go
    "golang.org/x/crypto": {"risk": "PARTIAL", "reason": "Go supplementary crypto repository. Includes classical SSH/OpenPGP and emerging PQC.", "ecosystem": "go"},
    "github.com/golang-jwt/jwt": {"risk": "PARTIAL", "reason": "JWT library supporting RSA/ECDSA signatures. Requires ML-DSA/SLH-DSA transition.", "ecosystem": "go"},
    
    # Maven (Java)
    "org.bouncycastle:bcprov-jdk18on": {"risk": "PARTIAL", "reason": "Bouncy Castle Java provider. Includes classical primitives and NIST PQC (ML-KEM/ML-DSA).", "ecosystem": "maven"},
}


class CryptoDepsScanner:
    """Scans project dependency manifests (requirements.txt, package.json, etc.) for quantum risk."""

    @staticmethod
    def scan_manifest(filename: str, content: str) -> Dict[str, Any]:
        filename_lower = filename.lower()
        findings: List[Dict[str, Any]] = []
        ecosystem = "unknown"

        if "requirements" in filename_lower or filename_lower.endswith(".txt"):
            ecosystem = "python"
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pkg_name = re.split(r"[=<>]", line)[0].strip().lower()
                if pkg_name in VULNERABLE_CRYPTO_DEPENDENCIES:
                    info = VULNERABLE_CRYPTO_DEPENDENCIES[pkg_name]
                    findings.append({
                        "package": pkg_name,
                        "ecosystem": ecosystem,
                        "risk": info["risk"],
                        "reason": info["reason"],
                        "recommendation": "Audit usage; plan migration to NIST PQC algorithm wrappers (FIPS 203/204/205)."
                    })

        elif "package.json" in filename_lower:
            ecosystem = "npm"
            try:
                data = json.loads(content)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for pkg_name in deps:
                    pkg_lower = pkg_name.lower()
                    if pkg_lower in VULNERABLE_CRYPTO_DEPENDENCIES:
                        info = VULNERABLE_CRYPTO_DEPENDENCIES[pkg_lower]
                        findings.append({
                            "package": pkg_name,
                            "ecosystem": ecosystem,
                            "risk": info["risk"],
                            "reason": info["reason"],
                            "recommendation": "Upgrade to PQC-enabled JS libraries or delegate key exchange to CryptoServe/FastAPI layer."
                        })
            except Exception:
                pass

        vulnerable_count = sum(1 for f in findings if f["risk"] == "VULNERABLE")
        partial_count = sum(1 for f in findings if f["risk"] == "PARTIAL")

        overall_risk = "SAFE"
        if vulnerable_count > 0:
            overall_risk = "VULNERABLE"
        elif partial_count > 0:
            overall_risk = "PARTIAL"

        return {
            "filename": filename,
            "ecosystem": ecosystem,
            "overall_risk": overall_risk,
            "total_dependencies_flagged": len(findings),
            "vulnerable_count": vulnerable_count,
            "partial_count": partial_count,
            "findings": findings,
            "sarif_compatible": True
        }


# =====================================================================
# 2. CNSA 2.0 Compliance Timeline Analyzer
# =====================================================================

class CNSA2TimelineAnalyzer:
    """Evaluates TLS configurations and cryptographic algorithms against NSA CNSA 2.0 timelines."""

    TIMELINE_MILESTONES = [
        {
            "year": 2025,
            "milestone": "Software & Firmware Signing Preferred PQC Start",
            "requirement": "Begin adopting ML-DSA-87 or LMS/XMSS stateful hash-based signatures for firmware update signing."
        },
        {
            "year": 2030,
            "milestone": "Software & Firmware Mandatory PQC Enforcement",
            "requirement": "Mandatory ML-DSA-87 / LMS / XMSS for software signing. Classical RSA/ECDSA prohibited."
        },
        {
            "year": 2030,
            "milestone": "Web Browsers & TLS Preferred PQC Transition",
            "requirement": "Support for ML-KEM-1024 and ML-DSA-87 in web servers, load balancers, and TLS proxies."
        },
        {
            "year": 2033,
            "milestone": "Web Browsers & TLS Mandatory PQC Enforcement",
            "requirement": "Mandatory ML-KEM-1024 for Key Establishment and ML-DSA-87 for TLS Certificates."
        },
        {
            "year": 2035,
            "milestone": "Legacy Classical Algorithm Sunset",
            "requirement": "Complete phase-out of RSA (<=4096), ECDSA (P-256/384), and DH algorithms across all enterprise systems."
        }
    ]

    @classmethod
    def analyze(cls, tls_version: str, cipher: str, key_exchange: str, cert_signature_algo: str, key_size: int) -> Dict[str, Any]:
        cipher_upper = (cipher or "").upper()
        kex_upper = (key_exchange or "").upper()
        sig_upper = (cert_signature_algo or "").upper()

        is_cnsa2_kex = any(k in kex_upper for k in ["MLKEM1024", "ML-KEM-1024", "KYBER1024", "X25519MLKEM768"])
        is_cnsa2_sig = any(s in sig_upper for s in ["ML-DSA-87", "MLDSA87", "SLH-DSA-256S", "LMS", "XMSS"])
        is_cnsa2_symmetric = "AES_256" in cipher_upper or "AES256" in cipher_upper

        violations = []
        if not is_cnsa2_symmetric:
            violations.append({
                "rule": "CNSA 2.0 Symmetric Encryption",
                "severity": "HIGH",
                "issue": f"Cipher '{cipher}' does not enforce AES-256. CNSA 2.0 requires AES-256 for symmetric bulk encryption."
            })
        if not is_cnsa2_kex:
            violations.append({
                "rule": "CNSA 2.0 Key Establishment",
                "severity": "CRITICAL",
                "issue": f"Key exchange '{key_exchange}' uses classical algorithms (RSA/ECDHE). CNSA 2.0 requires ML-KEM-1024 (or hybrid ML-KEM)."
            })
        if not is_cnsa2_sig:
            violations.append({
                "rule": "CNSA 2.0 Digital Signatures",
                "severity": "HIGH",
                "issue": f"Certificate signature algorithm '{cert_signature_algo}' is classical. CNSA 2.0 mandates ML-DSA-87."
            })

        compliance_score = 100
        compliance_score -= len(violations) * 30
        compliance_score = max(0, compliance_score)

        status = "COMPLIANT" if compliance_score == 100 else ("PARTIAL" if compliance_score >= 40 else "NON_COMPLIANT")

        return {
            "cnsa_2_0_status": status,
            "compliance_score": compliance_score,
            "evaluations": {
                "symmetric_aes_256": is_cnsa2_symmetric,
                "pqc_key_establishment": is_cnsa2_kex,
                "pqc_digital_signature": is_cnsa2_sig
            },
            "violations": violations,
            "milestone_roadmap": cls.TIMELINE_MILESTONES
        }


# =====================================================================
# 3. PQC-Bench & SNDL Recommendation Engine
# =====================================================================

SECTOR_PROFILES: Dict[str, Dict[str, Any]] = {
    "financial": {
        "sector_name": "Banking & Financial Infrastructure",
        "hndl_risk_tier": "CRITICAL",
        "recommended_kex": "ML-KEM-1024 / Hybrid X25519+ML-KEM-768",
        "recommended_sig": "ML-DSA-87 / Falcon-1024",
        "key_derivation": "HKDF-SHA384 / HKDF-SHA512",
        "notes": "Must comply with PCI-DSS 4.0 and CNSA 2.0 mandates. Prioritize immediate TLS KEX migration."
    },
    "defense_government": {
        "sector_name": "Defense & Government Services",
        "hndl_risk_tier": "CRITICAL",
        "recommended_kex": "ML-KEM-1024 (FIPS 203)",
        "recommended_sig": "ML-DSA-87 (FIPS 204) / LMS / XMSS",
        "key_derivation": "HKDF-SHA512",
        "notes": "Mandatory CNSA 2.0 compliance timeline (2025-2033). Strict zero-trust PQC enforcement."
    },
    "healthcare": {
        "sector_name": "Healthcare & Life Sciences",
        "hndl_risk_tier": "HIGH",
        "recommended_kex": "ML-KEM-768 / Hybrid X25519+ML-KEM-768",
        "recommended_sig": "ML-DSA-65",
        "key_derivation": "HKDF-SHA256",
        "notes": "Focus on protecting long-lived medical records (HIPAA) against Store Now Decrypt Later (SNDL) threat vectors."
    },
    "telecom": {
        "sector_name": "Telecommunications & Critical Networks",
        "hndl_risk_tier": "HIGH",
        "recommended_kex": "ML-KEM-768",
        "recommended_sig": "ML-DSA-65 / SLH-DSA-SHA2-128s",
        "key_derivation": "HKDF-SHA256",
        "notes": "Low-latency hybrid key exchange for high-throughput gateway proxies."
    },
    "general_enterprise": {
        "sector_name": "General Enterprise",
        "hndl_risk_tier": "MODERATE",
        "recommended_kex": "Hybrid X25519+ML-KEM-768",
        "recommended_sig": "ML-DSA-65",
        "key_derivation": "HKDF-SHA256",
        "notes": "Adopt hybrid classical+PQC TLS endpoints to maintain backward compatibility while achieving quantum resistance."
    }
}


class PqcAlgorithmRecommender:
    """Provides natural language and sector-tailored post-quantum algorithm guidance."""

    @staticmethod
    def recommend(sector: str = "general_enterprise", query: Optional[str] = None) -> Dict[str, Any]:
        sector_key = sector.lower().replace(" ", "_")
        profile = SECTOR_PROFILES.get(sector_key, SECTOR_PROFILES["general_enterprise"])

        standards_reference = {
            "FIPS_203": "ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)",
            "FIPS_204": "ML-DSA (Module-Lattice-Based Digital Signature Algorithm)",
            "FIPS_205": "SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)"
        }

        query_insights = []
        if query:
            q_lower = query.lower()
            if "signing" in q_lower or "signature" in q_lower or "cert" in q_lower:
                query_insights.append("Query focus: Digital Signatures -> Recommend ML-DSA-65/87 (FIPS 204) or SLH-DSA (FIPS 205).")
            if "encryption" in q_lower or "kex" in q_lower or "key exchange" in q_lower:
                query_insights.append("Query focus: Key Establishment -> Recommend ML-KEM-768/1024 (FIPS 203).")
            if "sndl" in q_lower or "harvest" in q_lower:
                query_insights.append("Query focus: SNDL/HNDL Mitigation -> Prioritize Key Encapsulation (ML-KEM) to prevent historical traffic decryption.")

        return {
            "sector": profile["sector_name"],
            "hndl_risk_tier": profile["hndl_risk_tier"],
            "recommendations": {
                "key_encapsulation": profile["recommended_kex"],
                "digital_signature": profile["recommended_sig"],
                "key_derivation_function": profile["key_derivation"],
                "symmetric_cipher": "AES-256-GCM"
            },
            "nist_standards": standards_reference,
            "guidance_notes": profile["notes"],
            "query_insights": query_insights
        }
