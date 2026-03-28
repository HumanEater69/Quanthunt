from __future__ import annotations

from typing import Any

from ..models import AssetFinding


def _key_exchange_algorithm(cipher_suite: str | None, key_exchange_group: str | None = None) -> str:
    c = (cipher_suite or "").upper()
    g = (key_exchange_group or "").upper()
    blob = f"{c} {g}"
    if any(x in blob for x in ("MLKEM", "ML-KEM", "KYBER", "0X11EC", "0X11ED")) and any(
        x in blob for x in ("X25519", "X448", "ECDHE", "DHE", "SECP256R1")
    ):
        return "Hybrid (Classical + ML-KEM)"
    if any(x in blob for x in ("MLKEM", "ML-KEM", "KYBER", "0X11EC", "0X11ED")):
        return "ML-KEM"
    if any(x in blob for x in ("X25519", "X448", "ECDHE", "DHE", "ECDH")):
        return "ECDHE/DHE"
    if "_RSA_" in blob or "TLS_RSA" in blob:
        return "RSA"
    return "unknown"


def _key_exchange_family(cipher_suite: str | None, key_exchange_group: str | None = None, named_group_ids: list[str] | None = None) -> str:
    c = (cipher_suite or "").upper()
    g = (key_exchange_group or "").upper()
    group_ids = " ".join(str(x).upper() for x in (named_group_ids or []))
    blob = f"{c} {g} {group_ids}"
    has_pqc = any(x in blob for x in ("MLKEM", "ML-KEM", "KYBER", "0X11EC", "0X11ED"))
    has_classic = any(x in blob for x in ("X25519", "X448", "ECDHE", "DHE", "ECDH", "RSA", "SECP256R1"))
    if has_pqc and has_classic:
        return "hybrid-pqc-classical"
    if has_pqc:
        return "pqc"
    if has_classic:
        return "classical"
    return "unknown"


def _signature_algorithm_family(sig_algo: str | None) -> str:
    s = (sig_algo or "").upper()
    if any(x in s for x in ("MLDSA", "ML-DSA", "DILITHIUM", "SLHDSA", "SLH-DSA", "SPHINCS")):
        return "pqc"
    if any(x in s for x in ("RSA", "ECDSA", "ED25519", "ED448", "SHA", "PKCS")):
        return "classical"
    return "unknown"


def _cipher_component_value(tls_obj: object, key: str) -> str:
    components = getattr(tls_obj, "cipher_components", {}) or {}
    value = components.get(key)
    return str(value or "unknown")


def _cipher_component_bool(tls_obj: object, key: str) -> bool:
    components = getattr(tls_obj, "cipher_components", {}) or {}
    return bool(components.get(key, False))

def build_cbom(domain: str, findings: list[AssetFinding]) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for f in findings:
        cipher = f.tls.cipher_suite or ""
        cert_sig = f.tls.cert_sig_algo or ""
        cipher_up = cipher.upper()
        cert_sig_up = cert_sig.upper()
        kx_group_up = (f.tls.key_exchange_group or "").upper()
        named_group_ids = [str(x).upper() for x in (f.tls.named_group_ids or [])]
        supported_text = " ".join(
            str((row or {}).get("suite") or "") + " " + str((row or {}).get("key_exchange") or "")
            for row in (getattr(f.tls, "supported_cipher_analysis", []) or [])
        ).upper()
        fips203 = (
            any(x in cipher_up for x in ["ML-KEM", "MLKEM", "KYBER"])
            or any(x in kx_group_up for x in ["ML-KEM", "MLKEM", "KYBER", "X25519MLKEM", "SECP256R1MLKEM"])
            or any(x in supported_text for x in ["ML-KEM", "MLKEM", "KYBER", "X25519MLKEM", "SECP256R1MLKEM"])
            or any(x in named_group_ids for x in ["0X11EC", "0X11ED"])
        )
        fips204 = any(x in cert_sig_up for x in ["ML-DSA", "MLDSA", "DILITHIUM"])
        fips205 = any(x in cert_sig_up for x in ["SLH-DSA", "SLHDSA", "SPHINCS"])
        pqc_detected = fips203 or fips204 or fips205
        pqc_label = "Quantum-Safe" if pqc_detected else "Classic-Secure"
        key_exchange_algo = _key_exchange_algorithm(f.tls.cipher_suite, f.tls.key_exchange_group)
        key_exchange_family = _key_exchange_family(f.tls.cipher_suite, f.tls.key_exchange_group, f.tls.named_group_ids)
        signature_family = _signature_algorithm_family(f.tls.cert_sig_algo)
        if key_exchange_family == "hybrid-pqc-classical" or signature_family == "pqc":
            posture_class = "pqc-capable"
        elif key_exchange_family == "classical":
            posture_class = "classical-only"
        else:
            posture_class = "unknown"
        components.append(
            {
                "type": "cryptographic-asset",
                "name": f.asset,
                "cryptoProperties": {
                    "assetType": "protocol",
                    "protocolProperties": {
                        "type": "tls",
                        "version": f.tls.tls_version or "unknown",
                        "keyExchangeAlgorithm": key_exchange_algo,
                        "keyExchangeGroup": f.tls.key_exchange_group or "unknown",
                        "keyExchangeNamedGroupIds": named_group_ids,
                        "primaryCipherSuite": f.tls.cipher_suite or "unknown",
                        "cipherSuites": f.tls.accepted_ciphers or ([f.tls.cipher_suite] if f.tls.cipher_suite else []),
                        "supportedCipherSuiteCount": len(getattr(f.tls, "supported_cipher_suites", []) or []),
                        "negotiatedCipherAnalysis": {
                            "keyExchange": _cipher_component_value(f.tls, "key_exchange"),
                            "authentication": _cipher_component_value(f.tls, "authentication"),
                            "bulkCipher": _cipher_component_value(f.tls, "bulk_cipher"),
                            "mode": _cipher_component_value(f.tls, "mode"),
                            "hash": _cipher_component_value(f.tls, "hash"),
                            "aead": _cipher_component_bool(f.tls, "aead"),
                            "forwardSecrecy": _cipher_component_bool(f.tls, "forward_secrecy"),
                            "pqcSignal": _cipher_component_bool(f.tls, "pqc_signal"),
                            "securityLevel": _cipher_component_value(f.tls, "security_level"),
                        },
                        "supportedCipherAnalyses": getattr(f.tls, "supported_cipher_analysis", []) or [],
                        "ikev2TransformTypes": [{"type": "keyExchange", "id": key_exchange_algo}],
                    },
                },
                "properties": [
                    {
                        "name": "quantum-safe",
                        "value": str(pqc_detected).lower(),
                    },
                    {"name": "hndl-risk-score", "value": str(f.hndl_risk_score)},
                    {"name": "pqc-posture-label", "value": pqc_label},
                    {"name": "crypto-posture-class", "value": posture_class},
                    {"name": "key-exchange-algorithm", "value": key_exchange_algo},
                    {"name": "key-exchange-family", "value": key_exchange_family},
                    {"name": "key-exchange-group", "value": f.tls.key_exchange_group or "unknown"},
                    {"name": "key-exchange-named-group-ids", "value": ",".join(named_group_ids)},
                    {"name": "primary-cipher-suite", "value": f.tls.cipher_suite or "unknown"},
                    {"name": "signature-algorithm", "value": f.tls.cert_sig_algo or "unknown"},
                    {"name": "signature-family", "value": signature_family},
                    {"name": "cipher-kx", "value": _cipher_component_value(f.tls, "key_exchange")},
                    {"name": "cipher-authentication", "value": _cipher_component_value(f.tls, "authentication")},
                    {"name": "cipher-bulk", "value": _cipher_component_value(f.tls, "bulk_cipher")},
                    {"name": "cipher-mode", "value": _cipher_component_value(f.tls, "mode")},
                    {"name": "cipher-hash", "value": _cipher_component_value(f.tls, "hash")},
                    {"name": "cipher-security-level", "value": _cipher_component_value(f.tls, "security_level")},
                    {"name": "cipher-aead", "value": str(_cipher_component_bool(f.tls, "aead")).lower()},
                    {"name": "cipher-forward-secrecy", "value": str(_cipher_component_bool(f.tls, "forward_secrecy")).lower()},
                    {"name": "cipher-pqc-signal", "value": str(_cipher_component_bool(f.tls, "pqc_signal")).lower()},
                    {"name": "supported-cipher-suite-count", "value": str(len(getattr(f.tls, "supported_cipher_suites", []) or []))},
                    {"name": "tls-scan-error", "value": f.tls.scan_error or ""},
                    {"name": "nist-fips-203-signal-detected", "value": str(fips203).lower()},
                    {"name": "nist-fips-204-signal-detected", "value": str(fips204).lower()},
                    {"name": "nist-fips-205-signal-detected", "value": str(fips205).lower()},
                    {"name": "pqc-detection-mode", "value": "heuristic-observation"},
                    {
                        "name": "pqc-detection-note",
                        "value": "Derived from observable TLS/certificate metadata; this is not formal cryptographic certification.",
                    },
                    {
                        "name": "scan-methodology",
                        "value": "active-network-handshake-plus-passive-metadata",
                    },
                    {"name": "agent-required", "value": "false"},
                    {"name": "nist-pqc-ref", "value": "FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)"},
                    {"name": "label", "value": pqc_label},
                    {"name": "hndl-label", "value": f.label},
                ],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {"name": domain, "type": "platform"},
            "properties": [
                {
                    "name": "scan-methodology",
                    "value": "active-network-handshake-plus-passive-metadata",
                },
                {
                    "name": "scan-methodology-note",
                    "value": "No endpoint agent is installed; detection is based on externally observable TLS and certificate metadata.",
                },
                {"name": "agent-required", "value": "false"},
            ],
        },
        "components": components,
    }
