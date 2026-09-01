"""
Unit tests for QRAMM Open Source Security Tools integration engine.
"""

from __future__ import annotations

from backend.scanner.qramm_tools_engine import (
    CryptoDepsScanner,
    CNSA2TimelineAnalyzer,
    PqcAlgorithmRecommender,
)


def test_cryptodeps_scanner_python():
    sample_requirements = """
# Python requirements file
cryptography==42.0.0
pycryptodome>=3.18.0
rsa==4.9
requests==2.31.0
"""
    result = CryptoDepsScanner.scan_manifest("requirements.txt", sample_requirements)
    assert result["ecosystem"] == "python"
    assert result["overall_risk"] == "VULNERABLE"
    assert result["total_dependencies_flagged"] == 3
    assert any(f["package"] == "rsa" and f["risk"] == "VULNERABLE" for f in result["findings"])


def test_cryptodeps_scanner_npm():
    sample_package_json = """
{
  "name": "sample-app",
  "dependencies": {
    "crypto-js": "^4.2.0",
    "express": "^4.19.0"
  },
  "devDependencies": {
    "node-forge": "^1.3.0"
  }
}
"""
    result = CryptoDepsScanner.scan_manifest("package.json", sample_package_json)
    assert result["ecosystem"] == "npm"
    assert result["overall_risk"] == "VULNERABLE"
    assert result["total_dependencies_flagged"] == 2


def test_cnsa2_timeline_analyzer_non_compliant():
    result = CNSA2TimelineAnalyzer.analyze(
        tls_version="TLSv1.2",
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
        key_exchange="ECDHE-RSA",
        cert_signature_algo="sha256WithRSAEncryption",
        key_size=2048,
    )
    assert result["cnsa_2_0_status"] in {"NON_COMPLIANT", "PARTIAL"}
    assert len(result["violations"]) >= 2
    assert len(result["milestone_roadmap"]) == 5


def test_cnsa2_timeline_analyzer_compliant():
    result = CNSA2TimelineAnalyzer.analyze(
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        key_exchange="X25519MLKEM768",
        cert_signature_algo="ML-DSA-87",
        key_size=4096,
    )
    assert result["cnsa_2_0_status"] == "COMPLIANT"
    assert result["compliance_score"] == 100
    assert len(result["violations"]) == 0


def test_pqc_algorithm_recommender():
    rec_fin = PqcAlgorithmRecommender.recommend(sector="financial", query="How to protect key exchange against HNDL?")
    assert rec_fin["sector"] == "Banking & Financial Infrastructure"
    assert "ML-KEM" in rec_fin["recommendations"]["key_encapsulation"]
    assert len(rec_fin["query_insights"]) > 0
