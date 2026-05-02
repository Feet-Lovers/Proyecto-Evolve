import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from ia.analyzers.vulnerability_classifier import VulnerabilityClassifier


def test_packet_sqli():
    """Test con un paquete HTTP con SQLi clásica."""
    print("\n" + "="*60)
    print("TEST 1 — Análisis de paquete con SQLi")
    print("="*60)

    packet = {
        "method": "GET",
        "url": "http://dvwa.local/vulnerabilities/sqli/?id=1'+OR+'1'='1&Submit=Submit",
        "status": 200,
        "request_headers": {
            "Host": "dvwa.local",
            "Cookie": "PHPSESSID=abc123; security=low"
        },
        "request_body": None,
        "response_headers": {
            "Content-Type": "text/html",
            "Server": "Apache/2.4.41"
        },
        "response_body": "ID: 1' OR '1'='1\nFirst name: admin\nSurname: admin\nFirst name: Gordon\nSurname: Brown"
    }

    classifier = VulnerabilityClassifier()
    result = classifier.analyze_packet(packet)

    if result:
        print("✅ VULNERABILIDAD DETECTADA:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("❌ No se detectó vulnerabilidad (confianza por debajo del umbral)")

    return result


def test_fingerprint():
    """Test de fingerprinting."""
    print("\n" + "="*60)
    print("TEST 2 — Fingerprint de aplicación")
    print("="*60)

    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "Content-Type": "text/html; charset=UTF-8",
        "Set-Cookie": "PHPSESSID=xyz; path=/"
    }

    classifier = VulnerabilityClassifier()
    result = classifier.fingerprint(
        headers=headers,
        url="http://dvwa.local",
        response_body="<html><body>Login</body></html>"
    )

    print("🔍 FINGERPRINT DETECTADO:")
    print(json.dumps(result, indent=2, ensure_ascii=False))

    return result


if __name__ == "__main__":
    print("🚀 HookSuite — Test standalone módulo IA")
    print("Conectando con Claude API...\n")

    test_packet_sqli()
    test_fingerprint()

    print("\n" + "="*60)
    print("✅ Tests completados")
    print("="*60)