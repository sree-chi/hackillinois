import requests
import time
import json
import sys

# BASE_URL = "http://localhost:8000"
BASE_URL = "https://hackillinois-sentinel-9m2fa.ondigitalocean.app/server"

EMAIL = f"test_user_{int(time.time())}@example.com"
PASSWORD = "Password123!"

def test_flow():
    print(f"--- 1. Registering/Logging in as {EMAIL} ---")
    try:
        # Try register
        requests.post(f"{BASE_URL}/v1/accounts", json={
            "email": EMAIL,
            "password": PASSWORD,
            "full_name": "Test User"
        })
    except:
        pass
        
    res = requests.post(f"{BASE_URL}/v1/accounts/login", json={
        "email": EMAIL,
        "password": PASSWORD
    })
    if res.status_code != 200:
        print(f"Login failed: {res.text}")
        return
    
    session_token = res.json()["session_token"]
    print(f"Session token: {session_token[:10]}...")

    print("\n--- 2. Issuing API Key ---")
    res = requests.post(f"{BASE_URL}/v1/developer/keys", 
                        headers={"Authorization": f"Bearer {session_token}"},
                        json={"app_name": "Test App"})
    if res.status_code != 200:
        print(f"Key issuance failed: {res.text}")
        return
    
    api_key = res.json()["api_key"]
    client_id = res.json()["client_id"]
    print(f"API Key: {api_key}")
    print(f"Client ID: {client_id}")

    print("\n--- 3. Creating Policy ---")
    res = requests.post(f"{BASE_URL}/v1/policies",
                        headers={"Authorization": f"Bearer {api_key}"},
                        json={
                            "name": "Test Policy",
                            "rules": {
                                "allowed_http_methods": ["POST"],
                                "max_spend_usd": 1000,
                                "max_requests_per_minute": 60
                            }
                        })
    if res.status_code != 200:
        print(f"Policy creation failed: {res.text}")
        return
    
    policy_id = res.json()["id"]
    print(f"Policy ID: {policy_id}")

    print("\n--- 4. Authorizing (Should FAIL - No Price set) ---")
    RESOURCE = "openai/v1/chat/completions"
    res = requests.post(f"{BASE_URL}/v1/authorize",
                        headers={"Authorization": f"Bearer {api_key}"},
                        json={
                            "policy_id": policy_id,
                            "requester": "test-script",
                            "action": {
                                "type": "llm_call",
                                "http_method": "POST",
                                "resource": RESOURCE,
                                "amount_usd": 0 # Sentinel will check pricing DB
                            }
                        })
    
    print(f"Status: {res.status_code}")
    print(f"Response: {res.text}")
    
    if res.status_code == 403 and "PRICE_NOT_FOUND" in res.text:
        print("Success: Call was correctly BLOCKED because price is unknown.")
    else:
        print("Warning: Expected 403 PRICE_NOT_FOUND if table is fresh.")

    print(f"\n--- 5. Setting Price for {RESOURCE} ---")
    res = requests.post(f"{BASE_URL}/v1/accounts/me/keys/{client_id}/pricing",
                        headers={"Authorization": f"Bearer {session_token}"},
                        json={
                            "api_link": RESOURCE,
                            "price_per_call_usd": 0.05
                        })
    if res.status_code != 200:
        print(f"Pricing setup failed: {res.text}")
        return
    print("Price saved successfully.")

    print("\n--- 6. Authorizing (Should SUCCEED now) ---")
    res = requests.post(f"{BASE_URL}/v1/authorize",
                        headers={"Authorization": f"Bearer {api_key}"},
                        json={
                            "policy_id": policy_id,
                            "requester": "test-script",
                            "action": {
                                "type": "llm_call",
                                "http_method": "POST",
                                "resource": RESOURCE,
                                "amount_usd": 0
                            }
                        })
    
    print(f"Status: {res.status_code}")
    if res.status_code == 200:
        print(f"Success! Authorization Allowed. Receipt: {res.json().get('receipt_signature')}")
    else:
        print(f"Failed: {res.text}")

if __name__ == "__main__":
    test_flow()
