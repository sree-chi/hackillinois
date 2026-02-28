import os
import json
import requests
import google.generativeai as genai
from dotenv import load_dotenv

# Load API keys from .env.local
load_dotenv(".env.local")

# --- CONFIGURATION ---
BASE_URL = "http://localhost:8000"

# 1. Setup Gemini
gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("Gemini_API_Key")
if not gemini_key:
    print("❌ ERROR: You must set your GEMINI_API_KEY environment variable first!")
    exit(1)

genai.configure(api_key=gemini_key)

# ==========================================
# PHASE 1: THE DEVELOPER (Setting up the rules)
# ==========================================
print("👨💻 [Developer] Requesting a new API Key from Sentinel-Auth...")
key_res = requests.post(f"{BASE_URL}/v1/developer/keys", json={
    "app_name": "Demo Agent CLI",
    "owner_email": "demo@example.com"
})

if key_res.status_code != 200 and key_res.status_code != 201:
    print(f"❌ Failed to generate key: {key_res.status_code} - {key_res.text}")
    exit(1)
    
api_key = key_res.json()["api_key"]

print("👨💻 [Developer] Creating a strict security policy ($1,000 max spend)...")
auth_headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
policy_res = requests.post(f"{BASE_URL}/v1/policies", headers=auth_headers, json={
    "name": "CLI Strict Policy",
    "description": "Auto-generated policy for the CLI demo.",
    "rules": {
        "allowed_http_methods": ["GET", "POST"],
        "max_spend_usd": 1000 # Strict limit!
    }
})

if policy_res.status_code != 200 and policy_res.status_code != 201:
    print(f"❌ Failed to create policy: {policy_res.status_code} - {policy_res.text}")
    exit(1)
    
policy_id = policy_res.json()["id"]
print(f"✅ Active Policy ID: {policy_id}\n")


# ==========================================
# PHASE 2: THE AI AGENT (Thinking and Acting)
# ==========================================
system_prompt = """
You are an autonomous financial AI agent. 
Before you act, you MUST request authorization from the Sentinel-Auth API. 
Return ONLY a valid JSON object matching this schema, with no markdown formatting:
{
  "policy_id": "The active policy ID provided in the prompt",
  "requester": "agent://gemini_financial_bot",
  "action": {
    "type": "wire_transfer",
    "http_method": "POST",
    "resource": "/wallets/treasury",
    "amount_usd": <estimated cost as a number>
  },
  "reasoning_trace": "A detailed explanation of WHY you are doing this."
}
"""

model = genai.GenerativeModel("gemini-2.5-flash", system_instruction=system_prompt)

# Notice how the human command is asking to spend $4,500, but the policy max is $1,000!
human_command = "I need you to move $4,500 to the treasury wallet to cover payroll."
print(f"�️  Human Command: {human_command}")
print("🧠 [Agent] Gemini is thinking...\n")

# Force Gemini to output JSON
response = model.generate_content(
    f"Active Policy: {policy_id}\nCommand: {human_command}",
    generation_config=genai.GenerationConfig(response_mime_type="application/json")
)

agent_intent = json.loads(response.text)
print(f"🤖 [Agent] Gemini's Generated Intent:\n{json.dumps(agent_intent, indent=2)}\n")

# ==========================================
# PHASE 3: THE PROXY INTERCEPT (Sentinel-Auth)
# ==========================================
print("🛡️  [Sentinel] Evaluating Agent Intent against Policy...")
proxy_response = requests.post(f"{BASE_URL}/v1/authorize", headers=auth_headers, json=agent_intent)

if proxy_response.status_code == 200:
    data = proxy_response.json()
    print(f"✅ APPROVED! Solana Receipt anchored: {data.get('receipt_signature')}")
else:
    print(f"🚨 BLOCKED BY SENTINEL! Status: {proxy_response.status_code}")
    
    # Prettify the error message for the demo
    detail = proxy_response.json().get("detail", {})
    message = detail if isinstance(detail, str) else detail.get("error", {}).get("message", "Unknown error")
    print(f"🛑 Reason: {message}")
