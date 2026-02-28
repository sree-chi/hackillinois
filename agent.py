import os
import json
import requests
import google.generativeai as genai
from dotenv import load_dotenv

# Load API keys from .env.local
load_dotenv(".env.local")

# Configuration
SENTINEL_API_URL = "http://localhost:8000/v1/authorize"
SENTINEL_API_KEY = "hackillinois_2026_super_secret" # The key from your docker-compose
POLICY_ID = "pol_your_active_policy_id_here" # Copy this from your new Developer Portal

# 1. Setup Gemini
# We use Gemini_API_Key from the .env.local file
genai.configure(api_key=os.environ.get("Gemini_API_Key") or os.environ.get("GEMINI_API_KEY"))

# 2. Give Gemini the System Prompt
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

model = genai.GenerativeModel(
    "gemini-2.5-flash",
    system_instruction=system_prompt
)

# 3. The Real-World Test
human_command = "I need you to move $4,500 to the treasury wallet to cover payroll."
print(f"👨💻 Human Command: {human_command}")
print("🧠 Gemini is thinking...")

# Force Gemini to output JSON
response = model.generate_content(
    f"Active Policy: {POLICY_ID}\nCommand: {human_command}",
    generation_config=genai.GenerationConfig(response_mime_type="application/json")
)

agent_intent = json.loads(response.text)
print(f"\n🤖 Gemini's Generated Intent:\n{json.dumps(agent_intent, indent=2)}")

# 4. Send Gemini's intent to Sentinel-Auth
print("\n🛡️ Sending intent to Sentinel-Auth for evaluation...")
headers = {
    "Authorization": f"Bearer {SENTINEL_API_KEY}",
    "Content-Type": "application/json"
}

proxy_response = requests.post(SENTINEL_API_URL, headers=headers, json=agent_intent)

if proxy_response.status_code == 200:
    data = proxy_response.json()
    print(f"\n✅ APPROVED! Solana Receipt anchored: {data.get('receipt_signature')}")
else:
    print(f"\n🚨 BLOCKED BY SENTINEL! Status: {proxy_response.status_code}")
    print(f"Reason: {json.dumps(proxy_response.json(), indent=2)}")
