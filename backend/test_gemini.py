import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

print("=" * 50)
print("GEMINI MANUAL TEST")
print("=" * 50)

print("API key found:", bool(api_key))

if not api_key:
    print("❌ GEMINI_API_KEY not found")
    exit()

print("API key starts with:", api_key[:8] + "...")

genai.configure(api_key=api_key)

model_name = "gemini-3.8-flash"

print("Model:", model_name)
print("Sending request...")

try:
    model = genai.GenerativeModel(model_name)

    response = model.generate_content(
        "Reply with exactly: GEMINI_TEST_OK"
    )

    print("\n========== RESPONSE ==========")
    print(response.text)
    print("==============================")

except Exception as e:
    print("\n========== ERROR ==========")
    print("Error type:", type(e).__name__)
    print("Error:", str(e))
    print("============================")