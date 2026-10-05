"""
VirusScan Security — Gemini AI Module
Handles Gemini API interaction for AI-assisted security reasoning.
"""

import os
import json
import re
import traceback

try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


def configure_gemini():
    if not GENAI_AVAILABLE:
        print("[Gemini] SDK unavailable")
        return False

    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    print("[Gemini] API key found:", bool(api_key))

    if api_key:
        print("[Gemini] Key prefix:", api_key[:10] + "...")

    if not api_key:
        print("[Gemini] GEMINI_API_KEY missing")
        return False

    try:
        genai.configure(api_key=api_key)
        print("[Gemini] Configured successfully")
        return True
    except Exception as e:
        print("[Gemini] Configuration error:", e)
        return False


def analyze_with_gemini(evidence):
    """
    Send structured security evidence to Gemini for AI-assisted analysis.

    Args:
        evidence (dict): Structured APK security indicators.

    Returns:
        dict: Gemini's structured security assessment, or None if unavailable.
    """
    if not configure_gemini():
        return None

    prompt = build_analysis_prompt(evidence)

    try:
        model = genai.GenerativeModel('gemini-3.8-flash')
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.3,
                max_output_tokens=2048,
            )
        )

        return parse_gemini_response(response.text)

    except Exception as e:
        print(f"[Gemini Error] {e}")
        traceback.print_exc()
        return None


def build_analysis_prompt(evidence):
    """Build a detailed prompt for Gemini security analysis."""
    evidence_json = json.dumps(evidence, indent=2, default=str)

    prompt = f"""You are an Android application security analyst.

Analyze the following static APK security indicators that were extracted by automated static analysis tools (Androguard).

Do NOT assume that one permission, API, URL, or component alone proves malware.
Evaluate combinations of indicators and application context.
Be balanced — many legitimate apps use sensitive permissions.

Here are the extracted indicators:

{evidence_json}

Based on this evidence, return a JSON object with the following fields:

{{
  "classification": "SAFE" or "SUSPICIOUS" or "MALICIOUS",
  "risk_score": <integer 0-100>,
  "summary": "<short 2-3 sentence explanation>",
  "reasons": ["<reason 1>", "<reason 2>", ...],
  "high_risk_indicators": ["<indicator 1>", "<indicator 2>", ...],
  "recommendations": ["<recommendation 1>", "<recommendation 2>", ...],
  "confidence": "LOW" or "MEDIUM" or "HIGH"
}}

Rules:
- classification must be exactly one of: SAFE, SUSPICIOUS, MALICIOUS
- risk_score must be an integer between 0 and 100
- reasons should contain human-readable explanations
- recommendations should be actionable security advice
- confidence reflects how certain you are based on available evidence
- The analysis must be based ONLY on the supplied evidence
- Return ONLY valid JSON, no additional text or markdown formatting
"""

    return prompt


def parse_gemini_response(response_text):
    """Parse and validate Gemini's JSON response."""
    if not response_text:
        return None

    # Try to extract JSON from the response
    # Handle cases where Gemini wraps in markdown code blocks
    text = response_text.strip()

    # Remove markdown code block wrappers
    if text.startswith('```json'):
        text = text[7:]
    elif text.startswith('```'):
        text = text[3:]
    if text.endswith('```'):
        text = text[:-3]

    text = text.strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in the text
        match = re.search(r'\{[\s\S]*\}', text)
        if match:
            try:
                data = json.loads(match.group())
            except json.JSONDecodeError:
                return None
        else:
            return None

    # Validate required fields
    valid_classifications = {'SAFE', 'SUSPICIOUS', 'MALICIOUS'}
    valid_confidence = {'LOW', 'MEDIUM', 'HIGH'}

    classification = data.get('classification', 'SUSPICIOUS').upper()
    if classification not in valid_classifications:
        classification = 'SUSPICIOUS'

    risk_score = data.get('risk_score', 50)
    if not isinstance(risk_score, (int, float)):
        risk_score = 50
    risk_score = max(0, min(100, int(risk_score)))

    confidence = data.get('confidence', 'MEDIUM').upper()
    if confidence not in valid_confidence:
        confidence = 'MEDIUM'

    return {
        'classification': classification,
        'risk_score': risk_score,
        'summary': data.get('summary', 'AI analysis completed.'),
        'reasons': data.get('reasons', []),
        'high_risk_indicators': data.get('high_risk_indicators', []),
        'recommendations': data.get('recommendations', []),
        'confidence': confidence
    }


def analyze_url_with_gemini(url_evidence):
    """Send URL analysis evidence to Gemini for assessment."""
    if not configure_gemini():
        return None

    evidence_json = json.dumps(url_evidence, indent=2)

    prompt = f"""You are a cybersecurity analyst specializing in URL and domain analysis.

Analyze the following URL indicators:

{evidence_json}

Return a JSON object with:
{{
  "classification": "SAFE" or "SUSPICIOUS" or "MALICIOUS",
  "risk_score": <integer 0-100>,
  "summary": "<short explanation>",
  "reasons": ["<reason>", ...],
  "recommendations": ["<recommendation>", ...],
  "confidence": "LOW" or "MEDIUM" or "HIGH"
}}

Rules:
- Do NOT mark a URL as malicious simply because it is unfamiliar
- Analyze the URL structure, protocol, domain patterns, and keywords
- Return ONLY valid JSON
"""

    try:
        model = genai.GenerativeModel('gemini-3.8-flash')
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.3,
                max_output_tokens=1024,
            )
        )
        return parse_gemini_response(response.text)
    except Exception as e:
        print(f"[Gemini URL Error] {e}")
        return None


def analyze_behavior_with_gemini(behavior_evidence):
    """Send behavioral evidence to Gemini for behavior analysis."""
    if not configure_gemini():
        return None

    evidence_json = json.dumps(behavior_evidence, indent=2)

    prompt = f"""You are an Android application behavior analyst.

Based on the following static indicators, infer the likely runtime behavior of this application.
This is a static behavioral inference — the APK was NOT executed.

Indicators:
{evidence_json}

Return a JSON object:
{{
  "classification": "SAFE" or "SUSPICIOUS" or "MALICIOUS",
  "risk_score": <integer 0-100>,
  "summary": "<short explanation of likely behavior>",
  "behavior_timeline": [
    {{"step": "<action>", "risk": "LOW" or "MEDIUM" or "HIGH", "description": "<explanation>"}},
    ...
  ],
  "reasons": ["<reason>", ...],
  "recommendations": ["<recommendation>", ...],
  "confidence": "LOW" or "MEDIUM" or "HIGH"
}}

Rules:
- Infer behaviors from permissions, APIs, intents, and components
- Label each behavior step with appropriate risk
- Return ONLY valid JSON
"""

    try:
        model = genai.GenerativeModel('gemini-3.8-flash')
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.3,
                max_output_tokens=2048,
            )
        )

        result = parse_gemini_response(response.text)
        if result:
            # Extract behavior_timeline if present
            text = response.text.strip()
            if text.startswith('```json'):
                text = text[7:]
            elif text.startswith('```'):
                text = text[3:]
            if text.endswith('```'):
                text = text[:-3]
            try:
                full_data = json.loads(text.strip())
                result['behavior_timeline'] = full_data.get('behavior_timeline', [])
            except:
                pass
        return result
    except Exception as e:
        print(f"[Gemini Behavior Error] {e}")
        return None
