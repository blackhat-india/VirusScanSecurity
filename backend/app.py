"""
VirusScan Security — Flask Backend Application
Main entry point for the REST API server.

Features:
- APK static analysis
- FUD / evasion detection
- Gemini AI security assessment
- Certificate analysis
- Static behavior analysis
- Scan history
- Statistics
- Contact form
"""

import os
import uuid
import traceback
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv


# ──────────────────────────────────────────────────
# Environment Configuration
# ──────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

load_dotenv(os.path.join(PROJECT_ROOT, ".env"))


# ──────────────────────────────────────────────────
# Analyzer Imports
# ──────────────────────────────────────────────────

from analyzer import (
    validate_apk,
    analyze_apk,
    combine_scores,
    classify_score,
    DEMO_RESULT,
    extract_certificate,
    ANDROGUARD_AVAILABLE,
)


# ──────────────────────────────────────────────────
# Gemini Imports
# ──────────────────────────────────────────────────

from gemini_module import (
    analyze_with_gemini,
    analyze_behavior_with_gemini,
    configure_gemini,
)


# ──────────────────────────────────────────────────
# Database Imports
# ──────────────────────────────────────────────────

from database import (
    init_db,
    save_scan,
    get_scan_history,
    get_scan_by_id,
    get_stats,
    save_contact_message,
)


# ──────────────────────────────────────────────────
# Flask Application
# ──────────────────────────────────────────────────

FRONTEND_FOLDER = os.path.abspath(
    os.path.join(BASE_DIR, "..", "frontend")
)

app = Flask(
    __name__,
    static_folder=FRONTEND_FOLDER
)

CORS(app)


# ──────────────────────────────────────────────────
# Upload Configuration
# ──────────────────────────────────────────────────

UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "..",
    "uploads"
)

MAX_APK_SIZE_MB = int(
    os.getenv("MAX_APK_SIZE_MB", 50)
)

MAX_APK_SIZE = MAX_APK_SIZE_MB * 1024 * 1024

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# ──────────────────────────────────────────────────
# Database Initialization
# ──────────────────────────────────────────────────

init_db()


# ══════════════════════════════════════════════════
# FRONTEND ROUTES
# ══════════════════════════════════════════════════

@app.route("/")
@app.route("/signin")
def serve_index():
    """Serve the landing/sign-in page."""
    return send_from_directory(
        FRONTEND_FOLDER,
        "index.html"
    )


@app.route("/home")
def serve_home():
    """Serve dashboard/home page."""
    return send_from_directory(
        FRONTEND_FOLDER,
        "home.html"
    )


@app.route("/scanner")
def serve_scanner():
    """Serve APK scanner page."""
    return send_from_directory(
        FRONTEND_FOLDER,
        "scanner.html"
    )


@app.route("/behavior")
def serve_behavior():
    """Serve behavior analysis page."""
    return send_from_directory(
        FRONTEND_FOLDER,
        "behavior.html"
    )


@app.route("/certificate")
def serve_certificate():
    """Serve certificate analysis page."""
    return send_from_directory(
        FRONTEND_FOLDER,
        "certificate.html"
    )


@app.route("/protection")
def serve_protection():
    """Serve protection/security information page."""
    return send_from_directory(
        FRONTEND_FOLDER,
        "protection.html"
    )


@app.route("/about")
def serve_about():
    """Serve about page."""
    return send_from_directory(
        FRONTEND_FOLDER,
        "about.html"
    )


@app.route("/contact")
def serve_contact():
    """Serve contact page."""
    return send_from_directory(
        FRONTEND_FOLDER,
        "contact.html"
    )


# ──────────────────────────────────────────────────
# Static CSS
# ──────────────────────────────────────────────────

@app.route("/css/<path:filename>")
def serve_css(filename):
    return send_from_directory(
        os.path.join(FRONTEND_FOLDER, "css"),
        filename
    )


# ──────────────────────────────────────────────────
# Static JavaScript
# ──────────────────────────────────────────────────

@app.route("/js/<path:filename>")
def serve_js(filename):
    return send_from_directory(
        os.path.join(FRONTEND_FOLDER, "js"),
        filename
    )


# ──────────────────────────────────────────────────
# Static File Fallback
# ──────────────────────────────────────────────────

@app.route("/<path:filename>")
def serve_fallback(filename):
    target = os.path.join(
        FRONTEND_FOLDER,
        filename
    )

    if os.path.isfile(target):
        return send_from_directory(
            FRONTEND_FOLDER,
            filename
        )

    return send_from_directory(
        FRONTEND_FOLDER,
        "home.html"
    )


# ══════════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════════

@app.route("/api/health", methods=["GET"])
def health_check():
    """Return backend and dependency status."""

    try:
        gemini_configured = configure_gemini()
    except Exception:
        gemini_configured = False

    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "androguard_available": ANDROGUARD_AVAILABLE,
        "gemini_configured": gemini_configured,
        "max_apk_size_mb": MAX_APK_SIZE_MB,
        "features": {
            "apk_analysis": True,
            "fud_detection": True,
            "certificate_analysis": True,
            "behavior_analysis": True,
            "url_analysis": False,
        }
    })


# ══════════════════════════════════════════════════
# APK ANALYSIS
# ══════════════════════════════════════════════════

@app.route("/api/analyze/apk", methods=["POST"])
def analyze_apk_endpoint():
    """
    Upload and analyze an APK.

    Pipeline:

        Upload
          ↓
        Validation
          ↓
        Static APK analysis
          ↓
        FUD / evasion detection
          ↓
        Risk scoring
          ↓
        Gemini AI assessment
          ↓
        Combined result
          ↓
        Database
          ↓
        JSON response
    """

    # ──────────────────────────────────────────────
    # Check uploaded file
    # ──────────────────────────────────────────────

    if "apk" not in request.files:
        return jsonify({
            "success": False,
            "error": "No APK file uploaded"
        }), 400

    file = request.files["apk"]

    if file.filename == "":
        return jsonify({
            "success": False,
            "error": "No file selected"
        }), 400

    if not file.filename.lower().endswith(".apk"):
        return jsonify({
            "success": False,
            "error": "File must have .apk extension"
        }), 400

    # ──────────────────────────────────────────────
    # Check file size
    # ──────────────────────────────────────────────

    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)

    if file_size > MAX_APK_SIZE:
        return jsonify({
            "success": False,
            "error": (
                f"File too large. Maximum size is "
                f"{MAX_APK_SIZE_MB} MB"
            )
        }), 400

    if file_size == 0:
        return jsonify({
            "success": False,
            "error": "File is empty"
        }), 400

    # ──────────────────────────────────────────────
    # Temporary file
    # ──────────────────────────────────────────────

    original_filename = file.filename

    temp_filename = (
        f"{uuid.uuid4().hex}.apk"
    )

    temp_path = os.path.join(
        UPLOAD_FOLDER,
        temp_filename
    )

    try:

        # ──────────────────────────────────────────
        # Save APK
        # ──────────────────────────────────────────

        file.save(temp_path)

        # ──────────────────────────────────────────
        # Validate APK
        # ──────────────────────────────────────────

        valid, validation_message = validate_apk(
            temp_path
        )

        if not valid:
            return jsonify({
                "success": False,
                "error": validation_message
            }), 400

        # ──────────────────────────────────────────
        # Static APK Analysis
        # ──────────────────────────────────────────

        result = analyze_apk(
            temp_path,
            original_filename
        )

        if not result.get("success"):
            return jsonify(result), 400

        # ──────────────────────────────────────────
        # Extract evidence for Gemini
        # ──────────────────────────────────────────

        permissions = result.get(
            "permissions",
            {}
        )

        components = result.get(
            "components",
            {}
        )

        intents = result.get(
            "intents",
            {}
        )

        api_indicators = result.get(
            "api_indicators",
            {}
        )

        network_indicators = result.get(
            "network_indicators",
            {}
        )

        suspicious_strings = result.get(
            "suspicious_strings",
            {}
        )

        certificate = result.get(
            "certificate",
            {}
        )

        resources = result.get(
            "resources",
            {}
        )

        metadata = result.get(
            "metadata",
            {}
        )

        # NEW:
        # FUD / Evasion analysis generated by analyzer.py
        fud_analysis = result.get(
            "fud_analysis",
            {}
        )

        evidence = {
            "package_name": metadata.get(
                "package_name",
                "Unknown"
            ),

            "app_name": metadata.get(
                "app_name",
                "Unknown"
            ),

            "permissions": permissions.get(
                "all",
                []
            ),

            "dangerous_permissions": [
                p.get("short_name", "")
                for p in permissions.get(
                    "dangerous",
                    []
                )
            ],

            "permission_combinations":
                permissions.get(
                    "suspicious_combinations",
                    []
                ),

            "components": {
                "activities": components.get(
                    "activities",
                    0
                ),

                "services": components.get(
                    "services",
                    0
                ),

                "receivers": components.get(
                    "receivers",
                    0
                ),

                "providers": components.get(
                    "providers",
                    0
                ),

                "exported_count": components.get(
                    "exported_count",
                    0
                ),
            },

            "suspicious_intents": [
                i.get("short_name", "")
                for i in intents.get(
                    "suspicious",
                    []
                )
            ],

            "suspicious_apis": [
                a.get("indicator", "")
                for a in api_indicators.get(
                    "indicators",
                    []
                )
            ],

            "suspicious_urls":
                network_indicators.get(
                    "suspicious_urls",
                    []
                )[:10],

            "domains":
                network_indicators.get(
                    "domains",
                    []
                )[:10],

            "suspicious_strings": [
                s.get("string", "")
                for s in suspicious_strings.get(
                    "strings",
                    []
                )
            ],

            # ────────────────────────────────
            # FUD / Evasion Evidence
            # ────────────────────────────────

            "fud_analysis": fud_analysis,

            "certificate": {
                "present": certificate.get(
                    "present",
                    False
                ),

                "algorithm": certificate.get(
                    "algorithm",
                    "Unknown"
                ),

                "is_debug": certificate.get(
                    "is_debug",
                    False
                ),
            },

            "suspicious_files_count":
                resources.get(
                    "suspicious_count",
                    0
                ),

            "preliminary_score":
                result.get(
                    "risk_analysis",
                    {}
                ).get(
                    "static_score",
                    0
                ),
        }

        # ──────────────────────────────────────────
        # Gemini AI Analysis
        # ──────────────────────────────────────────

        gemini_result = None

        try:

            gemini_result = analyze_with_gemini(
                evidence
            )

        except Exception as e:

            print(
                f"[Gemini Error] {e}"
            )

            traceback.print_exc()

        # ──────────────────────────────────────────
        # Combine Static + AI Score
        # ──────────────────────────────────────────

        static_score = result.get(
            "risk_analysis",
            {}
        ).get(
            "static_score",
            0
        )

        combined = combine_scores(
            static_score,
            gemini_result
        )

        result["combined_score"] = combined

        result["gemini_analysis"] = (
            gemini_result
        )

        # ──────────────────────────────────────────
        # Confidence Calculation
        # ──────────────────────────────────────────

        static_confidence = result.get(
            "risk_analysis",
            {}
        ).get(
            "confidence",
            "LOW"
        )

        ai_confidence = (
            gemini_result.get(
                "confidence",
                "LOW"
            )
            if gemini_result
            else "LOW"
        )

        if (
            static_confidence == "HIGH"
            and ai_confidence == "HIGH"
        ):
            confidence = "HIGH"

        elif (
            static_confidence == "HIGH"
            or (
                static_confidence == "MEDIUM"
                and ai_confidence in (
                    "MEDIUM",
                    "HIGH"
                )
            )
        ):
            confidence = "MEDIUM"

        else:
            confidence = "LOW"

        result["confidence"] = confidence

        # ──────────────────────────────────────────
        # Database
        # ──────────────────────────────────────────

        try:

            save_scan(
                scan_type="apk",
                filename=original_filename,
                package_name=metadata.get(
                    "package_name"
                ),
                risk_score=combined.get(
                    "final_score",
                    static_score
                ),
                classification=combined.get(
                    "classification",
                    result.get(
                        "risk_analysis",
                        {}
                    ).get(
                        "classification",
                        "UNKNOWN"
                    )
                ),
                confidence=confidence,
                summary=(
                    gemini_result.get(
                        "summary",
                        ""
                    )
                    if gemini_result
                    else ""
                ),
                result_json=result
            )

        except Exception as e:

            print(
                f"[DB Error] {e}"
            )

        # ──────────────────────────────────────────
        # Response
        # ──────────────────────────────────────────

        return jsonify(result)

    except Exception as e:

        traceback.print_exc()

        return jsonify({
            "success": False,
            "error": (
                f"Analysis failed: {str(e)}"
            )
        }), 500

    finally:

        # ──────────────────────────────────────────
        # Remove temporary APK
        # ──────────────────────────────────────────

        try:

            if os.path.exists(temp_path):
                os.remove(temp_path)

        except Exception:
            pass


# ══════════════════════════════════════════════════
# CERTIFICATE ANALYSIS
# ══════════════════════════════════════════════════

@app.route(
    "/api/analyze/certificate",
    methods=["POST"]
)
def analyze_certificate_endpoint():
    """
    Analyze the signing certificate of an APK.
    """

    if "apk" not in request.files:
        return jsonify({
            "success": False,
            "error": "No APK file uploaded"
        }), 400

    file = request.files["apk"]

    if not file.filename:
        return jsonify({
            "success": False,
            "error": "No file selected"
        }), 400

    if not file.filename.lower().endswith(".apk"):
        return jsonify({
            "success": False,
            "error": "File must have .apk extension"
        }), 400

    temp_filename = (
        f"{uuid.uuid4().hex}.apk"
    )

    temp_path = os.path.join(
        UPLOAD_FOLDER,
        temp_filename
    )

    try:

        file.save(temp_path)

        valid, message = validate_apk(
            temp_path
        )

        if not valid:
            return jsonify({
                "success": False,
                "error": message
            }), 400

        if not ANDROGUARD_AVAILABLE:
            return jsonify({
                "success": False,
                "error": (
                    "Androguard is not installed"
                )
            }), 500

        try:

            from androguard.core.apk import APK

        except ImportError:

            from androguard.core.bytecodes.apk import APK

        apk = APK(temp_path)

        cert_info = extract_certificate(
            apk
        )

        package_name = (
            apk.get_package()
            or "Unknown"
        )

        result = {
            "success": True,
            "filename": file.filename,
            "package_name": package_name,
            "certificate": cert_info,
        }

        # Save certificate scan
        try:

            is_debug = cert_info.get(
                "is_debug",
                False
            )

            save_scan(
                scan_type="certificate",
                filename=file.filename,
                package_name=package_name,
                risk_score=10 if is_debug else 0,
                classification=(
                    "SUSPICIOUS"
                    if is_debug
                    else "SAFE"
                ),
                confidence="MEDIUM",
                summary=(
                    "Certificate analysis completed"
                ),
                result_json=result
            )

        except Exception as e:

            print(
                f"[DB Error] {e}"
            )

        return jsonify(result)

    except Exception as e:

        traceback.print_exc()

        return jsonify({
            "success": False,
            "error": (
                "Certificate analysis failed: "
                f"{str(e)}"
            )
        }), 500

    finally:

        try:

            if os.path.exists(temp_path):
                os.remove(temp_path)

        except Exception:
            pass


# ══════════════════════════════════════════════════
# BEHAVIOR ANALYSIS
# ══════════════════════════════════════════════════

@app.route(
    "/api/analyze/behavior",
    methods=["POST"]
)
def analyze_behavior_endpoint():
    """
    Static behavioral inference.

    IMPORTANT:
    The APK is NOT executed.

    Behavior is inferred from:
    - Permissions
    - APIs
    - Intents
    - Services
    - Receivers
    - Network indicators
    - Suspicious strings
    - FUD/evasion indicators
    """

    if "apk" not in request.files:
        return jsonify({
            "success": False,
            "error": "No APK file uploaded"
        }), 400

    file = request.files["apk"]

    if not file.filename:
        return jsonify({
            "success": False,
            "error": "No file selected"
        }), 400

    if not file.filename.lower().endswith(".apk"):
        return jsonify({
            "success": False,
            "error": "File must have .apk extension"
        }), 400

    temp_filename = (
        f"{uuid.uuid4().hex}.apk"
    )

    temp_path = os.path.join(
        UPLOAD_FOLDER,
        temp_filename
    )

    try:

        file.save(temp_path)

        valid, message = validate_apk(
            temp_path
        )

        if not valid:
            return jsonify({
                "success": False,
                "error": message
            }), 400

        # ──────────────────────────────────────────
        # Full static analysis
        # ──────────────────────────────────────────

        analysis = analyze_apk(
            temp_path,
            file.filename
        )

        if not analysis.get("success"):
            return jsonify(analysis), 400

        permissions = analysis.get(
            "permissions",
            {}
        )

        components = analysis.get(
            "components",
            {}
        )

        intents = analysis.get(
            "intents",
            {}
        )

        api_indicators = analysis.get(
            "api_indicators",
            {}
        )

        network_indicators = analysis.get(
            "network_indicators",
            {}
        )

        suspicious_strings = analysis.get(
            "suspicious_strings",
            {}
        )

        # ──────────────────────────────────────────
        # Behavior evidence
        # ──────────────────────────────────────────

        behavior_evidence = {
            "package_name":
                analysis.get(
                    "metadata",
                    {}
                ).get(
                    "package_name",
                    "Unknown"
                ),

            "permissions":
                permissions.get(
                    "all",
                    []
                ),

            "dangerous_permissions": [
                p.get("short_name", "")
                for p in permissions.get(
                    "dangerous",
                    []
                )
            ],

            "services":
                components.get(
                    "service_names",
                    []
                ),

            "receivers":
                components.get(
                    "receiver_names",
                    []
                ),

            "intents": [
                i.get("short_name", "")
                for i in intents.get(
                    "suspicious",
                    []
                )
            ],

            "suspicious_apis": [
                a.get("indicator", "")
                for a in api_indicators.get(
                    "indicators",
                    []
                )
            ],

            "network_endpoints":
                network_indicators.get(
                    "suspicious_urls",
                    []
                )[:10],

            "exported_components": [
                c.get("name", "")
                for c in components.get(
                    "exported",
                    []
                )
            ],

            "suspicious_strings": [
                s.get("string", "")
                for s in suspicious_strings.get(
                    "strings",
                    []
                )
            ],

            # Include FUD analysis here too
            "fud_analysis":
                analysis.get(
                    "fud_analysis",
                    {}
                ),
        }

        # ──────────────────────────────────────────
        # Static behavior timeline
        # ──────────────────────────────────────────

        timeline = build_behavior_timeline(
            analysis
        )

        # ──────────────────────────────────────────
        # Gemini behavior analysis
        # ──────────────────────────────────────────

        gemini_result = None

        try:

            gemini_result = (
                analyze_behavior_with_gemini(
                    behavior_evidence
                )
            )

        except Exception as e:

            print(
                f"[Gemini Behavior Error] {e}"
            )

        # ──────────────────────────────────────────
        # Gemini timeline
        # ──────────────────────────────────────────

        if (
            gemini_result
            and gemini_result.get(
                "behavior_timeline"
            )
        ):

            ai_timeline = (
                gemini_result[
                    "behavior_timeline"
                ]
            )

        else:

            ai_timeline = None

        # ──────────────────────────────────────────
        # Final result
        # ──────────────────────────────────────────

        static_risk = analysis.get(
            "risk_analysis",
            {}
        )

        result = {
            "success": True,

            "filename":
                file.filename,

            "package_name":
                analysis.get(
                    "metadata",
                    {}
                ).get(
                    "package_name",
                    "Unknown"
                ),

            "behavior_timeline":
                ai_timeline or timeline,

            "risk_score":
                static_risk.get(
                    "static_score",
                    0
                ),

            "classification":
                static_risk.get(
                    "classification",
                    "UNKNOWN"
                ),

            "fud_analysis":
                analysis.get(
                    "fud_analysis",
                    {}
                ),

            "gemini_analysis":
                gemini_result,

            "ai_available":
                gemini_result is not None,

            "disclaimer": (
                "This is a static behavioral "
                "inference. The APK was not "
                "executed on the server."
            ),
        }

        # ──────────────────────────────────────────
        # Save
        # ──────────────────────────────────────────

        try:

            save_scan(
                scan_type="behavior",
                filename=file.filename,
                package_name=result[
                    "package_name"
                ],
                risk_score=result[
                    "risk_score"
                ],
                classification=result[
                    "classification"
                ],
                confidence=(
                    gemini_result.get(
                        "confidence",
                        "LOW"
                    )
                    if gemini_result
                    else "LOW"
                ),
                summary=(
                    "Behavior analysis completed"
                ),
                result_json=result
            )

        except Exception as e:

            print(
                f"[DB Error] {e}"
            )

        return jsonify(result)

    except Exception as e:

        traceback.print_exc()

        return jsonify({
            "success": False,
            "error": (
                f"Behavior analysis failed: "
                f"{str(e)}"
            )
        }), 500

    finally:

        try:

            if os.path.exists(temp_path):
                os.remove(temp_path)

        except Exception:
            pass


# ══════════════════════════════════════════════════
# BEHAVIOR TIMELINE BUILDER
# ══════════════════════════════════════════════════

def build_behavior_timeline(analysis):
    """
    Build a static behavior timeline from
    APK analysis results.
    """

    timeline = []

    metadata = analysis.get(
        "metadata",
        {}
    )

    permissions = analysis.get(
        "permissions",
        {}
    )

    components = analysis.get(
        "components",
        {}
    )

    intents = analysis.get(
        "intents",
        {}
    )

    api_indicators = analysis.get(
        "api_indicators",
        {}
    )

    network_indicators = analysis.get(
        "network_indicators",
        {}
    )

    # ──────────────────────────────────────────────
    # Installation
    # ──────────────────────────────────────────────

    timeline.append({
        "step": "Application installed",

        "risk": "LOW",

        "description": (
            f"Package "
            f"{metadata.get('package_name', 'Unknown')}"
            " installed on device"
        )
    })

    # ──────────────────────────────────────────────
    # Boot persistence
    # ──────────────────────────────────────────────

    boot_intents = [
        i
        for i in intents.get(
            "suspicious",
            []
        )
        if "BOOT_COMPLETED"
        in i.get(
            "short_name",
            ""
        )
    ]

    if boot_intents:

        timeline.append({
            "step":
                "Receives BOOT_COMPLETED",

            "risk":
                "MEDIUM",

            "description":
                "Application registers to start "
                "automatically when device boots"
        })

    # ──────────────────────────────────────────────
    # Background services
    # ──────────────────────────────────────────────

    service_count = components.get(
        "services",
        0
    )

    if service_count > 0:

        timeline.append({
            "step":
                f"Starts {service_count} "
                "background service(s)",

            "risk":
                "MEDIUM"
                if service_count > 2
                else "LOW",

            "description":
                "Background services can run "
                "persistently on the device"
        })

    # ──────────────────────────────────────────────
    # SMS monitoring
    # ──────────────────────────────────────────────

    sms_intents = [
        i
        for i in intents.get(
            "suspicious",
            []
        )
        if "SMS"
        in i.get(
            "short_name",
            ""
        )
    ]

    sms_permissions = [
        p
        for p in permissions.get(
            "dangerous",
            []
        )
        if "SMS"
        in p.get(
            "short_name",
            ""
        )
    ]

    if sms_intents or sms_permissions:

        timeline.append({
            "step":
                "Monitors SMS messages",

            "risk":
                "HIGH",

            "description":
                "Application can intercept, "
                "read, or send SMS messages"
        })

    # ──────────────────────────────────────────────
    # Network activity
    # ──────────────────────────────────────────────

    net_urls = network_indicators.get(
        "suspicious_urls",
        []
    )

    if net_urls:

        timeline.append({
            "step":
                f"Contacts {len(net_urls)} "
                "external endpoint(s)",

            "risk":
                "MEDIUM",

            "description":
                "Application contains network "
                "endpoints requiring review"
        })

    # ──────────────────────────────────────────────
    # Sensitive APIs
    # ──────────────────────────────────────────────

    sensitive_apis = api_indicators.get(
        "indicators",
        []
    )

    for api in sensitive_apis[:5]:

        indicator = api.get(
            "indicator",
            "Unknown API"
        )

        if indicator in (
            "Runtime.exec",
            "DexClassLoader",
            "DevicePolicyManager"
        ):

            risk = "HIGH"

        else:

            risk = "MEDIUM"

        timeline.append({
            "step":
                f"Uses {indicator}",

            "risk":
                risk,

            "description":
                api.get(
                    "description",
                    "Suspicious API detected"
                )
        })

    # ──────────────────────────────────────────────
    # Sensitive data access
    # ──────────────────────────────────────────────

    data_permissions = [
        p
        for p in permissions.get(
            "dangerous",
            []
        )
        if any(
            x in p.get(
                "short_name",
                ""
            )
            for x in (
                "CONTACTS",
                "CALL_LOG",
                "LOCATION",
                "CAMERA"
            )
        )
    ]

    if data_permissions:

        permission_names = [
            p.get(
                "short_name",
                ""
            )
            for p in data_permissions
        ]

        timeline.append({
            "step":
                "Accesses sensitive device data",

            "risk":
                "HIGH",

            "description":
                "Accesses: "
                + ", ".join(
                    permission_names
                )
        })

    # ──────────────────────────────────────────────
    # FUD / Evasion
    # ──────────────────────────────────────────────

    fud_analysis = analysis.get(
        "fud_analysis",
        {}
    )

    fud_classification = fud_analysis.get(
        "classification",
        "LOW"
    )

    if fud_classification in (
        "SUSPICIOUS",
        "HIGH",
        "VERY_HIGH"
    ):

        fud_score = fud_analysis.get(
            "score",
            0
        )

        timeline.append({
            "step":
                "Anti-analysis / evasion indicators detected",

            "risk":
                "HIGH"
                if fud_classification
                in ("HIGH", "VERY_HIGH")
                else "MEDIUM",

            "description":
                (
                    f"FUD/evasion analysis scored "
                    f"{fud_score}/100 "
                    f"({fud_classification}). "
                    "The APK may contain techniques "
                    "intended to complicate analysis."
                )
        })

    return timeline


# ══════════════════════════════════════════════════
# DEMO ANALYSIS
# ══════════════════════════════════════════════════

@app.route(
    "/api/analyze/demo",
    methods=["GET"]
)
def demo_analysis():
    """Return demo analysis data."""

    return jsonify(
        DEMO_RESULT
    )


# ══════════════════════════════════════════════════
# SCAN HISTORY
# ══════════════════════════════════════════════════

@app.route(
    "/api/history",
    methods=["GET"]
)
def history_endpoint():
    """Return scan history."""

    try:

        limit = request.args.get(
            "limit",
            50,
            type=int
        )

        # Prevent unreasonable values
        limit = max(
            1,
            min(
                limit,
                200
            )
        )

        history = get_scan_history(
            limit
        )

        return jsonify({
            "success": True,
            "history": history
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ══════════════════════════════════════════════════
# SCAN HISTORY DETAIL
# ══════════════════════════════════════════════════

@app.route(
    "/api/history/<int:scan_id>",
    methods=["GET"]
)
def history_detail_endpoint(scan_id):
    """Return a specific scan result."""

    try:

        scan = get_scan_by_id(
            scan_id
        )

        if scan:

            return jsonify({
                "success": True,
                "scan": scan
            })

        return jsonify({
            "success": False,
            "error": "Scan not found"
        }), 404

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ══════════════════════════════════════════════════
# STATISTICS
# ══════════════════════════════════════════════════

@app.route(
    "/api/stats",
    methods=["GET"]
)
def stats_endpoint():
    """Return dashboard statistics."""

    try:

        stats = get_stats()

        return jsonify({
            "success": True,
            "stats": stats
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ══════════════════════════════════════════════════
# CONTACT
# ══════════════════════════════════════════════════

@app.route(
    "/api/contact",
    methods=["POST"]
)
def contact_endpoint():
    """Save a contact form message."""

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({
            "success": False,
            "error": "No data provided"
        }), 400

    name = str(
        data.get(
            "name",
            ""
        )
    ).strip()

    email = str(
        data.get(
            "email",
            ""
        )
    ).strip()

    message = str(
        data.get(
            "message",
            ""
        )
    ).strip()

    if not name or not email or not message:

        return jsonify({
            "success": False,
            "error":
                "All fields are required"
        }), 400

    try:

        save_contact_message(
            name,
            email,
            message
        )

        return jsonify({
            "success": True,
            "message":
                "Thank you. Your message "
                "has been received."
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ══════════════════════════════════════════════════
# ERROR HANDLERS
# ══════════════════════════════════════════════════

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle oversized requests."""

    return jsonify({
        "success": False,
        "error":
            f"Uploaded file exceeds the "
            f"{MAX_APK_SIZE_MB} MB limit."
    }), 413


@app.errorhandler(404)
def not_found(error):
    """JSON response for missing API endpoints."""

    if request.path.startswith("/api/"):

        return jsonify({
            "success": False,
            "error": "API endpoint not found"
        }), 404

    return send_from_directory(
        FRONTEND_FOLDER,
        "home.html"
    )


# ══════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════

if __name__ == "__main__":

    import sys

    try:

        if hasattr(
            sys.stdout,
            "reconfigure"
        ):
            sys.stdout.reconfigure(
                encoding="utf-8"
            )

    except Exception:
        pass

    try:

        gemini_status = (
            configure_gemini()
        )

    except Exception:

        gemini_status = False

    print()
    print("=" * 60)
    print("       VirusScan Security - Backend")
    print("=" * 60)

    print(
        "  Androguard    : "
        + (
            "[+] Available"
            if ANDROGUARD_AVAILABLE
            else "[-] Not installed"
        )
    )

    print(
        "  Gemini AI     : "
        + (
            "[+] Configured"
            if gemini_status
            else "[-] Not configured"
        )
    )

    print(
        f"  Max APK Size  : "
        f"{MAX_APK_SIZE_MB} MB"
    )

    print(
        f"  Upload Dir    : "
        f"{UPLOAD_FOLDER}"
    )

    print()
    print("  Features:")
    print("    [+] APK Static Analysis")
    print("    [+] FUD / Evasion Detection")
    print("    [+] Risk Scoring")
    print("    [+] Gemini AI Assessment")
    print("    [+] Certificate Analysis")
    print("    [+] Behavior Analysis")
    print("    [+] Scan History")
    print("    [+] Dashboard Statistics")
    print("    [-] Standalone URL Analyzer Removed")

    print()
    print(
        "  Starting server on "
        "http://localhost:5000"
    )

    print("=" * 60)
    print()

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )