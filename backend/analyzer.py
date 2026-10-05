"""
VirusScan Security — APK Static Analyzer
Performs static analysis using Androguard, risk scoring, and evidence extraction.
"""

import os
import re
import hashlib
import math
from collections import Counter
import zipfile
import traceback
from datetime import datetime

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    ANDROGUARD_AVAILABLE = True
except ImportError:
    try:
        from androguard.misc import AnalyzeAPK
        from androguard.core.bytecodes.apk import APK
        ANDROGUARD_AVAILABLE = True
    except ImportError:
        ANDROGUARD_AVAILABLE = False

# ──────────────────────────────────────────────────
# Dangerous / sensitive permissions
# ──────────────────────────────────────────────────
DANGEROUS_PERMISSIONS = {
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.READ_CALL_LOG',
    'android.permission.WRITE_CALL_LOG',
    'android.permission.CAMERA',
    'android.permission.RECORD_AUDIO',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.ACCESS_BACKGROUND_LOCATION',
    'android.permission.READ_PHONE_STATE',
    'android.permission.CALL_PHONE',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.MANAGE_EXTERNAL_STORAGE',
    'android.permission.REQUEST_INSTALL_PACKAGES',
    'android.permission.SYSTEM_ALERT_WINDOW',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.permission.BIND_DEVICE_ADMIN',
    'android.permission.RECEIVE_BOOT_COMPLETED',
    'android.permission.READ_PHONE_NUMBERS',
    'android.permission.PROCESS_OUTGOING_CALLS',
    'android.permission.BODY_SENSORS',
    'android.permission.ACTIVITY_RECOGNITION',
}

# Highly suspicious permission combos
SUSPICIOUS_PERMISSION_COMBOS = [
    {'android.permission.READ_SMS', 'android.permission.SEND_SMS', 'android.permission.INTERNET'},
    {'android.permission.CAMERA', 'android.permission.RECORD_AUDIO', 'android.permission.INTERNET'},
    {'android.permission.READ_CONTACTS', 'android.permission.INTERNET', 'android.permission.READ_SMS'},
    {'android.permission.ACCESS_FINE_LOCATION', 'android.permission.INTERNET', 'android.permission.CAMERA'},
    {'android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.INTERNET'},
    {'android.permission.BIND_ACCESSIBILITY_SERVICE', 'android.permission.INTERNET'},
    {'android.permission.BIND_DEVICE_ADMIN', 'android.permission.INTERNET'},
]

# Suspicious intents
SUSPICIOUS_INTENTS = {
    'android.intent.action.BOOT_COMPLETED': 'App starts on device boot',
    'android.intent.action.PACKAGE_ADDED': 'Monitors new app installations',
    'android.intent.action.PACKAGE_REPLACED': 'Monitors app updates',
    'android.provider.Telephony.SMS_RECEIVED': 'Intercepts incoming SMS',
    'android.intent.action.PHONE_STATE': 'Monitors phone call state',
    'android.net.conn.CONNECTIVITY_CHANGE': 'Monitors network changes',
    'android.intent.action.USER_PRESENT': 'Detects device unlock',
    'android.intent.action.SCREEN_ON': 'Detects screen activation',
    'android.intent.action.SCREEN_OFF': 'Detects screen deactivation',
    'android.intent.action.NEW_OUTGOING_CALL': 'Monitors outgoing calls',
}

# Suspicious API indicators
SUSPICIOUS_APIS = {
    'Landroid/telephony/SmsManager': 'SMS API usage',
    'Ljava/lang/Runtime;->exec': 'Runtime command execution',
    'Ljava/lang/ProcessBuilder': 'Process creation',
    'Ljava/lang/reflect/': 'Java reflection',
    'Ldalvik/system/DexClassLoader': 'Dynamic DEX loading',
    'Ldalvik/system/PathClassLoader': 'Dynamic class loading',
    'Landroid/app/admin/DevicePolicyManager': 'Device administrator API',
    'Landroid/accessibilityservice/': 'Accessibility service API',
    'Landroid/view/WindowManager$LayoutParams;->TYPE_APPLICATION_OVERLAY': 'Overlay window',
    'Ljavax/crypto/Cipher': 'Cryptographic operations',
    'Ljava/net/HttpURLConnection': 'HTTP network connection',
    'Lokhttp3/': 'OkHttp network library',
    'Lretrofit2/': 'Retrofit network library',
    'Landroid/webkit/WebView;->loadUrl': 'WebView URL loading',
    'Landroid/webkit/WebView;->addJavascriptInterface': 'WebView JS bridge',
    'Landroid/content/pm/PackageManager;->getInstalledPackages': 'Lists installed apps',
    'Landroid/os/Build': 'Device info access',
    'Landroid/provider/Settings$Secure;->getString': 'Reads device settings',
}

# Suspicious strings

# Higher-confidence behavioral signals. These are scored only when corroborated
# by multiple independent static artifacts, reducing false positives from a
# single API/permission hit.
HIGH_RISK_APIS = {
    'Landroid/telephony/SmsManager': 10,
    'Ljava/lang/Runtime;->exec': 10,
    'Ljava/lang/ProcessBuilder': 8,
    'Ldalvik/system/DexClassLoader': 10,
    'Landroid/app/admin/DevicePolicyManager': 9,
    'Landroid/accessibilityservice/': 10,
    'Landroid/view/WindowManager$LayoutParams;->TYPE_APPLICATION_OVERLAY': 8,
    'Landroid/content/pm/PackageManager;->getInstalledPackages': 5,
}

HIGH_RISK_PERMISSION_NAMES = {
    'android.permission.READ_SMS', 'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS', 'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.permission.BIND_DEVICE_ADMIN', 'android.permission.REQUEST_INSTALL_PACKAGES',
    'android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.MANAGE_EXTERNAL_STORAGE',
}

SUSPICIOUS_TLDS = {
    'zip','top','xyz','click','work','download','loan','gq','tk','ml','cf','ga'
}

SUSPICIOUS_STRINGS = [
    'su ', '/system/bin/su', '/system/xbin/su',
    'shell', 'exec', 'payload', 'exploit',
    'decrypt', 'encrypt', 'keylogger', 'rootkit',
    'trojan', 'backdoor', 'c2server', 'command_and_control',
    'phishing', 'steal', 'inject', 'hook',
    'xposed', 'substrate', 'frida',
    'base64decode', 'obfuscate',
]


# ──────────────────────────────────────────────────
# FUD / evasion indicators
# ──────────────────────────────────────────────────
# FUD (Fully Undetectable) is not a formal malware verdict. Here it means
# techniques commonly used to hide, mutate, delay, or dynamically load code.
FUD_API_INDICATORS = {
    'Ldalvik/system/DexClassLoader': ('Dynamic code loading', 14),
    'Ldalvik/system/PathClassLoader': ('Dynamic class loading', 8),
    'Ljava/lang/reflect/': ('Reflection / indirect API access', 8),
    'Ljava/lang/Runtime;->exec': ('Runtime command execution', 12),
    'Ljava/lang/ProcessBuilder': ('Process creation', 10),
    'Landroid/app/ActivityManager;->isDebuggerConnected': ('Debugger detection', 10),
    'Landroid/os/Debug;->isDebuggerConnected': ('Debugger detection', 10),
    'Landroid/os/Debug;->waitingForDebugger': ('Debugger detection', 8),
    'Landroid/os/Debug;->getTracerPid': ('Tracer detection', 10),
}

FUD_STRING_INDICATORS = {
    'frida': ('Frida / instrumentation indicator', 9),
    'xposed': ('Xposed / hook framework indicator', 8),
    'substrate': ('Substrate / hook framework indicator', 8),
    'ptrace': ('Process tracing / anti-analysis indicator', 9),
    'isdebuggerconnected': ('Debugger detection', 8),
    'debugger': ('Debugger-related logic', 5),
    'emulator': ('Emulator detection', 5),
    'goldfish': ('Emulator artifact check', 6),
    'generic_x86': ('Emulator artifact check', 6),
    'ro.kernel.qemu': ('Emulator detection', 7),
    'rootcloak': ('Root hiding / evasion indicator', 9),
    'magisk': ('Root / environment detection', 6),
    'base64decode': ('Encoded payload / string obfuscation', 7),
    'decrypt': ('Runtime decryption indicator', 6),
    'encrypt': ('Runtime encryption indicator', 4),
    'payload': ('Payload terminology', 5),
    'obfuscate': ('Obfuscation indicator', 8),
}

FUD_FILE_MARKERS = {
    'libjiagu': 'Jiagu-style protection/packing marker',
    'libprotectclass': 'Class protection/packing marker',
    'libsecmain': 'SecNeo-style protection marker',
    'libdexprotector': 'DexProtector-style protection marker',
    'ijiami': 'Ijiami-style protection marker',
    'bangcle': 'Bangcle-style protection marker',
    'dexprotector': 'DexProtector-style protection marker',
    'appguard': 'Application protection marker',
    '360jiagu': '360 Jiagu-style protection marker',
}

FUD_CLASSIFICATION_THRESHOLDS = {
    'SUSPICIOUS': 12,
    'HIGH': 28,
    'VERY_HIGH': 45,
}


def _shannon_entropy(data):
    """Return Shannon entropy for bytes/text."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _scan_high_entropy_strings(data, minimum_length=80, entropy_threshold=4.6):
    """Find long printable strings with unusually high entropy."""
    try:
        text_data = data.decode('utf-8', errors='ignore')
    except Exception:
        return []

    hits = []
    strings = re.findall(r'[ -~]{%d,}' % minimum_length, text_data)
    for value in strings[:5000]:
        entropy = _shannon_entropy(value)
        if entropy >= entropy_threshold:
            hits.append({
                'length': len(value),
                'entropy': round(entropy, 2),
                'preview': value[:80],
            })
    return hits[:30]


def extract_fud_indicators(filepath, api_indicators=None, suspicious_strings=None):
    """
    Detect FUD/evasion/obfuscation indicators.

    FUD is NOT proof of malware. Legitimate applications can use protectors,
    reflection, encryption, native code, and anti-debugging.
    """
    findings = []
    seen = set()
    score = 0
    categories = set()

    def add(kind, indicator, description, points, severity='medium', evidence=None):
        nonlocal score
        key = (kind, indicator)
        if key in seen:
            return
        seen.add(key)
        score += points
        categories.add(kind)
        item = {
            'kind': kind,
            'indicator': indicator,
            'description': description,
            'points': points,
            'severity': severity,
        }
        if evidence:
            item['evidence'] = evidence
        findings.append(item)

    # Dynamic loading, reflection, command execution and anti-debug APIs.
    for item in (api_indicators or {}).get('indicators', []):
        pattern = item.get('pattern', '')
        if pattern in FUD_API_INDICATORS:
            description, points = FUD_API_INDICATORS[pattern]
            add('api_evasion', pattern, description, points,
                'high' if points >= 10 else 'medium', item.get('source'))

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            names = zf.namelist()

            # Known packer/protector markers.
            for name in names:
                lname = name.lower()
                for marker, description in FUD_FILE_MARKERS.items():
                    if marker in lname:
                        add('packer', marker, description, 12, 'high', name)

            for name in names:
                if not name.endswith('.dex'):
                    continue

                data = zf.read(name)
                lower = data.lower()

                # Anti-analysis / obfuscation strings.
                for marker, (description, points) in FUD_STRING_INDICATORS.items():
                    if marker.encode('utf-8') in lower:
                        add('string_evasion', marker, description, points,
                            'high' if points >= 8 else 'medium', name)

                try:
                    text_data = data.decode('utf-8', errors='ignore')

                    # Long Base64-like strings can be encoded config/payload data.
                    b64_hits = re.findall(
                        r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/])',
                        text_data
                    )
                    if b64_hits:
                        add(
                            'encoding',
                            'long_base64_like_string',
                            f'{len(b64_hits)} long Base64-like string(s) found; possible encoded configuration or data.',
                            min(10, 3 + len(b64_hits)),
                            'medium',
                            name
                        )

                    # High entropy printable strings can indicate encrypted/packed data.
                    entropy_hits = _scan_high_entropy_strings(data)
                    if entropy_hits:
                        add(
                            'entropy',
                            'high_entropy_strings',
                            f'{len(entropy_hits)} long high-entropy printable string(s) found; possible encoded/encrypted content.',
                            min(10, 3 + len(entropy_hits) // 3),
                            'medium',
                            name
                        )
                except Exception:
                    pass

    except Exception:
        pass

    # Reuse already extracted suspicious strings.
    for item in (suspicious_strings or {}).get('strings', []):
        value = str(item.get('string', '')).lower()
        for marker, (description, points) in FUD_STRING_INDICATORS.items():
            if marker in value:
                add('string_evasion', marker, description, min(points, 8),
                    'medium', item.get('source'))

    # Native code increases complexity only when paired with evasion evidence.
    native_count = 0
    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            native_count = sum(
                1 for n in zf.namelist()
                if n.startswith('lib/') and n.endswith('.so')
            )
    except Exception:
        pass

    if native_count and len(findings) >= 2:
        add(
            'native_evasion',
            'native_code_with_evasion',
            f'{native_count} native library/libraries are present alongside other evasion indicators.',
            min(8, native_count * 2),
            'medium'
        )

    # Multiple independent categories are much stronger than one hit.
    if len(categories) >= 3:
        score += 10
        findings.append({
            'kind': 'corroboration',
            'indicator': 'multi-layer-evasion',
            'description': f'FUD-style signals span {len(categories)} independent categories.',
            'points': 10,
            'severity': 'high',
        })

    score = min(100, round(score))

    if score >= FUD_CLASSIFICATION_THRESHOLDS['VERY_HIGH']:
        classification = 'VERY_HIGH'
    elif score >= FUD_CLASSIFICATION_THRESHOLDS['HIGH']:
        classification = 'HIGH'
    elif score >= FUD_CLASSIFICATION_THRESHOLDS['SUSPICIOUS']:
        classification = 'SUSPICIOUS'
    else:
        classification = 'LOW'

    if len(categories) >= 3 and len(findings) >= 4:
        confidence = 'HIGH'
    elif len(categories) >= 2 or len(findings) >= 2:
        confidence = 'MEDIUM'
    else:
        confidence = 'LOW'

    if classification in ('HIGH', 'VERY_HIGH'):
        verdict = (
            'Strong FUD/evasion indicators detected. The APK uses multiple '
            'techniques that can make static detection harder. Treat it as '
            'high-risk until its source and behavior are verified.'
        )
    elif classification == 'SUSPICIOUS':
        verdict = (
            'Some FUD/evasion indicators were detected. This may be legitimate '
            'app protection, but it deserves additional scrutiny.'
        )
    else:
        verdict = 'No strong FUD/evasion pattern was detected by static heuristics.'

    return {
        'score': score,
        'classification': classification,
        'confidence': confidence,
        'finding_count': len(findings),
        'evidence_categories': sorted(categories),
        'verdict': verdict,
        'findings': findings[:100],
    }




def validate_apk(filepath):
    """Validate that the file is a real APK."""
    if not os.path.exists(filepath):
        return False, "File not found"

    if not filepath.lower().endswith('.apk'):
        return False, "File is not an APK"

    # Check ZIP signature
    try:
        if not zipfile.is_zipfile(filepath):
            return False, "Invalid APK file (not a valid ZIP archive)"
    except Exception:
        return False, "Could not read file"

    # Check for AndroidManifest.xml
    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            names = zf.namelist()
            if 'AndroidManifest.xml' not in names:
                return False, "Invalid APK file (no AndroidManifest.xml)"
            if not any(n.endswith('.dex') for n in names):
                return False, "Invalid APK file (no DEX files)"
    except zipfile.BadZipFile:
        return False, "Corrupted APK file"

    return True, "Valid APK"


def analyze_apk(filepath, original_filename=None):
    """
    Perform complete static analysis on an APK file.

    Returns a comprehensive result dictionary.
    """
    if not ANDROGUARD_AVAILABLE:
        return {
            'success': False,
            'error': 'Androguard is not installed. Run: pip install androguard'
        }

    valid, msg = validate_apk(filepath)
    if not valid:
        return {'success': False, 'error': msg}

    try:
        apk = APK(filepath)
    except Exception as e:
        return {'success': False, 'error': f'Failed to parse APK: {str(e)}'}

    result = {
        'success': True,
        'metadata': extract_metadata(apk, filepath, original_filename),
        'permissions': extract_permissions(apk),
        'components': extract_components(apk),
        'intents': extract_intents(apk),
        'api_indicators': extract_api_indicators(filepath),
        'network_indicators': extract_network_indicators(filepath),
        'resources': extract_resources(filepath),
        'certificate': extract_certificate(apk),
        'suspicious_strings': extract_suspicious_strings(filepath),
    }

    # Separate FUD/evasion analysis.
    result['fud_analysis'] = extract_fud_indicators(
        filepath,
        result.get('api_indicators'),
        result.get('suspicious_strings')
    )

    # Calculate deterministic risk score
    result['risk_analysis'] = calculate_risk_score(result)

    return result


def extract_metadata(apk, filepath, original_filename=None):
    """Extract basic APK metadata."""
    file_size = os.path.getsize(filepath)

    return {
        'filename': original_filename or os.path.basename(filepath),
        'package_name': apk.get_package() or 'Unknown',
        'version_name': apk.get_androidversion_name() or 'Unknown',
        'version_code': apk.get_androidversion_code() or 'Unknown',
        'min_sdk': apk.get_min_sdk_version() or 'Unknown',
        'target_sdk': apk.get_target_sdk_version() or 'Unknown',
        'file_size': file_size,
        'file_size_readable': format_file_size(file_size),
        'sha256': compute_sha256(filepath),
        'main_activity': apk.get_main_activity() or 'Unknown',
        'app_name': apk.get_app_name() or 'Unknown',
    }


def extract_permissions(apk):
    """Extract and categorize permissions."""
    all_perms = apk.get_permissions() or []
    declared_perms = apk.get_declared_permissions() or []

    dangerous = []
    normal = []
    custom = []

    for p in all_perms:
        if p in DANGEROUS_PERMISSIONS:
            dangerous.append({
                'name': p,
                'short_name': p.split('.')[-1],
                'risk': 'dangerous'
            })
        elif p.startswith('android.permission.'):
            normal.append({
                'name': p,
                'short_name': p.split('.')[-1],
                'risk': 'normal'
            })
        else:
            custom.append({
                'name': p,
                'short_name': p.split('.')[-1],
                'risk': 'custom'
            })

    # Check for suspicious combos
    perm_set = set(all_perms)
    suspicious_combos_found = []
    for combo in SUSPICIOUS_PERMISSION_COMBOS:
        if combo.issubset(perm_set):
            combo_names = [p.split('.')[-1] for p in combo]
            suspicious_combos_found.append(combo_names)

    return {
        'total': len(all_perms),
        'dangerous': dangerous,
        'dangerous_count': len(dangerous),
        'normal': normal,
        'normal_count': len(normal),
        'custom': custom,
        'custom_count': len(custom),
        'declared': [p for p in declared_perms],
        'suspicious_combinations': suspicious_combos_found,
        'all': [p.split('.')[-1] for p in all_perms],
    }


def extract_components(apk):
    """Extract activities, services, receivers, and providers."""
    activities = apk.get_activities() or []
    services = apk.get_services() or []
    receivers = apk.get_receivers() or []
    providers = apk.get_providers() or []

    # Identify exported components
    exported = []

    for act in activities:
        try:
            if apk.get_attribute_value('activity', 'exported', name=act) == 'true':
                exported.append({'name': act.split('.')[-1], 'type': 'Activity'})
        except:
            pass

    for srv in services:
        try:
            if apk.get_attribute_value('service', 'exported', name=srv) == 'true':
                exported.append({'name': srv.split('.')[-1], 'type': 'Service'})
        except:
            pass

    for rec in receivers:
        try:
            if apk.get_attribute_value('receiver', 'exported', name=rec) == 'true':
                exported.append({'name': rec.split('.')[-1], 'type': 'Receiver'})
        except:
            pass

    return {
        'activities': len(activities),
        'services': len(services),
        'receivers': len(receivers),
        'providers': len(providers),
        'total': len(activities) + len(services) + len(receivers) + len(providers),
        'exported': exported,
        'exported_count': len(exported),
        'activity_names': [a.split('.')[-1] for a in activities[:20]],
        'service_names': [s.split('.')[-1] for s in services[:20]],
        'receiver_names': [r.split('.')[-1] for r in receivers[:20]],
    }


def extract_intents(apk):
    """Extract suspicious intent filters from receivers."""
    detected = []
    receivers = apk.get_receivers() or []

    # Get all intent filters
    try:
        for receiver in receivers:
            filters = apk.get_intent_filters('receiver', receiver)
            if filters and 'action' in filters:
                for action in filters['action']:
                    if action in SUSPICIOUS_INTENTS:
                        detected.append({
                            'action': action,
                            'short_name': action.split('.')[-1],
                            'description': SUSPICIOUS_INTENTS[action],
                            'component': receiver.split('.')[-1],
                        })
    except Exception:
        pass

    # Also check service intent filters
    services = apk.get_services() or []
    try:
        for service in services:
            filters = apk.get_intent_filters('service', service)
            if filters and 'action' in filters:
                for action in filters['action']:
                    if action in SUSPICIOUS_INTENTS:
                        detected.append({
                            'action': action,
                            'short_name': action.split('.')[-1],
                            'description': SUSPICIOUS_INTENTS[action],
                            'component': service.split('.')[-1],
                        })
    except Exception:
        pass

    return {
        'total': len(detected),
        'suspicious': detected,
    }


def extract_api_indicators(filepath):
    """Inspect DEX byte strings for security-relevant API families.
    A hit is an indicator, not proof of malicious behavior.
    """
    indicators = []
    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            for name in zf.namelist():
                if not name.endswith('.dex'):
                    continue
                dex_data = zf.read(name)
                # DEX is binary; searching raw bytes avoids losing UTF-8/UTF-16 fragments.
                for pattern, description in SUSPICIOUS_APIS.items():
                    raw = pattern.encode('utf-8', errors='ignore')
                    if raw in dex_data:
                        indicators.append({
                            'indicator': pattern.split('/')[-1].replace(';','').replace('->','.'),
                            'pattern': pattern,
                            'description': description,
                            'source': name,
                            'risk_weight': HIGH_RISK_APIS.get(pattern, 2)
                        })
    except Exception:
        pass

    unique = []
    seen = set()
    for ind in indicators:
        key = (ind['pattern'], ind['source'])
        if key not in seen:
            seen.add(key)
            unique.append(ind)

    # UI compatibility: total counts unique API families, not duplicate occurrences.
    families = {}
    for ind in unique:
        families.setdefault(ind['pattern'], ind)
    return {'total': len(families), 'indicators': list(families.values())}

def extract_network_indicators(filepath):
    """Extract network indicators with validation and basic reputation heuristics."""
    from urllib.parse import urlparse

    urls, domains, ips = set(), set(), set()
    url_pattern = re.compile(r'https?://[^\s<>"\'\\{}\[\]|^`]+', re.IGNORECASE)
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def valid_ip(value):
        try:
            parts = [int(x) for x in value.split('.')]
            return len(parts) == 4 and all(0 <= x <= 255 for x in parts)
        except Exception:
            return False

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            for name in zf.namelist():
                if not name.endswith(('.dex', '.xml', '.json', '.js', '.html', '.txt', '.properties', '.smali')):
                    continue
                try:
                    data = zf.read(name).decode('utf-8', errors='ignore')
                    for match in url_pattern.finditer(data):
                        url = match.group().rstrip('/.,;:)')
                        if 8 <= len(url) <= 2048:
                            try:
                                parsed = urlparse(url)
                                if parsed.scheme in ('http', 'https') and parsed.hostname:
                                    urls.add(url)
                                    domains.add(parsed.hostname.lower())
                            except Exception:
                                pass
                    for match in ip_pattern.finditer(data):
                        ip = match.group()
                        if valid_ip(ip) and not ip.startswith(('0.', '127.', '255.')):
                            ips.add(ip)
                except Exception:
                    continue
    except Exception:
        pass

    benign_domains = {
        'schemas.android.com', 'www.w3.org', 'xmlpull.org', 'ns.adobe.com',
        'xml.org', 'apache.org', 'google.com', 'googleapis.com', 'gstatic.com',
        'android.com', 'play.google.com', 'github.com', 'githubusercontent.com',
        'maven.org', 'gradle.org', 'firebaseio.com'
    }

    def benign(host):
        host = host.lower().rstrip('.')
        return any(host == d or host.endswith('.' + d) for d in benign_domains)

    suspicious_urls, safe_urls = [], []
    url_signals = []
    for url in sorted(urls):
        host = (urlparse(url).hostname or '').lower()
        if benign(host):
            safe_urls.append(url)
            continue
        parsed = urlparse(url)
        host_parts = host.split('.') if host else []
        tld = host_parts[-1] if host_parts else ''
        reasons = []
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            reasons.append('raw IP host')
        if tld in SUSPICIOUS_TLDS:
            reasons.append(f'uncommon TLD .{tld}')
        if len(host_parts) >= 5:
            reasons.append('deep subdomain')
        if any(k in (parsed.path + '?' + parsed.query).lower()
               for k in ('login','signin','verify','password','credential','install','update','payload')):
            reasons.append('credential/install-related path')
        if reasons:
            suspicious_urls.append(url)
            url_signals.append({'url': url, 'reasons': reasons})
        else:
            suspicious_urls.append(url)  # external endpoint; not automatically malicious

    return {
        'urls_total': len(urls),
        'domains_total': len(domains),
        'ips_total': len(ips),
        'urls': sorted(urls)[:100],
        'suspicious_urls': suspicious_urls[:50],
        'safe_urls': safe_urls[:30],
        'domains': sorted(domains)[:50],
        'ips': sorted(ips)[:30],
        'url_signals': url_signals[:50],
    }

def extract_resources(filepath):
    """Inspect APK resources for suspicious files."""
    suspicious_files = []
    native_libs = []
    dex_files = []
    assets = []

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            for info in zf.infolist():
                name = info.filename

                if name.endswith('.dex'):
                    dex_files.append({
                        'name': name,
                        'size': format_file_size(info.file_size)
                    })
                elif name.startswith('lib/') and name.endswith('.so'):
                    native_libs.append({
                        'name': name,
                        'size': format_file_size(info.file_size)
                    })
                elif name.startswith('assets/'):
                    assets.append(name)

                # Check for suspicious files
                suspicious_extensions = ['.sh', '.bin', '.dat', '.enc', '.key', '.elf']
                if any(name.endswith(ext) for ext in suspicious_extensions):
                    suspicious_files.append({
                        'name': name,
                        'size': format_file_size(info.file_size),
                        'reason': 'Suspicious file extension'
                    })
    except Exception:
        pass

    return {
        'dex_files': dex_files,
        'dex_count': len(dex_files),
        'native_libs': native_libs,
        'native_lib_count': len(native_libs),
        'assets_count': len(assets),
        'suspicious_files': suspicious_files,
        'suspicious_count': len(suspicious_files),
    }


def extract_certificate(apk):
    """Extract APK signing certificate information."""
    cert_info = {
        'present': False,
        'subject': 'Unknown',
        'issuer': 'Unknown',
        'serial_number': 'Unknown',
        'algorithm': 'Unknown',
        'valid_from': 'Unknown',
        'valid_until': 'Unknown',
        'sha256_fingerprint': 'Unknown',
        'is_debug': False,
        'checks': [],
    }

    try:
        certs = apk.get_certificates()
        if not certs:
            cert_info['checks'].append({
                'check': 'Certificate present',
                'status': 'fail',
                'message': 'No certificate found'
            })
            return cert_info

        cert = certs[0]  # Primary certificate
        cert_info['present'] = True

        # Extract subject
        try:
            subject = cert.subject
            subject_parts = []
            for attr in subject:
                for name_attr in attr:
                    subject_parts.append(f"{name_attr.oid._name}={name_attr.value}")
            cert_info['subject'] = ', '.join(subject_parts) if subject_parts else 'Unknown'
        except Exception:
            pass

        # Extract issuer
        try:
            issuer = cert.issuer
            issuer_parts = []
            for attr in issuer:
                for name_attr in attr:
                    issuer_parts.append(f"{name_attr.oid._name}={name_attr.value}")
            cert_info['issuer'] = ', '.join(issuer_parts) if issuer_parts else 'Unknown'
        except Exception:
            pass

        # Serial number
        try:
            cert_info['serial_number'] = format(cert.serial_number, 'X')
        except Exception:
            pass

        # Algorithm
        try:
            cert_info['algorithm'] = cert.signature_algorithm_oid._name
        except Exception:
            try:
                cert_info['algorithm'] = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'Unknown'
            except:
                pass

        # Validity dates
        try:
            cert_info['valid_from'] = cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
            cert_info['valid_until'] = cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            try:
                cert_info['valid_from'] = str(cert.not_valid_before)
                cert_info['valid_until'] = str(cert.not_valid_after)
            except:
                pass

        # SHA-256 fingerprint
        try:
            from cryptography.hazmat.primitives import hashes
            fingerprint = cert.fingerprint(hashes.SHA256())
            cert_info['sha256_fingerprint'] = ':'.join(f'{b:02X}' for b in fingerprint)
        except Exception:
            pass

        # Debug certificate detection
        subject_str = cert_info['subject'].lower()
        if 'debug' in subject_str or 'android debug' in subject_str:
            cert_info['is_debug'] = True

        # Security checks
        cert_info['checks'].append({
            'check': 'Certificate present',
            'status': 'pass',
            'message': 'APK is signed'
        })

        # Algorithm strength
        algo = cert_info['algorithm'].lower()
        if 'sha256' in algo or 'sha384' in algo or 'sha512' in algo:
            cert_info['checks'].append({
                'check': 'Strong signing algorithm',
                'status': 'pass',
                'message': cert_info['algorithm']
            })
        elif 'sha1' in algo or 'md5' in algo:
            cert_info['checks'].append({
                'check': 'Signing algorithm',
                'status': 'warn',
                'message': f'Weak algorithm: {cert_info["algorithm"]}'
            })
        else:
            cert_info['checks'].append({
                'check': 'Signing algorithm',
                'status': 'pass',
                'message': cert_info['algorithm']
            })

        # Validity check
        try:
            now = datetime.utcnow()
            not_before = cert.not_valid_before_utc.replace(tzinfo=None) if hasattr(cert.not_valid_before_utc, 'replace') else cert.not_valid_before
            not_after = cert.not_valid_after_utc.replace(tzinfo=None) if hasattr(cert.not_valid_after_utc, 'replace') else cert.not_valid_after

            if now < not_before:
                cert_info['checks'].append({
                    'check': 'Certificate validity',
                    'status': 'warn',
                    'message': 'Certificate not yet valid'
                })
            elif now > not_after:
                cert_info['checks'].append({
                    'check': 'Certificate validity',
                    'status': 'warn',
                    'message': 'Certificate has expired'
                })
            else:
                cert_info['checks'].append({
                    'check': 'Certificate currently valid',
                    'status': 'pass',
                    'message': f'Valid until {cert_info["valid_until"]}'
                })
        except Exception:
            pass

        # Debug check
        if cert_info['is_debug']:
            cert_info['checks'].append({
                'check': 'Debug certificate',
                'status': 'warn',
                'message': 'APK appears to be signed with a debug certificate'
            })

    except Exception as e:
        cert_info['checks'].append({
            'check': 'Certificate extraction',
            'status': 'fail',
            'message': f'Error: {str(e)}'
        })

    return cert_info


def extract_suspicious_strings(filepath):
    """Search for suspicious strings in the APK."""
    found = []

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.dex'):
                    data = zf.read(name).decode('utf-8', errors='ignore').lower()
                    for s in SUSPICIOUS_STRINGS:
                        if s.lower() in data:
                            found.append({
                                'string': s,
                                'source': name,
                            })
    except Exception:
        pass

    # Deduplicate
    seen = set()
    unique = []
    for f in found:
        if f['string'] not in seen:
            seen.add(f['string'])
            unique.append(f)

    return {
        'total': len(unique),
        'strings': unique,
    }


def calculate_risk_score(result):
    """Evidence-weighted 0-100 APK risk score.

    The score is deliberately conservative: isolated capabilities such as
    CAMERA or HTTPS are not treated as malware. Stronger findings require
    corroboration across permissions, APIs, intents, network behavior,
    packaging/resources and signing evidence.
    """
    reasons = []
    score = 0.0
    evidence_domains = 0

    def add(title, description, points, severity='medium'):
        nonlocal score
        points = max(0, float(points))
        if points:
            score += points
            reasons.append({'title': title, 'description': description,
                            'severity': severity, 'points': round(points)})

    perms = result.get('permissions', {})
    dangerous = perms.get('dangerous_count', 0)
    if dangerous:
        # Diminishing returns: 1-3 sensitive permissions are common.
        p = min(18, 3 + max(0, dangerous - 1) * 2.5)
        add(f'{dangerous} sensitive permissions',
            'Sensitive capabilities were requested; context is evaluated with other evidence.',
            p, 'medium' if dangerous < 5 else 'high')
        evidence_domains += 1

    combos = perms.get('suspicious_combinations', [])
    if combos:
        add('High-risk permission combinations',
            f'{len(combos)} combinations join sensitive capabilities in a potentially risky way.',
            min(24, 10 * len(combos)), 'high')
        evidence_domains += 1

    apis = result.get('api_indicators', {})
    api_items = apis.get('indicators', [])
    high_api = sum(1 for a in api_items if a.get('risk_weight', 0) >= 8)
    api_points = min(24, sum(a.get('risk_weight', 2) for a in api_items) * 0.8)
    if api_items:
        add(f'{len(api_items)} security-relevant API families',
            'Static bytecode inspection found APIs associated with sensitive device, execution, loading, or overlay behavior.',
            api_points, 'high' if high_api else 'medium')
        evidence_domains += 1

    intents = result.get('intents', {})
    intent_count = intents.get('total', 0)
    if intent_count:
        add(f'{intent_count} sensitive intent filters',
            'The manifest exposes lifecycle, SMS, call, or device-state event handlers.',
            min(14, intent_count * 4), 'medium')
        evidence_domains += 1

    network = result.get('network_indicators', {})
    external = len(network.get('suspicious_urls', []))
    network_signals = len(network.get('url_signals', [])) + network.get('ips_total', 0)
    if external:
        # External endpoints are common; only stronger URL signals carry larger weight.
        p = min(14, external * 0.8 + network_signals * 2)
        add(f'{external} external network endpoints',
            'External endpoints were extracted; stronger weight is applied only to concrete risk signals.',
            p, 'medium' if network_signals < 2 else 'high')
        evidence_domains += 1

    components = result.get('components', {})
    exported = components.get('exported_count', 0)
    if exported:
        # Exported components are not inherently malicious.
        p = min(8, max(0, exported - 3) * 1.5)
        if p:
            add(f'{exported} exported components',
                'Exported components increase attack surface and are assessed with intent/permission context.',
                p, 'medium')
            evidence_domains += 1

    resources = result.get('resources', {})
    native = resources.get('native_lib_count', 0)
    suspicious_files = resources.get('suspicious_count', 0)
    if native > 0:
        add(f'{native} native libraries',
            'Native code increases analysis complexity but is not malicious by itself.',
            min(4, native), 'low')
    if suspicious_files:
        add(f'{suspicious_files} unusual packaged files',
            'Unusual file types were found inside the APK package.',
            min(10, suspicious_files * 3), 'medium')
        evidence_domains += 1

    # Strong FUD/evasion evidence contributes to risk, but FUD alone never
    # forces a MALICIOUS verdict.
    fud = result.get('fud_analysis', {})
    fud_score = fud.get('score', 0)
    fud_class = fud.get('classification', 'LOW')
    if fud_score:
        fud_points = min(24, fud_score * 0.45)
        add(
            f'FUD/evasion pattern: {fud_class}',
            fud.get('verdict', 'FUD/evasion indicators were detected.'),
            fud_points,
            'high' if fud_class in ('HIGH', 'VERY_HIGH') else 'medium'
        )
        evidence_domains += 1

    cert = result.get('certificate', {})
    if not cert.get('present'):
        add('Signing certificate could not be verified',
            'No certificate was extracted from the APK. Treat this as a verification failure, not malware proof.',
            8, 'high')
        evidence_domains += 1
    elif cert.get('is_debug'):
        add('Debug certificate detected',
            'A debug signing identity was detected; this is a release hygiene issue, not proof of malware.',
            3, 'medium')

    strings = result.get('suspicious_strings', {})
    string_count = strings.get('total', 0)
    if string_count:
        add(f'{string_count} suspicious string families',
            'Potentially security-relevant strings were found in DEX data; strings alone are weak evidence.',
            min(8, string_count * 1.2), 'medium')
        evidence_domains += 1

    # Corroboration bonuses: multiple independent domains make a finding more credible.
    # Never let the bonus dominate the score.
    if evidence_domains >= 4:
        add('Multi-signal corroboration',
            f'Findings span {evidence_domains} independent evidence categories.',
            min(10, (evidence_domains - 3) * 2), 'high')
    elif evidence_domains >= 2 and (high_api or combos):
        add('Cross-signal corroboration',
            'Sensitive capabilities are supported by more than one independent static signal.',
            5, 'high')

    score = round(min(100, score))

    # A strong FUD pattern should not be displayed as SAFE. It is still not
    # sufficient evidence by itself to label the APK MALICIOUS.
    fud_class = result.get('fud_analysis', {}).get('classification', 'LOW')
    if fud_class in ('HIGH', 'VERY_HIGH') and score < 35:
        score = 35

    if score < 25:
        classification = 'SAFE'
    elif score < 55:
        classification = 'SUSPICIOUS'
    else:
        classification = 'MALICIOUS'

    # Confidence is based on evidence breadth and strength, not score alone.
    strong = int(bool(combos)) + min(2, high_api) + int(intent_count >= 2) + int(network_signals >= 2)
    if evidence_domains >= 4 and strong >= 2:
        confidence = 'HIGH'
    elif evidence_domains >= 2 or strong >= 1:
        confidence = 'MEDIUM'
    else:
        confidence = 'LOW'

    return {
        'static_score': score,
        'classification': classification,
        'confidence': confidence,
        'evidence_domains': evidence_domains,
        'reasons': reasons,
        'total_indicators': round(sum(r['points'] for r in reasons)),
    }

def combine_scores(static_score, gemini_result):
    """Combine deterministic evidence with AI as a bounded second opinion."""
    if not gemini_result:
        return {
            'final_score': static_score,
            'static_score': static_score,
            'gemini_score': None,
            'classification': classify_score(static_score),
            'ai_available': False,
            'method': 'static_evidence_only',
        }

    gemini_score = max(0, min(100, float(gemini_result.get('risk_score', static_score))))
    # AI is advisory: 25% weight prevents a model-only verdict from overriding evidence.
    final_score = round(static_score * 0.75 + gemini_score * 0.25)
    disagreement = abs(static_score - gemini_score)
    if disagreement >= 35:
        # Prefer the deterministic result when AI strongly disagrees.
        final_score = round(static_score * 0.90 + gemini_score * 0.10)

    final_score = max(0, min(100, final_score))
    return {
        'final_score': final_score,
        'static_score': static_score,
        'gemini_score': round(gemini_score),
        'classification': classify_score(final_score),
        'ai_available': True,
        'ai_weight': 0.25 if disagreement < 35 else 0.10,
        'score_disagreement': round(disagreement),
        'method': 'evidence_first_ai_second_opinion',
    }

def classify_score(score):
    """Classify a score into SAFE/SUSPICIOUS/MALICIOUS."""
    if score < 30:
        return 'SAFE'
    elif score < 60:
        return 'SUSPICIOUS'
    else:
        return 'MALICIOUS'


# ──────────────────────────────────────────────────
# Utility functions
# ──────────────────────────────────────────────────

def format_file_size(size_bytes):
    """Convert bytes to human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def compute_sha256(filepath):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


# ──────────────────────────────────────────────────
# Demo data for hackathon fallback
# ──────────────────────────────────────────────────

DEMO_RESULT = {
    'success': True,
    'is_demo': True,
    'metadata': {
        'filename': 'SuspiciousApp-demo.apk',
        'package_name': 'com.suspicious.banking.clone',
        'version_name': '2.4.1',
        'version_code': '24',
        'min_sdk': '21',
        'target_sdk': '33',
        'file_size': 8945672,
        'file_size_readable': '8.5 MB',
        'sha256': 'a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01',
        'main_activity': 'MainActivity',
        'app_name': 'BankSecure Pro',
    },
    'permissions': {
        'total': 18,
        'dangerous': [
            {'name': 'android.permission.READ_SMS', 'short_name': 'READ_SMS', 'risk': 'dangerous'},
            {'name': 'android.permission.SEND_SMS', 'short_name': 'SEND_SMS', 'risk': 'dangerous'},
            {'name': 'android.permission.RECEIVE_SMS', 'short_name': 'RECEIVE_SMS', 'risk': 'dangerous'},
            {'name': 'android.permission.READ_CONTACTS', 'short_name': 'READ_CONTACTS', 'risk': 'dangerous'},
            {'name': 'android.permission.CAMERA', 'short_name': 'CAMERA', 'risk': 'dangerous'},
            {'name': 'android.permission.ACCESS_FINE_LOCATION', 'short_name': 'ACCESS_FINE_LOCATION', 'risk': 'dangerous'},
            {'name': 'android.permission.READ_PHONE_STATE', 'short_name': 'READ_PHONE_STATE', 'risk': 'dangerous'},
            {'name': 'android.permission.RECORD_AUDIO', 'short_name': 'RECORD_AUDIO', 'risk': 'dangerous'},
        ],
        'dangerous_count': 8,
        'normal': [
            {'name': 'android.permission.INTERNET', 'short_name': 'INTERNET', 'risk': 'normal'},
            {'name': 'android.permission.ACCESS_NETWORK_STATE', 'short_name': 'ACCESS_NETWORK_STATE', 'risk': 'normal'},
            {'name': 'android.permission.VIBRATE', 'short_name': 'VIBRATE', 'risk': 'normal'},
            {'name': 'android.permission.WAKE_LOCK', 'short_name': 'WAKE_LOCK', 'risk': 'normal'},
        ],
        'normal_count': 4,
        'custom': [],
        'custom_count': 0,
        'declared': [],
        'suspicious_combinations': [
            ['READ_SMS', 'SEND_SMS', 'INTERNET'],
            ['CAMERA', 'RECORD_AUDIO', 'INTERNET'],
        ],
        'all': ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_CONTACTS', 'CAMERA',
                'ACCESS_FINE_LOCATION', 'READ_PHONE_STATE', 'RECORD_AUDIO',
                'INTERNET', 'ACCESS_NETWORK_STATE', 'VIBRATE', 'WAKE_LOCK',
                'RECEIVE_BOOT_COMPLETED', 'REQUEST_INSTALL_PACKAGES',
                'SYSTEM_ALERT_WINDOW', 'WRITE_EXTERNAL_STORAGE',
                'READ_CALL_LOG', 'BIND_ACCESSIBILITY_SERVICE'],
    },
    'components': {
        'activities': 14,
        'services': 5,
        'receivers': 7,
        'providers': 2,
        'total': 28,
        'exported': [
            {'name': 'MainActivity', 'type': 'Activity'},
            {'name': 'DataSyncService', 'type': 'Service'},
            {'name': 'BootReceiver', 'type': 'Receiver'},
            {'name': 'SmsReceiver', 'type': 'Receiver'},
            {'name': 'DataProvider', 'type': 'Provider'},
        ],
        'exported_count': 5,
        'activity_names': ['MainActivity', 'LoginActivity', 'TransferActivity', 'SettingsActivity'],
        'service_names': ['DataSyncService', 'LocationService', 'SmsService'],
        'receiver_names': ['BootReceiver', 'SmsReceiver', 'ConnectivityReceiver'],
    },
    'intents': {
        'total': 4,
        'suspicious': [
            {'action': 'android.intent.action.BOOT_COMPLETED', 'short_name': 'BOOT_COMPLETED',
             'description': 'App starts on device boot', 'component': 'BootReceiver'},
            {'action': 'android.provider.Telephony.SMS_RECEIVED', 'short_name': 'SMS_RECEIVED',
             'description': 'Intercepts incoming SMS', 'component': 'SmsReceiver'},
            {'action': 'android.intent.action.PHONE_STATE', 'short_name': 'PHONE_STATE',
             'description': 'Monitors phone call state', 'component': 'PhoneReceiver'},
            {'action': 'android.net.conn.CONNECTIVITY_CHANGE', 'short_name': 'CONNECTIVITY_CHANGE',
             'description': 'Monitors network changes', 'component': 'ConnectivityReceiver'},
        ],
    },
    'api_indicators': {
        'total': 7,
        'indicators': [
            {'indicator': 'SmsManager', 'description': 'SMS API usage', 'source': 'classes.dex'},
            {'indicator': 'Runtime.exec', 'description': 'Runtime command execution', 'source': 'classes.dex'},
            {'indicator': 'DexClassLoader', 'description': 'Dynamic DEX loading', 'source': 'classes.dex'},
            {'indicator': 'DevicePolicyManager', 'description': 'Device administrator API', 'source': 'classes.dex'},
            {'indicator': 'Cipher', 'description': 'Cryptographic operations', 'source': 'classes.dex'},
            {'indicator': 'HttpURLConnection', 'description': 'HTTP network connection', 'source': 'classes.dex'},
            {'indicator': 'WebView.addJavascriptInterface', 'description': 'WebView JS bridge', 'source': 'classes.dex'},
        ],
    },
    'network_indicators': {
        'urls_total': 12,
        'domains_total': 6,
        'ips_total': 2,
        'urls': [
            'https://api.banksecure-pro.xyz/v2/sync',
            'https://cdn.suspicious-domain.com/update',
            'http://192.168.1.100:8080/data',
            'https://tracker.analytics-dark.com/collect',
        ],
        'suspicious_urls': [
            'https://api.banksecure-pro.xyz/v2/sync',
            'https://cdn.suspicious-domain.com/update',
            'http://192.168.1.100:8080/data',
            'https://tracker.analytics-dark.com/collect',
        ],
        'safe_urls': ['https://fonts.googleapis.com/css2'],
        'domains': ['banksecure-pro.xyz', 'suspicious-domain.com', 'analytics-dark.com'],
        'ips': ['192.168.1.100'],
    },
    'resources': {
        'dex_files': [{'name': 'classes.dex', 'size': '4.2 MB'}, {'name': 'classes2.dex', 'size': '1.8 MB'}],
        'dex_count': 2,
        'native_libs': [{'name': 'lib/arm64-v8a/libnative.so', 'size': '520.0 KB'}],
        'native_lib_count': 1,
        'assets_count': 8,
        'suspicious_files': [{'name': 'assets/payload.dat', 'size': '128.0 KB', 'reason': 'Suspicious file extension'}],
        'suspicious_count': 1,
    },
    'certificate': {
        'present': True,
        'subject': 'commonName=Android Debug, organizationName=Unknown',
        'issuer': 'commonName=Android Debug, organizationName=Unknown',
        'serial_number': '1A2B3C4D',
        'algorithm': 'sha256WithRSAEncryption',
        'valid_from': '2024-01-15 00:00:00 UTC',
        'valid_until': '2054-01-15 00:00:00 UTC',
        'sha256_fingerprint': 'A1:B2:C3:D4:E5:F6:78:90:12:34:56:78:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01',
        'is_debug': True,
        'checks': [
            {'check': 'Certificate present', 'status': 'pass', 'message': 'APK is signed'},
            {'check': 'Strong signing algorithm', 'status': 'pass', 'message': 'sha256WithRSAEncryption'},
            {'check': 'Certificate currently valid', 'status': 'pass', 'message': 'Valid until 2054-01-15'},
            {'check': 'Debug certificate', 'status': 'warn', 'message': 'APK appears to be signed with a debug certificate'},
        ],
    },
    'suspicious_strings': {
        'total': 5,
        'strings': [
            {'string': 'exec', 'source': 'classes.dex'},
            {'string': 'shell', 'source': 'classes.dex'},
            {'string': 'payload', 'source': 'classes.dex'},
            {'string': 'decrypt', 'source': 'classes.dex'},
            {'string': 'download', 'source': 'classes.dex'},
        ],
    },
    'risk_analysis': {
        'static_score': 76,
        'classification': 'MALICIOUS',
        'reasons': [
            {'title': '8 sensitive permissions detected', 'description': 'The application requests access to sensitive device capabilities including SMS, camera, microphone, and location.', 'severity': 'high', 'points': 30},
            {'title': 'Suspicious permission combinations found', 'description': 'Found 2 suspicious combo(s): READ_SMS + SEND_SMS + INTERNET; CAMERA + RECORD_AUDIO + INTERNET', 'severity': 'high', 'points': 20},
            {'title': '7 suspicious API indicators detected', 'description': 'Detected: SmsManager, Runtime.exec, DexClassLoader, DevicePolicyManager, Cipher', 'severity': 'high', 'points': 25},
            {'title': '4 suspicious intent(s) detected', 'description': 'Intents: BOOT_COMPLETED, SMS_RECEIVED, PHONE_STATE, CONNECTIVITY_CHANGE', 'severity': 'medium', 'points': 16},
            {'title': '4 non-standard network endpoints', 'description': 'Multiple external network endpoints were identified outside common platforms.', 'severity': 'medium', 'points': 12},
            {'title': 'Debug certificate detected', 'description': 'The APK appears to be signed with a debug certificate.', 'severity': 'medium', 'points': 10},
            {'title': '5 suspicious string(s) found', 'description': 'Strings: exec, shell, payload, decrypt, download', 'severity': 'high', 'points': 12},
        ],
        'total_indicators': 125,
    },
    'combined_score': {
        'final_score': 76,
        'static_score': 76,
        'gemini_score': None,
        'classification': 'MALICIOUS',
        'ai_available': False,
    },
    'gemini_analysis': {
        'classification': 'MALICIOUS',
        'risk_score': 82,
        'summary': 'This application exhibits multiple high-risk characteristics consistent with SMS-stealing malware. The combination of SMS interception, boot persistence, dynamic code loading, and connections to suspicious domains strongly suggests malicious intent.',
        'reasons': [
            'SMS interception capability via SmsReceiver with READ_SMS, SEND_SMS, and RECEIVE_SMS permissions',
            'Boot persistence through BOOT_COMPLETED intent allows automatic startup',
            'Dynamic code loading (DexClassLoader) enables downloading and executing additional payloads',
            'Device administrator API usage can make the app difficult to uninstall',
            'Network communication with multiple suspicious domains outside standard platforms',
            'Debug certificate suggests the app is not from an established developer',
        ],
        'high_risk_indicators': ['SMS interception', 'Dynamic code loading', 'Boot persistence', 'Suspicious domains'],
        'recommendations': [
            'Do not install this APK until its source is verified',
            'Review the application\'s SMS and phone permissions carefully',
            'Verify the developer\'s signing certificate',
            'Avoid granting device administrator privileges',
            'Download applications only from trusted sources like Google Play Store',
        ],
        'confidence': 'HIGH',
    },
}
