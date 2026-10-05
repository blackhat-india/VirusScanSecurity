"""
VirusScan Security — Database Module
Handles SQLite scan history and basic result storage.
"""

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'virusscan.db')


def get_db():
    """Get a database connection with row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Initialize the database schema."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            filename TEXT,
            package_name TEXT,
            risk_score INTEGER,
            classification TEXT,
            confidence TEXT,
            summary TEXT,
            result_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contact_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


def save_scan(scan_type, filename, package_name, risk_score, classification,
              confidence, summary, result_json):
    """Save a scan result to history."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO scan_history
        (scan_type, filename, package_name, risk_score, classification,
         confidence, summary, result_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_type,
        filename,
        package_name,
        risk_score,
        classification,
        confidence,
        summary,
        json.dumps(result_json) if isinstance(result_json, dict) else result_json
    ))

    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_scan_history(limit=50):
    """Retrieve recent scan history."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, scan_type, filename, package_name, risk_score,
               classification, confidence, summary, created_at
        FROM scan_history
        ORDER BY created_at DESC
        LIMIT ?
    ''', (limit,))

    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append({
            'id': row['id'],
            'scan_type': row['scan_type'],
            'filename': row['filename'],
            'package_name': row['package_name'],
            'risk_score': row['risk_score'],
            'classification': row['classification'],
            'confidence': row['confidence'],
            'summary': row['summary'],
            'created_at': row['created_at']
        })

    return results


def get_scan_by_id(scan_id):
    """Retrieve a specific scan result."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM scan_history WHERE id = ?
    ''', (scan_id,))

    row = cursor.fetchone()
    conn.close()

    if row:
        result = dict(row)
        if result.get('result_json'):
            try:
                result['result_json'] = json.loads(result['result_json'])
            except json.JSONDecodeError:
                pass
        return result
    return None


def get_stats():
    """Get aggregate statistics for the dashboard."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) as total FROM scan_history WHERE scan_type = "apk"')
    apk_scans = cursor.fetchone()['total']

    cursor.execute('SELECT COUNT(*) as total FROM scan_history WHERE classification = "MALICIOUS"')
    threats = cursor.fetchone()['total']

    cursor.execute('SELECT COUNT(*) as total FROM scan_history WHERE scan_type = "url"')
    url_scans = cursor.fetchone()['total']

    cursor.execute('SELECT AVG(100 - risk_score) as avg FROM scan_history WHERE risk_score IS NOT NULL')
    row = cursor.fetchone()
    avg_score = round(row['avg']) if row['avg'] else 85

    conn.close()

    return {
        'apk_scans': apk_scans,
        'threats_detected': threats,
        'urls_analyzed': url_scans,
        'security_score': avg_score
    }


def save_contact_message(name, email, message):
    """Save a contact form message."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO contact_messages (name, email, message)
        VALUES (?, ?, ?)
    ''', (name, email, message))

    conn.commit()
    conn.close()
