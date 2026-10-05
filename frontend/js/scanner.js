/**
 * VirusScan Security — Scanner Page Logic
 * Handles APK upload, analysis progress, and result rendering.
 */

document.addEventListener('DOMContentLoaded', () => {
    if (!Auth.requireAuth()) return;

    let selectedFile = null;

    // File upload setup
    setupFileUpload('upload-zone', 'apk-input', {
        onFileSelected: (file) => {
            if (!file.name.toLowerCase().endsWith('.apk')) {
                Toast.error('Please select a valid APK file.');
                return;
            }

            selectedFile = file;
            showFileInfo(file);
        }
    });

    // Start scan button
    const scanBtn = document.getElementById('btn-start-scan');
    if (scanBtn) {
        scanBtn.addEventListener('click', () => {
            if (!selectedFile) {
                Toast.warning('Please select an APK file first.');
                return;
            }
            startAnalysis(selectedFile);
        });
    }

    // Demo button
    const demoBtn = document.getElementById('btn-demo');
    if (demoBtn) {
        demoBtn.addEventListener('click', startDemoAnalysis);
    }

    // Remove file button
    const removeBtn = document.getElementById('btn-remove-file');
    if (removeBtn) {
        removeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            clearFileSelection();
        });
    }
});


function showFileInfo(file) {
    const infoEl = document.getElementById('file-info');
    const nameEl = document.getElementById('file-name');
    const sizeEl = document.getElementById('file-size');
    const scanBtn = document.getElementById('btn-start-scan');

    if (infoEl) infoEl.classList.add('visible');
    if (nameEl) nameEl.textContent = file.name;
    if (sizeEl) sizeEl.textContent = formatFileSize(file.size);
    if (scanBtn) scanBtn.disabled = false;
}


function clearFileSelection() {
    const infoEl = document.getElementById('file-info');
    const fileInput = document.getElementById('apk-input');
    const scanBtn = document.getElementById('btn-start-scan');

    if (infoEl) infoEl.classList.remove('visible');
    if (fileInput) fileInput.value = '';
    if (scanBtn) scanBtn.disabled = true;
}


// ──────────────────────────────────────────────────
// Analysis progress
// ──────────────────────────────────────────────────

const ANALYSIS_STEPS = [
    'Validating APK file',
    'Reading manifest data',
    'Extracting permissions',
    'Inspecting components',
    'Analyzing network indicators',
    'Inspecting certificate',
    'Calculating risk score',
    'Generating AI security explanation',
];

function showProgress() {
    const progressEl = document.getElementById('analysis-progress');
    const uploadSection = document.getElementById('upload-section');
    const resultsSection = document.getElementById('results-section');

    if (uploadSection) uploadSection.style.display = 'none';
    if (resultsSection) resultsSection.classList.remove('visible');
    if (progressEl) {
        progressEl.classList.add('visible');
        renderProgressSteps();
    }
}

function renderProgressSteps() {
    const stepsContainer = document.getElementById('progress-steps');
    if (!stepsContainer) return;

    stepsContainer.innerHTML = ANALYSIS_STEPS.map((step, i) => `
        <div class="progress-step" id="step-${i}">
            <div class="progress-step-icon">
                <span class="step-icon-content">○</span>
            </div>
            <span>${step}</span>
        </div>
    `).join('');
}

function updateProgressStep(index, status) {
    const stepEl = document.getElementById(`step-${index}`);
    if (!stepEl) return;

    stepEl.classList.remove('active', 'done');
    const iconEl = stepEl.querySelector('.step-icon-content');

    if (status === 'active') {
        stepEl.classList.add('active');
        if (iconEl) iconEl.innerHTML = '<div class="spinner spinner-sm"></div>';
    } else if (status === 'done') {
        stepEl.classList.add('done');
        if (iconEl) iconEl.textContent = '✓';
    }
}

async function animateProgress() {
    for (let i = 0; i < ANALYSIS_STEPS.length; i++) {
        updateProgressStep(i, 'active');
        // Faster for early steps, slower for analysis/AI
        const delay = i < 5 ? 400 + Math.random() * 300 : 800 + Math.random() * 500;
        await new Promise(r => setTimeout(r, delay));
        updateProgressStep(i, 'done');
    }
}


// ──────────────────────────────────────────────────
// Start analysis
// ──────────────────────────────────────────────────

async function startAnalysis(file) {
    showProgress();

    // Start progress animation and API call concurrently
    const progressPromise = animateProgress();
    const analysisPromise = API.analyzeAPK(file);

    try {
        const [_, result] = await Promise.all([progressPromise, analysisPromise]);

        if (result.success) {
            // Small delay for visual completion
            await new Promise(r => setTimeout(r, 500));
            renderResults(result, false);
            Toast.success('Analysis complete!');
        } else {
            throw new Error(result.error || 'Analysis failed');
        }
    } catch (error) {
        Toast.error(error.message);
        // Show upload section again
        const progressEl = document.getElementById('analysis-progress');
        const uploadSection = document.getElementById('upload-section');
        if (progressEl) progressEl.classList.remove('visible');
        if (uploadSection) uploadSection.style.display = '';
    }
}


async function startDemoAnalysis() {
    showProgress();

    try {
        const progressPromise = animateProgress();
        const demoPromise = API.getDemoAnalysis();

        const [_, result] = await Promise.all([progressPromise, demoPromise]);

        await new Promise(r => setTimeout(r, 500));
        renderResults(result, true);
        Toast.info('Demo analysis loaded — this uses sample data.');
    } catch (error) {
        Toast.error('Failed to load demo data: ' + error.message);
        const progressEl = document.getElementById('analysis-progress');
        const uploadSection = document.getElementById('upload-section');
        if (progressEl) progressEl.classList.remove('visible');
        if (uploadSection) uploadSection.style.display = '';
    }
}


// ──────────────────────────────────────────────────
// Render results
// ──────────────────────────────────────────────────

function renderResults(data, isDemo = false) {
    const progressEl = document.getElementById('analysis-progress');
    const resultsSection = document.getElementById('results-section');

    if (progressEl) progressEl.classList.remove('visible');
    if (resultsSection) resultsSection.classList.add('visible');

    const combined = data.combined_score || data.risk_analysis || {};
    const score = combined.final_score ?? combined.static_score ?? 0;
    const classification = combined.classification || 'SUSPICIOUS';
    const confidence = data.confidence || data.gemini_analysis?.confidence || 'MEDIUM';

    // Demo banner
    const demoContainer = document.getElementById('demo-banner-container');
    if (demoContainer) {
        demoContainer.innerHTML = isDemo ?
            '<div class="demo-banner">⚡ DEMO RESULT — This analysis uses sample data for demonstration</div>' : '';
    }

    // Score circle
    drawScoreCircle('score-circle', score);

    // Classification
    const classEl = document.getElementById('result-classification');
    if (classEl) {
        classEl.textContent = classification;
        classEl.style.color = getClassificationColor(classification);
    }

    // Confidence
    const confEl = document.getElementById('result-confidence');
    if (confEl) {
        const method = data.combined_score?.method === 'evidence_first_ai_second_opinion'
            ? ' · Evidence-first scoring'
            : '';
        confEl.textContent = `Confidence: ${confidence}${method}`;
    }

    // Filename
    const fnEl = document.getElementById('result-filename');
    if (fnEl) {
        fnEl.textContent = data.metadata?.filename || 'Unknown';
    }

    // Package name
    const pkgEl = document.getElementById('result-package');
    if (pkgEl) {
        pkgEl.textContent = data.metadata?.package_name || '';
    }

    // Metric cards
    renderMetricCards(data);

    // Reasons
    renderReasons(data);

    // Permissions
    renderPermissions(data);

    // Network indicators
    renderNetworkIndicators(data);

    // Components & intents
    renderComponentsIntents(data);

    // Certificate
    renderCertificate(data);

    // AI Assessment
    renderAIAssessment(data);

    // Recommendations
    renderRecommendations(data);

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}


function renderMetricCards(data) {
    const container = document.getElementById('result-metrics');
    if (!container) return;

    const perms = data.permissions || {};
    const network = data.network_indicators || {};
    const components = data.components || {};
    const cert = data.certificate || {};
    const apis = data.api_indicators || {};

    container.innerHTML = `
        <div class="result-metric">
            <div class="result-metric-icon">🔐</div>
            <div class="result-metric-value">${perms.total || 0}</div>
            <div class="result-metric-sub">${perms.dangerous_count || 0} sensitive</div>
            <div class="result-metric-label">Permissions</div>
        </div>
        <div class="result-metric">
            <div class="result-metric-icon">🌐</div>
            <div class="result-metric-value">${network.urls_total || 0}</div>
            <div class="result-metric-sub">${network.domains_total || 0} domains</div>
            <div class="result-metric-label">Network</div>
        </div>
        <div class="result-metric">
            <div class="result-metric-icon">📦</div>
            <div class="result-metric-value">${components.total || 0}</div>
            <div class="result-metric-sub">${components.exported_count || 0} exported</div>
            <div class="result-metric-label">Components</div>
        </div>
        <div class="result-metric">
            <div class="result-metric-icon">📜</div>
            <div class="result-metric-value">${cert.present ? 'Valid' : 'Missing'}</div>
            <div class="result-metric-sub">${cert.algorithm || 'N/A'}</div>
            <div class="result-metric-label">Certificate</div>
        </div>
        <div class="result-metric">
            <div class="result-metric-icon">⚡</div>
            <div class="result-metric-value">${apis.total || 0}</div>
            <div class="result-metric-sub">API families</div>
            <div class="result-metric-label">Behavior</div>
        </div>
        <div class="result-metric">
            <div class="result-metric-icon">◎</div>
            <div class="result-metric-value">${data.risk_analysis?.evidence_domains || 0}</div>
            <div class="result-metric-sub">${escapeHtml(data.risk_analysis?.confidence || data.confidence || 'LOW')} confidence</div>
            <div class="result-metric-label">Evidence Coverage</div>
        </div>
    `;
}


function renderReasons(data) {
    const container = document.getElementById('result-reasons');
    if (!container) return;

    const reasons = data.risk_analysis?.reasons || [];

    if (reasons.length === 0) {
        container.innerHTML = `
            <div class="detail-card">
                <h3>✅ Analysis Results</h3>
                <p style="color: var(--color-safe); font-weight: 500;">
                    No significant security concerns were identified.
                </p>
            </div>
        `;
        return;
    }

    container.innerHTML = `
        <div class="detail-card">
            <h3>⚠ Why this APK was flagged</h3>
            ${reasons.map(r => `
                <div class="reason-item ${r.severity === 'high' ? 'high' : ''}">
                    <div class="reason-title">
                        ${r.severity === 'high' ? '🔴' : '🟡'} ${escapeHtml(r.title)}
                        <span class="badge badge-${r.severity === 'high' ? 'malicious' : 'suspicious'}"
                            style="margin-left: 8px; font-size: 10px;">
                            +${r.points} pts
                        </span>
                    </div>
                    <div class="reason-desc">${escapeHtml(r.description)}</div>
                </div>
            `).join('')}
        </div>
    `;
}


function renderPermissions(data) {
    const container = document.getElementById('result-permissions');
    if (!container) return;

    const perms = data.permissions || {};
    const dangerous = perms.dangerous || [];
    const normal = perms.normal || [];

    container.innerHTML = `
        <div class="detail-card">
            <h3>🔐 Permissions (${perms.total || 0})</h3>

            ${dangerous.length > 0 ? `
                <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">
                    <strong style="color: var(--color-malicious);">${dangerous.length} sensitive</strong> permissions detected
                </p>
                <div class="permission-list" style="margin-bottom: 16px;">
                    ${dangerous.map(p => `
                        <span class="permission-tag dangerous">${escapeHtml(p.short_name)}</span>
                    `).join('')}
                </div>
            ` : ''}

            ${normal.length > 0 ? `
                <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 8px;">
                    Standard permissions
                </p>
                <div class="permission-list">
                    ${normal.map(p => `
                        <span class="permission-tag normal">${escapeHtml(p.short_name)}</span>
                    `).join('')}
                </div>
            ` : ''}

            ${perms.suspicious_combinations?.length > 0 ? `
                <div style="margin-top: 16px; padding: 12px; background: var(--color-malicious-light);
                     border-radius: var(--radius-sm);">
                    <strong style="font-size: 13px; color: var(--color-malicious);">
                        ⚠ Suspicious Combinations
                    </strong>
                    ${perms.suspicious_combinations.map(combo => `
                        <div style="font-size: 12px; font-family: 'JetBrains Mono'; margin-top: 4px;
                             color: var(--text-main);">
                            ${combo.join(' + ')}
                        </div>
                    `).join('')}
                </div>
            ` : ''}
        </div>
    `;
}


function renderNetworkIndicators(data) {
    const container = document.getElementById('result-network');
    if (!container) return;

    const network = data.network_indicators || {};
    const suspiciousUrls = network.suspicious_urls || [];
    const domains = network.domains || [];
    const ips = network.ips || [];

    container.innerHTML = `
        <div class="detail-card">
            <h3>🌐 Network Indicators</h3>
            <div style="display: flex; gap: 16px; margin-bottom: 16px; flex-wrap: wrap;">
                <div class="badge badge-info">${network.urls_total || 0} URLs</div>
                <div class="badge badge-info">${network.domains_total || 0} Domains</div>
                <div class="badge badge-info">${network.ips_total || 0} IPs</div>
            </div>

            ${suspiciousUrls.length > 0 ? `
                <p style="font-size: 13px; font-weight: 600; margin-bottom: 8px; color: var(--color-suspicious);">
                    Suspicious URLs
                </p>
                <ul class="url-list" style="margin-bottom: 16px;">
                    ${suspiciousUrls.slice(0, 10).map(u => `
                        <li class="url-item">
                            <span style="color: var(--color-suspicious);">⚠</span>
                            ${escapeHtml(u)}
                        </li>
                    `).join('')}
                </ul>
            ` : ''}

            ${domains.length > 0 ? `
                <p style="font-size: 13px; font-weight: 600; margin-bottom: 8px;">Domains</p>
                <div class="permission-list" style="margin-bottom: 12px;">
                    ${domains.slice(0, 15).map(d => `
                        <span class="permission-tag normal">${escapeHtml(d)}</span>
                    `).join('')}
                </div>
            ` : ''}

            ${ips.length > 0 ? `
                <p style="font-size: 13px; font-weight: 600; margin-bottom: 8px;">IP Addresses</p>
                <div class="permission-list">
                    ${ips.map(ip => `
                        <span class="permission-tag sensitive">${escapeHtml(ip)}</span>
                    `).join('')}
                </div>
            ` : ''}

            ${(suspiciousUrls.length === 0 && domains.length === 0 && ips.length === 0) ? `
                <p style="color: var(--text-secondary); font-size: 14px;">
                    No significant network indicators found.
                </p>
            ` : ''}
        </div>
    `;
}


function renderComponentsIntents(data) {
    const container = document.getElementById('result-components');
    if (!container) return;

    const comp = data.components || {};
    const intents = data.intents || {};
    const apis = data.api_indicators || {};

    container.innerHTML = `
        <div class="detail-card">
            <h3>📦 Components & Intents</h3>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                 gap: 12px; margin-bottom: 16px;">
                <div style="text-align: center; padding: 12px; background: var(--bg-hover);
                     border-radius: var(--radius-sm);">
                    <div style="font-size: 18px; font-weight: 700;">${comp.activities || 0}</div>
                    <div style="font-size: 12px; color: var(--text-secondary);">Activities</div>
                </div>
                <div style="text-align: center; padding: 12px; background: var(--bg-hover);
                     border-radius: var(--radius-sm);">
                    <div style="font-size: 18px; font-weight: 700;">${comp.services || 0}</div>
                    <div style="font-size: 12px; color: var(--text-secondary);">Services</div>
                </div>
                <div style="text-align: center; padding: 12px; background: var(--bg-hover);
                     border-radius: var(--radius-sm);">
                    <div style="font-size: 18px; font-weight: 700;">${comp.receivers || 0}</div>
                    <div style="font-size: 12px; color: var(--text-secondary);">Receivers</div>
                </div>
                <div style="text-align: center; padding: 12px; background: var(--bg-hover);
                     border-radius: var(--radius-sm);">
                    <div style="font-size: 18px; font-weight: 700;">${comp.providers || 0}</div>
                    <div style="font-size: 12px; color: var(--text-secondary);">Providers</div>
                </div>
            </div>

            ${comp.exported?.length > 0 ? `
                <p style="font-size: 13px; font-weight: 600; margin-bottom: 8px; color: var(--color-suspicious);">
                    Exported Components (${comp.exported_count})
                </p>
                <div style="margin-bottom: 16px;">
                    ${comp.exported.map(c => `
                        <div style="padding: 6px 12px; background: var(--color-suspicious-light);
                             border-radius: var(--radius-sm); margin-bottom: 4px; font-size: 13px;">
                            <span style="font-weight: 600;">${escapeHtml(c.type)}</span>:
                            <span class="mono">${escapeHtml(c.name)}</span>
                        </div>
                    `).join('')}
                </div>
            ` : ''}

            ${intents.suspicious?.length > 0 ? `
                <p style="font-size: 13px; font-weight: 600; margin-bottom: 8px;">
                    Suspicious Intents (${intents.total})
                </p>
                ${intents.suspicious.map(i => `
                    <div class="reason-item" style="margin-bottom: 8px;">
                        <div class="reason-title">📡 ${escapeHtml(i.short_name)}</div>
                        <div class="reason-desc">${escapeHtml(i.description)}</div>
                    </div>
                `).join('')}
            ` : ''}

            ${apis.indicators?.length > 0 ? `
                <p style="font-size: 13px; font-weight: 600; margin: 16px 0 8px;">
                    API Indicators (${apis.total})
                </p>
                <div class="permission-list">
                    ${apis.indicators.map(a => `
                        <span class="permission-tag sensitive" title="${escapeHtml(a.description)}">
                            ${escapeHtml(a.indicator)}
                        </span>
                    `).join('')}
                </div>
            ` : ''}
        </div>
    `;
}


function renderCertificate(data) {
    const container = document.getElementById('result-certificate');
    if (!container) return;

    const cert = data.certificate || {};

    container.innerHTML = `
        <div class="detail-card">
            <h3>📜 Certificate Information</h3>

            ${cert.present ? `
                <div class="cert-grid" style="margin-bottom: 16px;">
                    <div class="cert-field">
                        <div class="cert-field-label">Subject</div>
                        <div class="cert-field-value">${escapeHtml(cert.subject || 'Unknown')}</div>
                    </div>
                    <div class="cert-field">
                        <div class="cert-field-label">Issuer</div>
                        <div class="cert-field-value">${escapeHtml(cert.issuer || 'Unknown')}</div>
                    </div>
                    <div class="cert-field">
                        <div class="cert-field-label">Algorithm</div>
                        <div class="cert-field-value">${escapeHtml(cert.algorithm || 'Unknown')}</div>
                    </div>
                    <div class="cert-field">
                        <div class="cert-field-label">Serial Number</div>
                        <div class="cert-field-value">${escapeHtml(cert.serial_number || 'Unknown')}</div>
                    </div>
                    <div class="cert-field">
                        <div class="cert-field-label">Valid From</div>
                        <div class="cert-field-value">${escapeHtml(cert.valid_from || 'Unknown')}</div>
                    </div>
                    <div class="cert-field">
                        <div class="cert-field-label">Valid Until</div>
                        <div class="cert-field-value">${escapeHtml(cert.valid_until || 'Unknown')}</div>
                    </div>
                </div>

                ${cert.sha256_fingerprint && cert.sha256_fingerprint !== 'Unknown' ? `
                    <div class="cert-field" style="margin-bottom: 16px;">
                        <div class="cert-field-label">SHA-256 Fingerprint</div>
                        <div class="cert-field-value" style="font-size: 11px; word-break: break-all;">
                            ${escapeHtml(cert.sha256_fingerprint)}
                        </div>
                    </div>
                ` : ''}

                <p style="font-size: 13px; font-weight: 600; margin-bottom: 8px;">Security Checks</p>
                ${(cert.checks || []).map(check => `
                    <div class="cert-check">
                        <div class="cert-check-icon ${check.status}">
                            ${check.status === 'pass' ? '✓' : check.status === 'warn' ? '⚠' : '✗'}
                        </div>
                        <div>
                            <strong>${escapeHtml(check.check)}</strong>
                            <div style="font-size: 12px; color: var(--text-secondary);">
                                ${escapeHtml(check.message)}
                            </div>
                        </div>
                    </div>
                `).join('')}
            ` : `
                <p style="color: var(--color-malicious); font-weight: 600;">
                    ✗ No certificate found in this APK.
                </p>
            `}
        </div>
    `;
}


function renderAIAssessment(data) {
    const container = document.getElementById('result-ai');
    if (!container) return;

    const ai = data.gemini_analysis;

    if (!ai) {
        container.innerHTML = `
            <div class="ai-assessment" style="background: var(--bg-hover); border-color: var(--border-color);">
                <h3 style="color: var(--text-secondary);">
                    🤖 AI Security Assessment
                </h3>
                <p style="color: var(--text-secondary);">
                    AI analysis unavailable. Showing static security analysis instead.
                    <br><br>
                    <em>To enable AI analysis, configure the GEMINI_API_KEY in your .env file.</em>
                </p>
            </div>
        `;
        return;
    }

    container.innerHTML = `
        <div class="ai-assessment">
            <h3>🤖 AI Security Assessment
                <span class="badge badge-info" style="margin-left: 8px; font-size: 10px;">
                    Powered by Gemini
                </span>
            </h3>
            <p style="margin-bottom: 16px;">${escapeHtml(ai.summary || '')}</p>

            ${ai.reasons?.length > 0 ? `
                <p style="font-size: 13px; font-weight: 600; margin-bottom: 8px;">Key Findings:</p>
                <ul style="list-style: none; padding: 0;">
                    ${ai.reasons.map(r => `
                        <li style="padding: 6px 0; font-size: 13px; display: flex; gap: 8px;">
                            <span style="color: var(--accent-secondary);">▸</span>
                            ${escapeHtml(r)}
                        </li>
                    `).join('')}
                </ul>
            ` : ''}

            ${ai.high_risk_indicators?.length > 0 ? `
                <div style="margin-top: 12px;">
                    <p style="font-size: 13px; font-weight: 600; margin-bottom: 6px; color: var(--color-malicious);">
                        High-Risk Indicators:
                    </p>
                    <div class="permission-list">
                        ${ai.high_risk_indicators.map(i => `
                            <span class="permission-tag dangerous">${escapeHtml(i)}</span>
                        `).join('')}
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}


function renderRecommendations(data) {
    const container = document.getElementById('result-recommendations');
    if (!container) return;

    const recs = data.gemini_analysis?.recommendations ||
                 getDefaultRecommendations(data);

    const combined = data.combined_score || data.risk_analysis || {};
    const classification = combined.classification || 'SUSPICIOUS';

    container.innerHTML = `
        <div class="detail-card">
            <h3>🛡 Recommended Actions</h3>

            <div style="padding: 16px; background: ${
                classification === 'MALICIOUS' ? 'var(--color-malicious-light)' :
                classification === 'SUSPICIOUS' ? 'var(--color-suspicious-light)' :
                'var(--color-safe-light)'
            }; border-radius: var(--radius-md); margin-bottom: 16px; text-align: center;">
                <div style="font-size: 16px; font-weight: 700; color: ${getClassificationColor(classification)};">
                    ${classification === 'MALICIOUS' ? 'DO NOT INSTALL' :
                      classification === 'SUSPICIOUS' ? 'INSTALL WITH CAUTION' :
                      'APPEARS SAFE'}
                </div>
                <div style="font-size: 13px; color: var(--text-secondary); margin-top: 4px;">
                    ${classification === 'MALICIOUS' ?
                        'Verify the APK source and developer certificate before considering installation.' :
                      classification === 'SUSPICIOUS' ?
                        'Review the flagged indicators before installation.' :
                        'No significant issues found, but always download from trusted sources.'}
                </div>
            </div>

            <ol class="recommendations-list">
                ${recs.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
            </ol>
        </div>

        <div class="disclaimer">
            <strong>Disclaimer:</strong> VirusScan Security performs automated static and heuristic analysis.
            A SAFE result does not guarantee that an application is completely free from malware.
            Do not install applications from untrusted sources.
        </div>
    `;
}


function getDefaultRecommendations(data) {
    const recs = [];
    const classification = data.risk_analysis?.classification || 'SUSPICIOUS';

    if (classification === 'MALICIOUS') {
        recs.push('Do not install this APK until its source is verified.');
    }

    const perms = data.permissions || {};
    if (perms.dangerous_count > 0) {
        recs.push(`Review the application's ${perms.dangerous_count} sensitive permissions.`);
    }

    if (data.certificate?.is_debug) {
        recs.push('Verify the developer signing certificate — debug signature detected.');
    }

    recs.push('Avoid granting unnecessary permissions.');
    recs.push('Download applications only from trusted sources.');

    if (data.network_indicators?.suspicious_urls?.length > 0) {
        recs.push('Investigate the network endpoints this application connects to.');
    }

    return recs;
}
