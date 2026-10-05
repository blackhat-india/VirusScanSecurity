/**
 * VirusScan Security — API Client Module
 * Handles all communication with the Flask backend.
 */

const API_BASE = window.location.origin;

const API = {
    /**
     * Upload and analyze an APK file.
     */
    async analyzeAPK(file, onProgress) {
        const formData = new FormData();
        formData.append('apk', file);

        try {
            const response = await fetch(`${API_BASE}/api/analyze/apk`, {
                method: 'POST',
                body: formData,
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Analysis failed');
            }

            return data;
        } catch (error) {
            if (error.message === 'Failed to fetch') {
                throw new Error('Unable to connect to the server. Make sure the backend is running.');
            }
            throw error;
        }
    },

    /**
     * Analyze a URL.
     */
    async analyzeURL(url) {
        try {
            const response = await fetch(`${API_BASE}/api/analyze/url`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'URL analysis failed');
            }

            return data;
        } catch (error) {
            if (error.message === 'Failed to fetch') {
                throw new Error('Unable to connect to the server.');
            }
            throw error;
        }
    },

    /**
     * Analyze certificate from an APK.
     */
    async analyzeCertificate(file) {
        const formData = new FormData();
        formData.append('apk', file);

        try {
            const response = await fetch(`${API_BASE}/api/analyze/certificate`, {
                method: 'POST',
                body: formData,
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Certificate analysis failed');
            }

            return data;
        } catch (error) {
            if (error.message === 'Failed to fetch') {
                throw new Error('Unable to connect to the server.');
            }
            throw error;
        }
    },

    /**
     * Analyze behavior from an APK.
     */
    async analyzeBehavior(file) {
        const formData = new FormData();
        formData.append('apk', file);

        try {
            const response = await fetch(`${API_BASE}/api/analyze/behavior`, {
                method: 'POST',
                body: formData,
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Behavior analysis failed');
            }

            return data;
        } catch (error) {
            if (error.message === 'Failed to fetch') {
                throw new Error('Unable to connect to the server.');
            }
            throw error;
        }
    },

    /**
     * Get demo analysis data.
     */
    async getDemoAnalysis() {
        try {
            const response = await fetch(`${API_BASE}/api/analyze/demo`);
            return await response.json();
        } catch (error) {
            throw new Error('Unable to load demo data.');
        }
    },

    /**
     * Get scan history.
     */
    async getHistory(limit = 50) {
        try {
            const response = await fetch(`${API_BASE}/api/history?limit=${limit}`);
            const data = await response.json();
            return data.history || [];
        } catch (error) {
            console.error('Failed to fetch history:', error);
            return [];
        }
    },

    /**
     * Get scan detail by ID.
     */
    async getScanDetail(scanId) {
        try {
            const response = await fetch(`${API_BASE}/api/history/${scanId}`);
            const data = await response.json();
            return data.scan || null;
        } catch (error) {
            console.error('Failed to fetch scan detail:', error);
            return null;
        }
    },

    /**
     * Get dashboard statistics.
     */
    async getStats() {
        try {
            const response = await fetch(`${API_BASE}/api/stats`);
            const data = await response.json();
            return data.stats || { apk_scans: 0, threats_detected: 0, urls_analyzed: 0, security_score: 85 };
        } catch (error) {
            console.error('Failed to fetch stats:', error);
            return { apk_scans: 0, threats_detected: 0, urls_analyzed: 0, security_score: 85 };
        }
    },

    /**
     * Submit contact form.
     */
    async submitContact(name, email, message) {
        try {
            const response = await fetch(`${API_BASE}/api/contact`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, email, message }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to send message');
            }

            return data;
        } catch (error) {
            if (error.message === 'Failed to fetch') {
                throw new Error('Unable to connect to the server.');
            }
            throw error;
        }
    },

    /**
     * Check backend health.
     */
    async checkHealth() {
        try {
            const response = await fetch(`${API_BASE}/api/health`);
            return await response.json();
        } catch (error) {
            return { status: 'unhealthy', error: error.message };
        }
    },
};
