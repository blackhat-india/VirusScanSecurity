/**
 * VirusScan Security — Main Application Module
 * Shared UI logic: navbar, toasts, auth, user dropdown.
 */

// ──────────────────────────────────────────────────
// Auth helpers (simple session-based for hackathon)
// ──────────────────────────────────────────────────

const Auth = {
    getUser() {
        const user = localStorage.getItem('vs_user');
        return user ? JSON.parse(user) : null;
    },

    setUser(user) {
        localStorage.setItem('vs_user', JSON.stringify(user));
    },

    logout() {
        localStorage.removeItem('vs_user');
        window.location.href = '/';
    },

    isLoggedIn() {
        return !!this.getUser();
    },

    requireAuth() {
        if (!this.isLoggedIn()) {
            window.location.href = '/';
            return false;
        }
        return true;
    },

    /**
     * Mock Google sign-in for hackathon MVP.
     * Replace with real Firebase/Google OAuth in production.
     */
    mockGoogleSignIn() {
        const user = {
            name: 'Hackathon User',
            email: 'user@hackathon.dev',
            avatar: 'HU',
            signedInAt: new Date().toISOString(),
        };
        this.setUser(user);
        window.location.href = '/home';
    },
};


// ──────────────────────────────────────────────────
// Toast notifications
// ──────────────────────────────────────────────────

const Toast = {
    container: null,

    init() {
        if (!this.container) {
            this.container = document.createElement('div');
            this.container.className = 'toast-container';
            document.body.appendChild(this.container);
        }
    },

    show(message, type = 'info', duration = 4000) {
        this.init();

        const icons = {
            success: '✓',
            error: '✗',
            warning: '⚠',
            info: 'ℹ',
        };

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `<span>${icons[type] || 'ℹ'}</span><span>${message}</span>`;

        this.container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(20px)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    },

    success(msg) { this.show(msg, 'success'); },
    error(msg) { this.show(msg, 'error', 6000); },
    warning(msg) { this.show(msg, 'warning'); },
    info(msg) { this.show(msg, 'info'); },
};


// ──────────────────────────────────────────────────
// Navbar initialization
// ──────────────────────────────────────────────────

function initNavbar() {
    const user = Auth.getUser();
    if (!user) return;

    // Set user avatar text
    const avatarEls = document.querySelectorAll('.navbar-user-avatar');
    avatarEls.forEach(el => {
        el.textContent = user.avatar || user.name.charAt(0).toUpperCase();
    });

    // Set user name
    const nameEls = document.querySelectorAll('.navbar-user-name');
    nameEls.forEach(el => {
        el.textContent = user.name;
    });

    // User dropdown toggle
    const userBtn = document.querySelector('.navbar-user-btn');
    const dropdown = document.querySelector('.navbar-dropdown');

    if (userBtn && dropdown) {
        userBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            dropdown.classList.toggle('open');
        });

        document.addEventListener('click', () => {
            dropdown.classList.remove('open');
        });
    }

    // Logout button
    const logoutBtn = document.getElementById('btn-logout');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            Auth.logout();
        });
    }

    // Mobile menu toggle
    const mobileToggle = document.querySelector('.navbar-mobile-toggle');
    const navMenu = document.querySelector('.navbar-nav');
    if (mobileToggle && navMenu) {
        mobileToggle.addEventListener('click', () => {
            navMenu.classList.toggle('open');
        });
    }

    // Highlight active nav item
    const currentPath = window.location.pathname;
    document.querySelectorAll('.navbar-nav a').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
}


// ──────────────────────────────────────────────────
// Score circle drawing
// ──────────────────────────────────────────────────

function drawScoreCircle(containerId, score, size = 180) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const radius = (size / 2) - 12;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (score / 100) * circumference;

    let colorClass = 'safe';
    if (score >= 60) colorClass = 'malicious';
    else if (score >= 30) colorClass = 'suspicious';

    container.innerHTML = `
        <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
            <circle class="score-circle-bg" cx="${size/2}" cy="${size/2}" r="${radius}"/>
            <circle class="score-circle-fill ${colorClass}" cx="${size/2}" cy="${size/2}" r="${radius}"
                stroke-dasharray="${circumference}"
                stroke-dashoffset="${circumference}"
                data-target-offset="${offset}"/>
        </svg>
        <div class="score-value">
            <div class="score-number" data-target="${score}">0</div>
            <div class="score-total">/ 100</div>
        </div>
    `;

    // Animate
    requestAnimationFrame(() => {
        const circle = container.querySelector('.score-circle-fill');
        const numberEl = container.querySelector('.score-number');

        if (circle) {
            circle.style.strokeDashoffset = offset;
        }

        // Animate number
        animateNumber(numberEl, 0, score, 1200);
    });
}

function animateNumber(el, start, end, duration) {
    if (!el) return;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
        const current = Math.round(start + (end - start) * eased);
        el.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}


// ──────────────────────────────────────────────────
// Classification helpers
// ──────────────────────────────────────────────────

function getClassificationColor(classification) {
    switch (classification) {
        case 'SAFE': return 'var(--color-safe)';
        case 'SUSPICIOUS': return 'var(--color-suspicious)';
        case 'MALICIOUS': return 'var(--color-malicious)';
        default: return 'var(--text-secondary)';
    }
}

function getClassificationBadge(classification) {
    const cls = classification.toLowerCase();
    return `<span class="badge badge-${cls}">${classification}</span>`;
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function formatDate(dateStr) {
    try {
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-US', {
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
    } catch {
        return dateStr;
    }
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}


// ──────────────────────────────────────────────────
// File upload helpers
// ──────────────────────────────────────────────────

function setupFileUpload(dropZoneId, fileInputId, callbacks = {}) {
    const dropZone = document.getElementById(dropZoneId);
    const fileInput = document.getElementById(fileInputId);

    if (!dropZone || !fileInput) return;

    // Click to browse
    dropZone.addEventListener('click', () => fileInput.click());

    // File selected
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file && callbacks.onFileSelected) {
            callbacks.onFileSelected(file);
        }
    });

    // Drag & drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');

        const file = e.dataTransfer.files[0];
        if (file && callbacks.onFileSelected) {
            callbacks.onFileSelected(file);
        }
    });
}


// ──────────────────────────────────────────────────
// Initialize on page load
// ──────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    initNavbar();
});
