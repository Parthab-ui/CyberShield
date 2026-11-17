/**
 * CyberShield SOC Console - Review 3 Full-Stack Application Logic
 * Automated Cybersecurity Monitoring, Threat Response & Incident Forensics
 */

// ==========================================
// 1. GLOBAL STATE & CONFIGURATION
// ==========================================
const CONFIG = {
    POLL_INTERVAL_MS: 5000,
    TOKEN_KEY: 'cybershield_token',
    USER_KEY: 'cybershield_user'
};

const state = {
    currentUser: null,
    token: null,
    activeView: 'view-dashboard',
    pollTimer: null,
    selectedIncidentId: null,
    cachedIncidents: [],
    cachedInvestigators: [],
    cachedAlerts: []
};

// ==========================================
// 2. HTTP API CLIENT (WITH BEARER AUTH & RBAC GATING)
// ==========================================
async function api(endpoint, method = 'GET', body = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (state.token) {
        headers['Authorization'] = `Bearer ${state.token}`;
    }

    const options = { method, headers };
    if (body !== null && method !== 'GET') {
        options.body = typeof body === 'string' ? body : JSON.stringify(body);
    }

    try {
        const response = await fetch(endpoint, options);

        if (response.status === 401) {
            console.warn('Unauthorized access (401) - triggering session termination');
            logout();
            showToast('Session expired or authentication invalid. Please sign in again.');
            throw new Error('Authentication required');
        }

        if (response.status === 403) {
            showToast('Access Denied: You lack permissions for this operation (RBAC).');
            throw new Error('Forbidden operation');
        }

        const data = await response.json();
        if (!response.ok) {
            const errorMsg = data.message || data.error || `HTTP error ${response.status}`;
            throw new Error(errorMsg);
        }
        return data;
    } catch (err) {
        console.error(`API Error [${method} ${endpoint}]:`, err);
        throw err;
    }
}

// ==========================================
// 3. INITIALIZATION & LIFECYCLE
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
    // Atomic initial state reset for all tab panels
    document.querySelectorAll('.content-view').forEach(panel => {
        panel.classList.remove('active');
        panel.style.removeProperty('display');
        panel.style.display = 'none';
    });
    const initialDefault = document.getElementById('view-dashboard');
    if (initialDefault) {
        initialDefault.classList.add('active');
        initialDefault.style.display = 'block';
    }

    initAuthForms();
    initNavigation();
    initIncidentEvents();
    initThreatResponseEvents();
    initInvestigationEvents();
    initAccountSecurityEvents();
    initAccessMonitoring();
    initActivityEvents();

    // Check for stored credentials
    const storedToken = sessionStorage.getItem(CONFIG.TOKEN_KEY);
    const storedUser = sessionStorage.getItem(CONFIG.USER_KEY);

    if (storedToken && storedUser) {
        try {
            state.token = storedToken;
            state.currentUser = JSON.parse(storedUser);
            showAppShell();
            startPolling();
        } catch (e) {
            sessionStorage.clear();
            showLoginModal();
        }
    } else {
        showLoginModal();
    }
});

// ==========================================
// 4. AUTHENTICATION & SESSION MANAGEMENT
// ==========================================
function initAuthForms() {
    const loginForm = document.getElementById('login-form');
    const loginError = document.getElementById('login-error');
    const btnClear = document.getElementById('btn-login-clear');
    const btnFillAdmin = document.getElementById('btn-fill-admin');
    const btnFillAnalyst = document.getElementById('btn-fill-analyst');
    const btnLogout = document.getElementById('btn-logout');

    if (btnFillAdmin) {
        btnFillAdmin.addEventListener('click', () => {
            document.getElementById('login-username').value = 'admin';
            document.getElementById('login-password').value = 'Admin@123';
        });
    }

    if (btnFillAnalyst) {
        btnFillAnalyst.addEventListener('click', () => {
            document.getElementById('login-username').value = 'analyst';
            document.getElementById('login-password').value = 'Analyst@123';
        });
    }

    if (btnClear) {
        btnClear.addEventListener('click', () => {
            document.getElementById('login-username').value = '';
            document.getElementById('login-password').value = '';
            if (loginError) loginError.style.display = 'none';
        });
    }

    if (btnLogout) {
        btnLogout.addEventListener('click', () => {
            logout();
            showToast('You have signed out successfully.');
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('login-username').value.trim();
            const password = document.getElementById('login-password').value;

            if (loginError) loginError.style.display = 'none';

            try {
                const res = await api('/api/auth/login', 'POST', { username, password });
                if (res && res.token && res.user) {
                    state.token = res.token;
                    state.currentUser = res.user;
                    sessionStorage.setItem(CONFIG.TOKEN_KEY, res.token);
                    sessionStorage.setItem(CONFIG.USER_KEY, JSON.stringify(res.user));

                    showAppShell();
                    startPolling();
                    showToast(`Welcome to CyberShield SOC Console, ${res.user.fullName || res.user.username}!`);
                } else {
                    throw new Error(res.message || 'Authentication failed');
                }
            } catch (err) {
                if (loginError) {
                    loginError.textContent = err.message || 'Invalid credentials or account locked.';
                    loginError.style.display = 'block';
                }
            }
        });
    }
}

function showLoginModal() {
    stopPolling();
    const loginModal = document.getElementById('login-modal');
    const appShell = document.getElementById('app-shell');
    if (loginModal) loginModal.style.display = 'flex';
    if (appShell) appShell.style.display = 'none';
}

function showAppShell() {
    const loginModal = document.getElementById('login-modal');
    const appShell = document.getElementById('app-shell');
    if (loginModal) loginModal.style.display = 'none';
    if (appShell) appShell.style.display = 'flex';

    // Update user profile in header
    const headerUsername = document.getElementById('header-username');
    const headerRole = document.getElementById('header-role');

    if (headerUsername && state.currentUser) {
        headerUsername.textContent = state.currentUser.fullName || state.currentUser.username;
    }
    if (headerRole && state.currentUser) {
        const role = (state.currentUser.role || 'USER').toUpperCase();
        headerRole.textContent = role;
        headerRole.className = `role-badge badge-role-${role.toLowerCase()}`;
    }

    applyRbacUI();
    navigateTo('view-dashboard');
}

function applyRbacUI() {
    const role = (state.currentUser && state.currentUser.role ? state.currentUser.role : 'USER').toUpperCase();
    const isAdmin = role === 'ADMIN';
    const isAnalyst = role === 'ANALYST';
    const isPrivileged = isAdmin || isAnalyst;

    // Manual IP block card (Admin only)
    const manualBlockCard = document.querySelector('#view-threat-response .threat-form-card');
    if (manualBlockCard) {
        manualBlockCard.style.display = isAdmin ? 'block' : 'none';
    }

    // Account Security Tab / Buttons (Admin only)
    const accSecurityNav = document.querySelector('a[data-target="view-account-security"]');
    if (accSecurityNav) {
        accSecurityNav.style.display = isAdmin ? 'flex' : 'none';
    }

    // Assign Investigator Section in Dossier (Admin only)
    const assignForm = document.getElementById('form-assign-investigator');
    if (assignForm) {
        const assignParent = assignForm.closest('.dossier-card');
        if (assignParent) assignParent.style.display = isAdmin ? 'block' : 'none';
    }

    // Root Cause & Resolution forms (Admin & Analyst only)
    const rootCauseForm = document.getElementById('form-root-cause');
    if (rootCauseForm) {
        const rcParent = rootCauseForm.closest('.dossier-card');
        if (rcParent) rcParent.style.display = isPrivileged ? 'block' : 'none';
    }

    const resolveForm = document.getElementById('form-resolve-incident');
    if (resolveForm) {
        const resParent = resolveForm.closest('.dossier-card');
        if (resParent) resParent.style.display = isPrivileged ? 'block' : 'none';
    }

    const addNoteForm = document.getElementById('form-add-investigation-note');
    if (addNoteForm) {
        const noteParent = addNoteForm.closest('.dossier-card');
        if (noteParent) noteParent.style.display = isPrivileged ? 'block' : 'none';
    }
}

function logout() {
    stopPolling();
    state.currentUser = null;
    state.token = null;
    state.selectedIncidentId = null;
    sessionStorage.removeItem(CONFIG.TOKEN_KEY);
    sessionStorage.removeItem(CONFIG.USER_KEY);
    showLoginModal();
}

// ==========================================
// 5. PERIODIC POLLING ENGINE (5-SECOND INTERVAL)
// ==========================================
function startPolling() {
    stopPolling();
    pollData(); // Immediate initial poll
    state.pollTimer = setInterval(pollData, CONFIG.POLL_INTERVAL_MS);
}

function stopPolling() {
    if (state.pollTimer) {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
    }
}

async function pollData() {
    if (!state.token) return;

    try {
        // Always refresh KPI stats and active alerts in background
        await loadDashboardStats(true);

        // Refresh currently active view dynamically
        if (state.activeView === 'view-incidents') {
            const modal = document.getElementById('incident-modal');
            if (!modal || modal.style.display !== 'flex') {
                await loadIncidents();
            }
        } else if (state.activeView === 'view-threat-response') {
            await loadThreatResponseData();
        } else if (state.activeView === 'view-account-security') {
            await loadAccountSecurityData();
        } else if (state.activeView === 'view-investigation') {
            if (state.selectedIncidentId) {
                await refreshInvestigationCase(state.selectedIncidentId, true);
            }
        }
    } catch (e) {
        // Silent error catch to prevent unhandled rejection during background poll
        console.debug('Background poll cycle notice:', e.message);
    }
}

// ==========================================
// 6. NAVIGATION & VIEW SWITCHING
// ==========================================
function initNavigation() {
    const navItems = document.querySelectorAll('.sidebar-nav .nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetView = item.getAttribute('data-target');
            if (targetView) {
                navigateTo(targetView);
            }
        });
    });

    const btnRefreshDash = document.getElementById('btn-refresh-dashboard');
    if (btnRefreshDash) btnRefreshDash.addEventListener('click', () => loadDashboardStats(false));

    const btnRefreshThreat = document.getElementById('btn-refresh-threat-response');
    if (btnRefreshThreat) btnRefreshThreat.addEventListener('click', () => loadThreatResponseData());

    const btnRefreshInv = document.getElementById('btn-refresh-investigation');
    if (btnRefreshInv) btnRefreshInv.addEventListener('click', () => {
        if (state.selectedIncidentId) {
            loadInvestigationCase(state.selectedIncidentId);
        } else {
            loadInvestigationIncidentsList();
        }
    });

    const btnRefreshAcc = document.getElementById('btn-refresh-accounts');
    if (btnRefreshAcc) btnRefreshAcc.addEventListener('click', () => loadAccountSecurityData());

    const btnRefreshAct = document.getElementById('btn-refresh-activity');
    if (btnRefreshAct) btnRefreshAct.addEventListener('click', () => loadActivityHistory());

    const linkAllIncidents = document.getElementById('dashboard-view-all-incidents');
    if (linkAllIncidents) {
        linkAllIncidents.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo('view-incidents');
        });
    }

    const linkAllActivity = document.getElementById('dashboard-view-all-activity');
    if (linkAllActivity) {
        linkAllActivity.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo('view-activity');
        });
    }

    const btnViewAlert = document.getElementById('btn-view-alert-incident');
    if (btnViewAlert) {
        btnViewAlert.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo('view-incidents');
        });
    }
}

function navigateTo(viewId) {
    state.activeView = viewId;

    // Toggle nav active state
    document.querySelectorAll('.sidebar-nav .nav-item').forEach(item => {
        if (item.getAttribute('data-target') === viewId) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    // Atomic panel reset — hide ALL content panels, strip inline display styles
    document.querySelectorAll('.content-view').forEach(section => {
        section.classList.remove('active');
        section.style.removeProperty('display');
    });

    // Show only the target panel
    const targetSection = document.getElementById(viewId);
    if (targetSection) {
        targetSection.classList.add('active');
    }

    // Viewport scroll reset
    const mainContent = document.querySelector('.main-content');
    if (mainContent) mainContent.scrollTop = 0;

    // Update Header Page Title
    const titleElem = document.getElementById('page-title');
    if (titleElem) {
        switch (viewId) {
            case 'view-dashboard': titleElem.textContent = 'SOC Overview Dashboard'; break;
            case 'view-incidents': titleElem.textContent = 'Incident Management'; break;
            case 'view-threat-response': titleElem.textContent = 'Automated Threat Response Center'; break;
            case 'view-investigation': titleElem.textContent = 'Investigation & Forensic Triage Center'; break;
            case 'view-account-security': titleElem.textContent = 'Account Security & Credential Protection'; break;
            case 'view-activity': titleElem.textContent = 'Activity & Audit Log'; break;
            case 'view-access': titleElem.textContent = 'Access Monitoring & Simulation'; break;
            case 'view-lab': titleElem.textContent = 'Swing Component Lab'; break;
            case 'view-about': titleElem.textContent = 'About CyberShield'; break;
            default: titleElem.textContent = 'CyberShield Console';
        }
    }

    // Trigger immediate view data loader
    if (viewId === 'view-dashboard') {
        loadDashboardStats(false);
    } else if (viewId === 'view-incidents') {
        loadIncidents();
    } else if (viewId === 'view-threat-response') {
        loadThreatResponseData();
    } else if (viewId === 'view-investigation') {
        loadInvestigationIncidentsList();
    } else if (viewId === 'view-account-security') {
        loadAccountSecurityData();
    } else if (viewId === 'view-activity') {
        loadActivityHistory();
    } else if (viewId === 'view-access') {
        loadAccessEvents();
    }
}

// ==========================================
// 7. VIEW 1: OVERVIEW DASHBOARD
// ==========================================
async function loadDashboardStats(isBackground = false) {
    try {
        const stats = await api('/api/dashboard/stats');
        if (stats) {
            updateDashboardKPIs(stats);
        }

        // Check active security alerts
        const alerts = await api('/api/security-alerts');
        state.cachedAlerts = alerts || [];
        updateSecurityAlertBanner(alerts);

        if (!isBackground) {
            // Load latest incidents on dashboard
            const incidents = await api('/api/incidents');
            renderDashboardIncidents(incidents ? incidents.slice(0, 5) : []);

            // Load latest activity
            const activities = await api('/api/activity');
            renderDashboardActivity(activities ? activities.slice(0, 5) : []);
        }
    } catch (err) {
        if (!isBackground) {
            console.error('Failed to load dashboard metrics:', err);
        }
    }
}

function updateDashboardKPIs(s) {
    const setSafe = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val !== undefined && val !== null ? val : '0';
    };

    setSafe('stat-total', s.totalIncidents);
    setSafe('stat-open', s.openIncidents);
    setSafe('stat-high-critical', s.highCriticalIncidents !== undefined ? s.highCriticalIncidents : (s.highSeverityIncidents || 0));
    setSafe('stat-threats', s.threatsDetected || s.activeAlerts || 0);
    setSafe('stat-blocked-ips', s.activeBlockedIps || 0);
    setSafe('stat-locked-accounts', s.lockedAccounts || 0);
    setSafe('stat-success-responses', s.successfulThreatResponses || 0);
    setSafe('stat-failed-responses', s.failedThreatResponses || 0);
}

function updateSecurityAlertBanner(alerts) {
    const banner = document.getElementById('security-alert-banner');
    if (!banner) return;

    const activeAlert = alerts && alerts.find(a => a.status === 'NEW' || a.status === 'INVESTIGATING');
    if (!activeAlert) {
        banner.style.display = 'none';
        return;
    }

    banner.style.display = 'block';
    const setSafe = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val || 'N/A';
    };

    setSafe('alert-category', activeAlert.category || 'BRUTE_FORCE');
    setSafe('alert-title', activeAlert.title || 'Automated Threat Detection');
    setSafe('alert-ip', activeAlert.sourceIp || 'N/A');
    setSafe('alert-attempts', activeAlert.attemptCount || 'Multiple');
    setSafe('alert-severity', activeAlert.severity || 'HIGH');
    setSafe('alert-status', activeAlert.status || 'NEW');
    setSafe('alert-timestamp', activeAlert.timestamp ? formatTimestamp(activeAlert.timestamp) : 'Recent');

    const ruleNote = document.getElementById('alert-rule-note');
    if (ruleNote) {
        ruleNote.textContent = activeAlert.description || 'Threshold breached: 5 failed logins within 120s. Automated containment active.';
    }

    const btnViewAlert = document.getElementById('btn-view-alert-incident');
    if (btnViewAlert) {
        btnViewAlert.onclick = () => {
            if (activeAlert.incidentId) {
                navigateTo('view-investigation');
                loadInvestigationCase(activeAlert.incidentId);
            } else {
                navigateTo('view-incidents');
            }
        };
    }
}

function renderDashboardIncidents(incidents) {
    const tbody = document.getElementById('dashboard-incidents-body');
    if (!tbody) return;

    if (!incidents || incidents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No incidents registered.</td></tr>';
        return;
    }

    tbody.innerHTML = incidents.map(inc => `
        <tr>
            <td><strong>#${inc.id}</strong></td>
            <td>${escapeHtml(inc.title)}</td>
            <td><span class="badge badge-sev-${(inc.severity || 'low').toLowerCase()}">${escapeHtml(inc.severity)}</span></td>
            <td><span class="badge badge-status-${(inc.status || 'open').toLowerCase()}">${escapeHtml(inc.status)}</span></td>
            <td>
                <button class="btn btn-xs btn-outline" onclick="openIncidentDetailsFromDash(${inc.id})">Inspect</button>
            </td>
        </tr>
    `).join('');
}

function openIncidentDetailsFromDash(id) {
    navigateTo('view-investigation');
    loadInvestigationCase(id);
}

function renderDashboardActivity(activities) {
    const list = document.getElementById('dashboard-activity-list');
    if (!list) return;

    if (!activities || activities.length === 0) {
        list.innerHTML = '<li class="text-muted">No recent activity logged.</li>';
        return;
    }

    list.innerHTML = activities.map(act => `
        <li class="activity-feed-item">
            <span class="feed-user">👤 ${escapeHtml(act.username || 'system')}</span>
            <span class="feed-action">${escapeHtml(act.action)}</span>
            <span class="feed-detail">${escapeHtml(act.details || '')}</span>
            <span class="feed-time">${formatTimestamp(act.timestamp)}</span>
        </li>
    `).join('');
}

// ==========================================
// 8. VIEW 2: INCIDENT MANAGEMENT
// ==========================================
function initIncidentEvents() {
    const btnOpenModal = document.getElementById('btn-open-incident-modal');
    const btnCloseModal = document.getElementById('btn-close-incident-modal');
    const btnCancel = document.getElementById('btn-cancel-incident');
    const modal = document.getElementById('incident-modal');
    const incidentForm = document.getElementById('incident-form');
    const searchInput = document.getElementById('incident-search');
    const filterSev = document.getElementById('filter-severity');
    const filterStat = document.getElementById('filter-status');
    const btnReset = document.getElementById('btn-reset-filters');

    if (btnOpenModal) {
        btnOpenModal.addEventListener('click', () => openIncidentModal());
    }

    if (btnCloseModal) {
        btnCloseModal.addEventListener('click', () => { if (modal) modal.style.display = 'none'; });
    }

    if (btnCancel) {
        btnCancel.addEventListener('click', () => { if (modal) modal.style.display = 'none'; });
    }

    if (incidentForm) {
        incidentForm.addEventListener('submit', handleSaveIncident);
    }

    if (searchInput) searchInput.addEventListener('input', filterIncidentsTable);
    if (filterSev) filterSev.addEventListener('change', filterIncidentsTable);
    if (filterStat) filterStat.addEventListener('change', filterIncidentsTable);
    if (btnReset) {
        btnReset.addEventListener('click', () => {
            if (searchInput) searchInput.value = '';
            if (filterSev) filterSev.value = 'ALL';
            if (filterStat) filterStat.value = 'ALL';
            filterIncidentsTable();
        });
    }
}

async function loadIncidents() {
    try {
        const incidents = await api('/api/incidents');
        state.cachedIncidents = incidents || [];
        filterIncidentsTable();
    } catch (err) {
        console.error('Failed to load incidents:', err);
    }
}

function filterIncidentsTable() {
    const tbody = document.getElementById('incidents-table-body');
    if (!tbody) return;

    const query = (document.getElementById('incident-search')?.value || '').toLowerCase();
    const sevFilter = document.getElementById('filter-severity')?.value || 'ALL';
    const statFilter = document.getElementById('filter-status')?.value || 'ALL';

    const filtered = state.cachedIncidents.filter(inc => {
        const matchesQuery = !query || 
            (inc.title && inc.title.toLowerCase().includes(query)) ||
            (inc.description && inc.description.toLowerCase().includes(query)) ||
            String(inc.id).includes(query);
        const matchesSev = (sevFilter === 'ALL') || (inc.severity && inc.severity.toUpperCase() === sevFilter);
        const matchesStat = (statFilter === 'ALL') || (inc.status && inc.status.toUpperCase() === statFilter);
        return matchesQuery && matchesSev && matchesStat;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No matching incidents found.</td></tr>';
        return;
    }

    tbody.innerHTML = filtered.map(inc => `
        <tr>
            <td><strong>#${inc.id}</strong></td>
            <td><strong>${escapeHtml(inc.title)}</strong></td>
            <td><span class="badge badge-sev-${(inc.severity || 'low').toLowerCase()}">${escapeHtml(inc.severity)}</span></td>
            <td><span class="badge badge-status-${(inc.status || 'open').toLowerCase()}">${escapeHtml(inc.status)}</span></td>
            <td>${escapeHtml(inc.assignedAnalyst || inc.assignedTo || 'Unassigned')}</td>
            <td>${formatTimestamp(inc.createdAt)}</td>
            <td>
                <div class="table-actions">
                    <button class="btn btn-xs btn-primary" onclick="launchInvestigation(${inc.id})" title="Investigate in Forensic Center">🔬 Investigate</button>
                    <button class="btn btn-xs btn-outline" onclick="openIncidentModal(${inc.id})" title="Edit Incident Metadata">✏️ Edit</button>
                </div>
            </td>
        </tr>
    `).join('');
}

function launchInvestigation(id) {
    navigateTo('view-investigation');
    loadInvestigationCase(id);
}

function openIncidentModal(incidentId = null) {
    const modal = document.getElementById('incident-modal');
    const modalTitle = document.getElementById('incident-modal-title');
    const form = document.getElementById('incident-form');
    if (!modal || !form) return;

    form.reset();
    document.getElementById('incident-id').value = '';

    if (incidentId) {
        const inc = state.cachedIncidents.find(i => i.id === incidentId);
        if (inc) {
            modalTitle.textContent = `Edit Incident #${inc.id}`;
            document.getElementById('incident-id').value = inc.id;
            document.getElementById('incident-title').value = inc.title || '';
            document.getElementById('incident-severity').value = inc.severity || 'MEDIUM';
            document.getElementById('incident-status').value = inc.status || 'OPEN';
            document.getElementById('incident-description').value = inc.description || '';
        }
    } else {
        modalTitle.textContent = 'Create New Incident';
        document.getElementById('incident-severity').value = 'MEDIUM';
        document.getElementById('incident-status').value = 'OPEN';
    }

    modal.style.display = 'flex';
}

async function handleSaveIncident(e) {
    e.preventDefault();
    const idVal = document.getElementById('incident-id').value;
    const title = document.getElementById('incident-title').value.trim();
    const severity = document.getElementById('incident-severity').value;
    const status = document.getElementById('incident-status').value;
    const description = document.getElementById('incident-description').value.trim();

    const payload = { title, severity, status, description };

    try {
        if (idVal) {
            await api(`/api/incidents/${idVal}`, 'PUT', payload);
            showToast(`Incident #${idVal} successfully updated.`);
        } else {
            await api('/api/incidents', 'POST', payload);
            showToast('New incident created successfully.');
        }

        const modal = document.getElementById('incident-modal');
        if (modal) modal.style.display = 'none';
        await loadIncidents();
    } catch (err) {
        showToast(`Failed to save incident: ${err.message}`);
    }
}

// ==========================================
// 9. VIEW 3: THREAT RESPONSE CENTER
// ==========================================
function initThreatResponseEvents() {
    const formBlock = document.getElementById('form-manual-block');
    const filterBlocked = document.getElementById('filter-blocked-status');
    const filterThreatIp = document.getElementById('filter-threat-ip');
    const filterThreatStatus = document.getElementById('filter-threat-status');
    const btnDismissThreatModal = document.getElementById('btn-dismiss-threat-modal');
    const btnCloseThreatModal = document.getElementById('btn-close-threat-modal');
    const threatModal = document.getElementById('threat-details-modal');

    if (formBlock) {
        formBlock.addEventListener('submit', async (e) => {
            e.preventDefault();
            const ip = document.getElementById('block-ip-address').value.trim();
            const reason = document.getElementById('block-ip-reason').value.trim();
            const durationMinutes = parseInt(document.getElementById('block-ip-duration').value, 10) || 60;

            try {
                const res = await api('/api/firewall/block', 'POST', { ip, reason, durationMinutes });
                showToast(res.message || `IP ${ip} blocked successfully.`);
                formBlock.reset();
                document.getElementById('block-ip-duration').value = '60';
                await loadThreatResponseData();
            } catch (err) {
                showToast(`Block failed: ${err.message}`);
            }
        });
    }

    if (filterBlocked) filterBlocked.addEventListener('change', () => loadBlockedIps());
    if (filterThreatIp) filterThreatIp.addEventListener('input', () => loadThreatResponseHistory());
    if (filterThreatStatus) filterThreatStatus.addEventListener('change', () => loadThreatResponseHistory());

    if (btnDismissThreatModal) {
        btnDismissThreatModal.addEventListener('click', () => { if (threatModal) threatModal.style.display = 'none'; });
    }
    if (btnCloseThreatModal) {
        btnCloseThreatModal.addEventListener('click', () => { if (threatModal) threatModal.style.display = 'none'; });
    }
}

async function loadThreatResponseData() {
    await Promise.all([
        loadBlockedIps(),
        loadThreatResponseHistory()
    ]);
}

async function loadBlockedIps() {
    const tbody = document.getElementById('blocked-ips-tbody');
    if (!tbody) return;

    const statusFilter = document.getElementById('filter-blocked-status')?.value || 'ALL';
    try {
        const query = statusFilter !== 'ALL' ? `?status=${encodeURIComponent(statusFilter)}` : '';
        const blockedIps = await api(`/api/firewall/blocked-ips${query}`);

        if (!blockedIps || blockedIps.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No blocked IPs found for selected criteria.</td></tr>';
            return;
        }

        const isAdmin = state.currentUser && state.currentUser.role === 'ADMIN';

        tbody.innerHTML = blockedIps.map(b => {
            const isCurrentlyActive = b.status === 'ACTIVE';
            const actionBtn = (isAdmin && isCurrentlyActive)
                ? `<button class="btn btn-xs btn-danger" onclick="unblockIp('${escapeHtml(b.ipAddress)}')">Unblock</button>`
                : `<span class="text-muted">—</span>`;

            return `
                <tr>
                    <td><code>${escapeHtml(b.ipAddress)}</code></td>
                    <td>${escapeHtml(b.reason || 'Manual block')}</td>
                    <td>${formatTimestamp(b.blockedAt)}</td>
                    <td>${b.expiresAt ? formatTimestamp(b.expiresAt) : 'Permanent'}</td>
                    <td><span class="badge badge-${(b.status || 'active').toLowerCase()}">${escapeHtml(b.status)}</span></td>
                    <td>${actionBtn}</td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Failed to load firewall list: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function unblockIp(ip) {
    if (!confirm(`Are you sure you want to lift the block on IP ${ip}?`)) return;

    try {
        const res = await api('/api/firewall/unblock', 'POST', { ip });
        showToast(res.message || `IP ${ip} has been unblocked.`);
        await loadThreatResponseData();
        await loadDashboardStats(true);
    } catch (err) {
        showToast(`Failed to unblock ${ip}: ${err.message}`);
    }
}

async function loadThreatResponseHistory() {
    const tbody = document.getElementById('threat-responses-tbody');
    if (!tbody) return;

    const filterIp = (document.getElementById('filter-threat-ip')?.value || '').trim().toLowerCase();
    const filterStatus = document.getElementById('filter-threat-status')?.value || 'ALL';

    try {
        const params = new URLSearchParams();
        if (filterIp) params.set('targetIp', filterIp);
        if (filterStatus !== 'ALL') params.set('status', filterStatus);

        const url = `/api/threat-responses${params.toString() ? '?' + params.toString() : ''}`;
        const responses = await api(url);

        if (!responses || responses.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No automated threat responses on record.</td></tr>';
            return;
        }

        tbody.innerHTML = responses.map(tr => {
            const statusClass = (tr.status || '').toLowerCase().replace(/_/g, '-');
            return `
                <tr>
                    <td><strong>#${tr.id}</strong></td>
                    <td>${tr.incidentId ? `<a href="#investigation" onclick="launchInvestigation(${tr.incidentId})">#${tr.incidentId}</a>` : '<span class="text-muted">—</span>'}</td>
                    <td><span class="badge badge-outline">${escapeHtml(tr.triggerType || 'IDS_ALERT')}</span></td>
                    <td><code>${escapeHtml(tr.actionType)}</code></td>
                    <td><code>${escapeHtml(tr.targetIp || 'N/A')}</code></td>
                    <td><span class="badge badge-${statusClass}">${escapeHtml(tr.status)}</span></td>
                    <td>${formatTimestamp(tr.executedAt || tr.timestamp)}</td>
                    <td>
                        <button class="btn btn-xs btn-outline" onclick="showThreatResponseDetails(${tr.id})">Details</button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger">Failed to load responses: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function showThreatResponseDetails(id) {
    const modal = document.getElementById('threat-details-modal');
    const modalBody = document.getElementById('threat-modal-body');
    const modalTitle = document.getElementById('threat-modal-title');
    if (!modal || !modalBody) return;

    try {
        const tr = await api(`/api/threat-responses/${id}`);
        if (!tr) throw new Error('Record not found');

        modalTitle.textContent = `Threat Response Action #${tr.id}`;
        modalBody.innerHTML = `
            <div class="threat-details-grid">
                <div><strong>Action ID:</strong> #${tr.id}</div>
                <div><strong>Linked Incident:</strong> ${tr.incidentId ? '#' + tr.incidentId : 'None'}</div>
                <div><strong>Trigger Source:</strong> ${escapeHtml(tr.triggerType || 'IDS_ALERT')}</div>
                <div><strong>Action Type:</strong> <code>${escapeHtml(tr.actionType)}</code></div>
                <div><strong>Target IP:</strong> <code>${escapeHtml(tr.targetIp || 'N/A')}</code></div>
                <div><strong>Status:</strong> <span class="badge badge-${(tr.status||'').toLowerCase()}">${escapeHtml(tr.status)}</span></div>
                <div><strong>Execution Timestamp:</strong> ${formatTimestamp(tr.executedAt || tr.timestamp)}</div>
                <div><strong>Failure/Skipped Reason:</strong> ${tr.failureReason ? `<span class="text-danger">${escapeHtml(tr.failureReason)}</span>` : '<span class="text-success">Executed Successfully / Verified</span>'}</div>
            </div>
            ${tr.executionDetails ? `
                <div style="margin-top: 15px;">
                    <strong>Raw Execution Payload:</strong>
                    <pre class="json-code-box"><code>${escapeHtml(typeof tr.executionDetails === 'object' ? JSON.stringify(tr.executionDetails, null, 2) : tr.executionDetails)}</code></pre>
                </div>
            ` : ''}
        `;
        modal.style.display = 'flex';
    } catch (err) {
        showToast(`Cannot view action details: ${err.message}`);
    }
}

// ==========================================
// 10. VIEW 4: INVESTIGATION & FORENSIC TRIAGE
// ==========================================
function initInvestigationEvents() {
    const selectIncident = document.getElementById('investigation-incident-select');
    const formAddNote = document.getElementById('form-add-investigation-note');
    const formAssign = document.getElementById('form-assign-investigator');
    const formRootCause = document.getElementById('form-root-cause');
    const formResolve = document.getElementById('form-resolve-incident');
    const btnCloseCase = document.getElementById('btn-close-case');

    // Presets for JSON evidence
    const btnPresetLogin = document.getElementById('btn-preset-login');
    const btnPresetIp = document.getElementById('btn-preset-ip');
    const btnPresetAlert = document.getElementById('btn-preset-alert');
    const evidenceText = document.getElementById('inv-evidence-data');

    if (btnPresetLogin && evidenceText) {
        btnPresetLogin.addEventListener('click', () => {
            evidenceText.value = JSON.stringify({
                event_type: "FAILED_AUTH_SERIES",
                source_ip: "198.51.100.42",
                target_user: "admin",
                consecutive_failures: 5,
                protocol: "HTTP/1.1",
                user_agent: "Hydra/v9.3",
                attack_signature: "T1110.001 - Brute Force"
            }, null, 2);
        });
    }

    if (btnPresetIp && evidenceText) {
        btnPresetIp.addEventListener('click', () => {
            evidenceText.value = JSON.stringify({
                threat_feed: "AbuseIPDB",
                confidence_score: 98,
                country_code: "RO",
                asn: "AS9009",
                domain: "badactor-c2.net",
                prior_reports: 1420
            }, null, 2);
        });
    }

    if (btnPresetAlert && evidenceText) {
        btnPresetAlert.addEventListener('click', () => {
            evidenceText.value = JSON.stringify({
                ids_rule: "IDS-AUTH-BRUTE-001",
                threshold_breached: "5 failures within 120s",
                action_dispatched: "APPLICATION_IP_BLOCK",
                cooldown_applied: true,
                containment_latency_ms: 14
            }, null, 2);
        });
    }

    if (selectIncident) {
        selectIncident.addEventListener('change', (e) => {
            const val = e.target.value;
            if (val) {
                loadInvestigationCase(parseInt(val, 10));
            } else {
                state.selectedIncidentId = null;
                showInvestigationEmptyState();
            }
        });
    }

    if (formAddNote) {
        formAddNote.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!state.selectedIncidentId) return;

            const narrative = document.getElementById('inv-note-narrative').value.trim();
            const rawEvidence = document.getElementById('inv-evidence-data').value.trim();

            if (!narrative) {
                showToast('Please enter an investigation note narrative.');
                return;
            }

            // Validate JSON if provided
            if (rawEvidence) {
                try {
                    JSON.parse(rawEvidence);
                } catch (parseErr) {
                    showToast('Invalid JSON structure in structured evidence box. Fix syntax before submitting.');
                    return;
                }
            }

            try {
                await api(`/api/incidents/${state.selectedIncidentId}/investigations`, 'POST', {
                    notes: narrative,
                    evidenceData: rawEvidence || null
                });

                showToast('Forensic investigation note successfully recorded.');
                formAddNote.reset();
                await refreshInvestigationCase(state.selectedIncidentId, false);
            } catch (err) {
                showToast(`Failed to record note: ${err.message}`);
            }
        });
    }

    if (formAssign) {
        formAssign.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!state.selectedIncidentId) return;

            const analyst = document.getElementById('assign-investigator-select').value;
            if (!analyst) {
                showToast('Select an investigator to assign.');
                return;
            }

            try {
                await api(`/api/incidents/${state.selectedIncidentId}/assign`, 'POST', {
                    assignedAnalyst: analyst
                });
                showToast(`Incident #${state.selectedIncidentId} assigned to ${analyst}.`);
                await refreshInvestigationCase(state.selectedIncidentId, false);
            } catch (err) {
                showToast(`Assignment failed: ${err.message}`);
            }
        });
    }

    if (formRootCause) {
        formRootCause.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!state.selectedIncidentId) return;

            const category = document.getElementById('root-cause-category').value;
            const explanation = document.getElementById('root-cause-explanation').value.trim();

            if (!explanation) {
                showToast('Provide an explanation for the root cause determination.');
                return;
            }

            try {
                await api(`/api/incidents/${state.selectedIncidentId}/root-cause`, 'POST', {
                    category,
                    explanation
                });
                showToast('Root cause determination saved and status moved to INVESTIGATING.');
                await refreshInvestigationCase(state.selectedIncidentId, false);
            } catch (err) {
                showToast(`Failed to save root cause: ${err.message}`);
            }
        });
    }

    if (formResolve) {
        formResolve.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!state.selectedIncidentId) return;

            const summary = document.getElementById('resolve-summary-text').value.trim();
            if (!summary) {
                showToast('Provide a resolution summary before marking the incident resolved.');
                return;
            }

            try {
                await api(`/api/incidents/${state.selectedIncidentId}/resolve`, 'POST', {
                    resolutionSummary: summary
                });
                showToast(`Incident #${state.selectedIncidentId} has been marked RESOLVED.`);
                await refreshInvestigationCase(state.selectedIncidentId, false);
                await loadDashboardStats(true);
            } catch (err) {
                showToast(`Resolution failed: ${err.message}`);
            }
        });
    }

    if (btnCloseCase) {
        btnCloseCase.addEventListener('click', async () => {
            if (!state.selectedIncidentId) return;
            if (!confirm(`Are you sure you want to mark Incident #${state.selectedIncidentId} as CLOSED?`)) return;

            try {
                await api(`/api/incidents/${state.selectedIncidentId}`, 'PUT', {
                    status: 'CLOSED'
                });
                showToast(`Incident #${state.selectedIncidentId} is now CLOSED.`);
                await refreshInvestigationCase(state.selectedIncidentId, false);
                await loadDashboardStats(true);
            } catch (err) {
                showToast(`Close failed: ${err.message}`);
            }
        });
    }
}

async function loadInvestigationIncidentsList() {
    const select = document.getElementById('investigation-incident-select');
    if (!select) return;

    try {
        const incidents = await api('/api/incidents');
        state.cachedIncidents = incidents || [];

        const currentVal = select.value;
        select.innerHTML = '<option value="">-- Choose an Incident to Triage --</option>';

        incidents.forEach(inc => {
            const opt = document.createElement('option');
            opt.value = inc.id;
            opt.textContent = `#${inc.id} - [${inc.severity}] ${inc.title} (${inc.status})`;
            select.appendChild(opt);
        });

        if (state.selectedIncidentId && incidents.some(i => i.id === state.selectedIncidentId)) {
            select.value = state.selectedIncidentId;
            await loadInvestigationCase(state.selectedIncidentId);
        } else if (currentVal && incidents.some(i => i.id == currentVal)) {
            select.value = currentVal;
            await loadInvestigationCase(parseInt(currentVal, 10));
        } else {
            showInvestigationEmptyState();
        }

        // Also fetch investigators list for assignment dropdown
        await loadInvestigatorsDropdown();
    } catch (err) {
        console.error('Failed to load incidents list in investigation:', err);
    }
}

async function loadInvestigatorsDropdown() {
    const select = document.getElementById('assign-investigator-select');
    if (!select) return;

    try {
        const investigators = await api('/api/investigators');
        state.cachedInvestigators = investigators || [];

        const cur = select.value;
        select.innerHTML = '<option value="">-- Select Investigator --</option>';
        investigators.forEach(u => {
            const opt = document.createElement('option');
            opt.value = u.username;
            opt.textContent = `${u.fullName || u.username} (${u.role})`;
            select.appendChild(opt);
        });
        if (cur) select.value = cur;
    } catch (err) {
        console.warn('Investigators list retrieval restricted or failed:', err.message);
    }
}

function showInvestigationEmptyState() {
    const emptyState = document.getElementById('investigation-empty-state');
    const dossier = document.getElementById('investigation-case-dossier');
    const workspace = document.getElementById('investigation-workspace');

    if (emptyState) emptyState.style.display = 'block';
    if (dossier) dossier.style.display = 'none';
    if (workspace) workspace.style.display = 'none';
}

async function loadInvestigationCase(incidentId) {
    state.selectedIncidentId = incidentId;
    const select = document.getElementById('investigation-incident-select');
    if (select && select.value != incidentId) {
        select.value = incidentId;
    }

    const emptyState = document.getElementById('investigation-empty-state');
    const dossier = document.getElementById('investigation-case-dossier');
    const workspace = document.getElementById('investigation-workspace');

    if (emptyState) emptyState.style.display = 'none';
    if (dossier) dossier.style.display = 'block';
    if (workspace) workspace.style.display = 'grid';

    await refreshInvestigationCase(incidentId, false);
}

async function refreshInvestigationCase(incidentId, isBackground = false) {
    try {
        const [summary, notes, timeline] = await Promise.all([
            api(`/api/incidents/${incidentId}/investigation-summary`),
            api(`/api/incidents/${incidentId}/investigations`),
            api(`/api/incidents/${incidentId}/timeline`)
        ]);

        renderInvestigationDossier(summary);
        renderInvestigationNotes(notes);
        renderInvestigationTimeline(timeline);
    } catch (err) {
        if (!isBackground) {
            showToast(`Could not load investigation case #${incidentId}: ${err.message}`);
        }
    }
}

function renderInvestigationDossier(s) {
    if (!s) return;
    const setSafe = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val !== undefined && val !== null ? val : 'N/A';
    };

    setSafe('dossier-id-badge', `#${s.incidentId || s.id}`);
    setSafe('dossier-title', s.title || 'Untitled Case');
    setSafe('dossier-desc', s.description || 'No description provided.');

    const sevBadge = document.getElementById('dossier-severity-badge');
    if (sevBadge) {
        const sev = s.severity || 'LOW';
        sevBadge.textContent = sev;
        sevBadge.className = `badge badge-sev-${sev.toLowerCase()}`;
    }

    const statBadge = document.getElementById('dossier-status-badge');
    if (statBadge) {
        const stat = s.status || 'OPEN';
        statBadge.textContent = stat;
        statBadge.className = `badge badge-status-${stat.toLowerCase()}`;
    }

    setSafe('dossier-author', s.createdBy || 'system');
    setSafe('dossier-created', formatTimestamp(s.createdAt));
    setSafe('dossier-assigned', s.assignedAnalyst || 'Unassigned');
    setSafe('dossier-root-cause', s.rootCauseCategory ? `${s.rootCauseCategory}: ${s.rootCauseExplanation || ''}` : 'Pending Analysis');
    setSafe('dossier-total-notes', s.totalNotes || (s.investigationNotes ? s.investigationNotes.length : 0));
    setSafe('dossier-total-responses', s.totalResponses || (s.threatResponses ? s.threatResponses.length : 0));

    // Update assignment select value if present
    const assignSelect = document.getElementById('assign-investigator-select');
    if (assignSelect && s.assignedAnalyst) {
        assignSelect.value = s.assignedAnalyst;
    }

    // Update root cause values if set
    if (s.rootCauseCategory) {
        const rcCat = document.getElementById('root-cause-category');
        const rcExp = document.getElementById('root-cause-explanation');
        if (rcCat) rcCat.value = s.rootCauseCategory;
        if (rcExp && !rcExp.value) rcExp.value = s.rootCauseExplanation || '';
    }

    // Resolution box
    const resBox = document.getElementById('dossier-resolution-box');
    const resText = document.getElementById('dossier-resolution-text');
    if (resBox && resText) {
        if (s.resolutionSummary) {
            resBox.style.display = 'block';
            resText.textContent = s.resolutionSummary;
        } else {
            resBox.style.display = 'none';
        }
    }
}

function renderInvestigationNotes(notes) {
    const list = document.getElementById('investigation-notes-list');
    const badge = document.getElementById('notes-count-badge');
    if (!list) return;

    if (badge) {
        badge.textContent = `${notes ? notes.length : 0} Notes`;
    }

    if (!notes || notes.length === 0) {
        list.innerHTML = '<div class="text-muted text-center" style="padding: 20px;">No forensic investigation notes recorded yet.</div>';
        return;
    }

    list.innerHTML = notes.map(n => {
        let evidenceBlock = '';
        if (n.evidenceData) {
            let prettyJson = n.evidenceData;
            try {
                const parsed = JSON.parse(n.evidenceData);
                prettyJson = JSON.stringify(parsed, null, 2);
            } catch (e) {
                // Keep raw string
            }
            evidenceBlock = `
                <div class="note-evidence-wrapper">
                    <span class="evidence-tag">Forensic Artifact / Evidence:</span>
                    <pre class="json-code-box"><code>${escapeHtml(prettyJson)}</code></pre>
                </div>
            `;
        }

        return `
            <div class="investigation-note-card">
                <div class="note-header">
                    <span class="note-author">🔬 <strong>${escapeHtml(n.analystUsername || n.analyst || 'Analyst')}</strong></span>
                    <span class="note-time">${formatTimestamp(n.timestamp || n.createdAt)}</span>
                </div>
                <div class="note-narrative">${escapeHtml(n.notes || n.narrative)}</div>
                ${evidenceBlock}
            </div>
        `;
    }).join('');
}

function renderInvestigationTimeline(timeline) {
    const container = document.getElementById('investigation-timeline-container');
    if (!container) return;

    if (!timeline || timeline.length === 0) {
        container.innerHTML = '<div class="text-muted text-center" style="padding: 15px;">No timeline milestones recorded for this case.</div>';
        return;
    }

    container.innerHTML = timeline.map(item => {
        const typeClass = (item.type || 'info').toLowerCase().replace(/_/g, '-');
        return `
            <div class="timeline-entry timeline-${typeClass}">
                <div class="timeline-marker"></div>
                <div class="timeline-content">
                    <div class="timeline-header">
                        <span class="timeline-title"><strong>${escapeHtml(item.title || item.type)}</strong></span>
                        <span class="timeline-time">${formatTimestamp(item.timestamp)}</span>
                    </div>
                    <div class="timeline-desc">${escapeHtml(item.description || item.details || '')}</div>
                    ${item.metadata ? `<pre class="timeline-meta"><code>${escapeHtml(typeof item.metadata === 'object' ? JSON.stringify(item.metadata, null, 2) : item.metadata)}</code></pre>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

// ==========================================
// 11. VIEW 5: ACCOUNT SECURITY CENTER
// ==========================================
function initAccountSecurityEvents() {
    // Handlers already registered via navigation
}

async function loadAccountSecurityData() {
    const tbody = document.getElementById('account-security-tbody');
    if (!tbody) return;

    try {
        const lockedAccounts = await api('/api/auth/locked-accounts');
        const statTotal = document.getElementById('stat-acc-total');
        const statLocked = document.getElementById('stat-acc-locked');

        if (statLocked) {
            statLocked.textContent = lockedAccounts ? lockedAccounts.length : '0';
        }

        if (!lockedAccounts || lockedAccounts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No user accounts are currently locked. System is secure.</td></tr>';
            return;
        }

        const isAdmin = state.currentUser && state.currentUser.role === 'ADMIN';

        tbody.innerHTML = lockedAccounts.map(acc => {
            const now = Date.now();
            const lockExpiry = acc.lockedUntil ? (acc.lockedUntil > 1000000000000 ? acc.lockedUntil : acc.lockedUntil * 1000) : 0;
            const remainingMs = lockExpiry - now;
            let statusText = 'LOCKED';
            let remainingText = 'Permanent';

            if (remainingMs > 0) {
                const remainingSecs = Math.ceil(remainingMs / 1000);
                const mins = Math.floor(remainingSecs / 60);
                const secs = remainingSecs % 60;
                remainingText = `${mins}m ${secs}s`;
            } else if (lockExpiry > 0) {
                statusText = 'EXPIRED';
                remainingText = 'Lock expired (awaiting next login reset)';
            }

            const actionBtn = isAdmin
                ? `<button class="btn btn-xs btn-primary" onclick="unlockUserAccount('${escapeHtml(acc.username)}')">🔓 Unlock Account</button>`
                : `<span class="text-muted">—</span>`;

            return `
                <tr>
                    <td><strong>👤 ${escapeHtml(acc.username)}</strong></td>
                    <td><span class="badge badge-danger">${acc.failedAttempts || 5}</span></td>
                    <td>${acc.lockedAt ? formatTimestamp(acc.lockedAt) : 'Recent'}</td>
                    <td>${acc.lockedUntil ? formatTimestamp(acc.lockedUntil) : 'Indefinite'}</td>
                    <td><span class="badge badge-locked">${statusText} (${remainingText})</span></td>
                    <td>${actionBtn}</td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Failed to load locked accounts: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function unlockUserAccount(username) {
    if (!confirm(`Are you sure you want to unlock account '${username}' and reset its failed attempt counter?`)) return;

    try {
        const res = await api('/api/auth/unlock', 'POST', { username });
        showToast(res.message || `Account '${username}' unlocked successfully.`);
        await loadAccountSecurityData();
        await loadDashboardStats(true);
    } catch (err) {
        showToast(`Unlock failed: ${err.message}`);
    }
}

// ==========================================
// 12. VIEW 6: ACCESS MONITORING & IDS SIMULATION
// ==========================================
function initAccessMonitoring() {
    const btnSimulate = document.getElementById('btn-simulate-threat');
    const btnBruteForce = document.getElementById('btn-simulate-brute-force');

    if (btnSimulate) {
        btnSimulate.addEventListener('click', async () => {
            try {
                await api('/api/access-events', 'POST', {
                    username: 'intruder',
                    sourceIp: '203.0.113.88',
                    status: 'FAILURE',
                    action: 'UNAUTHORIZED_PROBE'
                });
                showToast('Threat event dispatched to IDS engine.');
                await loadAccessEvents();
                await loadDashboardStats(true);
            } catch (err) {
                showToast(`Simulation error: ${err.message}`);
            }
        });
    }

    if (btnBruteForce) {
        btnBruteForce.addEventListener('click', async () => {
            showToast('Simulating rapid brute-force attack (5 failed attempts)...');
            const targetIp = '198.51.100.99';
            try {
                for (let i = 1; i <= 5; i++) {
                    await api('/api/auth/login', 'POST', {
                        username: 'admin',
                        password: `wrong_pass_${i}`
                    }).catch(() => {});
                }
                showToast('Brute-force burst completed. Check Security Alerts & Threat Response.');
                await loadDashboardStats(true);
                await loadAccessEvents();
            } catch (err) {
                console.error('Simulation error:', err);
            }
        });
    }
}

async function loadAccessEvents() {
    const tbody = document.getElementById('access-events-body');
    if (!tbody) return;

    try {
        const events = await api('/api/access-events');
        if (!events || events.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No access log entries recorded.</td></tr>';
            return;
        }

        tbody.innerHTML = events.slice(0, 50).map(evt => `
            <tr>
                <td>${formatTimestamp(evt.timestamp)}</td>
                <td><code>${escapeHtml(evt.sourceIp || '127.0.0.1')}</code></td>
                <td>👤 ${escapeHtml(evt.username || 'unknown')}</td>
                <td><span class="badge badge-${(evt.status || 'success').toLowerCase()}">${escapeHtml(evt.status)}</span></td>
                <td>${escapeHtml(evt.action || 'LOGIN_ATTEMPT')}</td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger">Failed to load access events: ${escapeHtml(err.message)}</td></tr>`;
    }
}

// ==========================================
// 13. VIEW 7: ACTIVITY HISTORY
// ==========================================
function initActivityEvents() {
    // Handlers registered via navigation
}

async function loadActivityHistory() {
    const tbody = document.getElementById('activity-table-body');
    if (!tbody) return;

    try {
        const activities = await api('/api/activity');
        if (!activities || activities.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No activity records on file.</td></tr>';
            return;
        }

        tbody.innerHTML = activities.map(act => `
            <tr>
                <td><strong>#${act.id}</strong></td>
                <td>${formatTimestamp(act.timestamp)}</td>
                <td>👤 <strong>${escapeHtml(act.username || 'system')}</strong></td>
                <td><span class="badge badge-outline">${escapeHtml(act.action)}</span></td>
                <td>${escapeHtml(act.details || '')}</td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger">Failed to load activity logs: ${escapeHtml(err.message)}</td></tr>`;
    }
}

// ==========================================
// 14. UTILITY & FORMATTING HELPERS
// ==========================================
function formatTimestamp(ts) {
    if (!ts) return 'N/A';
    try {
        const numeric = typeof ts === 'number' ? (ts > 1000000000000 ? ts : ts * 1000) : Date.parse(ts);
        if (isNaN(numeric)) return String(ts);
        const d = new Date(numeric);
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch (e) {
        return String(ts);
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function showToast(message) {
    const toast = document.getElementById('toast');
    if (!toast) return;

    toast.textContent = message;
    toast.className = 'toast show';
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => {
        toast.className = 'toast';
    }, 4000);
}
