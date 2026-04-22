// app.js — UI logic for MedVault dashboard

let currentUser = null;
let doctorConsentTab = 'request';
let recordsTab = 'browse';

// ── Loading spinner ────────────────────────────────────
function setLoading(elId, loading, text = '') {
  const el = document.getElementById(elId);
  if (!el) return;
  if (loading) {
    el.innerHTML = `<div style="display:flex;align-items:center;gap:0.6rem;color:#94a3b8;padding:1rem 0">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 0.8s linear infinite">
        <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
      </svg>
      <span>${text || 'Loading…'}</span>
    </div>`;
  }
}

// Inject spinner CSS once
(function() {
  const s = document.createElement('style');
  s.textContent = '@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}';
  document.head.appendChild(s);
})();

function showAlert(elId, type, msg) {
  const el = document.getElementById(elId);
  if (!el) return;
  el.className = `alert ${type}`;
  el.textContent = msg;
  el.classList.remove('hidden');
}

function displayName(user) {
  if (!user) return '';
  return user.full_name ? `${user.full_name} (${user.email})` : user.email;
}

function formatUserLabel(name, email, fallback) {
  if (name && email) return `${name} (${email})`;
  return email || fallback || 'Unknown user';
}

// ── Login ──────────────────────────────────────────────
async function login() {
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;
  const el = document.getElementById('login-response');
  const btn = document.querySelector('#login-screen .btn-primary');
  el.classList.remove('hidden', 'error', 'success');

  if (!email || !password) {
    el.className = 'alert error'; el.textContent = 'Enter your email and password'; el.classList.remove('hidden'); return;
  }

  btn.disabled = true;
  btn.textContent = 'Signing in…';

  try {
    const res = await api.login(email, password);
    if (!res.ok) throw new Error(res.data.detail || `Error ${res.status}`);

    // MFA required — show TOTP input
    if (res.data.partial_token) {
      btn.disabled = false;
      btn.textContent = 'Sign In';
      el.classList.add('success');
      el.innerHTML = `
        MFA required. Enter your 6-digit code:<br/>
        <input type="text" id="mfa-login-code" placeholder="123456" maxlength="6" style="margin-top:0.5rem;letter-spacing:0.2em;text-align:center" />
        <button class="btn btn-primary btn-sm" style="margin-top:0.5rem;width:100%" onclick="verifyMFALogin('${res.data.partial_token}')">Verify</button>
      `;
      return;
    }

    localStorage.setItem('access_token', res.data.access_token);
    localStorage.setItem('refresh_token', res.data.refresh_token);
    el.classList.add('success');
    el.textContent = 'Login successful!';
    setTimeout(initApp, 400);
  } catch (e) {
    el.classList.add('error');
    el.textContent = e.message;
    btn.disabled = false;
    btn.textContent = 'Sign In';
  }
}

async function verifyMFALogin(partialToken) {
  const code = document.getElementById('mfa-login-code').value;
  const el = document.getElementById('login-response');
  if (!code || code.length !== 6) { alert('Enter a 6-digit code'); return; }

  try {
    const res = await api.mfaVerify(partialToken, code);
    if (!res.ok) throw new Error(res.data.detail || 'Invalid code');
    localStorage.setItem('access_token', res.data.access_token);
    localStorage.setItem('refresh_token', res.data.refresh_token);
    el.classList.remove('error'); el.classList.add('success');
    el.textContent = 'MFA verified! Loading dashboard...';
    setTimeout(initApp, 400);
  } catch (e) {
    el.classList.remove('success'); el.classList.add('error');
    el.textContent = e.message;
  }
}

// ── Init App ───────────────────────────────────────────
async function initApp() {
  const token = localStorage.getItem('access_token');
  if (!token) return;

  try {
    const res = await api.getMe();
    if (!res.ok) { logout(); return; }
    currentUser = res.data;
  } catch { logout(); return; }

  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');

  // Sidebar user info
  document.getElementById('user-info-sidebar').innerHTML =
    `<span class="user-name">${currentUser.full_name || currentUser.email}</span>` +
    `<span class="user-email">${currentUser.email}</span>` +
    `<span class="role-badge role-${currentUser.role}">${currentUser.role}</span>`;

  // Top bar badge
  document.getElementById('user-badge').innerHTML =
    `<span class="user-name-inline">${currentUser.full_name || currentUser.email}</span>` +
    `<span class="role-badge role-${currentUser.role}">${currentUser.role}</span>` +
    `<span>${currentUser.email}</span>`;

  buildNav();
  showSection('profile');
  checkForcedPasswordChange();
}

// ── Navigation ─────────────────────────────────────────
const NAV_ICONS = {
  profile: '👤', consent: '🤝', 'request-consent': '📋',
  records: '📁', attachments: '📎', admin: '⚙️', audit: '🔍', security: '🔒',
  frontdesk: '🏥'
};

function buildNav() {
  const nav = document.getElementById('main-nav');
  const tabs = [{ id: 'profile', label: 'Profile' }];
  const role = currentUser.role;

  // Patient
  if (role === 'Patient') {
    tabs.push({ id: 'consent', label: 'Consent Grants' });
    tabs.push({ id: 'records', label: 'My Records' });
  }

  // Doctor
  if (role === 'Doctor') {
    tabs.push({ id: 'request-consent', label: 'Request Access' });
    tabs.push({ id: 'records', label: 'Medical Records' });
    tabs.push({ id: 'attachments', label: 'Attachments' });
  }

  // Nurse
  if (role === 'Nurse') {
    tabs.push({ id: 'records', label: 'Patient Records' });
  }

  // Lab Technician — attachments only (no timeline, no new record)
  if (role === 'Lab_Technician') {
    tabs.push({ id: 'attachments', label: 'Lab Results' });
  }

  // Front Desk
  if (role === 'Front_Desk') {
    tabs.push({ id: 'frontdesk', label: 'Register Patient' });
    tabs.push({ id: 'records', label: 'Patient Directory' });
  }

  // Emergency Contact
  if (role === 'Emergency_Contact') {
    tabs.push({ id: 'consent', label: 'Consent Grants' });
    tabs.push({ id: 'records', label: 'Patient Summary' });
  }

  // Admin roles
  if (role === 'Admin' || role === 'SuperAdmin') {
    tabs.push({ id: 'admin', label: 'User Management' });
  }

  // Everyone gets their activity log (admins see full audit)
  tabs.push({ id: 'audit', label: role === 'Admin' || role === 'SuperAdmin' ? 'Audit Log' : 'My Activity' });

  tabs.push({ id: 'security', label: 'Security' });

  nav.innerHTML = tabs.map(t =>
    `<a href="#" onclick="showSection('${t.id}');return false" id="nav-${t.id}">${NAV_ICONS[t.id] || '•'} ${t.label}</a>`
  ).join('');
}

function showSection(id) {
  closeSidebarOnMobile();
  document.querySelectorAll('.section').forEach(el => el.classList.add('hidden'));
  const sec = document.getElementById('section-' + id);
  if (sec) sec.classList.remove('hidden');
  document.querySelectorAll('#main-nav a').forEach(a => a.classList.remove('active'));
  const link = document.getElementById('nav-' + id);
  if (link) link.classList.add('active');

  const titles = {
    profile: 'My Profile', consent: 'Consent Grants', 'request-consent': 'Request Patient Access',
    records: 'Medical Records', attachments: 'File Attachments', admin: 'User Management',
    audit: currentUser.role === 'Admin' || currentUser.role === 'SuperAdmin' ? 'Audit Log' : 'My Activity',
    security: 'Security Settings', frontdesk: 'Register New Patient'
  };
  document.getElementById('page-title').textContent = titles[id] || 'Dashboard';

  // Auto-load data
  if (id === 'profile') loadProfile();
  if (id === 'consent') loadGrants();
  if (id === 'admin') loadAdminUsers();
  if (id === 'request-consent') showDoctorConsentTab(doctorConsentTab);
  if (id === 'audit') {
    const verifyBtn = document.getElementById('verify-chain-btn');
    const title = document.getElementById('audit-title');
    if (currentUser.role === 'Patient') {
      title.textContent = 'Who Accessed My Data';
    } else if (currentUser.role === 'Admin' || currentUser.role === 'SuperAdmin') {
      title.textContent = 'Audit Log';
    } else {
      title.textContent = 'My Activity';
    }
    // Show verify button for everyone — patients verify their own entries, admins verify full chain
    if (verifyBtn) verifyBtn.style.display = '';
    loadAudit();
  }
  if (id === 'attachments') {
    if (currentUser.role === 'Lab_Technician') {
      showLabTechView();
    }
  }
  if (id === 'records') {
    const tabs = document.getElementById('records-tabs');
    const createCard = document.getElementById('create-record-card');
    const searchArea = document.getElementById('patient-search-area');
    const role = currentUser.role;

    if (role === 'Patient') {
      if (tabs) tabs.classList.add('hidden');
      if (createCard) createCard.style.display = 'none';
      if (searchArea) searchArea.style.display = 'none';
      document.getElementById('selected-patient-id').value = currentUser.id;
      showRecordsTab('browse');
      loadRecords();
    } else if (role === 'Nurse') {
      if (tabs) tabs.classList.remove('hidden');
      if (createCard) createCard.style.display = '';
      if (searchArea) searchArea.style.display = '';
      // Nurse: vitals, medication_log, triage only
      const typeSelect = document.getElementById('record-type');
      if (typeSelect) typeSelect.innerHTML =
        '<option value="vitals">Vitals</option>' +
        '<option value="medication_log">Medication Log</option>' +
        '<option value="triage">Triage</option>';
      // Nurse always saves as draft (no publish option)
      const statusSel = document.getElementById('record-status-select');
      if (statusSel) statusSel.closest('.form-group').style.display = 'none';
      const accessTabBtn = document.getElementById('records-tab-access');
      if (accessTabBtn) accessTabBtn.style.display = 'none';
      updateRecordForm();
      showRecordsTab(recordsTab);
    } else if (role === 'Front_Desk') {
      if (tabs) tabs.classList.add('hidden');
      if (createCard) createCard.style.display = 'none';
      if (searchArea) searchArea.style.display = '';
      showRecordsTab('browse');
    } else if (role === 'Emergency_Contact') {
      if (tabs) tabs.classList.add('hidden');
      if (createCard) createCard.style.display = 'none';
      if (searchArea) searchArea.style.display = 'none';
      showRecordsTab('browse');
    } else {
      // Doctor
      if (tabs) tabs.classList.remove('hidden');
      if (createCard) createCard.style.display = '';
      if (searchArea) searchArea.style.display = '';
      const accessTabBtn = document.getElementById('records-tab-access');
      if (accessTabBtn) accessTabBtn.style.display = '';
      // Restore all record types for doctor
      const typeSelect = document.getElementById('record-type');
      if (typeSelect && typeSelect.options.length < 4) {
        typeSelect.innerHTML =
          '<option value="diagnosis">Diagnosis</option>' +
          '<option value="prescription">Prescription</option>' +
          '<option value="lab_result">Lab Result</option>' +
          '<option value="vitals">Vitals</option>';
      }
      const statusSel = document.getElementById('record-status-select');
      if (statusSel) statusSel.closest('.form-group').style.display = '';
      updateRecordForm();
      showRecordsTab(recordsTab);
    }
  }
  if (id === 'security') loadMFAStatus();
}

function toggleSidebar() {
  const app = document.getElementById('app');
  const backdrop = document.getElementById('sidebar-backdrop');
  const isOpen = app.classList.toggle('sidebar-open');
  if (backdrop) backdrop.style.display = isOpen ? 'block' : 'none';
}

function closeSidebarOnMobile() {
  if (window.innerWidth <= 900) {
    document.getElementById('app').classList.remove('sidebar-open');
    const backdrop = document.getElementById('sidebar-backdrop');
    if (backdrop) backdrop.style.display = 'none';
  }
}

function showRecordsTab(tab) {
  recordsTab = tab;
  const browse = document.getElementById('records-pane-browse');
  const create = document.getElementById('records-pane-create');
  const access = document.getElementById('records-pane-access');
  const browseBtn = document.getElementById('records-tab-browse');
  const createBtn = document.getElementById('records-tab-create');
  const accessBtn = document.getElementById('records-tab-access');

  if (browse) browse.classList.toggle('hidden', tab !== 'browse');
  if (create) create.classList.toggle('hidden', tab !== 'create');
  if (access) access.classList.toggle('hidden', tab !== 'access');
  if (browseBtn) browseBtn.classList.toggle('active', tab === 'browse');
  if (createBtn) createBtn.classList.toggle('active', tab === 'create');
  if (accessBtn) accessBtn.classList.toggle('active', tab === 'access');

  if (tab === 'access') loadDoctorAccessGrants();
}

// ── Logout ─────────────────────────────────────────────
function logout() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  currentUser = null;
  document.getElementById('app').classList.add('hidden');
  document.getElementById('login-screen').classList.remove('hidden');
  document.getElementById('login-response').classList.add('hidden');
}

// ── Profile ────────────────────────────────────────────
let profileEditOpen = false;
let demographicsEditOpen = false;

function toggleProfileEdit() {
  profileEditOpen = !profileEditOpen;
  document.getElementById('profile-edit-form').classList.toggle('hidden', !profileEditOpen);
}

function toggleDemographicsEdit() {
  demographicsEditOpen = !demographicsEditOpen;
  document.getElementById('demographics-edit-form').classList.toggle('hidden', !demographicsEditOpen);
}

async function loadProfile() {
  const el = document.getElementById('profile-data');
  setLoading('profile-data', true, 'Loading profile…');
  const res = await api.getMe();
  if (!res.ok) { el.textContent = 'Failed to load profile'; return; }
  const u = res.data;

  // Pre-fill edit form
  document.getElementById('edit-full-name').value = u.full_name || '';
  document.getElementById('edit-email').value = u.email || '';
  document.getElementById('recovery-email-input').value = u.recovery_email || '';

  el.innerHTML = `
    <div class="profile-grid">
      <div class="profile-item"><label>Full Name</label><div class="value">${u.full_name || '<span style="color:#94a3b8">Not set</span>'}</div></div>
      <div class="profile-item"><label>Email</label><div class="value">${u.email}</div></div>
      <div class="profile-item"><label>Role</label><div class="value"><span class="role-badge role-${u.role}">${u.role.replace('_',' ')}</span></div></div>
      <div class="profile-item"><label>MFA</label><div class="value">${u.mfa_enabled ? '✅ Enabled' : '❌ Disabled'}</div></div>
      <div class="profile-item"><label>Recovery Email</label><div class="value">${u.recovery_email || '<span style="color:#94a3b8">Not set</span>'}</div></div>
      <div class="profile-item"><label>Account Since</label><div class="value">${new Date(u.created_at).toLocaleDateString()}</div></div>
    </div>`;

  // Load patient-specific sections
  if (currentUser.role === 'Patient') {
    document.getElementById('patient-demographics-card').classList.remove('hidden');
    document.getElementById('emergency-contacts-card').classList.remove('hidden');
    loadDemographics();
    loadEmergencyContacts();
  }
}

async function saveProfile() {
  const el = document.getElementById('profile-edit-response');
  el.classList.remove('hidden', 'error', 'success');
  const full_name = document.getElementById('edit-full-name').value.trim();
  const email = document.getElementById('edit-email').value.trim();
  const recovery_email = document.getElementById('recovery-email-input').value.trim();

  const res = await api.updateMe({ full_name, email });
  if (!res.ok) { el.classList.add('error'); el.textContent = res.data.detail || 'Failed to update'; return; }

  if (recovery_email) await api.setRecoveryEmail(recovery_email);

  el.classList.add('success');
  el.textContent = 'Profile updated!';
  // Update currentUser display
  currentUser.full_name = full_name || currentUser.full_name;
  document.getElementById('user-info-sidebar').innerHTML =
    `<span class="user-name">${currentUser.full_name || currentUser.email}</span>
     <span class="user-email">${currentUser.email}</span>`;
  loadProfile();
}

async function loadDemographics() {
  const el = document.getElementById('demographics-data');
  const res = await api.getMyProfile();
  if (!res.ok) { el.innerHTML = '<p class="text-muted">Could not load demographics.</p>'; return; }
  const p = res.data;

  // Pre-fill edit form
  if (p.date_of_birth) document.getElementById('demo-dob').value = p.date_of_birth;
  if (p.sex) document.getElementById('demo-sex').value = p.sex;
  if (p.nationality) document.getElementById('demo-nationality').value = p.nationality;
  if (p.phone_number) document.getElementById('demo-phone').value = p.phone_number;
  if (p.insurance_provider) document.getElementById('demo-insurance').value = p.insurance_provider;
  if (p.blood_type) document.getElementById('demo-blood').value = p.blood_type;
  if (p.known_allergies) document.getElementById('demo-allergies').value = p.known_allergies;
  if (p.known_conditions) document.getElementById('demo-conditions').value = p.known_conditions;
  if (p.dnr_status) document.getElementById('demo-dnr').checked = p.dnr_status;

  const none = '<span style="color:#94a3b8">Not set</span>';
  el.innerHTML = `<div class="demo-grid">
    <div class="demo-item sensitivity-medium"><label>Date of Birth</label><div class="value">${p.date_of_birth || none}</div></div>
    <div class="demo-item sensitivity-medium"><label>Sex</label><div class="value">${p.sex || none}</div></div>
    <div class="demo-item sensitivity-low"><label>Nationality</label><div class="value">${p.nationality || none}</div></div>
    <div class="demo-item sensitivity-medium"><label>Phone</label><div class="value">${p.phone_number || none}</div></div>
    <div class="demo-item sensitivity-medium"><label>Insurance</label><div class="value">${p.insurance_provider || none}</div></div>
    <div class="demo-item sensitivity-high"><label>Blood Type</label><div class="value">${p.blood_type || none}</div></div>
    <div class="demo-item sensitivity-high" style="grid-column:1/-1"><label>Known Allergies</label><div class="value">${p.known_allergies || none}</div></div>
    <div class="demo-item sensitivity-high" style="grid-column:1/-1"><label>Known Conditions</label><div class="value">${p.known_conditions || none}</div></div>
    <div class="demo-item sensitivity-high"><label>DNR Status</label><div class="value">${p.dnr_status ? '⚠️ DNR Active' : 'Not set'}</div></div>
  </div>`;
}

async function saveDemographics() {
  const el = document.getElementById('demographics-response');
  el.classList.remove('hidden', 'error', 'success');
  const data = {
    date_of_birth: document.getElementById('demo-dob').value || null,
    sex: document.getElementById('demo-sex').value || null,
    nationality: document.getElementById('demo-nationality').value || null,
    phone_number: document.getElementById('demo-phone').value || null,
    insurance_provider: document.getElementById('demo-insurance').value || null,
    blood_type: document.getElementById('demo-blood').value || null,
    known_allergies: document.getElementById('demo-allergies').value || null,
    known_conditions: document.getElementById('demo-conditions').value || null,
    dnr_status: document.getElementById('demo-dnr').checked,
  };
  const res = await api.updateMyProfile(data);
  if (res.ok) { el.classList.add('success'); el.textContent = 'Demographics saved!'; loadDemographics(); }
  else { el.classList.add('error'); el.textContent = res.data.detail || 'Failed'; }
}

async function loadEmergencyContacts() {
  const el = document.getElementById('emergency-contacts-list');
  const res = await api.listEmergencyContacts();
  if (!res.ok) { el.innerHTML = '<p class="text-muted">Could not load contacts.</p>'; return; }
  const contacts = res.data || [];
  if (!contacts.length) {
    el.innerHTML = '<p class="text-muted">No emergency contacts designated yet.</p>';
    return;
  }
  el.innerHTML = contacts.map(c => `
    <div class="grant-item">
      <div>
        <strong>${c.contact_name || 'Unknown'}</strong> — ${c.contact_email}<br/>
        <span class="text-muted">${c.relationship || 'Relationship not specified'}</span>
      </div>
      <button class="btn btn-danger btn-sm" onclick="removeEmergencyContact('${c.id}')">Remove</button>
    </div>`).join('');

  // Hide add form if at max
  document.getElementById('add-emergency-contact-form').style.display = contacts.length >= 2 ? 'none' : '';
}

async function addEmergencyContact() {
  const email = document.getElementById('ec-email').value.trim();
  const rel = document.getElementById('ec-relationship').value.trim();
  const el = document.getElementById('ec-response');
  el.classList.remove('hidden', 'error', 'success');
  if (!email) { el.classList.add('error'); el.textContent = 'Enter an email address'; return; }
  const res = await api.addEmergencyContact(email, rel || null);
  if (res.ok) {
    el.classList.add('success'); el.textContent = 'Emergency contact added!';
    document.getElementById('ec-email').value = '';
    document.getElementById('ec-relationship').value = '';
    loadEmergencyContacts();
  } else { el.classList.add('error'); el.textContent = res.data.detail || 'Failed'; }
}

async function removeEmergencyContact(linkId) {
  if (!confirm('Remove this emergency contact?')) return;
  const res = await api.removeEmergencyContact(linkId);
  if (res.ok) loadEmergencyContacts();
  else alert(res.data.detail || 'Failed');
}

// ── Consent (Patient) ──────────────────────────────────
async function loadGrants() {
  const el = document.getElementById('grants-list');
  setLoading('grants-list', true, 'Loading consent grants…');
  const res = await api.listGrants();
  if (!res.ok) { el.innerHTML = '<p class="text-muted">Failed to load grants.</p>'; return; }
  const grants = res.data;
  if (!grants || !grants.length) { el.innerHTML = '<p class="text-muted">No consent grants found.</p>'; return; }
  el.innerHTML = grants.map(g => {
    const duration = g.requested_duration_hours >= 24
      ? `${Math.round(g.requested_duration_hours / 24)} day(s)`
      : `${g.requested_duration_hours} hour(s)`;
    const doctorLabel = g.doctor_name ? `${g.doctor_name} (${g.doctor_email})` : g.doctor_email || g.doctor_id;
    return `
    <div class="grant-item">
      <div>
        <strong style="font-size:0.85rem">Doctor:</strong> ${doctorLabel}<br/>
        <span class="status-${g.status}">${g.status}</span> — ${duration}
        ${g.expires_at ? ` — expires ${new Date(g.expires_at).toLocaleString()}` : ''}
      </div>
      <div>
        ${g.status === 'pending' ? `<button class="btn btn-success btn-sm" onclick="approveGrant('${g.id}')">Approve</button><button class="btn btn-danger btn-sm" onclick="rejectGrant('${g.id}')">Reject</button>` : ''}
        ${g.status === 'active' ? `<button class="btn btn-danger btn-sm" onclick="revokeGrant('${g.id}')">Revoke</button>` : ''}
      </div>
    </div>
  `}).join('');
}

async function approveGrant(id) { const r = await api.approveGrant(id); if (r.ok) loadGrants(); else alert(r.data.detail || 'Failed'); }
async function rejectGrant(id) { const r = await api.rejectGrant(id); if (r.ok) loadGrants(); else alert(r.data.detail || 'Failed'); }
async function revokeGrant(id) { const r = await api.revokeGrant(id); if (r.ok) loadGrants(); else alert(r.data.detail || 'Failed'); }

function showDoctorConsentTab(tab) {
  doctorConsentTab = tab;
  document.getElementById('doctor-consent-pane-request').classList.toggle('hidden', tab !== 'request');
  document.getElementById('doctor-consent-pane-grants').classList.toggle('hidden', tab !== 'grants');
  document.getElementById('doctor-consent-tab-request').classList.toggle('active', tab === 'request');
  document.getElementById('doctor-consent-tab-grants').classList.toggle('active', tab === 'grants');
  if (tab === 'grants') loadDoctorGrants();
}

async function loadDoctorGrants() {
  const el = document.getElementById('doctor-grants-list');
  setLoading('doctor-grants-list', true, 'Loading requests…');
  const res = await api.listDoctorGrants();
  if (!res.ok) { el.innerHTML = '<p class="text-muted">Failed to load requests.</p>'; return; }
  const grants = res.data || [];
  if (!grants.length) {
    el.innerHTML = '<p class="text-muted">No access requests yet.</p>';
    return;
  }
  el.innerHTML = grants.map(g => {
    const patientLabel = formatUserLabel(g.patient_name, g.patient_email, g.patient_id);
    const duration = g.requested_duration_hours >= 24
      ? `${Math.round(g.requested_duration_hours / 24)} day(s)`
      : `${g.requested_duration_hours} hour(s)`;
    const expires = g.expires_at ? `Access until ${new Date(g.expires_at).toLocaleString()}` : 'Awaiting patient action';
    return `
      <div class="grant-item">
        <div>
          <strong style="font-size:0.85rem">Patient:</strong> ${patientLabel}<br/>
          <span class="status-${g.status}">${g.status}</span> - ${duration}<br/>
          <span class="text-muted">${expires}</span>
        </div>
        <div>
          ${g.status === 'active' ? `<button class="btn btn-danger btn-sm" onclick="releaseGrant('${g.id}')">Remove Access</button>` : ''}
        </div>
      </div>
    `;
  }).join('');
}

// ── Doctor Access Grants (in Records section) ─────────
async function loadDoctorAccessGrants() {
  const el = document.getElementById('doctor-access-grants-list');
  if (!el) return;
  setLoading('doctor-access-grants-list', true, 'Loading access grants…');
  const res = await api.listDoctorGrants();
  if (!res.ok) { el.innerHTML = '<p class="text-muted">Failed to load.</p>'; return; }
  const grants = (res.data || []).filter(g => g.status === 'active');
  if (!grants.length) {
    el.innerHTML = '<p class="text-muted">No active access grants. Request access from a patient first.</p>';
    return;
  }
  el.innerHTML = grants.map(g => {
    const patientLabel = formatUserLabel(g.patient_name, g.patient_email, g.patient_id);
    const expires = g.expires_at ? new Date(g.expires_at).toLocaleString() : '—';
    return `
      <div class="grant-item">
        <div>
          <strong style="font-size:0.9rem">${patientLabel}</strong><br/>
          <span class="text-muted" style="font-size:0.8rem">Access until: ${expires}</span>
        </div>
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap">
          <button class="btn btn-outline btn-sm" onclick="selectPatient('${g.patient_id}','${g.patient_email || ''}','${g.patient_name || ''}');showRecordsTab('browse')">View Records</button>
          <button class="btn btn-danger btn-sm" onclick="releaseGrant('${g.id}').then(()=>loadDoctorAccessGrants())">Revoke Access</button>
        </div>
      </div>`;
  }).join('');
}

// ── Request Consent (Doctor) ───────────────────────────
async function requestConsent() {
  const patient_email = document.getElementById('consent-patient-email').value;
  let duration = parseInt(document.getElementById('consent-duration').value);
  const unit = document.getElementById('consent-unit').value;
  if (unit === 'days') duration = duration * 24;
  const el = document.getElementById('consent-response');
  el.classList.remove('hidden', 'error', 'success');
  if (!patient_email) { showAlert('consent-response', 'error', 'Enter patient email'); return; }
  el.className = 'alert'; el.textContent = 'Sending request…'; el.classList.remove('hidden');
  const res = await api.requestConsent(patient_email, duration);
  if (res.ok) showAlert('consent-response', 'success', `Access request sent to ${patient_email}. They will be notified by email.`);
  else showAlert('consent-response', 'error', res.data.detail || 'Failed');
}

// ── Consent duration unit toggle ──────────────────────
function updateConsentDuration() {
  // No conversion needed — we just read the value and unit together in requestConsent()
  // This function exists to satisfy the onchange handler on the unit select
}
let searchTimeout = null;

async function searchPatients() {
  const q = document.getElementById('patient-search').value;
  const el = document.getElementById('patient-search-results');
  if (q.length < 3) { el.style.display = 'none'; return; }
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(async () => {
    const res = await api.searchPatients(q);
    if (!res.ok || !res.data.length) { el.style.display = 'none'; return; }
    el.style.display = 'block';
    el.innerHTML = res.data.map(u =>
      `<div style="padding:0.5rem 0.75rem;cursor:pointer;font-size:0.85rem;border-bottom:1px solid #f1f5f9"
            onmouseover="this.style.background='#f0f7ff'" onmouseout="this.style.background=''"
            onclick="selectPatient('${u.id}','${u.email}','${(u.full_name || '').replace(/'/g, "\\'")}')">${displayName(u)} <span class="role-badge role-${u.role}">${u.role}</span></div>`
    ).join('');
  }, 300);
}

function selectPatient(id, email, fullName = '') {
  document.getElementById('selected-patient-id').value = id;
  document.getElementById('patient-search').value = email;
  document.getElementById('selected-patient-info').textContent = fullName ? `Selected: ${fullName} (${email})` : `Selected: ${email} (${id})`;
  document.getElementById('patient-search-results').style.display = 'none';
}

async function searchPatientsForCreate() {
  const q = document.getElementById('create-patient-search').value;
  const el = document.getElementById('create-patient-results');
  if (q.length < 3) { el.style.display = 'none'; return; }
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(async () => {
    const res = await api.searchPatients(q);
    if (!res.ok || !res.data.length) { el.style.display = 'none'; return; }
    el.style.display = 'block';
    el.innerHTML = res.data.map(u =>
      `<div style="padding:0.5rem 0.75rem;cursor:pointer;font-size:0.85rem;border-bottom:1px solid #f1f5f9"
            onmouseover="this.style.background='#f0f7ff'" onmouseout="this.style.background=''"
            onclick="selectPatientForCreate('${u.id}','${u.email}','${(u.full_name || '').replace(/'/g, "\\'")}')">${displayName(u)}</div>`
    ).join('');
  }, 300);
}

function selectPatientForCreate(id, email, fullName = '') {
  document.getElementById('create-patient-id').value = id;
  document.getElementById('create-patient-search').value = email;
  document.getElementById('create-patient-info').textContent = fullName ? `Patient: ${fullName} (${email})` : `Patient: ${email}`;
  document.getElementById('create-patient-results').style.display = 'none';
}

// ── Structured Record Form ─────────────────────────────
const RECORD_FIELDS = {
  diagnosis: [
    { name: 'diagnosis', label: 'Diagnosis', type: 'text', required: true, placeholder: 'e.g. Hypertension' },
    { name: 'severity', label: 'Severity', type: 'select', options: ['Mild', 'Moderate', 'Severe'], required: true },
    { name: 'treatment', label: 'Treatment Plan', type: 'textarea', placeholder: 'Prescribed treatment...' },
  ],
  prescription: [
    { name: 'medication', label: 'Medication', type: 'text', required: true, placeholder: 'e.g. Amoxicillin 500mg' },
    { name: 'dosage', label: 'Dosage', type: 'text', required: true, placeholder: 'e.g. 1 tablet 3x daily' },
    { name: 'duration', label: 'Duration', type: 'text', placeholder: 'e.g. 7 days' },
    { name: 'refills', label: 'Refills', type: 'number', placeholder: '0' },
  ],
  lab_result: [
    { name: 'test_name', label: 'Test Name', type: 'text', required: true, placeholder: 'e.g. Complete Blood Count' },
    { name: 'result', label: 'Result', type: 'text', required: true, placeholder: 'e.g. Normal' },
    { name: 'reference_range', label: 'Reference Range', type: 'text', placeholder: 'e.g. 4.5-11.0 x10^9/L' },
    { name: 'unit', label: 'Unit', type: 'text', placeholder: 'e.g. x10^9/L' },
  ],
  vitals: [
    { name: 'blood_pressure', label: 'Blood Pressure', type: 'text', required: true, placeholder: 'e.g. 120/80 mmHg' },
    { name: 'heart_rate', label: 'Heart Rate (bpm)', type: 'number', required: true, placeholder: '72' },
    { name: 'temperature', label: 'Temperature (°C)', type: 'number', placeholder: '36.6' },
    { name: 'respiratory_rate', label: 'Respiratory Rate (/min)', type: 'number', placeholder: '16' },
    { name: 'oxygen_saturation', label: 'O₂ Saturation (%)', type: 'number', placeholder: '98' },
    { name: 'weight', label: 'Weight (kg)', type: 'number', placeholder: '70' },
    { name: 'height', label: 'Height (cm)', type: 'number', placeholder: '175' },
  ],
  medication_log: [
    { name: 'medication', label: 'Medication', type: 'text', required: true, placeholder: 'e.g. Metformin 500mg' },
    { name: 'dose_given', label: 'Dose Given', type: 'text', required: true, placeholder: 'e.g. 1 tablet' },
    { name: 'route', label: 'Route', type: 'select', options: ['Oral', 'IV', 'IM', 'Subcutaneous', 'Topical', 'Inhaled'], required: true },
    { name: 'time_given', label: 'Time Given', type: 'text', placeholder: 'e.g. 08:00' },
    { name: 'patient_response', label: 'Patient Response', type: 'textarea', placeholder: 'Any observed reaction...' },
  ],
  triage: [
    { name: 'chief_complaint', label: 'Chief Complaint', type: 'text', required: true, placeholder: 'e.g. Chest pain' },
    { name: 'triage_level', label: 'Triage Level', type: 'select', options: ['Immediate', 'Urgent', 'Less Urgent', 'Non-Urgent'], required: true },
    { name: 'pain_score', label: 'Pain Score (0-10)', type: 'number', placeholder: '5' },
    { name: 'observations', label: 'Observations', type: 'textarea', placeholder: 'Clinical observations...' },
  ],
};

function updateRecordForm() {
  const type = document.getElementById('record-type').value;
  const fields = RECORD_FIELDS[type] || [];
  const el = document.getElementById('record-fields');
  el.innerHTML = fields.map(f => {
    const req = f.required ? ' *' : '';
    if (f.type === 'select') {
      return `<div class="form-group"><label>${f.label}${req}</label>
        <select id="rf-${f.name}">${f.options.map(o => `<option value="${o}">${o}</option>`).join('')}</select></div>`;
    }
    if (f.type === 'textarea') {
      return `<div class="form-group"><label>${f.label}${req}</label>
        <textarea id="rf-${f.name}" rows="2" placeholder="${f.placeholder || ''}"></textarea></div>`;
    }
    return `<div class="form-group"><label>${f.label}${req}</label>
      <input type="${f.type}" id="rf-${f.name}" placeholder="${f.placeholder || ''}" /></div>`;
  }).join('');
}

// ── Records ────────────────────────────────────────────
let recordsPage = 0;
const RECORDS_PER_PAGE = 10;

const TL_ICONS = {
  diagnosis: '🩺', prescription: '💊', lab_result: '🔬',
  vitals: '📊', medication_log: '💉', triage: '🚨', default: '📋',
};

function tlIconClass(type) {
  return ['diagnosis','prescription','lab_result','vitals','medication_log','triage'].includes(type) ? type : 'default';
}

function formatTlDate(iso) {
  const d = new Date(iso);
  return `${d.toLocaleDateString(undefined, { month:'short', day:'numeric' })}<br/>${d.getFullYear()}`;
}

async function loadRecords(page = 0) {
  recordsPage = page;
  const pid = document.getElementById('selected-patient-id').value || currentUser.id;
  const el = document.getElementById('records-list');
  setLoading('records-list', true, 'Loading records…');
  const res = await api.listRecords(pid);
  if (!res.ok) { el.innerHTML = `<p class="text-muted">${res.data.detail || 'Failed to load records'}</p>`; return; }
  let records = Array.isArray(res.data) ? res.data : (res.data.items || []);

  // Date filters
  const fromDate = document.getElementById('records-from').value;
  const toDate = document.getElementById('records-to').value;
  if (fromDate) records = records.filter(r => r.created_at >= fromDate);
  if (toDate) records = records.filter(r => r.created_at <= toDate + 'T23:59:59');

  // Sort newest first
  records.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  const total = records.length;
  const totalPages = Math.ceil(total / RECORDS_PER_PAGE);
  const paged = records.slice(page * RECORDS_PER_PAGE, (page + 1) * RECORDS_PER_PAGE);

  if (!paged.length) { el.innerHTML = '<p class="text-muted">No records found.</p>'; return; }

  // Fetch active consent for this patient (for doctors/nurses — shows expiry)
  let consentExpiry = null;
  if ((currentUser.role === 'Doctor' || currentUser.role === 'Nurse') && pid !== currentUser.id) {
    const grantsRes = await api.listDoctorGrants();
    if (grantsRes.ok) {
      const active = (grantsRes.data || []).find(g =>
        g.patient_id === pid && g.status === 'active' && g.expires_at
      );
      if (active) consentExpiry = new Date(active.expires_at);
    }
  }

  const isCreator = (r) => r.created_by === currentUser.id;
  const canPublish = (r) => isCreator(r) && r.status === 'draft';
  const canEdit = (r) => isCreator(r) || (currentUser.role === 'Doctor' && r.status === 'published');

  // Consent expiry banner
  let consentBanner = '';
  if (consentExpiry) {
    const now = new Date();
    const diffMs = consentExpiry - now;
    const diffH = Math.round(diffMs / 3600000);
    const isExpiringSoon = diffH < 2;
    consentBanner = `<div style="background:${isExpiringSoon ? '#fef3c7' : '#f0fdf4'};border:1px solid ${isExpiringSoon ? '#fde68a' : '#bbf7d0'};border-radius:8px;padding:0.65rem 1rem;margin-bottom:1rem;font-size:0.83rem;color:${isExpiringSoon ? '#92400e' : '#166534'}">
      ${isExpiringSoon ? '⚠️' : '🔓'} Access granted until <strong>${consentExpiry.toLocaleString()}</strong>${isExpiringSoon ? ' — expiring soon' : ''}
    </div>`;
  }

  const items = paged.map(r => {
    const data = r.data || {};
    const fields = Object.entries(data)
      .filter(([k]) => k !== 'notes')
      .map(([k, v]) => `<span class="tl-field"><strong>${k.replace(/_/g,' ')}:</strong> ${v}</span>`)
      .join('');
    const notes = data.notes ? `<div class="tl-meta" style="margin-top:0.3rem;font-style:italic">${data.notes}</div>` : '';
    const actorLabel = formatUserLabel(r.creator_name, r.creator_email, r.created_by);
    const draftBadge = r.status === 'draft' ? '<span class="tl-draft-badge">Draft</span>' : '';
    const publishedInfo = r.status === 'published' && r.published_at
      ? `<span class="tl-published-badge">Published</span>`
      : '';

    const actions = [];
    if (canPublish(r)) {
      actions.push(`<button class="btn btn-success btn-sm" onclick="publishRecord('${r.id}')">Publish</button>`);
    }
    if (canEdit(r) && currentUser.role !== 'Patient') {
      actions.push(`<button class="btn btn-outline btn-sm" onclick="editRecord('${r.id}')">Edit</button>`);
    }
    if (currentUser.role === 'Doctor' && isCreator(r)) {
      actions.push(`<button class="btn btn-danger btn-sm" onclick="deleteRecord('${r.id}')">Delete</button>`);
    }

    return `<div class="tl-item">
      <div class="tl-date">${formatTlDate(r.created_at)}</div>
      <div class="tl-icon ${tlIconClass(r.record_type)}">${TL_ICONS[r.record_type] || TL_ICONS.default}</div>
      <div class="tl-card">
        <div class="tl-card-title">
          ${r.record_type.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase())}
          ${draftBadge} ${publishedInfo}
        </div>
        <div class="tl-fields">${fields}</div>
        ${notes}
        <div class="tl-meta">By ${actorLabel} · ${new Date(r.created_at).toLocaleString()}</div>
        ${actions.length ? `<div class="tl-actions">${actions.join('')}</div>` : ''}
      </div>
    </div>`;
  }).join('');

  let pagination = '';
  if (totalPages > 1) {
    pagination = `<div style="display:flex;justify-content:space-between;align-items:center;margin-top:1rem;padding-top:0.75rem;border-top:1px solid #e2e8f0">
      <span class="text-muted">Page ${page + 1} of ${totalPages} (${total} records)</span>
      <div>
        ${page > 0 ? `<button class="btn btn-outline btn-sm" onclick="loadRecords(${page - 1})">← Previous</button>` : ''}
        ${page < totalPages - 1 ? `<button class="btn btn-outline btn-sm" onclick="loadRecords(${page + 1})">Next →</button>` : ''}
      </div>
    </div>`;
  }

  el.innerHTML = consentBanner + `<div class="timeline">${items}</div>${pagination}
    <p class="text-muted" style="margin-top:0.5rem">${total} record${total !== 1 ? 's' : ''}</p>`;
}

async function publishRecord(recordId) {
  if (!confirm('Publish this record? The patient will be notified by email.')) return;
  const res = await api.publishRecord(recordId);
  if (res.ok) loadRecords(recordsPage);
  else alert(res.data.detail || 'Failed to publish');
}

async function deleteRecord(recordId) {
  if (!confirm('Delete this record? This cannot be undone.')) return;
  const res = await api.deleteRecord(recordId);
  if (res.ok) loadRecords(recordsPage);
  else alert(res.data.detail || 'Failed to delete');
}

async function editRecord(recordId) {
  // Simple inline edit — load record and switch to create tab with pre-filled data
  const res = await api.getRecord(recordId);
  if (!res.ok) { alert('Could not load record'); return; }
  const r = res.data;
  // Switch to create tab and pre-fill
  showRecordsTab('create');
  document.getElementById('create-patient-id').value = r.patient_id;
  document.getElementById('create-patient-info').textContent = `Editing record for patient`;
  const typeSelect = document.getElementById('record-type');
  if (typeSelect) { typeSelect.value = r.record_type; updateRecordForm(); }
  // Fill fields
  const data = r.data || {};
  setTimeout(() => {
    Object.entries(data).forEach(([k, v]) => {
      const el = document.getElementById(`rf-${k}`);
      if (el) el.value = v;
    });
    if (data.notes) document.getElementById('record-notes').value = data.notes;
    // Store editing record id
    document.getElementById('create-record-response').dataset.editingId = recordId;
  }, 50);
}

async function createRecord() {
  const patient_id = document.getElementById('create-patient-id').value;
  const record_type = document.getElementById('record-type').value;
  if (!patient_id) { alert('Select a patient first'); return; }

  const fields = RECORD_FIELDS[record_type] || [];
  const data = {};
  for (const f of fields) {
    const val = document.getElementById(`rf-${f.name}`)?.value || '';
    if (f.required && !val) { alert(`${f.label} is required`); return; }
    if (val) data[f.name] = f.type === 'number' ? parseFloat(val) : val;
  }
  const notes = document.getElementById('record-notes').value;
  if (notes) data.notes = notes;

  const el = document.getElementById('create-record-response');
  el.className = 'alert'; el.textContent = 'Saving…'; el.classList.remove('hidden');

  // Check if editing existing record
  const editingId = el.dataset.editingId;
  if (editingId) {
    const res = await api.updateRecord(editingId, data);
    if (res.ok) {
      el.className = 'alert success'; el.textContent = 'Record updated!';
      delete el.dataset.editingId;
      setTimeout(() => { showRecordsTab('browse'); loadRecords(); }, 800);
    } else { el.className = 'alert error'; el.textContent = res.data.detail || 'Failed'; }
    return;
  }

  // Nurses always save as draft (status select is hidden for them)
  const statusSel = document.getElementById('record-status-select');
  const record_status = (statusSel && statusSel.closest('.form-group').style.display !== 'none')
    ? statusSel.value
    : 'draft';

  const res = await api.createRecord(patient_id, record_type, data, record_status);
  if (res.ok) {
    el.className = 'alert success';
    el.textContent = record_status === 'draft'
      ? `Draft saved. Publish when ready.`
      : `Record published! Patient has been notified.`;
  } else { el.className = 'alert error'; el.textContent = res.data.detail || 'Failed'; }
}

// ── Attachments ────────────────────────────────────────
function mimeIcon(mime) {
  if (mime && mime.startsWith('image/')) return '🖼️';
  if (mime === 'application/pdf') return '📄';
  return '📎';
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

async function loadAttachments() {
  const recordId = document.getElementById('att-record-id').value;
  if (!recordId) { alert('Enter a record ID'); return; }
  const el = document.getElementById('attachments-list');
  el.innerHTML = '<p class="text-muted">Loading...</p>';
  const res = await api.listAttachments(recordId);
  if (!res.ok) { el.innerHTML = `<p class="text-muted">${res.data.detail || 'Failed'}</p>`; return; }
  const atts = Array.isArray(res.data) ? res.data : (res.data.items || []);
  if (!atts.length) { el.innerHTML = '<p class="text-muted">No attachments found.</p>'; return; }
  el.innerHTML = atts.map(a => `
    <div class="att-item">
      <div class="att-info">
        <span class="att-icon">${mimeIcon(a.mime_type)}</span>
        <div class="att-meta">
          <span class="att-name">${a.original_filename}</span>
          <span class="att-detail">${a.mime_type} · ${formatBytes(a.file_size_bytes)} · ${new Date(a.created_at).toLocaleDateString()}</span>
        </div>
      </div>
      <div>
        <button class="btn btn-outline btn-sm" onclick="downloadAttachment('${a.record_id || recordId}','${a.id}','${a.original_filename}')">Download</button>
        ${currentUser.role === 'Doctor' ? `<button class="btn btn-danger btn-sm" onclick="deleteAttachment('${a.record_id || recordId}','${a.id}')">Delete</button>` : ''}
      </div>
    </div>
  `).join('');
}

async function uploadAttachment() {
  const recordId = document.getElementById('upload-record-id').value;
  const fileInput = document.getElementById('upload-file');
  const el = document.getElementById('upload-response');
  el.classList.remove('hidden', 'error', 'success');

  if (!recordId) { el.classList.add('error'); el.textContent = 'Enter a record ID'; return; }
  if (!fileInput.files.length) { el.classList.add('error'); el.textContent = 'Select a file'; return; }

  const file = fileInput.files[0];
  const res = await api.uploadAttachment(recordId, file);
  if (res.ok) {
    el.classList.add('success');
    el.textContent = `Uploaded: ${res.data.original_filename || file.name} (${res.data.id})`;
    fileInput.value = '';
  } else {
    el.classList.add('error');
    el.textContent = res.data.detail || 'Upload failed';
  }
}

async function downloadAttachment(recordId, attachmentId, filename) {
  try {
    const blob = await api.downloadAttachment(recordId, attachmentId);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename || 'attachment';
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (e) { alert('Download failed: ' + e.message); }
}

async function deleteAttachment(recordId, attachmentId) {
  if (!confirm('Delete this attachment?')) return;
  const res = await api.deleteAttachment(recordId, attachmentId);
  if (res.ok) loadAttachments();
  else alert(res.data.detail || 'Delete failed');
}

// ── Lab Technician dedicated view ─────────────────────
function showLabTechView() {
  const section = document.getElementById('section-attachments');
  if (!section) return;
  // Replace content with lab-tech specific UI
  section.innerHTML = `
    <div class="card">
      <div class="card-header">
        <h3>🔬 Submit Lab Result</h3>
        <span class="text-muted" style="font-size:0.78rem">Results are private until you publish them</span>
      </div>
      <div class="card-body">
        <div class="form-group">
          <label>Patient Email</label>
          <div style="position:relative">
            <input type="text" id="lt-patient-search" placeholder="Type patient email…" oninput="searchLabPatient()" autocomplete="off" />
            <div id="lt-patient-results" style="position:absolute;top:100%;left:0;right:0;background:#fff;border:1px solid #e2e8f0;border-radius:0 0 7px 7px;max-height:160px;overflow-y:auto;display:none;z-index:10;box-shadow:0 4px 12px rgba(0,0,0,0.08)"></div>
          </div>
          <input type="hidden" id="lt-patient-id" />
          <div id="lt-patient-info" class="text-muted" style="margin-top:0.3rem"></div>
        </div>
        <div class="form-row">
          <div class="form-group" style="flex:1">
            <label>Test Name &amp; Type *</label>
            <input type="text" id="lt-test-name" placeholder="e.g. Complete Blood Count (CBC)" />
          </div>
          <div class="form-group" style="flex:1">
            <label>Sample Date *</label>
            <input type="date" id="lt-sample-date" />
          </div>
        </div>
        <div class="form-row">
          <div class="form-group" style="flex:1">
            <label>Result Date</label>
            <input type="date" id="lt-result-date" />
          </div>
          <div class="form-group" style="flex:1">
            <label>Result Summary *</label>
            <input type="text" id="lt-result" placeholder="e.g. Hemoglobin 13.5 g/dL — Normal" />
          </div>
        </div>
        <div class="form-group">
          <label>Report File (PDF, JPEG, PNG, TIFF, DICOM — max 20 MB) *</label>
          <div class="file-drop" id="lt-file-drop">
            <input type="file" id="lt-file" accept=".jpg,.jpeg,.png,.pdf,.tiff,.tif,.dcm" />
            <p>📎 Drag &amp; drop or click to select the report file</p>
          </div>
          <div id="lt-file-name" class="text-muted" style="margin-top:0.3rem"></div>
        </div>
        <div class="form-group">
          <label>Additional Notes</label>
          <textarea id="lt-notes" rows="2" placeholder="Any additional observations…"></textarea>
        </div>
        <div style="display:flex;gap:0.75rem;flex-wrap:wrap">
          <button class="btn btn-outline" onclick="submitLabResult('draft')">Save as Draft</button>
          <button class="btn btn-primary" onclick="submitLabResult('published')">Submit &amp; Publish</button>
        </div>
        <div id="lt-response" class="alert hidden"></div>
      </div>
    </div>

    <div class="card" id="lt-my-results-card">
      <div class="card-header">
        <h3>My Submitted Results</h3>
        <button class="btn btn-outline btn-sm" onclick="loadMyLabResults()">↻ Refresh</button>
      </div>
      <div class="card-body" id="lt-results-list">
        <p class="text-muted">Click Refresh to view your submitted results.</p>
      </div>
    </div>
  `;

  // Wire up file name display
  document.getElementById('lt-file').addEventListener('change', function() {
    const f = this.files[0];
    document.getElementById('lt-file-name').textContent = f ? `Selected: ${f.name} (${formatBytes(f.size)})` : '';
  });
}

let ltSearchTimeout = null;
async function searchLabPatient() {
  const q = document.getElementById('lt-patient-search').value;
  const el = document.getElementById('lt-patient-results');
  if (q.length < 3) { el.style.display = 'none'; return; }
  clearTimeout(ltSearchTimeout);
  ltSearchTimeout = setTimeout(async () => {
    const res = await api.searchPatients(q);
    if (!res.ok || !res.data.length) { el.style.display = 'none'; return; }
    el.style.display = 'block';
    el.innerHTML = res.data.map(u =>
      `<div style="padding:0.5rem 0.75rem;cursor:pointer;font-size:0.85rem;border-bottom:1px solid #f1f5f9"
            onmouseover="this.style.background='#f0f7ff'" onmouseout="this.style.background=''"
            onclick="selectLabPatient('${u.id}','${u.email}','${(u.full_name||'').replace(/'/g,"\\'")}')">
        ${displayName(u)}
      </div>`
    ).join('');
  }, 300);
}

function selectLabPatient(id, email, name) {
  document.getElementById('lt-patient-id').value = id;
  document.getElementById('lt-patient-search').value = email;
  document.getElementById('lt-patient-info').textContent = name ? `Patient: ${name} (${email})` : `Patient: ${email}`;
  document.getElementById('lt-patient-results').style.display = 'none';
}

async function submitLabResult(recordStatus) {
  const patientId = document.getElementById('lt-patient-id').value;
  const testName = document.getElementById('lt-test-name').value.trim();
  const sampleDate = document.getElementById('lt-sample-date').value;
  const resultDate = document.getElementById('lt-result-date').value;
  const result = document.getElementById('lt-result').value.trim();
  const notes = document.getElementById('lt-notes').value.trim();
  const fileInput = document.getElementById('lt-file');
  const el = document.getElementById('lt-response');

  el.classList.remove('hidden', 'error', 'success');

  if (!patientId) { showAlert('lt-response', 'error', 'Select a patient first'); return; }
  if (!testName) { showAlert('lt-response', 'error', 'Test name is required'); return; }
  if (!sampleDate) { showAlert('lt-response', 'error', 'Sample date is required'); return; }
  if (!result) { showAlert('lt-response', 'error', 'Result summary is required'); return; }
  if (!fileInput.files.length) { showAlert('lt-response', 'error', 'Attach the report file'); return; }

  el.className = 'alert'; el.textContent = 'Submitting…'; el.classList.remove('hidden');

  // Step 1: create the record
  const data = {
    test_name: testName,
    sample_date: sampleDate,
    result_date: resultDate || null,
    result: result,
    lab_technician_id: currentUser.id,
  };
  if (notes) data.notes = notes;

  const recRes = await api.createRecord(patientId, 'lab_result', data, recordStatus);
  if (!recRes.ok) { showAlert('lt-response', 'error', recRes.data.detail || 'Failed to create record'); return; }

  const recordId = recRes.data.id;

  // Step 2: upload the file attachment
  const uploadRes = await api.uploadAttachment(recordId, fileInput.files[0]);
  if (!uploadRes.ok) {
    showAlert('lt-response', 'error', `Record created but file upload failed: ${uploadRes.data.detail || 'Unknown error'}`);
    return;
  }

  showAlert('lt-response', 'success',
    recordStatus === 'published'
      ? `Lab result published! Patient has been notified. Record ID: ${recordId}`
      : `Draft saved. You can review and publish when ready. Record ID: ${recordId}`
  );

  // Clear form
  document.getElementById('lt-test-name').value = '';
  document.getElementById('lt-sample-date').value = '';
  document.getElementById('lt-result-date').value = '';
  document.getElementById('lt-result').value = '';
  document.getElementById('lt-notes').value = '';
  document.getElementById('lt-patient-id').value = '';
  document.getElementById('lt-patient-search').value = '';
  document.getElementById('lt-patient-info').textContent = '';
  document.getElementById('lt-file-name').textContent = '';
  fileInput.value = '';
}

async function loadMyLabResults() {
  const el = document.getElementById('lt-results-list');
  if (!el) return;
  el.innerHTML = `<p class="text-muted">To view a submitted result, search for the patient above and check the record ID shown after submission.</p>
    <p class="text-muted" style="margin-top:0.5rem">Once published, results are visible to the patient and their consented doctors.</p>`;
}

// ── Admin Panel ────────────────────────────────────────
async function loadAdminUsers() {
  const role = document.getElementById('admin-filter-role').value;
  const el = document.getElementById('admin-users-list');
  setLoading('admin-users-list', true, 'Loading users…');
  const res = await api.adminListUsers(role);
  if (!res.ok) { el.innerHTML = `<p class="text-muted">${res.data.detail || 'Failed'}</p>`; return; }
  const users = res.data.items || [];
  if (!users.length) { el.innerHTML = '<p class="text-muted">No users found.</p>'; return; }
  el.innerHTML = `
    <table class="admin-table">
      <thead>
        <tr>
          <th>Full Name</th>
          <th>Email</th>
          <th>Role</th>
          <th>Status</th>
          <th>MFA</th>
          <th>Created</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        ${users.map(u => `
          <tr>
            <td>${u.full_name || '<span style="color:#94a3b8">—</span>'}</td>
            <td style="font-size:0.8rem">${u.email}</td>
            <td><span class="role-badge role-${u.role}">${u.role.replace('_',' ')}</span></td>
            <td>${u.is_active !== false ? '<span style="color:#059669;font-weight:600">Active</span>' : '<span style="color:#dc2626;font-weight:600">Inactive</span>'}</td>
            <td>${u.mfa_enabled
              ? `<span style="color:#059669">On</span> <button class="btn btn-ghost btn-sm" onclick="adminDisableMFA('${u.id}','${u.email}')">Disable</button>`
              : '<span style="color:#94a3b8">Off</span>'}</td>
            <td style="color:#94a3b8">${new Date(u.created_at).toLocaleDateString()}</td>
            <td>
              <button class="btn btn-outline btn-sm" onclick="adminResetPwd('${u.id}','${u.email}')">Reset Pwd</button>
              ${u.is_active !== false
                ? `<button class="btn btn-danger btn-sm" onclick="adminDeactivate('${u.id}')">Deactivate</button>`
                : `<button class="btn btn-success btn-sm" onclick="adminReactivate('${u.id}')">Reactivate</button>`}
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    <p class="text-muted" style="margin-top:0.75rem">Total: ${res.data.total} users</p>
  `;
}

async function adminCreateUser() {
  const full_name = document.getElementById('admin-new-name').value.trim();
  const email = document.getElementById('admin-new-email').value;
  const password = document.getElementById('admin-new-password').value;
  const role = document.getElementById('admin-new-role').value;
  const el = document.getElementById('admin-create-response');
  el.classList.remove('hidden', 'error', 'success');

  if (!full_name) { el.classList.add('error'); el.textContent = 'Full name required'; return; }
  if (!email) { el.classList.add('error'); el.textContent = 'Email required'; return; }
  if (!password) { el.classList.add('error'); el.textContent = 'Click "Generate" to create a password first'; return; }

  el.className = 'alert'; el.textContent = 'Creating account…'; el.classList.remove('hidden');
  const res = await api.adminCreateUser(email, password, role, full_name);
  if (res.ok) {
    el.classList.add('success');
    el.textContent = `Account created: ${res.data.email} (${res.data.role}). Password emailed to user.`;
    document.getElementById('admin-new-name').value = '';
    document.getElementById('admin-new-email').value = '';
    document.getElementById('admin-new-password').value = '';
    loadAdminUsers();
  } else {
    el.classList.add('error');
    el.textContent = res.data.detail || 'Failed';
  }
}

function generateTempPassword(targetId) {
  const id = targetId || 'admin-new-password';
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const specials = '!@#$%&*';
  let pwd = '';
  for (let i = 0; i < 12; i++) pwd += chars[Math.floor(Math.random() * chars.length)];
  // Ensure at least one uppercase, one digit, one special
  pwd = pwd.slice(0, 10)
    + specials[Math.floor(Math.random() * specials.length)]
    + (Math.floor(Math.random() * 9) + 1);
  document.getElementById(id).value = pwd;
}

function copyPassword() {
  const pwd = document.getElementById('admin-new-password').value;
  if (!pwd) { alert('Generate a password first'); return; }
  navigator.clipboard.writeText(pwd).then(() => alert('Password copied!'));
}

// ── Front Desk ─────────────────────────────────────────
async function frontdeskRegister() {
  const full_name = document.getElementById('fd-name').value.trim();
  const email = document.getElementById('fd-email').value;
  const password = document.getElementById('fd-password').value;
  const el = document.getElementById('fd-response');
  el.classList.remove('hidden', 'error', 'success');
  if (!full_name) { el.classList.add('error'); el.textContent = 'Enter patient full name'; return; }
  if (!email) { el.classList.add('error'); el.textContent = 'Enter patient email'; return; }
  if (!password) { el.classList.add('error'); el.textContent = 'Click Generate first'; return; }
  el.className = 'alert'; el.textContent = 'Registering patient…'; el.classList.remove('hidden');
  const res = await api.frontdeskRegisterPatient(email, full_name, password);
  if (res.ok) {
    el.classList.add('success');
    el.textContent = `Patient registered: ${res.data.email}. Password emailed.`;
    document.getElementById('fd-name').value = '';
    document.getElementById('fd-email').value = '';
    document.getElementById('fd-password').value = '';
  } else {
    el.classList.add('error');
    el.textContent = res.data.detail || 'Failed';
  }
}

async function adminDisableMFA(userId, email) {
  if (!confirm(`Disable MFA for ${email}? They will be able to log in with just their password.`)) return;
  const res = await api.adminDisableMFA(userId);
  if (res.ok) { alert(res.data.message); loadAdminUsers(); }
  else alert(res.data.detail || 'Failed');
}

async function adminResetPwd(userId, email) {
  // Generate a password and show it for confirmation
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const specials = '!@#$%&*';
  let pwd = '';
  for (let i = 0; i < 12; i++) pwd += chars[Math.floor(Math.random() * chars.length)];
  pwd = pwd.slice(0, 10) + specials[Math.floor(Math.random() * specials.length)] + (Math.floor(Math.random() * 9) + 1);

  const ok = confirm(`Reset password for ${email}?\n\nNew password: ${pwd}\n\nThis will be emailed to the user and all their sessions will be revoked.`);
  if (!ok) return;

  const res = await api.adminResetPassword(userId, pwd);
  if (res.ok) {
    alert(`Password reset for ${email}. New password emailed.`);
    loadAdminUsers();
  } else {
    alert(res.data.detail || 'Failed to reset password');
  }
}

async function adminDeactivate(userId) {
  if (!confirm('Deactivate this user? Their sessions will be revoked.')) return;
  const res = await api.adminDeactivateUser(userId);
  if (res.ok) loadAdminUsers();
  else alert(res.data.detail || 'Failed');
}

async function adminReactivate(userId) {
  const res = await api.adminReactivateUser(userId);
  if (res.ok) loadAdminUsers();
  else alert(res.data.detail || 'Failed');
}

// ── Audit ──────────────────────────────────────────────
const EVENT_DESCRIPTIONS = {
  'USER_LOGIN': { icon: '🔑', label: 'Login', patientDesc: 'logged into the system', adminDesc: 'User logged in' },
  'USER_CREATED_BY_ADMIN': { icon: '👤', label: 'Account Created', patientDesc: 'account was created', adminDesc: 'Admin created account' },
  'USER_UPDATED_BY_ADMIN': { icon: '✏️', label: 'Account Updated', patientDesc: 'account was modified', adminDesc: 'Admin updated account' },
  'USER_DEACTIVATED': { icon: '🚫', label: 'Account Deactivated', patientDesc: 'account was deactivated', adminDesc: 'Admin deactivated account' },
  'USER_REACTIVATED': { icon: '✅', label: 'Account Reactivated', patientDesc: 'account was reactivated', adminDesc: 'Admin reactivated account' },
  'PASSWORD_RESET_BY_ADMIN': { icon: '🔒', label: 'Password Reset', patientDesc: 'reset your password', adminDesc: 'Admin reset password' },
  'MFA_DISABLED_BY_ADMIN': { icon: '📱', label: 'MFA Disabled', patientDesc: 'disabled your two-factor authentication', adminDesc: 'Admin disabled MFA' },
  'CONSENT_REQUESTED': { icon: '📋', label: 'Access Requested', patientDesc: 'requested access to your records', adminDesc: 'Consent requested' },
  'CONSENT_APPROVED': { icon: '✅', label: 'Access Approved', patientDesc: 'was granted access to your records', adminDesc: 'Consent approved' },
  'CONSENT_REVOKED': { icon: '🚫', label: 'Access Revoked', patientDesc: 'had access to your records revoked', adminDesc: 'Consent revoked' },
  'RECORD_CREATED': { icon: '📝', label: 'Record Created', patientDesc: 'added a new record to your file', adminDesc: 'Record created (draft)' },
  'RECORD_PUBLISHED': { icon: '📢', label: 'Record Published', patientDesc: 'published a record to your file', adminDesc: 'Record published' },
  'RECORD_READ': { icon: '👁️', label: 'Record Viewed', patientDesc: 'viewed your medical record', adminDesc: 'Record viewed' },
  'RECORD_UPDATED': { icon: '✏️', label: 'Record Updated', patientDesc: 'modified your medical record', adminDesc: 'Record updated' },
  'RECORD_DELETED': { icon: '🗑️', label: 'Record Deleted', patientDesc: 'removed a record from your file', adminDesc: 'Record deleted' },
  'ACCESS_DENIED': { icon: '⛔', label: 'Access Denied', patientDesc: 'attempted to access your records without permission', adminDesc: '⚠️ Access denied — unauthorized attempt' },
  'LOGIN_FAILED': { icon: '🚨', label: 'Failed Login', patientDesc: 'failed login attempt', adminDesc: '⚠️ Failed login attempt' },
  'ATTACHMENT_UPLOAD': { icon: '📎', label: 'File Uploaded', patientDesc: 'uploaded a file to your record', adminDesc: 'Attachment uploaded' },
  'ATTACHMENT_DOWNLOAD': { icon: '⬇️', label: 'File Downloaded', patientDesc: 'downloaded a file from your record', adminDesc: 'Attachment downloaded' },
  'ATTACHMENT_DELETE': { icon: '🗑️', label: 'File Deleted', patientDesc: 'removed a file from your record', adminDesc: 'Attachment deleted' },
  'PATIENT_REGISTERED_BY_FRONTDESK': { icon: '🏥', label: 'Patient Registered', patientDesc: 'registered your account', adminDesc: 'Front desk registered patient' },
};

function describeEvent(eventType) {
  return EVENT_DESCRIPTIONS[eventType] || { icon: '•', label: eventType, patientDesc: eventType, adminDesc: eventType };
}

// Cache for resolving user IDs to emails
const userCache = {};
async function resolveUser(userId) {
  if (userCache[userId]) return userCache[userId];
  // If it's the current user, we know them
  if (userId === currentUser.id) { userCache[userId] = `You (${currentUser.email})`; return userCache[userId]; }
  try {
    const res = await api.getMe(); // We can't look up other users as patient, so show ID
    userCache[userId] = userId; // fallback to ID
    return userId;
  } catch { return userId; }
}

EVENT_DESCRIPTIONS.CONSENT_APPROVED = {
  ...EVENT_DESCRIPTIONS.CONSENT_APPROVED,
  patientDesc: 'approved access to your records',
};
EVENT_DESCRIPTIONS.CONSENT_REJECTED = {
  icon: 'Rejected',
  label: 'Access Rejected',
  patientDesc: 'rejected an access request to your records',
  adminDesc: 'Consent rejected',
};
EVENT_DESCRIPTIONS.CONSENT_RELEASED = {
  icon: 'Removed',
  label: 'Access Removed',
  patientDesc: 'removed access to your records',
  adminDesc: 'Doctor released consent access',
};

async function loadAudit() {
  const el = document.getElementById('audit-list');
  setLoading('audit-list', true, 'Loading audit log…');
  const res = await api.listAudit();
  if (!res.ok) { el.innerHTML = `<p class="text-muted">${res.data.detail || 'Failed to load.'}</p>`; return; }
  let entries = Array.isArray(res.data) ? res.data : (res.data.items || []);
  if (!entries.length) { el.innerHTML = '<p class="text-muted">No activity recorded yet.</p>'; return; }

  // Non-admins never see security failure events
  const isAdmin = currentUser.role === 'Admin' || currentUser.role === 'SuperAdmin';
  if (!isAdmin) {
    entries = entries.filter(e => e.event_type !== 'LOGIN_FAILED' && e.event_type !== 'ACCESS_DENIED');
  }

  // Sort most recent first
  entries.sort((a, b) => new Date(b.occurred_at) - new Date(a.occurred_at));

  el.innerHTML = entries.map(e => {
    const ev = describeEvent(e.event_type);
    const time = new Date(e.occurred_at).toLocaleString();
    const actorId = e.actor_id;
    const isSelf = actorId === currentUser.id;
    const actorLabel = isSelf ? 'You' : formatUserLabel(e.actor_name, e.actor_email, `User ${String(actorId).substring(0, 8)}...`);
    const who = actorLabel;

    if (currentUser.role === 'Patient') {
      // Pick the right description based on who did the action
      let desc;
      if (isSelf) {
        // Patient did the action themselves
        const selfDescs = {
          'USER_LOGIN': 'logged into the system',
          'CONSENT_APPROVED': 'approved access to your records',
          'CONSENT_REVOKED': 'revoked access to your records',
          'CONSENT_REQUESTED': 'requested access (on your behalf)',
          'PASSWORD_RESET_BY_ADMIN': 'had your password reset',
        };
        desc = selfDescs[e.event_type] || ev.patientDesc;
      } else {
        desc = ev.patientDesc;
      }
      return `
        <div class="audit-item">
          <div class="audit-dot" style="background:${isSelf ? '#3b82f6' : '#f59e0b'}"></div>
          <div class="audit-content">
            <div class="audit-event">${ev.icon} ${ev.label}</div>
            <div class="audit-details"><strong>${who}</strong> ${desc} · ${time}</div>
          </div>
        </div>`;
    }
    return `
      <div class="audit-item">
        <div class="audit-dot"></div>
        <div class="audit-content">
          <div class="audit-event">${ev.icon} ${ev.label} <code class="text-sm" style="color:#94a3b8">${e.event_type}</code></div>
          <div class="audit-details">${ev.adminDesc}<br/>Actor: ${actorId} · Resource: ${e.resource_id} · ${time}</div>
        </div>
      </div>`;
  }).join('');
}

async function releaseGrant(id) {
  const res = await api.releaseGrant(id);
  if (res.ok) loadDoctorGrants();
  else alert(res.data.detail || 'Failed');
}

async function verifyChain() {
  const el = document.getElementById('audit-verify-result');
  const isAdmin = currentUser.role === 'Admin' || currentUser.role === 'SuperAdmin';
  const isPatient = currentUser.role === 'Patient';

  el.innerHTML = `<p class="text-muted">${isPatient ? 'Verifying your records have not been tampered with…' : 'Verifying full audit chain integrity…'}</p>`;

  const res = await api.verifyChain();
  if (!res.ok) {
    el.innerHTML = `<div class="alert error">${res.data.detail || 'Failed to verify'}</div>`;
    return;
  }
  const d = res.data;

  if (d.chain_intact) {
    const msg = isPatient
      ? `✅ Your records are intact — ${d.entries_checked} audit entries verified. No tampering detected on your data.`
      : `✅ Audit chain integrity verified — ${d.entries_checked} entries checked, no tampering detected.`;
    el.innerHTML = `<div class="alert success">${msg}</div>`;
  } else {
    const ev = describeEvent(d.broken_entry_event || '');
    const time = d.broken_entry_occurred_at ? new Date(d.broken_entry_occurred_at).toLocaleString() : 'unknown';
    const who = isPatient
      ? 'An entry in your audit log has been altered.'
      : `The audit chain is broken at entry #${d.first_broken_at_id}.`;
    el.innerHTML = `
      <div class="alert error">
        <strong>❌ Tampering Detected</strong><br/>
        ${who}<br/>
        <strong>Affected entry:</strong> ${ev.icon} ${ev.label} — ${time}<br/>
        ${!isPatient ? `<strong>Actor:</strong> ${d.broken_entry_actor_id || 'unknown'}<br/>` : ''}
        <span class="text-sm">${d.entries_checked} entries checked. ${isPatient ? 'Contact your administrator immediately.' : 'All entries from this point forward may be unreliable.'}</span>
      </div>`;
  }
}

// ── MFA ─────────────────────────────────────────────────
async function loadMFAStatus() {
  const el = document.getElementById('mfa-status');
  if (currentUser.mfa_enabled) {
    el.innerHTML = '<p style="color:#059669;font-weight:600">✅ MFA is enabled on your account.</p>';
    document.getElementById('mfa-enroll-area').classList.add('hidden');
  } else {
    el.innerHTML = `
      <p style="margin-bottom:0.75rem">MFA is not enabled. We recommend enabling it for extra security.</p>
      <button class="btn btn-primary" onclick="enrollMFA()">Set Up MFA</button>
    `;
  }
}

async function enrollMFA() {
  const res = await api.mfaEnroll();
  if (!res.ok) { alert(res.data.detail || 'Failed to enroll'); return; }

  document.getElementById('mfa-status').innerHTML = '';
  document.getElementById('mfa-enroll-area').classList.remove('hidden');

  // Show QR code using a free QR API
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(res.data.provisioning_uri)}`;
  document.getElementById('mfa-qr').innerHTML = `<img src="${qrUrl}" alt="MFA QR Code" style="border-radius:8px" />`;
  document.getElementById('mfa-secret').textContent = res.data.secret;
}

async function confirmMFA() {
  const code = document.getElementById('mfa-confirm-code').value;
  const el = document.getElementById('mfa-confirm-response');
  el.classList.remove('hidden', 'error', 'success');

  if (!code || code.length !== 6) { el.classList.add('error'); el.textContent = 'Enter a 6-digit code'; return; }

  const res = await api.mfaConfirm(code);
  if (res.ok) {
    el.classList.add('success');
    el.textContent = 'MFA enabled successfully!';
    currentUser.mfa_enabled = true;
    setTimeout(() => loadMFAStatus(), 1500);
  } else {
    el.classList.add('error');
    el.textContent = res.data.detail || 'Invalid code. Try again.';
  }
}

// ── Forced Password Change ─────────────────────────────
function checkForcedPasswordChange() {
  if (currentUser.must_change_password) {
    showSection('security');
    alert('Your account requires a password change. Please update your password before continuing.');
  }
}

// ── Password Change ────────────────────────────────────
async function changePassword() {
  const current = document.getElementById('current-password').value;
  const newPwd = document.getElementById('new-password').value;
  const el = document.getElementById('reset-response');
  el.classList.remove('hidden', 'error', 'success');

  if (!current) { el.classList.add('error'); el.textContent = 'Enter your current password'; return; }
  if (!newPwd || newPwd.length < 12) { el.classList.add('error'); el.textContent = 'New password must be at least 12 characters'; return; }

  const res = await api.changePassword(current, newPwd);
  if (res.ok) {
    el.classList.add('success');
    el.textContent = 'Password changed successfully!';
    currentUser.must_change_password = false;
    document.getElementById('current-password').value = '';
    document.getElementById('new-password').value = '';
  } else {
    el.classList.add('error');
    el.textContent = res.data.detail || 'Failed to change password';
  }
}

// ── Auto-init ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  if (localStorage.getItem('access_token')) initApp();
});
