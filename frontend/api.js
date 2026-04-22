// api.js — Backend API client with replay protection

const BASE_URL = window.location.origin;

function generateNonce() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

function replayHeaders() {
  return { 'X-Nonce': generateNonce(), 'X-Timestamp': new Date().toISOString() };
}

function authHeader() {
  const token = localStorage.getItem('access_token');
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}

async function request(method, path, body = null, withReplay = false) {
  const headers = { 'Content-Type': 'application/json', ...authHeader() };
  if (withReplay) Object.assign(headers, replayHeaders());

  let res = await fetch(`${BASE_URL}${path}`, {
    method, headers,
    body: body ? JSON.stringify(body) : null,
  });

  // Auto-refresh on token expiry
  if (res.status === 401) {
    const refreshed = await tryRefreshToken();
    if (refreshed) {
      // Retry the original request with new token
      const retryHeaders = { 'Content-Type': 'application/json', ...authHeader() };
      if (withReplay) Object.assign(retryHeaders, replayHeaders());
      res = await fetch(`${BASE_URL}${path}`, {
        method, headers: retryHeaders,
        body: body ? JSON.stringify(body) : null,
      });
    }
  }

  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

async function tryRefreshToken() {
  const refresh = localStorage.getItem('refresh_token');
  if (!refresh) return false;
  try {
    const res = await fetch(`${BASE_URL}/auth/token/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refresh }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    return true;
  } catch {
    return false;
  }
}

// ── API Methods ────────────────────────────────────────
const api = {
  // Expose raw request for custom calls
  request: (method, path, body = null, withReplay = false) => request(method, path, body, withReplay),
  // Auth
  register: (email, full_name, password, role) =>
    request('POST', '/auth/register', { email, full_name, password, role }),
  login: (email, password) =>
    request('POST', '/auth/login', { email, password }, true),
  refreshToken: (refresh_token) =>
    request('POST', '/auth/token/refresh', { refresh_token }),

  // Users
  getMe: () => request('GET', '/users/me'),
  changePassword: (current_password, new_password) =>
    request('POST', '/users/me/change-password', { current_password, new_password }),
  setRecoveryEmail: (recovery_email) =>
    request('POST', '/users/me/recovery-email', { recovery_email }),
  searchPatients: (email) => request('GET', `/users/search?email=${encodeURIComponent(email)}&role=Patient`),

  // MFA
  mfaEnroll: () => request('POST', '/auth/mfa/enroll'),
  mfaConfirm: (totp_code) => request('POST', '/auth/mfa/confirm', { totp_code }),
  mfaVerify: (partial_token, totp_code) =>
    request('POST', '/auth/mfa/verify', { partial_token, totp_code }, true),

  // Consent
  requestConsent: (patient_email, duration_hours) =>
    request('POST', '/consent', { patient_email, duration_hours }),
  listGrants: () => request('GET', '/consent'),
  listDoctorGrants: () => request('GET', '/consent/my-requests'),
  approveGrant: (grant_id) => request('POST', `/consent/${grant_id}/approve`),
  rejectGrant: (grant_id) => request('POST', `/consent/${grant_id}/reject`),
  revokeGrant: (grant_id) => request('POST', `/consent/${grant_id}/revoke`),
  releaseGrant: (grant_id) => request('POST', `/consent/${grant_id}/release`),

  // Records
  createRecord: (patient_id, record_type, data, record_status = 'draft') =>
    request('POST', '/records', { patient_id, record_type, data, status: record_status }, true),
  publishRecord: (record_id) =>
    request('POST', `/records/${record_id}/publish`, null, true),
  getRecord: (record_id) => request('GET', `/records/${record_id}`),
  listRecords: (patient_id) => request('GET', `/records?patient_id=${patient_id}`),
  updateRecord: (record_id, data) => request('PATCH', `/records/${record_id}`, { data }, true),
  deleteRecord: (record_id) => request('DELETE', `/records/${record_id}`, null, true),

  // Patient profile & emergency contacts
  getMyProfile: () => request('GET', '/users/me/profile'),
  updateMyProfile: (data) => request('PATCH', '/users/me/profile', data, true),
  updateMe: (data) => request('PATCH', '/users/me', data, true),
  listEmergencyContacts: () => request('GET', '/users/me/emergency-contacts'),
  addEmergencyContact: (contact_email, relationship) =>
    request('POST', '/users/me/emergency-contacts', { contact_email, relationship }, true),
  removeEmergencyContact: (link_id) =>
    request('DELETE', `/users/me/emergency-contacts/${link_id}`, null, true),

  // Attachments
  listAttachments: (record_id) => request('GET', `/records/${record_id}/attachments`),

  uploadAttachment: async (record_id, file) => {
    const formData = new FormData();
    formData.append('file', file);
    const headers = { ...authHeader(), ...replayHeaders() };
    // No Content-Type — browser sets multipart boundary automatically
    const res = await fetch(`${BASE_URL}/records/${record_id}/attachments`, {
      method: 'POST', headers, body: formData,
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  },

  downloadAttachment: async (record_id, attachment_id) => {
    const headers = { ...authHeader() };
    const res = await fetch(`${BASE_URL}/records/${record_id}/attachments/${attachment_id}`, {
      method: 'GET', headers,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Download failed (${res.status})`);
    }
    return await res.blob();
  },

  deleteAttachment: (record_id, attachment_id) =>
    request('DELETE', `/records/${record_id}/attachments/${attachment_id}`, null, true),

  // Audit
  listAudit: () => request('GET', '/audit'),
  verifyChain: () => request('GET', '/audit/verify'),
  // Security event log — fetch only security-relevant events, high limit
  securityEventLog: (windowHours = 24) => {
    const from = new Date(Date.now() - windowHours * 3600 * 1000).toISOString();
    return request('GET', `/audit?limit=200&from=${encodeURIComponent(from)}`);
  },
  // Admin — User Management
  adminListUsers: (role = '', offset = 0, limit = 50) => {
    let path = `/admin/users?offset=${offset}&limit=${limit}`;
    if (role) path += `&role=${role}`;
    return request('GET', path);
  },
  adminGetUser: (user_id) => request('GET', `/admin/users/${user_id}`),
  adminCreateUser: (email, password, role, full_name) =>
    request('POST', '/admin/users', { email, password, role, full_name }),
  adminUpdateUser: (user_id, data) =>
    request('PATCH', `/admin/users/${user_id}`, data),
  adminDeactivateUser: (user_id) =>
    request('POST', `/admin/users/${user_id}/deactivate`),
  adminReactivateUser: (user_id) =>
    request('POST', `/admin/users/${user_id}/reactivate`),
  adminResetPassword: (user_id, new_password) =>
    request('POST', `/admin/users/${user_id}/reset-password`, { new_password }),
  adminDisableMFA: (user_id) =>
    request('POST', `/admin/users/${user_id}/disable-mfa`),
  frontdeskRegisterPatient: (email, full_name, password) =>
    request('POST', '/admin/register-patient', { email, full_name, password }),

  // Security alerts (SuperAdmin only)
  securityAlerts: (windowHours = 24) =>
    request('GET', `/admin/security-alerts?window_hours=${windowHours}`),

  // Password reset
  requestReset: (email) => request('POST', '/auth/password-reset/request', { email }, true),
  completeReset: (token, new_password, totp_code = null) =>
    request('POST', '/auth/password-reset/complete', { token, new_password, totp_code }, true),
};
