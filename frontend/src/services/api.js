/**
 * AEGIS API Service Layer
 * All backend calls are centralised here.
 * Components never call fetch() directly.
 */

const BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000/api'

function getToken() {
  return localStorage.getItem('aegis_token')
}

async function request(method, path, body, requiresAuth = false) {
  const headers = { 'Content-Type': 'application/json' }
  if (requiresAuth) {
    const token = getToken()
    if (token) headers['Authorization'] = `Bearer ${token}`
  }
  const options = { method, headers }
  if (body !== undefined) options.body = JSON.stringify(body)

  const res = await fetch(`${BASE_URL}${path}`, options)

  // Token expired or invalid — clear local storage and redirect to login
  if (res.status === 401) {
    localStorage.removeItem('aegis_token')
    localStorage.removeItem('aegis_user')
    window.location.href = '/login'
    throw new Error('Session expired. Please sign in again.')
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail ?? 'Request failed')
  }
  return res.json()
}

// -- Auth ------------------------------------------------------------------
export const auth = {
  login:    (email, password)    => request('POST', '/auth/login',    { email, password }),
  register: (data)               => request('POST', '/auth/register', data),
  me:       ()                   => request('GET',  '/auth/me', undefined, true),
}

// -- Dashboard -------------------------------------------------------------
export const dashboard = {
  getSummary: () => request('GET', '/dashboard/summary'),
}

// -- URL Analysis ----------------------------------------------------------
export const urlAnalysis = {
  analyze: (url) => request('POST', '/v1/analysis/url', { url }, true),
}

// -- Phishing --------------------------------------------------------------
// data: { sender, reply_to, subject, body, links, attachment_names }
export const phishing = {
  analyze: (data) => request('POST', '/v1/analysis/email', data, true),
}

// -- Password --------------------------------------------------------------
export const password = {
  analyze: (pwd) => request('POST', '/v1/analysis/password', { password: pwd }, true),
}

// -- AI Assistant ----------------------------------------------------------
// message: string, history: [{role, content}], scan_context: optional
export const assistant = {
  chat:   (message, history, scan_context = null) =>
    request('POST', '/v1/assistant/chat', { message, history, scan_context }, true),
  status: () => request('GET', '/v1/assistant/status', undefined, true),
}

// -- AI Explain ------------------------------------------------------------
// evidence: { scan_type, risk_score, risk_level, indicators, context_fields }
// Raw passwords and full email bodies are NEVER included in evidence.
export const ai = {
  explain: (evidence) => request('POST', '/v1/ai/explain', evidence, true),
}

// -- Scan History ----------------------------------------------------------
export const scanHistory = {
  list:      (params) => request('GET',  `/scans?${new URLSearchParams(params)}`),
  getById:   (id)     => request('GET',  `/scans/${id}`),
  deleteById:(id)     => request('DELETE',`/scans/${id}`),
}

// -- Reports ---------------------------------------------------------------
export const reports = {
  list:     () => request('GET',  '/reports'),
  getById:  (id) => request('GET', `/reports/${id}`),
  generate: (data) => request('POST', '/reports', data),
}
