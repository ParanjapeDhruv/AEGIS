/**
 * Mock data used when the backend is unavailable.
 * Replace with real API calls once endpoints are live.
 */

export const mockDashboardSummary = {
  securityScore: 74,
  scoreLabel: 'Good',
  scoreAccent: 'success',

  recentScans: {
    total: 128,
    lastScan: '2 minutes ago',
    changeLabel: '+12 this week',
  },

  threatSummary: {
    high: 2,
    medium: 7,
    low: 14,
    safe: 105,
  },
}

export const mockRecentScans = [
  { id: 1, type: 'URL',      target: 'https://suspicious-site.net',  result: 'Malicious', severity: 'danger',  time: '2 min ago' },
  { id: 2, type: 'Password', target: 'P@ssw0rd123',                  result: 'Weak',      severity: 'warning', time: '15 min ago' },
  { id: 3, type: 'Email',    target: 'Phishing attempt #38',         result: 'Phishing',  severity: 'danger',  time: '1 hr ago' },
  { id: 4, type: 'URL',      target: 'https://github.com',           result: 'Safe',      severity: 'success', time: '2 hr ago' },
  { id: 5, type: 'Password', target: '••••••••••',                   result: 'Strong',    severity: 'success', time: '3 hr ago' },
]

export const mockQuickActions = [
  { id: 'url',       label: 'Analyze URL',        icon: '🔗', path: '/url',       description: 'Check if a URL is safe' },
  { id: 'phishing',  label: 'Check Email',         icon: '🎣', path: '/phishing',  description: 'Detect phishing attempts' },
  { id: 'password',  label: 'Test Password',       icon: '🔒', path: '/password',  description: 'Evaluate password strength' },
  { id: 'assistant', label: 'Ask AI Assistant',    icon: '🤖', path: '/assistant', description: 'Get security advice' },
]
