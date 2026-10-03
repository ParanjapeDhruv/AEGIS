import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import DashboardCard from '../components/DashboardCard'
import { dashboard } from '../services/api'
import { mockQuickActions } from '../data/mockData'
import './DashboardPage.css'

// ---------------------------------------------------------------------------
// Security score: computed from real threat_stats
// Penalties: critical -20, high -12, medium -5, low -1 per scan (capped at 0)
// ---------------------------------------------------------------------------
function computeSecurityScore(stats) {
  if (!stats || stats.total === 0) return null
  const penalty =
    stats.critical * 20 +
    stats.high     * 12 +
    stats.medium   *  5 +
    stats.low      *  1
  return Math.max(0, 100 - penalty)
}

function scoreLabel(score) {
  if (score === null) return 'No scans yet'
  if (score >= 80) return 'Good'
  if (score >= 60) return 'Fair'
  if (score >= 40) return 'Poor'
  return 'Critical'
}

function scoreAccent(score) {
  if (score === null) return 'default'
  if (score >= 80) return 'success'
  if (score >= 60) return 'warning'
  return 'danger'
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const SEVERITY_MAP = {
  safe:     'success',
  low:      'info',
  medium:   'warning',
  high:     'danger',
  critical: 'danger',
}

const RISK_LABEL = {
  safe:     'Safe',
  low:      'Low',
  medium:   'Medium',
  high:     'High',
  critical: 'Critical',
}

const TYPE_LABEL = {
  url:      'URL',
  phishing: 'Email',
  password: 'Password',
}

function timeAgo(isoString) {
  const diff = Math.floor((Date.now() - new Date(isoString)) / 1000)
  if (diff < 60)  return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function ThreatRow({ label, count, total, color }) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0
  return (
    <div className="threat-row">
      <span className="threat-label">{label}</span>
      <div className="threat-bar-track">
        <div className="threat-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="threat-count">{count}</span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function DashboardPage() {
  const navigate = useNavigate()
  const [summary,  setSummary]  = useState(null)
  const [loading,  setLoading]  = useState(true)
  const [apiError, setApiError] = useState(null)

  useEffect(() => {
    setLoading(true)
    setApiError(null)
    dashboard.getSummary()
      .then(data => {
        setSummary(data)
        setLoading(false)
      })
      .catch(err => {
        setApiError(err.message ?? 'Failed to load dashboard data.')
        setLoading(false)
      })
  }, [])

  const stats   = summary?.threat_stats  ?? null
  const score   = computeSecurityScore(stats)
  const label   = scoreLabel(score)
  const accent  = scoreAccent(score)
  const total   = stats?.total ?? 0
  const weekCount = summary?.scans_this_week ?? 0

  function handleRetry() {
    setLoading(true)
    setApiError(null)
    dashboard.getSummary()
      .then(data => { setSummary(data); setLoading(false) })
      .catch(err => { setApiError(err.message ?? 'Failed to load.'); setLoading(false) })
  }

  return (
    <div className="dashboard">
      {/* Dashboard header with refresh */}
      <div className="dashboard-header">
        <div>
          <h1 className="dashboard-title">Security Dashboard</h1>
          {!loading && summary && (
            <p className="dashboard-subtitle">
              {total === 0
                ? 'No scans yet — run an analysis to populate your dashboard.'
                : `${total} total scan${total !== 1 ? 's' : ''} on record`}
            </p>
          )}
        </div>
        {!loading && (
          <button className="dashboard-refresh-btn" onClick={handleRetry} title="Refresh dashboard">
            ↻ Refresh
          </button>
        )}
      </div>

      {/* Top metric cards */}
      <section className="dashboard-metrics">
        <DashboardCard
          title="Security Score"
          value={loading ? '…' : score !== null ? `${score}/100` : 'N/A'}
          subtitle={loading ? 'Loading…' : `Status: ${label}`}
          icon="◆"
          accent={loading ? 'default' : accent}
        />

        <DashboardCard
          title="Total Scans"
          value={loading ? '…' : total}
          subtitle={loading ? 'Loading…' : weekCount > 0 ? `+${weekCount} this week` : 'No scans this week'}
          icon="◆"
          accent="info"
        />

        <DashboardCard
          title="High Risk"
          value={loading ? '…' : (stats?.critical ?? 0) + (stats?.high ?? 0)}
          subtitle={
            loading ? 'Loading…'
            : `${stats?.critical ?? 0} critical · ${stats?.high ?? 0} high`
          }
          icon="◆"
          accent={!loading && ((stats?.critical ?? 0) + (stats?.high ?? 0)) > 0 ? 'danger' : 'warning'}
        />

        <DashboardCard
          title="Medium / Low"
          value={loading ? '…' : (stats?.medium ?? 0) + (stats?.low ?? 0)}
          subtitle={
            loading ? 'Loading…'
            : `${stats?.medium ?? 0} medium · ${stats?.low ?? 0} low`
          }
          icon="◆"
          accent={!loading && (stats?.medium ?? 0) > 0 ? 'warning' : 'default'}
        />

        <DashboardCard
          title="Safe Results"
          value={loading ? '…' : stats?.safe ?? 0}
          subtitle={loading ? 'Loading…' : 'No threats detected'}
          icon="◆"
          accent="success"
        />
      </section>

      {/* Error banner */}
      {apiError && !loading && (
        <div className="dashboard-error" role="alert">
          <span>{apiError}</span>
          <button className="dashboard-error-retry" onClick={handleRetry}>
            Retry
          </button>
        </div>
      )}

      {/* Threat breakdown + recent scans */}
      <section className="dashboard-grid">
        {/* Threat summary card */}
        <DashboardCard title="Threat Summary" icon="◆">
          {loading ? (
            <div className="dashboard-skeleton-rows">
              {[1,2,3,4].map(i => <div key={i} className="dashboard-skeleton-row" />)}
            </div>
          ) : total === 0 ? (
            <p className="dashboard-empty-hint">Run a scan to see your threat breakdown.</p>
          ) : (
            <div className="threat-breakdown">
              <ThreatRow label="Critical" count={stats.critical} total={total} color="var(--danger)" />
              <ThreatRow label="High"     count={stats.high}     total={total} color="#f0803c" />
              <ThreatRow label="Medium"   count={stats.medium}   total={total} color="var(--warning)" />
              <ThreatRow label="Low"      count={stats.low}      total={total} color="var(--info)" />
              <ThreatRow label="Safe"     count={stats.safe}     total={total} color="var(--success)" />
            </div>
          )}
        </DashboardCard>

        {/* Recent scans card */}
        <DashboardCard title="Recent Scans" icon="◆">
          {loading ? (
            <div className="dashboard-skeleton-rows">
              {[1,2,3,4,5].map(i => <div key={i} className="dashboard-skeleton-row" />)}
            </div>
          ) : !summary?.recent_scans?.length ? (
            <p className="dashboard-empty-hint">No scans yet. Try analyzing a URL or email.</p>
          ) : (
            <>
              {summary.scans_by_type && (
                <div className="scan-type-counts">
                  {Object.entries(summary.scans_by_type)
                    .filter(([, n]) => n > 0)
                    .map(([type, n]) => (
                      <span key={type} className="scan-type-pill">
                        {TYPE_LABEL[type] ?? type}: {n}
                      </span>
                    ))}
                </div>
              )}
              <ul className="scan-list">
                {summary.recent_scans.map((scan) => {
                  const sev = SEVERITY_MAP[scan.risk_level] ?? 'info'
                  return (
                    <li key={scan.id} className="scan-item">
                      <span className={`scan-badge scan-badge--${sev}`}>
                        {TYPE_LABEL[scan.scan_type] ?? scan.scan_type}
                      </span>
                      <span className="scan-target" title={scan.target}>
                        {scan.target}
                      </span>
                      <span className={`scan-result scan-result--${sev}`}>
                        {RISK_LABEL[scan.risk_level] ?? scan.risk_level}
                      </span>
                      <span className="scan-time">{timeAgo(scan.scanned_at)}</span>
                    </li>
                  )
                })}
              </ul>
            </>
          )}
        </DashboardCard>
      </section>

      {/* Quick actions — static navigation, no API data needed */}
      <section className="dashboard-actions">
        <h2 className="section-heading">Quick Analysis</h2>
        <div className="action-grid">
          {mockQuickActions.map((action) => (
            <button
              key={action.id}
              className="action-card"
              onClick={() => navigate(action.path)}
            >
              <span className="action-icon">{action.icon}</span>
              <span className="action-label">{action.label}</span>
              <span className="action-desc">{action.description}</span>
            </button>
          ))}
        </div>
      </section>
    </div>
  )
}
