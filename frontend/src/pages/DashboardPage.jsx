import { useNavigate } from 'react-router-dom'
import DashboardCard from '../components/DashboardCard'
import {
  mockDashboardSummary,
  mockRecentScans,
  mockQuickActions,
} from '../data/mockData'
import './DashboardPage.css'

const SEVERITY_LABEL = {
  danger:  'Malicious',
  warning: 'Warning',
  success: 'Safe',
  info:    'Info',
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const { securityScore, scoreLabel, scoreAccent, recentScans, threatSummary } =
    mockDashboardSummary

  return (
    <div className="dashboard">
      {/* Top metric cards */}
      <section className="dashboard-metrics">
        <DashboardCard
          title="Security Score"
          value={`${securityScore}/100`}
          subtitle={`Status: ${scoreLabel}`}
          icon="🛡️"
          accent={scoreAccent}
        />

        <DashboardCard
          title="Recent Scans"
          value={recentScans.total}
          subtitle={recentScans.changeLabel}
          icon="🔍"
          accent="info"
        />

        <DashboardCard
          title="Active Threats"
          value={threatSummary.high + threatSummary.medium}
          subtitle={`${threatSummary.high} high · ${threatSummary.medium} medium`}
          icon="⚠️"
          accent={threatSummary.high > 0 ? 'danger' : 'warning'}
        />

        <DashboardCard
          title="Safe Results"
          value={threatSummary.safe}
          subtitle="No threats detected"
          icon="✅"
          accent="success"
        />
      </section>

      {/* Threat breakdown + recent scans */}
      <section className="dashboard-grid">
        <DashboardCard title="Threat Summary" icon="📊">
          <div className="threat-breakdown">
            <ThreatRow label="High" count={threatSummary.high}   color="var(--danger)" />
            <ThreatRow label="Medium" count={threatSummary.medium} color="var(--warning)" />
            <ThreatRow label="Low"  count={threatSummary.low}    color="var(--info)" />
            <ThreatRow label="Safe" count={threatSummary.safe}   color="var(--success)" />
          </div>
        </DashboardCard>

        <DashboardCard title="Recent Scans" icon="🕒">
          <ul className="scan-list">
            {mockRecentScans.map((scan) => (
              <li key={scan.id} className="scan-item">
                <span className={`scan-badge scan-badge--${scan.severity}`}>
                  {scan.type}
                </span>
                <span className="scan-target" title={scan.target}>
                  {scan.target}
                </span>
                <span className={`scan-result scan-result--${scan.severity}`}>
                  {scan.result}
                </span>
                <span className="scan-time">{scan.time}</span>
              </li>
            ))}
          </ul>
        </DashboardCard>
      </section>

      {/* Quick actions */}
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

function ThreatRow({ label, count, color }) {
  const max = mockDashboardSummary.recentScans.total || 1
  const pct = Math.round((count / max) * 100)
  return (
    <div className="threat-row">
      <span className="threat-label">{label}</span>
      <div className="threat-bar-track">
        <div
          className="threat-bar-fill"
          style={{ width: `${pct}%`, background: color }}
        />
      </div>
      <span className="threat-count">{count}</span>
    </div>
  )
}
