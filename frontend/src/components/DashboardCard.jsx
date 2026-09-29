import './DashboardCard.css'

/**
 * Reusable metric/info card for the dashboard.
 * Props:
 *   title       - card heading
 *   value       - big number or label
 *   subtitle    - secondary text below value
 *   icon        - emoji or JSX icon
 *   accent      - 'success' | 'danger' | 'warning' | 'info' | 'default'
 *   children    - optional body content below the metric
 */
export default function DashboardCard({
  title,
  value,
  subtitle,
  icon,
  accent = 'default',
  children,
}) {
  return (
    <div className={`card card--${accent}`}>
      <div className="card-header">
        <span className="card-title">{title}</span>
        {icon && <span className="card-icon">{icon}</span>}
      </div>
      {value !== undefined && (
        <div className="card-metric">
          <span className="card-value">{value}</span>
          {subtitle && <span className="card-subtitle">{subtitle}</span>}
        </div>
      )}
      {children && <div className="card-body">{children}</div>}
    </div>
  )
}
