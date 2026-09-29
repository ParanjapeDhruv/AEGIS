import './StubPage.css'

/**
 * Placeholder for pages not yet implemented.
 */
export default function StubPage({ title, icon, description }) {
  return (
    <div className="stub">
      <span className="stub-icon">{icon}</span>
      <h2 className="stub-title">{title}</h2>
      <p className="stub-desc">{description}</p>
      <span className="stub-badge">Coming Soon</span>
    </div>
  )
}
