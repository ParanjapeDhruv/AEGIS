import { NavLink } from 'react-router-dom'
import './Sidebar.css'

const NAV_ITEMS = [
  { path: '/',          label: 'Dashboard',         icon: '⬡' },
  { path: '/url',       label: 'URL Analysis',       icon: '🔗' },
  { path: '/phishing',  label: 'Phishing Email',     icon: '🎣' },
  { path: '/password',  label: 'Password Analysis',  icon: '🔒' },
  { path: '/assistant', label: 'AI Assistant',        icon: '🤖' },
  { path: '/history',   label: 'Scan History',       icon: '📋' },
  { path: '/reports',   label: 'Reports',            icon: '📊' },
  { path: '/profile',   label: 'Profile',            icon: '👤' },
]

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <span className="brand-icon">⬡</span>
        <span className="brand-name">AEGIS</span>
      </div>

      <nav className="sidebar-nav">
        <ul>
          {NAV_ITEMS.map(({ path, label, icon }) => (
            <li key={path}>
              <NavLink
                to={path}
                end={path === '/'}
                className={({ isActive }) =>
                  `nav-item${isActive ? ' nav-item--active' : ''}`
                }
              >
                <span className="nav-icon">{icon}</span>
                <span className="nav-label">{label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      <div className="sidebar-footer">
        <span className="sidebar-version">v0.1.0</span>
      </div>
    </aside>
  )
}
