import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import './Header.css'

export default function Header({ title }) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const displayName = user?.name ?? 'User'
  const displayRole = user?.role === 'admin' ? 'Administrator' : 'Security Analyst'
  const initials    = displayName.split(' ').map(p => p[0]).join('').slice(0, 2).toUpperCase()

  function handleLogout() {
    logout()
    navigate('/login')
  }

  return (
    <header className="header">
      <div className="header-left">
        <h1 className="header-title">{title}</h1>
      </div>

      <div className="header-right">
        <div className="header-status">
          <span className="status-dot status-dot--online" />
          <span className="status-label">Systems Online</span>
        </div>

        <div className="header-user">
          <div className="user-info">
            <span className="user-name">{displayName}</span>
            <span className="user-role">{displayRole}</span>
          </div>
          <div className="user-avatar" title={displayName}>{initials}</div>
          <button className="logout-btn" onClick={handleLogout} title="Sign out">
            ⏻
          </button>
        </div>
      </div>
    </header>
  )
}
