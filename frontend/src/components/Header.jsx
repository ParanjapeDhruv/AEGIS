import './Header.css'

export default function Header({ title }) {
  const user = { name: 'Demo User', role: 'Security Analyst', initials: 'DU' }

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
            <span className="user-name">{user.name}</span>
            <span className="user-role">{user.role}</span>
          </div>
          <div className="user-avatar">{user.initials}</div>
        </div>
      </div>
    </header>
  )
}
