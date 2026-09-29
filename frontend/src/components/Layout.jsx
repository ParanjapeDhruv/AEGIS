import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar'
import Header from './Header'
import './Layout.css'

const PAGE_TITLES = {
  '/':          'Dashboard',
  '/url':       'URL Analysis',
  '/phishing':  'Phishing Email Analysis',
  '/password':  'Password Analysis',
  '/assistant': 'AI Assistant',
  '/history':   'Scan History',
  '/reports':   'Reports',
  '/profile':   'Profile',
}

export default function Layout() {
  const { pathname } = useLocation()
  const title = PAGE_TITLES[pathname] ?? 'AEGIS'

  return (
    <div className="layout">
      <Sidebar />
      <div className="layout-main">
        <Header title={title} />
        <main className="layout-content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
