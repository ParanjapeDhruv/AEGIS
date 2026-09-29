import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import RequireAuth       from './components/RequireAuth'
import Layout            from './components/Layout'
import LoginPage         from './pages/LoginPage'
import RegisterPage      from './pages/RegisterPage'
import DashboardPage     from './pages/DashboardPage'
import UrlAnalysisPage   from './pages/UrlAnalysisPage'
import PhishingPage      from './pages/PhishingPage'
import PasswordPage      from './pages/PasswordPage'
import AssistantPage     from './pages/AssistantPage'
import ScanHistoryPage   from './pages/ScanHistoryPage'
import ReportsPage       from './pages/ReportsPage'
import ProfilePage       from './pages/ProfilePage'

/**
 * ProtectedLayout gates the entire Layout behind auth.
 * RequireAuth redirects to /login when unauthenticated.
 * Layout renders <Outlet /> for child routes.
 */
function ProtectedLayout() {
  return (
    <RequireAuth>
      <Layout />
    </RequireAuth>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public */}
          <Route path="/login"    element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Protected — all nested routes share the Layout shell */}
          <Route element={<ProtectedLayout />}>
            <Route index           element={<DashboardPage />} />
            <Route path="url"      element={<UrlAnalysisPage />} />
            <Route path="phishing" element={<PhishingPage />} />
            <Route path="password" element={<PasswordPage />} />
            <Route path="assistant"element={<AssistantPage />} />
            <Route path="history"  element={<ScanHistoryPage />} />
            <Route path="reports"  element={<ReportsPage />} />
            <Route path="profile"  element={<ProfilePage />} />
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
