import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import DashboardPage    from './pages/DashboardPage'
import UrlAnalysisPage  from './pages/UrlAnalysisPage'
import PhishingPage     from './pages/PhishingPage'
import PasswordPage     from './pages/PasswordPage'
import AssistantPage    from './pages/AssistantPage'
import ScanHistoryPage  from './pages/ScanHistoryPage'
import ReportsPage      from './pages/ReportsPage'
import ProfilePage      from './pages/ProfilePage'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index           element={<DashboardPage />} />
          <Route path="url"      element={<UrlAnalysisPage />} />
          <Route path="phishing" element={<PhishingPage />} />
          <Route path="password" element={<PasswordPage />} />
          <Route path="assistant"element={<AssistantPage />} />
          <Route path="history"  element={<ScanHistoryPage />} />
          <Route path="reports"  element={<ReportsPage />} />
          <Route path="profile"  element={<ProfilePage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
