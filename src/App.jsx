import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from '@/components/layout/Layout'
import { ProxyPage } from '@/pages/proxy/ProxyPage'
import { RepeaterPage } from '@/pages/repeater/RepeaterPage'
import { IntruderPage } from '@/pages/intruder/IntruderPage'
import { UtilitiesPage } from '@/pages/utilities/UtilitiesPage'
import { VulnerabilitiesPage } from '@/pages/vulnerabilities/VulnerabilitiesPage'
import { NetworkPage } from '@/pages/network/NetworkPage'
import { LoginPage } from '@/pages/auth/LoginPage'
import { useAuth } from '@/hooks/useAuth'

export default function App() {
  const { uid, proxyPort, login, logout, loading, error } = useAuth()

  if (!uid) {
    return <LoginPage onLogin={login} loading={loading} error={error} />
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout onLogout={logout} proxyPort={proxyPort} />}>
          <Route index element={<Navigate to="/proxy" replace />} />
          <Route path="proxy" element={<ProxyPage />} />
          <Route path="repeater" element={<RepeaterPage />} />
          <Route path="intruder" element={<IntruderPage />} />
          <Route path="utilities" element={<UtilitiesPage />} />
          <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="network" element={<NetworkPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}