import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from '@/components/layout/Layout'
import { ProxyPage } from '@/pages/proxy/ProxyPage'
import { RepeaterPage } from '@/pages/repeater/RepeaterPage'
import { IntruderPage } from '@/pages/intruder/IntruderPage'
import { UtilitiesPage } from '@/pages/utilities/UtilitiesPage'
import { VulnerabilitiesPage } from '@/pages/vulnerabilities/VulnerabilitiesPage'
import { NetworkPage } from '@/pages/network/NetworkPage'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
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