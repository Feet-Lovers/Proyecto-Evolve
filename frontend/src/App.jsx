import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AppProvider } from '@/AppContext'
import { AuthProvider, useAuth } from '@/AuthContext'
import { LoginPage } from '@/pages/auth/LoginPage'
import { Layout } from '@/components/layout/Layout'
import { ProxyPage } from '@/pages/proxy/ProxyPage'
import { RepeaterPage } from '@/pages/repeater/RepeaterPage'
import { IntruderPage } from '@/pages/intruder/IntruderPage'
import { UtilitiesPage } from '@/pages/utilities/UtilitiesPage'
import { VulnerabilitiesPage } from '@/pages/vulnerabilities/VulnerabilitiesPage'
import { NetworkPage } from '@/pages/network/NetworkPage'

/** Decide qué se ve: el panel de entrada o la herramienta.
 *
 *  `AppProvider` se monta DENTRO del área autenticada a propósito: abre el WebSocket
 *  y pide datos de sesión, y no tiene sentido que haga nada mientras no haya usuario.
 *  Montarlo fuera abriría un socket sin identidad en cada carga de la página.
 */
function Puerta() {
  const { estado } = useAuth()

  if (estado === 'comprobando') {
    // Pantalla sobria mientras se comprueba el token guardado: sin esto se vería el
    // formulario de entrada un instante aunque la sesión siga siendo válida.
    return <div className="min-h-screen bg-[#090a0d]" />
  }

  if (estado !== 'dentro') return <LoginPage />

  return (
    <AppProvider>
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
    </AppProvider>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <Puerta />
    </AuthProvider>
  )
}
