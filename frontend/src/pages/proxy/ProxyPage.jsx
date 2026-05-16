import { useState, useEffect } from 'react'
import { useSession } from '@/hooks/useSession'
import { useWebSocket } from '@/hooks/useWebSocket'
import { RequestsTable } from './RequestsTable'
import { RequestDetail } from './RequestDetail'
import { PacOnboarding } from './PacOnboarding'
import { ImportRequest } from './ImportRequest'
import { Button } from '@/components/ui'

export function ProxyPage() {
  const sessionToken = useSession()
  const { requests, connected, clearRequests } = useWebSocket(sessionToken)
  const [selectedRequest, setSelectedRequest] = useState(null)
  const [showOnboarding, setShowOnboarding] = useState(false)
  const [showImport, setShowImport] = useState(false)

  useEffect(() => {
    const seen = localStorage.getItem('hooksuite_pac_configured')
    if (!seen) setShowOnboarding(true)
  }, [])

  const handleOnboardingComplete = () => {
    localStorage.setItem('hooksuite_pac_configured', 'true')
    setShowOnboarding(false)
  }

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center justify-between px-5 py-3 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <div className="flex items-center gap-3">
          <h2
            className="text-[14px] font-bold tracking-wide"
            style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
          >
            Proxy Interceptor
          </h2>
          <span
            className="flex items-center gap-1.5 px-2 py-0.5 rounded border text-[10px]"
            style={{
              fontFamily: 'var(--font-mono)',
              background: connected ? '#0f1f17' : '#13161c',
              borderColor: connected ? '#1e3d2a' : 'var(--hs-border)',
              color: connected ? '#3a7d4f' : 'var(--hs-text-dim)',
            }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full"
              style={{ background: connected ? '#3a7d4f' : 'var(--hs-text-dim)' }}
            />
            {connected ? 'conectado' : 'sin conexión'}
          </span>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="ghost" onClick={() => setShowImport(true)}>importar petición</Button>
          <Button size="sm" variant="ghost" onClick={clearRequests}>limpiar</Button>
          <Button size="sm" variant="ghost" onClick={() => setShowOnboarding(true)}>configurar proxy</Button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div className="w-1/2 border-r overflow-hidden flex flex-col" style={{ borderColor: 'var(--hs-border)' }}>
          <RequestsTable requests={requests} onSelect={setSelectedRequest} selectedId={selectedRequest?.id} />
        </div>
        <div className="w-1/2 overflow-hidden flex flex-col">
          <RequestDetail
            request={selectedRequest}
            onSendToRepeater={(req) => {
              sessionStorage.setItem('repeater_request', JSON.stringify(req))
              window.location.href = '/repeater'
            }}
          />
        </div>
      </div>

      {showOnboarding && <PacOnboarding onComplete={handleOnboardingComplete} />}
      {showImport && (
        <ImportRequest
          onClose={() => setShowImport(false)}
          onImport={(parsed) => {
            sessionStorage.setItem('repeater_request', JSON.stringify(parsed))
            setShowImport(false)
          }}
        />
      )}
    </div>
  )
}