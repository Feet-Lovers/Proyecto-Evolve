import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppContext } from '@/AppContext'
import { RequestsTable } from './RequestsTable'
import { RequestDetail } from './RequestDetail'
import { ImportRequest } from './ImportRequest'
import { Button } from '@/components/ui'
import { config } from '@/services/api'

export function ProxyPage() {
  const { sessionToken, requests, connected, clearRequests, resetWs, activeUrl, setActiveUrl, sessionCookies, setSessionCookies } = useAppContext()
  const [selectedRequest, setSelectedRequest] = useState(null)
  const [showImport, setShowImport] = useState(false)
  const [targetUrl, setTargetUrl] = useState('')
  const [speed, setSpeed] = useState('normal')
  const [spiderRunning, setSpiderRunning] = useState(false)
  const [spiderMessage, setSpiderMessage] = useState('')
  const navigate = useNavigate()

  const handleStartSpider = async () => {
    const urlToUse = activeUrl || targetUrl.trim()
    if (!urlToUse) return
    setActiveUrl(urlToUse)
    setSpiderRunning(true)
    setSpiderMessage('Spider en ejecucion...')
    try {
      const body = {
        url: urlToUse,
        session_token: sessionToken,
        speed: speed,
      }
      const res = await fetch(`${config.API_BASE}/api/spider/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json()
      if (data.status === 'started') {
        const poll = setInterval(async () => {
          const r = await fetch(`${config.API_BASE}/api/spider/status/${sessionToken}`)
          const s = await r.json()
          if (!s.running) {
            clearInterval(poll)
            setSpiderRunning(false)
            setSpiderMessage('Spider completado')
          }
        }, 2000)
      }
    } catch (e) {
      setSpiderRunning(false)
      setSpiderMessage('Error al iniciar el spider')
    }
  }

  const handleNewAudit = async () => {
    try {
      await fetch(`${config.API_BASE}/api/spider/reset/${sessionToken}`, {
        method: 'POST',
      })
      clearRequests()
      setSelectedRequest(null)
      setTargetUrl('')
      setSpiderMessage('')
      setActiveUrl(null)
      setSessionCookies({})
      resetWs()
    } catch (e) {
      console.error('Error al resetear sesion', e)
    }
  }

  const handleReleaseSession = async () => {
    try {
      await fetch(`${config.API_BASE}/api/spider/release-session/${sessionToken}`, {
        method: 'POST',
      })
      setSessionCookies({})
    } catch (e) {
      console.error('Error al liberar sesion', e)
    }
  }

  const handleSendToRepeater = (req) => {
    sessionStorage.setItem('repeater_request', JSON.stringify(req))
    navigate('/repeater')
  }

  const handleSendToIntruder = (req) => {
    sessionStorage.setItem('intruder_request', JSON.stringify(req))
    navigate('/intruder')
  }

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex flex-col gap-3 px-5 py-3 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <div className="flex items-center justify-between">
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
              {connected ? 'conectado' : 'sin conexion'}
            </span>
          </div>
          <div className="flex gap-2">
            <Button size="sm" variant="ghost" onClick={() => setShowImport(true)}>importar peticion</Button>
            <Button size="sm" variant="ghost" onClick={async () => {
              await fetch(`${config.API_BASE}/api/spider/clear/${sessionToken}`, { method: 'POST' })
              clearRequests()
              setSelectedRequest(null)
              setSpiderMessage('')
            }}>limpiar</Button>
            <Button size="sm" variant="danger" onClick={handleNewAudit}>nueva auditoria</Button>
          </div>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            placeholder="URL objetivo (ej: http://dvwa)"
            value={activeUrl || targetUrl}
            onChange={e => !activeUrl && setTargetUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !spiderRunning && !activeUrl && handleStartSpider()}
            readOnly={!!activeUrl}
            className="flex-1 px-3 py-1.5 rounded text-[12px]"
            style={{
              background: activeUrl ? 'var(--hs-surface)' : 'var(--hs-bg)',
              border: `1px solid ${activeUrl ? 'var(--hs-accent)' : 'var(--hs-border)'}`,
              color: 'var(--hs-text-primary)',
              fontFamily: 'var(--font-mono)',
              opacity: activeUrl ? 0.8 : 1,
            }}
          />
          <select
            value={speed}
            onChange={e => setSpeed(e.target.value)}
            className="px-2 py-1.5 rounded text-[12px]"
            style={{
              background: 'var(--hs-bg)',
              border: '1px solid var(--hs-border)',
              color: 'var(--hs-text-primary)',
            }}
          >
            <option value="rapido">Rapido (50)</option>
            <option value="normal">Normal (200)</option>
            <option value="completo">Completo (500)</option>
          </select>
          <Button
            size="sm"
            onClick={handleStartSpider}
            disabled={spiderRunning || (!activeUrl && !targetUrl.trim())}
          >
            {spiderRunning ? 'Ejecutando...' : 'Iniciar spider'}
          </Button>
        </div>

        {spiderMessage && (
          <span className="text-[11px]" style={{ color: 'var(--hs-text-dim)', fontFamily: 'var(--font-mono)' }}>
            {spiderMessage}
          </span>
        )}

        {activeUrl && (
          <div className="flex items-center gap-3 px-3 py-1.5 rounded" style={{ background: 'var(--hs-bg)', border: '1px solid var(--hs-border)' }}>
            <div className="flex items-center gap-2 flex-1">
              {Object.keys(sessionCookies).length > 0 ? (
                <>
                  <span className="w-2 h-2 rounded-full" style={{ background: '#3a7d4f', flexShrink: 0 }} />
                  <span className="text-[10px] truncate" style={{ fontFamily: 'var(--font-mono)', color: '#3a7d4f' }}>
                    {Object.entries(sessionCookies).map(([k, v]) => `${k}=${v}`).join('; ')}
                  </span>
                </>
              ) : (
                <>
                  <span className="w-2 h-2 rounded-full" style={{ background: 'var(--hs-text-dim)', flexShrink: 0 }} />
                  <span className="text-[10px]" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
                    sin autenticar
                  </span>
                </>
              )}
            </div>
            {Object.keys(sessionCookies).length > 0 && (
              <button
                onClick={handleReleaseSession}
                className="text-[9px] px-2 py-0.5 rounded"
                style={{ background: 'var(--hs-surface)', border: '1px solid var(--hs-accent)', color: 'var(--hs-accent)', cursor: 'pointer', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)' }}
              >
                liberar sesion
              </button>
            )}
          </div>
        )}
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div className="w-1/2 border-r overflow-hidden flex flex-col" style={{ borderColor: 'var(--hs-border)' }}>
          <RequestsTable requests={requests} onSelect={setSelectedRequest} selectedId={selectedRequest?.id} />
        </div>
        <div className="w-1/2 overflow-hidden flex flex-col">
          <RequestDetail
            request={selectedRequest}
            onSendToRepeater={handleSendToRepeater}
            onSendToIntruder={handleSendToIntruder}
          />
        </div>
      </div>

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
