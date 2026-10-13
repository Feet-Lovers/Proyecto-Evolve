import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppContext } from '@/AppContext'
import { RequestsTable } from './RequestsTable'
import { RequestDetail } from './RequestDetail'
import { Button } from '@/components/ui'
import { config, apiFetch } from '@/services/api'

export function ProxyPage() {
  const { sessionToken, spiderEvento, requests, connected, clearRequests, resetWs, activeUrl, setActiveUrl, sessionCookies, setSessionCookies } = useAppContext()
  const [selectedRequest, setSelectedRequest] = useState(null)
  const [targetUrl, setTargetUrl] = useState('')
  const [speed, setSpeed] = useState('normal')
  const [spiderRunning, setSpiderRunning] = useState(false)
  const pollRef = useRef(null)
  const [spiderMessage, setSpiderMessage] = useState('')
  const navigate = useNavigate()

  // El backend distingue completado / detenido a mano / limite alcanzado y manda el
  // recuento de paginas; hasta ahora ese evento se descartaba y se pintaba un texto fijo.
  useEffect(() => {
    if (spiderEvento?.tipo === 'completado' && spiderEvento.mensaje) {
      setSpiderMessage(spiderEvento.mensaje)
      setSpiderRunning(false)
    }
  }, [spiderEvento])

  // Tras un F5 se perdia el objetivo y se podia lanzar otro spider encima, mezclando
  // objetivos en el mismo panel. El backend lo recuerda: se lo preguntamos al montar.
  useEffect(() => {
    if (!sessionToken || activeUrl) return
    apiFetch(`/api/spider/status/${sessionToken}`)
      .then(r => r.json())
      .then(d => { if (d && d.target) setActiveUrl(d.target) })
      .catch(() => {})
  }, [sessionToken])

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
      const res = await apiFetch(`/api/spider/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json()
      if (data.status === 'started') {
        const poll = setInterval(async () => {
          const r = await apiFetch(`/api/spider/status/${sessionToken}`)
          const s = await r.json()
          if (!s.running) {
            clearInterval(poll)
            pollRef.current = null
            setSpiderRunning(false)
            setSpiderMessage(prev =>
                          prev === 'Deteniendo el spider...' ? 'Spider detenido'
                          : /p[áa]ginas/.test(prev) ? prev
                          : 'Spider finalizado')
          }
        }, 2000)
        pollRef.current = poll
      }
    } catch (e) {
      setSpiderRunning(false)
      setSpiderMessage('Error al iniciar el spider')
    }
  }

  // Al salir de la pantalla, cortar el sondeo de estado: si no, sigue pidiendo
  // /spider/status cada 2 s aunque ya no haya nadie mirando.
  useEffect(() => () => {
    if (pollRef.current) clearInterval(pollRef.current)
  }, [])

  // Detener el rastreo en curso. El backend corta el bucle en la siguiente
  // iteracion; el sondeo de estado confirma la parada y pone el mensaje final.
  const handleStopSpider = async () => {
    setSpiderMessage('Deteniendo el spider...')
    try {
      await apiFetch(`/api/spider/stop/${sessionToken}`, { method: 'POST' })
    } catch (e) {
      setSpiderMessage('Error al detener el spider')
    }
  }

  const handleNewAudit = async () => {
    try {
      await apiFetch(`/api/spider/reset/${sessionToken}`, {
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
      await apiFetch(`/api/spider/release-session/${sessionToken}`, {
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
              Spider
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
        {activeUrl && (
          <div className="flex items-center gap-3 px-3 py-1.5 rounded" style={{ background: 'var(--hs-bg)', border: '1px solid var(--hs-border)' }}>
            <div className="flex items-center gap-2 flex-1">
              {Object.keys(sessionCookies).length > 0 ? (
                <>
                  <span className="w-2 h-2 rounded-full" style={{ background: '#3a7d4f', flexShrink: 0 }} />
                  <span className="text-[10px] truncate" style={{ fontFamily: 'var(--font-mono)', color: '#3a7d4f' }}>
                    {'con sesión · ' + Object.keys(sessionCookies).join(', ')}
                  </span>
                </>
              ) : (
                <>
                  <span className="w-2 h-2 rounded-full" style={{ background: 'var(--hs-text-dim)', flexShrink: 0 }} />
                  <span className="text-[10px]" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
                    sin cookies de sesión
                  </span>
                </>
              )}
            </div>
            {Object.keys(sessionCookies).length > 0 && (
              <button
                onClick={handleReleaseSession}
                title="Suelta las cookies de sesión. Mantiene las peticiones capturadas y el objetivo."
                className="text-[9px] px-2 py-0.5 rounded"
                style={{ background: 'var(--hs-surface)', border: '1px solid var(--hs-accent)', color: 'var(--hs-accent)', cursor: 'pointer', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)' }}
              >
                liberar sesion
              </button>
            )}
          </div>
        )}
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            placeholder="URL objetivo (ej: https://ejemplo.com)"
            title={activeUrl ? "Objetivo fijado para esta auditoría. Pulsa «nueva auditoria» para cambiarlo." : "URL del sitio que se va a rastrear"}
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
            title="Máximo de páginas que visita el spider. Cada página puede generar varias peticiones en el panel, una por cada formulario."
            value={speed}
            onChange={e => setSpeed(e.target.value)}
            className="px-2 py-1.5 rounded text-[12px]"
            style={{
              background: 'var(--hs-bg)',
              border: '1px solid var(--hs-border)',
              color: 'var(--hs-text-primary)',
            }}
          >
            <option value="rapido">hasta 50 páginas</option>
            <option value="normal">hasta 200 páginas</option>
            <option value="completo">hasta 500 páginas</option>
          </select>
          <Button
            size="sm"
            onClick={handleStartSpider}
            disabled={spiderRunning || (!activeUrl && !targetUrl.trim())}
          >
            {spiderRunning ? 'Ejecutando...' : 'Iniciar spider'}
          </Button>
          {spiderRunning && (
            <Button size="sm" variant="danger" onClick={handleStopSpider}>
              Detener
            </Button>
          )}
        </div>

        {activeUrl && (
          <span className="text-[11px]" style={{ color: "var(--hs-text-dim)", fontFamily: "var(--font-mono)" }}>
            objetivo fijado · pulsa «nueva auditoria» para cambiarlo
          </span>
        )}

        {spiderMessage && (
          <span className="text-[11px]" style={{ color: 'var(--hs-text-dim)', fontFamily: 'var(--font-mono)' }}>
            {spiderMessage}
          </span>
        )}

      </div>

      <div className="flex flex-1 overflow-hidden">
        <div className="w-1/2 border-r overflow-hidden flex flex-col" style={{ borderColor: 'var(--hs-border)' }}>
          <div className="flex items-center gap-2 px-3 py-2 border-b" style={{ borderColor: 'var(--hs-border)' }}>
              <Button size="sm" variant="ghost" title="Vacía la lista de peticiones y detiene el spider. Mantiene la sesión y el objetivo." onClick={async () => {
                await apiFetch(`/api/spider/clear/${sessionToken}`, { method: 'POST' })
                clearRequests()
                setSelectedRequest(null)
                setSpiderMessage('')
              }}>limpiar</Button>
              <Button size="sm" variant="danger" title="Empieza de cero: vacía la lista, suelta la sesión y libera el campo de URL." onClick={handleNewAudit}>nueva auditoria</Button>
          </div>
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

    </div>
  )
}
