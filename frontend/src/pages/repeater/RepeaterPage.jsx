import { useState, useEffect } from 'react'
import { RequestEditor } from './RequestEditor'
import { ResponsePanel } from './ResponsePanel'
import { api, config } from '@/services/api'
import { useAppContext } from '@/AppContext'

function normalizeResponse(data) {
  return {
    ...data,
    body: data.body || data.response_body || '',
    headers: data.headers || data.response_headers || {},
    time: data.time || 0,
    size: data.size || 0,
    status: data.status || 0,
  }
}

// Replica el criterio de color de ResponsePanel. Se duplica a proposito y no se exporta:
// a un dia de la congelacion no se toca un fichero ya cerrado solo por esto. Si algun dia
// cambia el criterio, hay que cambiarlo en los dos sitios.
function colorEstado(status) {
  if (status >= 200 && status < 300) return '#4a9a5a'
  if (status >= 400) return '#ef5a5a'
  return '#dfc050'
}

// El timestamp es un Date mientras la entrada vive en memoria y una cadena ISO cuando
// viene de sessionStorage tras un F5. new Date() traga las dos.
function hora(ts) {
  try { return new Date(ts).toLocaleTimeString('es-ES', { hour12: false }) } catch { return '' }
}
export function RepeaterPage() {
  const {
    sessionToken,
    repeaterResponse: response, setRepeaterResponse: setResponse,
    repeaterHistory: history, setRepeaterHistory: setHistory,
    repeaterLastUrl: lastUrl, setRepeaterLastUrl: setLastUrl,
  } = useAppContext()
  const [initialRequest, setInitialRequest] = useState(null)
  const [loading, setLoading] = useState(false)
  const [histOpen, setHistOpen] = useState(false)
  const [confirmaVaciar, setConfirmaVaciar] = useState(false)

  useEffect(() => {
    const stored = sessionStorage.getItem('repeater_request')
    if (stored) {
      setInitialRequest(JSON.parse(stored))
      sessionStorage.removeItem('repeater_request')
    }
  }, [])

  // Pulsar una fila del historial devuelve la peticion al editor (izquierda) y su
  // respuesta al panel (derecha).
  //
  // La traduccion de nombres NO es cosmetica: el editor ENVIA { method, url, headers,
  // body } pero LEE de initialRequest { requestHeaders, requestBody } —ese formato nacio
  // para recibir paquetes del Proxy, que vienen normalizados—. Pasarle el objeto enviado
  // tal cual cargaria metodo y URL y perderia cabeceras y cuerpo EN SILENCIO.
  //
  // Y se construye un objeto NUEVO cada vez a proposito: el useEffect del editor depende
  // de la identidad de initialRequest, asi que reutilizarlo no volveria a dispararlo y
  // pulsar dos veces la misma fila no haria nada.
  const cargarDelHistorial = (entrada) => {
    const r = entrada.request || {}
    setInitialRequest({
      method: r.method,
      url: r.url,
      requestHeaders: r.headers,   // ya es lista de pares; aPares() la acepta
      requestBody: r.body || '',
    })
    setResponse(entrada.response || null)
    setLastUrl(r.url || '')
    setHistOpen(false)
  }

  // Borrar NO necesita tocar sessionStorage: el guardado esta atado a los cambios del
  // historial, asi que lo que se quita de la lista desaparece tambien de lo persistido y
  // no reaparece tras un F5.
  const borrarEntrada = (i) => setHistory(prev => prev.filter((_, j) => j !== i))

  const vaciarHistorial = () => {
    setHistory([])
    setConfirmaVaciar(false)
  }
  const handleSend = async (request) => {
    setLoading(true)
    setLastUrl(request.url || '')
    try {
      const res = await api.post(`/api/repeater/send`, {
        ...request,
        session_token: sessionToken,
      })
      const normalized = normalizeResponse(res.data)
      setResponse(normalized)
      setHistory(prev => [{ request, response: normalized, timestamp: new Date() }, ...prev.slice(0, 99)])
    } catch (e) {
      setResponse({ status: 0, time: 0, size: 0, body: 'Error: ' + e.message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center justify-between px-5 py-3 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <h2
          className="text-[14px] font-bold tracking-wide"
          style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
        >
          Repeater
        </h2>
        <div className="flex items-center gap-3">
          {/* El contador ERA el defecto: decia cuantas habia y no habia forma de abrirlo.
              Ahora es el propio boton que las abre. */}
          <button
            onClick={() => { setConfirmaVaciar(false); setHistOpen(v => !v) }}
            disabled={history.length === 0}
            className="text-[10px] px-2 py-0.5 rounded border transition-all"
            style={{
              fontFamily: 'var(--font-mono)',
              color: history.length === 0 ? 'var(--hs-text-dim)' : 'var(--hs-accent)',
              background: histOpen ? 'var(--hs-accent-bg)' : 'transparent',
              borderColor: histOpen ? 'var(--hs-accent-border)' : 'transparent',
              cursor: history.length === 0 ? 'default' : 'pointer',
            }}
            title={history.length === 0
              ? 'Todavia no has enviado ninguna peticion'
              : 'Ver las peticiones enviadas en esta sesion'}
          >
            {history.length} peticiones en historial
            {history.length > 0 && (histOpen ? ' \u25BE' : ' \u25B8')}
          </button>
        </div>
      </div>
      {histOpen && history.length > 0 && (
        <div className="border-b" style={{ background: 'var(--hs-bg)', borderColor: 'var(--hs-border)' }}>
          {/* El boton de vaciar NO borra al primer clic: se arma y pide un segundo. Borrar
              cien peticiones no tiene vuelta atras y no debe irse en un clic distraido. No se
              usa el dialogo del navegador porque bloquea y es ajeno a esta interfaz. Abrir o
              cerrar el panel lo desarma. */}
          <div
            className="flex items-center justify-between px-5 py-1 border-b"
            style={{ borderColor: 'var(--hs-border)' }}
          >
            <span
              className="text-[10px] tracking-widest uppercase"
              style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
            >
              historial de esta sesión
            </span>
            <button
              onClick={() => (confirmaVaciar ? vaciarHistorial() : setConfirmaVaciar(true))}
              className="text-[10px] px-2 py-0.5 rounded border transition-all"
              style={{
                fontFamily: 'var(--font-mono)',
                // Rojo del sistema (variante `danger` del Badge): el borrado se tiene que
                // ver. En reposo basta el texto; armado se enciende el bloque entero.
                color: '#ef5a5a',
                borderColor: confirmaVaciar ? '#4d1515' : 'transparent',
                background: confirmaVaciar ? '#1f0a0a' : 'transparent',
              }}
              title={confirmaVaciar
                ? 'Pulsa otra vez para borrar todo el historial'
                : 'Borrar todas las peticiones del historial'}
            >
              {confirmaVaciar ? '¿seguro? pulsa otra vez' : 'vaciar'}
            </button>
          </div>
          <div className="overflow-auto" style={{ maxHeight: '11rem' }}>
            {history.map((h, i) => (
              /* La fila es un contenedor y no un boton: dentro va la zona pulsable y la ✕,
                 y un boton dentro de otro boton no es HTML valido. */
              <div
                key={i}
                className="flex items-center border-b"
                style={{ borderColor: 'var(--hs-border)' }}
              >
                <button
                  onClick={() => cargarDelHistorial(h)}
                  className="flex-1 min-w-0 flex items-center gap-3 px-5 py-1.5 text-left"
                  title="Cargar esta petición en el editor"
                >
                  <span
                    className="min-w-[56px] text-[10px] font-bold"
                    style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-secondary)' }}
                  >
                    {h.request?.method}
                  </span>
                  <span
                    className="flex-1 truncate text-[10px]"
                    style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-secondary)' }}
                  >
                    {h.request?.url}
                  </span>
                  <span
                    className="text-[10px] font-bold"
                    style={{ fontFamily: 'var(--font-mono)', color: colorEstado(h.response?.status) }}
                  >
                    {h.response?.status}
                  </span>
                  <span
                    className="min-w-[52px] text-right text-[10px]"
                    style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
                  >
                    {h.response?.time}ms
                  </span>
                  <span
                    className="text-[10px]"
                    style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
                  >
                    {hora(h.timestamp)}
                  </span>
                </button>
                <button
                  onClick={() => borrarEntrada(i)}
                  className="px-3 py-1.5 text-[11px] shrink-0"
                  style={{ color: '#ef5a5a' }}
                  title="Quitar esta petición del historial"
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">
        <div className="w-1/2 border-r overflow-hidden flex flex-col" style={{ borderColor: 'var(--hs-border)' }}>
          <RequestEditor
            initialRequest={initialRequest}
            onSend={handleSend}
            onClear={() => { setResponse(null); setLastUrl('') }}
            loading={loading}
          />
        </div>
        <div className="w-1/2 overflow-hidden flex flex-col">
          <ResponsePanel response={response} requestUrl={lastUrl} />
        </div>
      </div>
    </div>
  )
}
