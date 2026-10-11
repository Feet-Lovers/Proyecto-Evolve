import { useState, useEffect } from 'react'
import { Button } from '@/components/ui'

// El borrador se guarda en el navegador, no solo en memoria: asi vuelve tambien
// despues de un F5, igual que el objetivo del Spider. Va en sessionStorage y no en
// localStorage a proposito -el estado de sesion es volatil por diseno, apdo. 10-:
// al cerrar la pestana del navegador se va, y no queda en disco una peticion contra
// un objetivo real con sus cabeceras.
const CLAVE_BORRADOR = 'repeater_borrador'

const CABECERAS_POR_DEFECTO = { 'Content-Type': 'application/json' }

function leerBorrador() {
  try {
    const crudo = sessionStorage.getItem(CLAVE_BORRADOR)
    return crudo ? JSON.parse(crudo) : null
  } catch {
    return null   // un borrador corrupto no puede impedir usar el Repeater
  }
}

export function RequestEditor({ initialRequest, onSend, loading }) {
  // Lo que llega del Spider manda sobre el borrador guardado; si no hay nada nuevo,
  // se recupera lo que se estaba editando.
  const partida = initialRequest || leerBorrador()

  const [method, setMethod] = useState(partida?.method || 'GET')
  const [url, setUrl] = useState(partida?.url || '')
  const [headers, setHeaders] = useState(
    Object.entries(partida?.requestHeaders || CABECERAS_POR_DEFECTO)
      .map(([k, v]) => ({ key: k, value: v }))
  )
  const [body, setBody] = useState(partida?.requestBody || '')

  // Guarda segun se escribe. Se guarda el BORRADOR, no la respuesta: una respuesta
  // puede pesar megas y no cabe aqui.
  useEffect(() => {
    const borrador = {
      method,
      url,
      requestHeaders: Object.fromEntries(headers.filter(h => h.key).map(h => [h.key, h.value])),
      requestBody: body,
    }
    try {
      sessionStorage.setItem(CLAVE_BORRADOR, JSON.stringify(borrador))
    } catch { /* sin sitio en el navegador se sigue trabajando, solo se pierde al navegar */ }
  }, [method, url, headers, body])

  useEffect(() => {
    if (!initialRequest) return
    setMethod(initialRequest.method || 'GET')
    setUrl(initialRequest.url || '')
    setHeaders(
      Object.entries(initialRequest.requestHeaders || CABECERAS_POR_DEFECTO)
        .map(([k, v]) => ({ key: k, value: v }))
    )
    setBody(initialRequest.requestBody || '')
  }, [initialRequest])

  const addHeader = () => setHeaders(prev => [...prev, { key: '', value: '' }])
  const removeHeader = (i) => setHeaders(prev => prev.filter((_, idx) => idx !== i))
  const updateHeader = (i, field, val) => setHeaders(prev =>
    prev.map((h, idx) => idx === i ? { ...h, [field]: val } : h)
  )

  const handleSend = () => {
    const headersObj = Object.fromEntries(headers.filter(h => h.key).map(h => [h.key, h.value]))
    onSend({ method, url, headers: headersObj, body: body || null })
  }

  const inputStyle = {
    fontFamily: 'var(--font-mono)',
    background: 'var(--hs-bg)',
    borderColor: 'var(--hs-border-hover)',
    color: 'var(--hs-text-secondary)',
  }

  return (
    <div className="flex flex-col gap-4 p-4 h-full overflow-auto">
      <div className="flex gap-2">
        <select
          value={method}
          onChange={e => setMethod(e.target.value)}
          className="px-3 py-2 rounded border outline-none text-[11px] cursor-pointer"
          style={inputStyle}
        >
          {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
        <input
          type="text"
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="https://objetivo.com/endpoint"
          className="flex-1 px-3 py-2 rounded border outline-none text-[11px]"
          style={inputStyle}
        />
        <Button onClick={handleSend} disabled={loading || !url}>
          {loading ? 'enviando...' : 'enviar'}
        </Button>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <p className="text-[10px] tracking-widest uppercase" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
            headers
          </p>
          <Button size="sm" variant="ghost" onClick={addHeader}>+ añadir</Button>
        </div>
        <div className="space-y-1.5">
          {headers.map((h, i) => (
            <div key={i} className="flex gap-2">
              <input
                placeholder="nombre"
                value={h.key}
                onChange={e => updateHeader(i, 'key', e.target.value)}
                className="w-1/3 px-2 py-1.5 rounded border outline-none text-[10px]"
                style={inputStyle}
              />
              <input
                placeholder="valor"
                value={h.value}
                onChange={e => updateHeader(i, 'value', e.target.value)}
                className="flex-1 px-2 py-1.5 rounded border outline-none text-[10px]"
                style={inputStyle}
              />
              <button
                onClick={() => removeHeader(i)}
                className="px-2 text-[11px] transition-colors"
                style={{ color: 'var(--hs-text-dim)' }}
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      </div>

      <div>
        <p className="text-[10px] tracking-widest uppercase mb-2" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
          body
        </p>
        <textarea
          value={body}
          onChange={e => setBody(e.target.value)}
          placeholder="body de la petición (JSON, form data, etc.)"
          className="w-full h-32 px-3 py-2 rounded border outline-none resize-none text-[10px]"
          style={inputStyle}
        />
      </div>
    </div>
  )
}
