import { useState, useEffect } from 'react'
import { Button } from '@/components/ui'

// El borrador se guarda en el navegador, no solo en memoria: asi vuelve tambien
// despues de un F5, igual que el objetivo del Spider. Va en sessionStorage y no en
// localStorage a proposito -el estado de sesion es volatil por diseno, apdo. 10-:
// al cerrar la pestana del navegador se va, y no queda en disco una peticion contra
// un objetivo real con sus cabeceras.
const CLAVE_BORRADOR = 'repeater_borrador'

const CABECERAS_POR_DEFECTO = { 'Content-Type': 'application/json' }

// Cabeceras que significan "esta peticion viaja con la sesion de otro". Importa
// ensenarlo: una peticion traida del Spider llega con la cookie y el token del sitio
// auditado, y entonces la respuesta ya no depende solo de la URL y el metodo. Estaban a
// la vista en la lista de cabeceras, pero como una fila mas entre otras.
const CABECERAS_DE_SESION = ['cookie', 'authorization', 'proxy-authorization', 'x-xsrf-token', 'x-csrf-token']

// Acepta tanto un objeto de cabeceras (lo que manda el Spider) como una lista de
// pares (lo que guarda el borrador), y devuelve siempre la lista editable.
function aPares(cabeceras) {
  if (!cabeceras) return null
  if (Array.isArray(cabeceras)) return cabeceras.map(([k, v]) => ({ key: k, value: v }))
  return Object.entries(cabeceras).map(([k, v]) => ({ key: k, value: v }))
}

function leerBorrador() {
  try {
    const crudo = sessionStorage.getItem(CLAVE_BORRADOR)
    return crudo ? JSON.parse(crudo) : null
  } catch {
    return null   // un borrador corrupto no puede impedir usar el Repeater
  }
}

export function RequestEditor({ initialRequest, onSend, onClear, loading, onInicialConsumida }) {
  // Lo que llega del Spider manda sobre el borrador guardado; si no hay nada nuevo,
  // se recupera lo que se estaba editando.
  const partida = initialRequest || leerBorrador()

  const [method, setMethod] = useState(partida?.method || 'GET')
  const [url, setUrl] = useState(partida?.url || '')
  const [headers, setHeaders] = useState(
    aPares(partida?.requestHeaders) || aPares(CABECERAS_POR_DEFECTO)
  )
  const [body, setBody] = useState(partida?.requestBody || '')

  // Guarda segun se escribe. Se guarda el BORRADOR, no la respuesta: una respuesta
  // puede pesar megas y no cabe aqui.
  useEffect(() => {
    const borrador = {
      method,
      url,
      // Pares y no objeto: si no, dos cabeceras con el mismo nombre se fundirian en una
      // al guardar el borrador, igual que pasaba al enviar.
      requestHeaders: headers.filter(h => h.key).map(h => [h.key, h.value]),
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
    setHeaders(aPares(initialRequest.requestHeaders) || aPares(CABECERAS_POR_DEFECTO))
    setBody(initialRequest.requestBody || '')
    // Aplicada y consumida: el padre la descarta. Si siguiera puesta, cada vez que se
    // vuelve a esta pestana el editor se repondria desde ella y `limpiar` no seria
    // definitivo. No se anade a las dependencias a proposito: volveria a entrar aqui en
    // cada render. El unico reentrada posible es con initialRequest ya a null, que sale
    // por el return de arriba.
    onInicialConsumida?.()
  }, [initialRequest])

  const addHeader = () => setHeaders(prev => [...prev, { key: '', value: '' }])
  const removeHeader = (i) => setHeaders(prev => prev.filter((_, idx) => idx !== i))
  const updateHeader = (i, field, val) => setHeaders(prev =>
    prev.map((h, idx) => idx === i ? { ...h, [field]: val } : h)
  )

  const handleSend = () => {
    // Lista de pares, no objeto: `Object.fromEntries` se quedaba solo con la ULTIMA de
    // dos cabeceras con el mismo nombre, asi que la herramienta hacia imposible una
    // prueba habitual -repetir una cabecera- y ademas en silencio.
    const paresCabeceras = headers.filter(h => h.key).map(h => [h.key, h.value])
    onSend({ method, url, headers: paresCabeceras, body: body || null })
  }

  const handleClear = () => {
    setMethod('GET')
    setUrl('')
    setHeaders(aPares(CABECERAS_POR_DEFECTO))
    setBody('')
    try { sessionStorage.removeItem(CLAVE_BORRADOR) } catch { /* nada que borrar */ }
    onClear?.()
  }

  // Quita SOLO las cabeceras de sesion. Probar la misma peticion con y sin sesion es LA
  // operacion que un auditor necesita -es el experimento que costo media manana
  // reconstruir a mano-, y hasta ahora habia que borrarlas una a una: el boton `limpiar`
  // vacia la peticion entera y te deja sin nada que probar.
  const quitarSesion = () => setHeaders(prev =>
    prev.filter(h => !(h.key && CABECERAS_DE_SESION.includes(h.key.trim().toLowerCase())))
  )

  const sesionHeredada = headers
    .filter(h => h.key && CABECERAS_DE_SESION.includes(h.key.trim().toLowerCase()))
    .map(h => h.key.trim())

  const inputStyle = {
    fontFamily: 'var(--font-mono)',
    background: 'var(--hs-bg)',
    borderColor: 'var(--hs-border-hover)',
    color: 'var(--hs-text-secondary)',
  }

  return (
    <div className="flex flex-col gap-4 p-4 h-full overflow-auto">
      {sesionHeredada.length > 0 && (
        <div
          className="px-3 py-2 rounded border"
          style={{ borderColor: '#3d2f10', background: '#1a1405' }}
        >
          <p
            className="text-[10px] tracking-widest uppercase"
            style={{ fontFamily: 'var(--font-mono)', color: '#d9a93a' }}
          >
            {'\u26A0 '}viaja con una sesión heredada
          </p>
          <p
            className="text-[10px] mt-1 leading-relaxed"
            style={{ fontFamily: 'var(--font-mono)', color: '#d9a93a' }}
          >
            Lleva <b>{sesionHeredada.join(', ')}</b>. La respuesta depende de esa sesión y no
            solo de la URL y el método: la misma petición con y sin ella puede dar resultados
            distintos.
          </p>
          <button
            onClick={quitarSesion}
            className="mt-2 text-[10px] px-2 py-0.5 rounded border transition-all"
            style={{ fontFamily: 'var(--font-mono)', color: '#d9a93a', borderColor: '#3d2f10' }}
            title="Quita solo las cabeceras de sesión. El método, la URL, el cuerpo y las demás cabeceras no se tocan"
          >
            quitar la sesión
          </button>
        </div>
      )}
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
        <Button
          size="sm"
          variant="ghost"
          onClick={handleClear}
          title="Vacía la petición y la respuesta. Mantiene el historial."
        >
          limpiar
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
