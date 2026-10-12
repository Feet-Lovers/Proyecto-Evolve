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

// Numero del ultimo envio. Vive FUERA del componente A PROPOSITO: la pantalla se desmonta
// al cambiar de pestana y un useRef se reiniciaria, que es justo cuando se cuela el fallo.
// Sirve para que una respuesta que llega tarde no pise la que estas mirando.
// Campos ocultos de un formulario HTML. Se leen TODOS (no solo `_token`) para que esto
// valga con cualquier framework: Laravel usa `_token`, Rails `authenticity_token`, otros
// `csrf_token`. Lo que tengan en comun es que van en <input type="hidden">.
function extraerOcultos(html) {
  const ocultos = {}
  for (const tag of (html || '').match(/<input\b[^>]*>/gi) || []) {
    const tipo = (tag.match(/type\s*=\s*["']([^"']+)["']/i) || [])[1]
    if (!tipo || tipo.toLowerCase() !== 'hidden') continue
    const nombre = (tag.match(/name\s*=\s*["']([^"']+)["']/i) || [])[1]
    const valor = (tag.match(/value\s*=\s*["']([^"']*)["']/i) || [])[1]
    if (nombre && valor !== undefined) ocultos[nombre] = valor
  }
  return ocultos
}

// Cookies de una cabecera Set-Cookie. El backend las entrega unidas por coma, y las fechas
// de caducidad TAMBIEN llevan comas, asi que se toma solo el primer par de cada trozo y se
// descartan los atributos conocidos. Si algo no encaja se ignora: preferible no tocar la
// cookie a corromperla.
const ATRIBUTOS_COOKIE = ['expires', 'path', 'domain', 'max-age', 'samesite', 'secure', 'httponly', 'version', 'comment']
function cookiesDeSetCookie(cabeceras) {
  const bruto = (cabeceras || {})['set-cookie'] || (cabeceras || {})['Set-Cookie'] || ''
  const out = {}
  for (const trozo of String(bruto).split(',')) {
    const primero = trozo.split(';')[0].trim()
    const i = primero.indexOf('=')
    if (i <= 0) continue
    const k = primero.slice(0, i).trim()
    if (!k || ATRIBUTOS_COOKIE.includes(k.toLowerCase())) continue
    out[k] = primero.slice(i + 1).trim()
  }
  return out
}

let _ultimoEnvio = 0

export function RepeaterPage() {
  const {
    repeaterResponse: response, setRepeaterResponse: setResponse,
    repeaterLastUrl: lastUrl, setRepeaterLastUrl: setLastUrl,
  } = useAppContext()
  const [initialRequest, setInitialRequest] = useState(null)
  const [loading, setLoading] = useState(false)
  // De que pagina cuelga el formulario (lo guarda el Spider) y el HTML que se trajo la
  // ultima preparacion, para poder verlo sin reenviar nada.
  const [urlFormulario, setUrlFormulario] = useState(null)
  const [formulario, setFormulario] = useState(null)

  useEffect(() => {
    const stored = sessionStorage.getItem('repeater_request')
    if (stored) {
      const paquete = JSON.parse(stored)
      setInitialRequest(paquete)
      setUrlFormulario(paquete.pagina_origen || null)
      sessionStorage.removeItem('repeater_request')
    }
  }, [])

  // "Preparar" hace lo que hace un navegador antes de enviar un formulario: pedir la
  // pagina. De ahi salen el token fresco y, si el servidor la cambia, la cookie nueva.
  //
  // Hace falta porque la peticion que trae el Spider NO es una peticion capturada: es una
  // plantilla leida del HTML, con el token que habia en ese momento. Nace vieja, y al
  // enviarla el servidor la rechaza o la rebota.
  //
  // Se usa el mismo endpoint de envio: no hay nada nuevo en el backend.
  const prepararPeticion = async (peticion) => {
    const url = urlFormulario || peticion.url
    const res = await api.post(`/api/repeater/send`, { method: 'GET', url, headers: peticion.headers })
    const r = normalizeResponse(res.data)
    setFormulario({ url, html: r.body || '', status: r.status })
    return { ocultos: extraerOcultos(r.body), cookies: cookiesDeSetCookie(r.headers) }
  }

  const handleSend = async (request) => {
    const miEnvio = ++_ultimoEnvio
    setLoading(true)
    setLastUrl(request.url || '')
    try {
      // Sin `session_token` en el cuerpo. El backend NO lo lee desde el 6-oct: el espacio
      // sale del token firmado (`Depends(usuario_actual)` en routes/repeater.py). Mandarlo
      // era residuo, y del malo: sugiere que el cliente puede elegir espacio, que es
      // justo el hueco de autorizacion que se cerro ese dia.
      const res = await api.post(`/api/repeater/send`, request)
      const normalized = normalizeResponse(res.data)
      if (miEnvio !== _ultimoEnvio) return   // llego tarde: ya hay otro envio mas reciente
      setResponse(normalized)
    } catch (e) {
      // Un fallo de red NO es una respuesta. Se marca para que el panel no lo pinte como
      // un "estado 0", que parece un codigo HTTP cuando no existe ninguno.
      if (miEnvio !== _ultimoEnvio) return   // un error viejo tampoco debe pisar
      setResponse({ status: 0, time: 0, size: 0, errorDeRed: true, body: 'No hubo respuesta: ' + e.message })
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
      </div>
      <div className="flex flex-1 overflow-hidden">
        <div className="w-1/2 border-r overflow-hidden flex flex-col" style={{ borderColor: 'var(--hs-border)' }}>
          {/* `onInicialConsumida`: una vez el editor ha aplicado la peticion inicial, se
              descarta. Si se queda puesta, el editor se repone desde ella cada vez que
              vuelves a esta pestana y `limpiar` deja de ser definitivo: reaparecen la
              peticion y sus cabeceras heredadas. Asi vuelve a ser lo que era antes del
              historial: una orden de un solo uso. Lo que se conserva al volver es el
              BORRADOR, que es lo ultimo que estabas editando. */}
          <RequestEditor
            initialRequest={initialRequest}
            onInicialConsumida={() => setInitialRequest(null)}
            onSend={handleSend}
            onPreparar={prepararPeticion}
            onClear={() => { setResponse(null); setLastUrl('') }}
            loading={loading}
          />
        </div>
        <div className="w-1/2 overflow-hidden flex flex-col">
          <ResponsePanel response={response} requestUrl={lastUrl} formulario={formulario} />
        </div>
      </div>
    </div>
  )
}
