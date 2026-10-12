import { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react'
import { api, config, leerToken } from '@/services/api'
import { useAuth } from '@/AuthContext'
import { mockRequests, mockVulnerabilities } from '@/services/mockData'

const WS_URL = config.API_BASE
  ? `${config.API_BASE.replace(/^http/, 'ws')}/ws`
  : `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`  // '' = mismo origen (Nginx /ws)

// Aqui vivia un generador de UUID con Math.random() que fabricaba el identificador de
// sesion EN EL NAVEGADOR y lo guardaba en localStorage; el servidor se lo creia y
// abria una sesion para cualquier cadena que llegara. Dos problemas de distinta
// gravedad: Math.random() no es criptograficamente seguro, y —lo serio— el cliente no
// deberia poder elegir en que espacio de datos escribe. Ahora el espacio lo determina
// el usuario del token, que emite y firma el servidor.
const CLAVE_SESION_ANTIGUA = 'hooksuite_session'

// El historial del Repeater vive en el NAVEGADOR, no en el servidor. El backend no
// guarda las peticiones del Repeater: `routes/repeater.py` llama a `forward_request` y
// devuelve el resultado sin guardarlo, asi que no hay nada que recuperar de alli.
const CLAVE_HISTORIAL = 'repeater_historial'

// Cabeceras que NO se guardan en el navegador. En una herramienta de auditoria estas
// llevan credenciales del SITIO AUDITADO (la cookie de sesion, el token CSRF), y
// persistirlas dejaria las credenciales de otro en el almacenamiento del navegador,
// legibles por cualquier codigo que corra en esta pagina: justo el riesgo que cerro el
// sandbox="" de la vista previa. La peticion recuperada tras un F5 se puede volver a
// lanzar, pero sin sesion: habra que anadirla a mano.
const CABECERAS_QUE_NO_SE_GUARDAN = ['cookie', 'authorization', 'proxy-authorization', 'x-xsrf-token', 'x-csrf-token']

// Identificador estable de cada entrada. Antes la lista usaba la POSICION como clave y
// borrar una fila mientras llegaba una respuesta nueva podia quitar la de al lado: la
// entrante se inserta por delante y los indices se desplazan.
let _contadorHistorial = 0
export function nuevaIdHistorial() {
  _contadorHistorial += 1
  return String(Date.now()) + '-' + String(_contadorHistorial)
}

// Que se guarda y que no. La peticion entera (es pequena y es lo que permite repetirla);
// de la respuesta, solo los metadatos. El cuerpo NO: `forward_request` devuelve hasta
// 50.000 caracteres por respuesta y con el tope de 100 entradas eso son ~5 MB, justo la
// cuota de sessionStorage. Las entradas recuperadas quedan marcadas para que el panel
// avise de que su cuerpo no esta, en vez de ensenar una respuesta vacia sin explicacion.
function sinCredenciales(peticion) {
  const p = peticion || {}
  if (!Array.isArray(p.headers)) return p
  return { ...p, headers: p.headers.filter(([k]) => !CABECERAS_QUE_NO_SE_GUARDAN.includes(String(k).toLowerCase())) }
}

function aLigera(entrada) {
  const r = entrada.response || {}
  return {
    id: entrada.id,
    request: sinCredenciales(entrada.request),
    response: {
      status: r.status, time: r.time, size: r.size,
      body: '', headers: {},
      cuerpoNoConservado: true,
    },
    timestamp: entrada.timestamp,
  }
}

function leerHistorialGuardado() {
  try {
    const crudo = sessionStorage.getItem(CLAVE_HISTORIAL)
    const lista = crudo ? JSON.parse(crudo) : []
    if (!Array.isArray(lista)) return []
    return lista.map(e => (e && e.id) ? e : { ...e, id: nuevaIdHistorial() })
  } catch {
    return []   // un historial corrupto no puede impedir usar el Repeater
  }
}

// Si no cabe, se van soltando las MAS ANTIGUAS hasta que entre, en vez de petar con
// QuotaExceededError y perderlo todo.
function guardarHistorial(historial) {
  let lista = historial.map(aLigera)
  while (true) {
    try {
      sessionStorage.setItem(CLAVE_HISTORIAL, JSON.stringify(lista))
      return
    } catch {
      if (lista.length === 0) return   // no cabe ni una: se sigue sin persistir
      lista = lista.slice(0, -1)
    }
  }
}

function normalizePacket(p) {
  return {
    ...p,
    requestHeaders: p.requestHeaders || p.request_headers || {},
    responseHeaders: p.responseHeaders || p.response_headers || {},
    requestBody: p.requestBody || p.request_body || '',
    responseBody: p.responseBody || p.response_body || '',
  }
}

const AppContext = createContext(null)

export function AppProvider({ children }) {
  const { usuario } = useAuth()
  // El espacio de datos es el usuario autenticado. No se guarda en localStorage ni se
  // genera aqui: viene del token, asi que el navegador no puede elegirlo.
  const sessionToken = usuario
  const [requests, setRequests] = useState(config.USE_MOCKS ? mockRequests : [])
  const [networkPackets, setNetworkPackets] = useState([])
  const [vulnerabilities, setVulnerabilities] = useState(config.USE_MOCKS ? mockVulnerabilities : [])
  const [connected, setConnected] = useState(config.USE_MOCKS)
  const [activeUrl, setActiveUrl] = useState(null)
  const [spiderEvento, setSpiderEvento] = useState(null)
  const [sessionCookies, setSessionCookies] = useState({})
  const [wsKey, setWsKey] = useState(0)
  // Estado del Repeater que debe sobrevivir a cambiar de pestana. Vive aqui y no en
  // RepeaterPage porque el router la desmonta al navegar y se perdia TODO: la peticion
  // que estabas editando, su respuesta y el historial.
  const [repeaterResponse, setRepeaterResponse] = useState(null)
  const [repeaterHistory, setRepeaterHistory] = useState(leerHistorialGuardado)
  const [repeaterLastUrl, setRepeaterLastUrl] = useState('')
  const wsRef = useRef(null)

  // Limpieza del identificador que el navegador se inventaba antes: si se queda, no
  // hace daño, pero confunde a quien depure y es una pista falsa de como funciona esto.
  useEffect(() => { localStorage.removeItem(CLAVE_SESION_ANTIGUA) }, [])

  // Guarda el historial del Repeater segun cambia, para que un F5 no lo borre. Lo que
  // sobrevive es la peticion completa: lo util de un historial es poder repetirla.
  useEffect(() => { guardarHistorial(repeaterHistory) }, [repeaterHistory])

  // Carga el historial YA GUARDADO al entrar.
  //
  // Sin esto, la lista arrancaba vacía y solo se llenaba con los eventos que llegaban
  // en vivo por el WebSocket: el Spider guardaba sus resultados en el servidor, pero al
  // recargar la página o volver a entrar el panel aparecía vacío y parecía que no había
  // hecho nada. El endpoint ya existía (`/api/repeater/history/...`, que lee el mismo
  // sitio donde el Spider escribe); simplemente nadie lo llamaba. Es también la causa
  //
  // ⚠️ CORREGIDO el 12-oct. Aquí se afirmaba que esto era «también la causa del historial
  // vacío del Repeater, el mismo fallo visto desde otra pantalla». Era FALSO: el Repeater
  // NO guarda sus peticiones en el servidor, así que este endpoint no puede llenar su
  // historial —lo que devuelve son las del Spider y del Proxy—. El historial del Repeater
  // vive en el navegador; ver CLAVE_HISTORIAL arriba.
  useEffect(() => {
    if (config.USE_MOCKS || !sessionToken) return
    let cancelado = false
    api.get(`/api/repeater/history/${encodeURIComponent(sessionToken)}`)
      .then(({ data }) => {
        if (cancelado || !Array.isArray(data)) return
        // El servidor las guarda de más antigua a más reciente y la interfaz las muestra
        // al revés (los eventos nuevos se insertan por delante), así que se invierte.
        setRequests(data.map(normalizePacket).reverse())
      })
      .catch(() => { /* sin historial no se rompe nada: se sigue con la lista vacía */ })
    return () => { cancelado = true }
  }, [sessionToken])

  useEffect(() => {
    if (config.USE_MOCKS || !sessionToken) return
    // El token va en el PRIMER MENSAJE, no en la URL. Un WebSocket del navegador no
    // admite cabeceras, y meter el token en la ruta lo dejaria escrito en los registros
    // de acceso de Nginx: un token en un log es un token regalado. El servidor acepta
    // la conexion, espera esta credencial y cierra si no llega o no vale.
    // La barra final es obligatoria: Nginx proxea `location /ws/`, y `/ws` sin barra
    // no casaria con ese bloque y acabaria en el frontend.
    const ws = new WebSocket(`${WS_URL}/`)
    wsRef.current = ws
    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'auth', token: leerToken() }))
      setConnected(true)
    }
    ws.onclose = () => setConnected(false)
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.type === 'request_intercepted') { console.log('packet:', data.payload.method, data.payload.url); setRequests(prev => [normalizePacket(data.payload), ...prev]) }
      if (data.type === 'vulnerability_detected') setVulnerabilities(prev => [data.payload, ...prev])
      if (data.type === 'session_cookies') setSessionCookies(data.payload.cookies)
      // El backend distingue completado / detenido a mano / limite alcanzado y manda
      // el recuento de paginas. Antes estos dos eventos llegaban y se descartaban.
      if (data.type === 'spider_completed') setSpiderEvento({ tipo: 'completado', ...data.payload })
      if (data.type === 'spider_started') setSpiderEvento({ tipo: 'iniciado', ...data.payload })
      if (data.type === 'network_packet') setNetworkPackets(prev => [normalizePacket(data.payload), ...prev])
    }
    return () => ws.close()
  }, [sessionToken, wsKey])

  const clearRequests = useCallback(() => setRequests([]), [])

  return (
    <AppContext.Provider value={{
      sessionToken,
      requests,
      networkPackets,
      vulnerabilities,
      connected,
      clearRequests,
      resetWs: () => setWsKey(k => k + 1),
      activeUrl,
      spiderEvento,
      setSpiderEvento,
      setActiveUrl,
      sessionCookies,
      setSessionCookies,
      repeaterResponse,
      setRepeaterResponse,
      repeaterHistory,
      setRepeaterHistory,
      repeaterLastUrl,
      setRepeaterLastUrl,
    }}>
      {children}
    </AppContext.Provider>
  )
}

export function useAppContext() {
  return useContext(AppContext)
}
