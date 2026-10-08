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
  const [sessionCookies, setSessionCookies] = useState({})
  const [wsKey, setWsKey] = useState(0)
  const wsRef = useRef(null)

  // Limpieza del identificador que el navegador se inventaba antes: si se queda, no
  // hace daño, pero confunde a quien depure y es una pista falsa de como funciona esto.
  useEffect(() => { localStorage.removeItem(CLAVE_SESION_ANTIGUA) }, [])

  // Carga el historial YA GUARDADO al entrar.
  //
  // Sin esto, la lista arrancaba vacía y solo se llenaba con los eventos que llegaban
  // en vivo por el WebSocket: el Spider guardaba sus resultados en el servidor, pero al
  // recargar la página o volver a entrar el panel aparecía vacío y parecía que no había
  // hecho nada. El endpoint ya existía (`/api/repeater/history/...`, que lee el mismo
  // sitio donde el Spider escribe); simplemente nadie lo llamaba. Es también la causa
  // del «historial vacío del Repeater» que teníamos anotado como bug aparte: era el
  // mismo fallo visto desde otra pantalla.
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
      setActiveUrl,
      sessionCookies,
      setSessionCookies,
    }}>
      {children}
    </AppContext.Provider>
  )
}

export function useAppContext() {
  return useContext(AppContext)
}
