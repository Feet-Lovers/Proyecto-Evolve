import { useEffect, useRef, useState, useCallback } from 'react'
import { config, leerToken } from '@/services/api'
import { mockRequests, mockVulnerabilities } from '@/services/mockData'

const WS_URL = config.API_BASE
  ? `${config.API_BASE.replace(/^http/, 'ws')}/ws`
  : `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`  // '' = mismo origen (Nginx /ws)

function normalizePacket(p) {
  return {
    ...p,
    requestHeaders: p.requestHeaders || p.request_headers || {},
    responseHeaders: p.responseHeaders || p.response_headers || {},
    requestBody: p.requestBody || p.request_body || '',
    responseBody: p.responseBody || p.response_body || '',
  }
}

export function useWebSocket(sessionToken) {
  const [requests, setRequests] = useState(config.USE_MOCKS ? mockRequests : [])
  const [networkPackets, setNetworkPackets] = useState([])
  const [vulnerabilities, setVulnerabilities] = useState(config.USE_MOCKS ? mockVulnerabilities : [])
  // RNF-06. Hasta el 10-oct el estado degradado no llegaba aqui: el modulo de IA lo
  // calculaba y lo publicaba, y no habia consumidor ni en el backend ni en el panel.
  // Un fallo de analisis era indistinguible de «no hay vulnerabilidades».
  const [noAnalizados, setNoAnalizados] = useState([])
  const [connected, setConnected] = useState(config.USE_MOCKS)
  const wsRef = useRef(null)

  useEffect(() => {
    if (config.USE_MOCKS || !sessionToken) return
    // El token ya no va en la ruta (quedaria escrito en los logs de acceso de Nginx):
    // se presenta en el primer mensaje. La barra final es obligatoria, porque Nginx
    // proxea `location /ws/` y `/ws` pelado acabaria en el frontend.
    // Este es el SEGUNDO consumidor de WebSocket del frontend (el otro esta en
    // AppContext): las paginas de Vulnerabilidades y Red usan este hook. El backend
    // admite varios sockets por usuario, asi que ambos conviven.
    const ws = new WebSocket(`${WS_URL}/`)
    wsRef.current = ws
    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'auth', token: leerToken() }))
      setConnected(true)
    }
    ws.onclose = () => setConnected(false)
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.type === 'request_intercepted') setRequests(prev => [normalizePacket(data.payload), ...prev])
      if (data.type === 'vulnerability_detected') setVulnerabilities(prev => [data.payload, ...prev])
      if (data.type === 'ia_no_analizado') setNoAnalizados(prev => [data.payload, ...prev])
      if (data.type === 'network_packet') setNetworkPackets(prev => [normalizePacket(data.payload), ...prev])
    }
    return () => ws.close()
  }, [sessionToken])

  const clearRequests = useCallback(() => setRequests([]), [])
  return { requests, networkPackets, connected, clearRequests, vulnerabilities, noAnalizados }
}
