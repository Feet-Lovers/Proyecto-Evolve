import { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react'
import { config } from '@/services/api'
import { mockRequests, mockVulnerabilities } from '@/services/mockData'

const WS_URL = `ws://${(config.API_BASE || 'http://localhost:8000').replace('http://', '').replace('https://', '')}/ws`

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0
    const v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
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
  const [sessionToken, setSessionToken] = useState(null)
  const [requests, setRequests] = useState(config.USE_MOCKS ? mockRequests : [])
  const [networkPackets, setNetworkPackets] = useState([])
  const [vulnerabilities, setVulnerabilities] = useState(config.USE_MOCKS ? mockVulnerabilities : [])
  const [connected, setConnected] = useState(config.USE_MOCKS)
  const [activeUrl, setActiveUrl] = useState(null)
  const [sessionCookies, setSessionCookies] = useState({})
  const [wsKey, setWsKey] = useState(0)
  const wsRef = useRef(null)

  useEffect(() => {
    let stored = localStorage.getItem('hooksuite_session')
    if (!stored) {
      stored = generateUUID()
      localStorage.setItem('hooksuite_session', stored)
    }
    setSessionToken(stored)
  }, [])

  useEffect(() => {
    if (config.USE_MOCKS || !sessionToken) return
    const ws = new WebSocket(`${WS_URL}/${sessionToken}`)
    wsRef.current = ws
    ws.onopen = () => setConnected(true)
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
