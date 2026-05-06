import { useEffect, useRef, useState, useCallback } from 'react'
import { config } from '@/services/api'
import { mockRequests, mockVulnerabilities } from '@/services/mockData'

const WS_URL = `ws://${(config.API_BASE || 'http://localhost:8000').replace('http://', '').replace('https://', '')}/ws`

export function useWebSocket(sessionToken) {
  const [requests, setRequests] = useState(config.USE_MOCKS ? mockRequests : [])
  const [vulnerabilities, setVulnerabilities] = useState(config.USE_MOCKS ? mockVulnerabilities : [])
  const [connected, setConnected] = useState(config.USE_MOCKS)
  const wsRef = useRef(null)

  useEffect(() => {
    if (config.USE_MOCKS || !sessionToken) return

    const ws = new WebSocket(`${WS_URL}/${sessionToken}`)
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.type === 'request_intercepted') {
        setRequests(prev => [data.payload, ...prev])
      }
      if (data.type === 'vulnerability_detected') {
        setVulnerabilities(prev => [data.payload, ...prev])
      }
      if (data.type === 'network_packet') {
        setRequests(prev => [data.payload, ...prev])
      }
    }

    return () => ws.close()
  }, [sessionToken])

  const clearRequests = useCallback(() => setRequests([]), [])

  return { requests, connected, clearRequests, vulnerabilities }
}