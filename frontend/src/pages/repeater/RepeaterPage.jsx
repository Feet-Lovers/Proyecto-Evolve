import { useState, useEffect } from 'react'
import { RequestEditor } from './RequestEditor'
import { ResponsePanel } from './ResponsePanel'
import axios from 'axios'
import { config } from '@/services/api'

const MOCK_RESPONSE = {
  status: 200,
  time: 134,
  size: 2048,
  body: JSON.stringify({ message: 'OK', data: { id: 1, name: 'admin' } }, null, 2),
  headers: { 'Content-Type': 'application/json' },
}

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

export function RepeaterPage() {
  const [initialRequest, setInitialRequest] = useState(null)
  const [response, setResponse] = useState(null)
  const [loading, setLoading] = useState(false)
  const [history, setHistory] = useState([])
  const [lastUrl, setLastUrl] = useState('')

  useEffect(() => {
    const stored = sessionStorage.getItem('repeater_request')
    if (stored) {
      setInitialRequest(JSON.parse(stored))
      sessionStorage.removeItem('repeater_request')
    }
  }, [])

  const handleSend = async (request) => {
    setLoading(true)
    setLastUrl(request.url || '')
    try {
      if (config.USE_MOCKS) {
        await new Promise(r => setTimeout(r, 500))
        setResponse(MOCK_RESPONSE)
        setHistory(prev => [{ request, response: MOCK_RESPONSE, timestamp: new Date() }, ...prev.slice(0, 99)])
        return
      }
      const res = await axios.post(`${config.API_BASE}/api/repeater/send`, request)
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
        <span
          className="text-[10px]"
          style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
        >
          {history.length} peticiones en historial
        </span>
      </div>
      <div className="flex flex-1 overflow-hidden">
        <div className="w-1/2 border-r overflow-hidden flex flex-col" style={{ borderColor: 'var(--hs-border)' }}>
          <RequestEditor initialRequest={initialRequest} onSend={handleSend} loading={loading} />
        </div>
        <div className="w-1/2 overflow-hidden flex flex-col">
          <ResponsePanel response={response} requestUrl={lastUrl} />
        </div>
      </div>
    </div>
  )
}
