import { useState, useEffect, useRef } from 'react'
import { Button, Badge } from '@/components/ui'
import axios from 'axios'
import { config } from '@/services/api'
import { useAppContext } from '@/AppContext'

const ATTACK_TYPES = [
  { id: 'sqli', label: 'SQL Injection' },
  { id: 'blind_sqli', label: 'Blind SQLi' },
  { id: 'xss', label: 'XSS' },
  { id: 'fuzzing', label: 'Fuzzing generico' },
]

const inputStyle = {
  fontFamily: 'var(--font-mono)',
  background: 'var(--hs-bg)',
  borderColor: 'var(--hs-border-hover)',
  color: 'var(--hs-text-secondary)',
}

function parseParams(str, isBody = false) {
  try {
    const q = isBody ? str : (str.includes('?') ? str.split('?')[1] : '')
    if (!q) return []
    return q.split('&').map(p => {
      const [k, ...rest] = p.split('=')
      return { key: k, value: rest.join('=') || '' }
    }).filter(p => p.key)
  } catch { return [] }
}

function renderHighlighted(text) {
  if (!text.includes('*')) return text.replace(/</g, '&lt;').replace(/>/g, '&gt;')
  return text.split('*').map((part, i, arr) => {
    const escaped = part.replace(/</g, '&lt;').replace(/>/g, '&gt;')
    if (i < arr.length - 1) {
      return escaped + '<span style="color:#f5a623;font-weight:bold;background:rgba(245,166,35,0.15);border-radius:3px;padding:0 2px">*</span>'
    }
    return escaped
  }).join('')
}

function BodyDisplay({ body }) {
  if (!body.includes('*')) return <span style={{ color: 'var(--hs-text-secondary)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{body}</span>
  const parts = body.split('*')
  return (
    <>
      {parts.map((part, i) => (
        <span key={i}>
          <span style={{ color: 'var(--hs-text-secondary)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{part}</span>
          {i < parts.length - 1 && (
            <span style={{ color: '#f5a623', fontWeight: 'bold', background: 'rgba(245,166,35,0.15)', borderRadius: '3px', padding: '0 2px' }}>*</span>
          )}
        </span>
      ))}
    </>
  )
}

function UrlDisplay({ url }) {
  if (!url.includes('*')) return <span style={{ color: 'var(--hs-text-secondary)' }}>{url}</span>
  const parts = url.split('*')
  return (
    <>
      {parts.map((part, i) => (
        <span key={i}>
          <span style={{ color: 'var(--hs-text-secondary)' }}>{part}</span>
          {i < parts.length - 1 && (
            <span style={{ color: '#f5a623', fontWeight: 'bold', background: 'rgba(245,166,35,0.15)', borderRadius: '3px', padding: '0 2px' }}>*</span>
          )}
        </span>
      ))}
    </>
  )
}

export function IntruderPage() {
  const { sessionToken } = useAppContext()
  const [url, setUrl] = useState('')
  const [method, setMethod] = useState('GET')
  const [body, setBody] = useState('')
  const [attackType, setAttackType] = useState('sqli')
  const [results, setResults] = useState([])
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [total, setTotal] = useState(0)

  const [originalParams, setOriginalParams] = useState([])
  const originalRef = useRef({})
  const bodyRef = useRef(null)
  const params = method === 'GET' ? parseParams(url) : parseParams(body, true)

  useEffect(() => {
    const target = method === 'GET' ? url : body
    if (target.includes('*')) return
    const p = method === 'GET' ? parseParams(url) : parseParams(body)
    if (p.length > 0) setOriginalParams(p)
  }, [url, body, method])

  const getOriginalValue = (key) => {
    const found = originalParams.find(p => p.key === key)
    return found ? found.value : key
  }

  useEffect(() => {
    if (bodyRef.current) {
      const current = bodyRef.current.textContent
      if (current !== body) {
        const sel = window.getSelection()
        const hadFocus = document.activeElement === bodyRef.current
        bodyRef.current.innerHTML = renderHighlighted(body)
        if (hadFocus && sel) {
          const range = document.createRange()
          range.selectNodeContents(bodyRef.current)
          range.collapse(false)
          sel.removeAllRanges()
          sel.addRange(range)
        }
      }
    }
  }, [body])

  useEffect(() => {
    const stored = sessionStorage.getItem('intruder_request')
    if (stored) {
      try {
        const req = JSON.parse(stored)
        setUrl(req.url || '')
        setMethod(req.method || 'GET')
        setBody(req.requestBody || '')
        sessionStorage.removeItem('intruder_request')
      } catch {}
    }
  }, [])

  const markParam = (paramKey) => {
    const isGet = method === 'GET'
    const target = isGet ? url : body
    const isMarked = target.includes(`${paramKey}=*`)
    let newTarget = target

    // Desmarcar todos restaurando valores originales desde el ref
    Object.entries(originalRef.current).forEach(([k, v]) => {
      newTarget = newTarget.replace(`${k}=*`, `${k}=${v}`)
    })

    if (!isMarked) {
      // Guardar el valor original antes de marcarlo
      const currentVal = params.find(p => p.key === paramKey)?.value || paramKey
      originalRef.current[paramKey] = currentVal
      newTarget = newTarget.replace(`${paramKey}=${currentVal}`, `${paramKey}=*`)
    }

    if (isGet) setUrl(newTarget)
    else setBody(newTarget)
  }

  const pollResults = async (token) => {
    let done = false
    while (!done) {
      await new Promise(r => setTimeout(r, 1000))
      try {
        const res = await axios.get(`${config.API_BASE}/api/intruder/results/${token}`)
        const data = res.data
        setResults(data.results || [])
        setProgress((data.results || []).length)
        if (data.status === 'complete' || data.status === 'cancelled') {
          done = true
          setRunning(false)
        }
      } catch {
        done = true
        setRunning(false)
      }
    }
  }

  const handleStart = async () => {
    setResults([])
    setRunning(true)
    setProgress(0)
    try {
      await axios.post(`${config.API_BASE}/api/intruder/start`, {
        url,
        method,
        body,
        injection_point: '*',
        attack_type: attackType,
        session_token: sessionToken,
        concurrency: 5,
        delay_ms: 0
      })
      pollResults(sessionToken)
    } catch {
      setRunning(false)
    }
  }

  const handleCancel = async () => {
    await axios.post(`${config.API_BASE}/api/intruder/cancel/${sessionToken}`)
    setRunning(false)
  }

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center px-5 py-3 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <h2
          className="text-[14px] font-bold tracking-wide"
          style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
        >
          Intruder
        </h2>
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div
          className="w-72 border-r p-4 overflow-auto flex flex-col gap-4"
          style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
        >
          <div>
            <label className="block text-[9px] tracking-widest uppercase mb-1.5" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
              URL objetivo
            </label>
            <div
              contentEditable
              suppressContentEditableWarning
              onInput={e => setUrl(e.currentTarget.textContent)}
              className="w-full px-3 py-2 rounded border text-[10px]"
              style={{ ...inputStyle, minHeight: '32px', wordBreak: 'break-all', lineHeight: '1.6', outline: 'none', whiteSpace: 'pre-wrap' }}
              data-placeholder="http://dvwa/sqli/?id=1&Submit=Submit"
            >
              <UrlDisplay url={url} />
            </div>
          </div>

          {method === 'GET' && params.length > 0 && (
            <div>
              <label className="block text-[9px] tracking-widest uppercase mb-1.5" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
                Parametros detectados en la URL
              </label>
              <div className="flex flex-col gap-1">
                {params.map(p => (
                  <div key={p.key} className="flex items-center justify-between px-2 py-1 rounded" style={{ background: 'var(--hs-bg)', border: '1px solid var(--hs-border)' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', color: url.includes(`${p.key}=*`) ? '#f5a623' : 'var(--hs-text-secondary)', fontSize: '10px' }}>
                      {p.key}={url.includes(`${p.key}=*`) ? '*' : p.value}
                    </span>
                    <button
                      onClick={() => markParam(p.key)}
                      style={{ fontSize: '9px', color: url.includes(`${p.key}=*`) ? '#f5a623' : 'var(--hs-accent)', cursor: 'pointer', background: 'none', border: 'none', padding: '0 4px' }}
                    >
                      {url.includes(`${p.key}=*`) ? '✓' : '→ marcar'}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <label className="block text-[9px] tracking-widest uppercase mb-1.5" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
              Metodo
            </label>
            <select value={method} onChange={e => setMethod(e.target.value)} className="w-full px-3 py-2 rounded border outline-none text-[10px] cursor-pointer" style={inputStyle}>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>
          </div>

          {method !== 'GET' && (
            <div>
              <label className="block text-[9px] tracking-widest uppercase mb-1.5" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
                Body
              </label>
              <div
                ref={bodyRef}
                contentEditable
                suppressContentEditableWarning
                spellCheck={false}
                onInput={e => setBody(e.currentTarget.textContent)}
                className="w-full px-3 py-2 rounded border text-[10px]"
                style={{ ...inputStyle, minHeight: '80px', wordBreak: 'break-all', lineHeight: '1.6', outline: 'none', whiteSpace: 'pre-wrap' }}
              />
            </div>
          )}
          {method !== 'GET' && params.length > 0 && (
            <div>
              <label className="block text-[9px] tracking-widest uppercase mb-1.5" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
                Parametros detectados en el body
              </label>
              <div className="flex flex-col gap-1">
                {params.map(p => (
                  <div key={p.key} className="flex items-center justify-between px-2 py-1 rounded" style={{ background: 'var(--hs-bg)', border: '1px solid var(--hs-border)' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', color: body.includes(`${p.key}=*`) ? '#f5a623' : 'var(--hs-text-secondary)', fontSize: '10px' }}>
                      {p.key}={body.includes(`${p.key}=*`) ? '*' : p.value}
                    </span>
                    <button
                      onClick={() => markParam(p.key)}
                      style={{ fontSize: '9px', color: body.includes(`${p.key}=*`) ? '#f5a623' : 'var(--hs-accent)', cursor: 'pointer', background: 'none', border: 'none', padding: '0 4px' }}
                    >
                      {body.includes(`${p.key}=*`) ? '✓' : '→ marcar'}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <label className="block text-[9px] tracking-widest uppercase mb-1.5" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
              Tipo de ataque
            </label>
            <select value={attackType} onChange={e => setAttackType(e.target.value)} className="w-full px-3 py-2 rounded border outline-none text-[10px] cursor-pointer" style={inputStyle}>
              {ATTACK_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
          </div>

          {running ? (
            <div className="space-y-2">
              <div className="w-full rounded-full h-1.5" style={{ background: 'var(--hs-border)' }}>
                <div className="h-1.5 rounded-full transition-all" style={{ width: total ? `${(progress / total) * 100}%` : '0%', background: 'var(--hs-accent)' }} />
              </div>
              <p className="text-[10px]" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>{progress} / {total || '?'} payloads</p>
              <Button variant="danger" onClick={handleCancel} className="w-full">cancelar ataque</Button>
            </div>
          ) : (
            <Button onClick={handleStart} className="w-full" disabled={!url || !(url.includes('*') || body.includes('*'))}>iniciar ataque</Button>
          )}
        </div>

        <div className="flex-1 overflow-auto">
          <table className="w-full text-[10px]" style={{ fontFamily: 'var(--font-mono)' }}>
            <thead className="sticky top-0" style={{ background: 'var(--hs-surface)', borderBottom: '1px solid var(--hs-border)' }}>
              <tr>
                {['#', 'payload', 'status', 'size', 'tiempo', 'resultado'].map(h => (
                  <th key={h} className="px-4 py-2 text-left text-[9px] font-semibold tracking-widest uppercase" style={{ color: 'var(--hs-text-dim)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {results.map(r => (
                <tr key={r.id} className="border-b transition-colors" style={{ borderColor: '#13161c', background: (r.vulnerable || r.validated) ? '#1a0d0d' : 'transparent' }}>
                  <td className="px-4 py-2" style={{ color: 'var(--hs-text-dim)' }}>{r.id}</td>
                  <td className="px-4 py-2" style={{ color: 'var(--hs-text-secondary)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.payload}</td>
                  <td className="px-4 py-2" style={{ color: r.status >= 500 ? '#ef5a5a' : 'var(--hs-text-muted)' }}>{r.status}</td>
                  <td className="px-4 py-2" style={{ color: 'var(--hs-text-dim)' }}>{r.size || r.length || 0}B</td>
                  <td className="px-4 py-2" style={{ color: 'var(--hs-text-dim)' }}>{r.time}ms</td>
                  <td className="px-4 py-2">
                    {(r.vulnerable || r.validated) ? <Badge variant="critical">vulnerable</Badge> : <Badge variant="default">limpio</Badge>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {results.length === 0 && !running && (
            <div className="flex items-center justify-center h-32 text-[11px]" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
              marca un parametro de inyeccion y haz clic en iniciar
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
