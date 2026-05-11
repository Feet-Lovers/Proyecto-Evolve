import { useState } from 'react'
import { Button, Badge } from '@/components/ui'
import axios from 'axios'
import { config } from '@/services/api'
import { useSession } from '@/hooks/useSession'

const ATTACK_TYPES = [
  { id: 'sqli', label: 'SQL Injection' },
  { id: 'blind_sqli', label: 'Blind SQLi' },
  { id: 'xss', label: 'XSS' },
  { id: 'fuzzing', label: 'Fuzzing genérico' },
]

const MOCK_RESULTS = [
  { id: 1, payload: "' OR '1'='1", status: 200, size: 8934, time: 312, vulnerable: true },
  { id: 2, payload: "' OR '1'='2", status: 200, size: 4823, time: 89, vulnerable: false },
  { id: 3, payload: "1 UNION SELECT null--", status: 500, size: 1024, time: 156, vulnerable: true },
  { id: 4, payload: "1; DROP TABLE users--", status: 200, size: 4823, time: 91, vulnerable: false },
]

const inputStyle = {
  fontFamily: 'var(--font-mono)',
  background: 'var(--hs-bg)',
  borderColor: 'var(--hs-border-hover)',
  color: 'var(--hs-text-secondary)',
}

export function IntruderPage() {
  const sessionToken = useSession()
  const [url, setUrl] = useState('')
  const [injectionPoint, setInjectionPoint] = useState('')
  const [attackType, setAttackType] = useState('sqli')
  const [results, setResults] = useState([])
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [total, setTotal] = useState(0)

  const handleStart = async () => {
    setResults([])
    setRunning(true)
    setProgress(0)

    if (config.USE_MOCKS) {
      setTotal(MOCK_RESULTS.length)
      for (let i = 0; i < MOCK_RESULTS.length; i++) {
        await new Promise(r => setTimeout(r, 400))
        setResults(prev => [...prev, MOCK_RESULTS[i]])
        setProgress(i + 1)
      }
      setRunning(false)
      return
    }

    try {
      await axios.post(`${config.API_BASE}/api/intruder/start`, {
        url, injectionPoint, attackType, sessionToken
      })
    } catch {
      setRunning(false)
    }
  }

  const handleCancel = async () => {
    if (!config.USE_MOCKS) {
      await axios.post(`${config.API_BASE}/api/intruder/cancel/${sessionToken}`)
    }
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
            <label
              className="block text-[9px] tracking-widest uppercase mb-1.5"
              style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
            >
              URL objetivo
            </label>
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="http://dvwa.local/sqli/?id=1"
              className="w-full px-3 py-2 rounded border outline-none text-[10px]"
              style={inputStyle}
            />
          </div>

          <div>
            <label
              className="block text-[9px] tracking-widest uppercase mb-1.5"
              style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
            >
              Punto de inyección
            </label>
            <input
              value={injectionPoint}
              onChange={e => setInjectionPoint(e.target.value)}
              placeholder="id"
              className="w-full px-3 py-2 rounded border outline-none text-[10px]"
              style={inputStyle}
            />
          </div>

          <div>
            <label
              className="block text-[9px] tracking-widest uppercase mb-1.5"
              style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
            >
              Tipo de ataque
            </label>
            <select
              value={attackType}
              onChange={e => setAttackType(e.target.value)}
              className="w-full px-3 py-2 rounded border outline-none text-[10px] cursor-pointer"
              style={inputStyle}
            >
              {ATTACK_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
          </div>

          {running ? (
            <div className="space-y-2">
              <div className="w-full rounded-full h-1.5" style={{ background: 'var(--hs-border)' }}>
                <div
                  className="h-1.5 rounded-full transition-all"
                  style={{ width: total ? `${(progress / total) * 100}%` : '0%', background: 'var(--hs-accent)' }}
                />
              </div>
              <p className="text-[10px]" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
                {progress} / {total || '?'} payloads
              </p>
              <Button variant="danger" onClick={handleCancel} className="w-full">cancelar ataque</Button>
            </div>
          ) : (
            <Button onClick={handleStart} className="w-full" disabled={!url}>iniciar ataque</Button>
          )}
        </div>

        <div className="flex-1 overflow-auto">
          <table className="w-full text-[10px]" style={{ fontFamily: 'var(--font-mono)' }}>
            <thead
              className="sticky top-0"
              style={{ background: 'var(--hs-surface)', borderBottom: '1px solid var(--hs-border)' }}
            >
              <tr>
                {['#', 'payload', 'status', 'size', 'tiempo', 'resultado'].map(h => (
                  <th
                    key={h}
                    className="px-4 py-2 text-left text-[9px] font-semibold tracking-widest uppercase"
                    style={{ color: 'var(--hs-text-dim)' }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {results.map(r => (
                <tr
                  key={r.id}
                  className="border-b transition-colors"
                  style={{
                    borderColor: '#13161c',
                    background: r.vulnerable ? '#1a0d0d' : 'transparent',
                  }}
                >
                  <td className="px-4 py-2" style={{ color: 'var(--hs-text-dim)' }}>{r.id}</td>
                  <td className="px-4 py-2" style={{ color: 'var(--hs-text-secondary)' }}>{r.payload}</td>
                  <td className="px-4 py-2" style={{ color: r.status >= 500 ? '#ef5a5a' : 'var(--hs-text-muted)' }}>{r.status}</td>
                  <td className="px-4 py-2" style={{ color: 'var(--hs-text-dim)' }}>{r.size}B</td>
                  <td className="px-4 py-2" style={{ color: 'var(--hs-text-dim)' }}>{r.time}ms</td>
                  <td className="px-4 py-2">
                    {r.vulnerable
                      ? <Badge variant="critical">vulnerable</Badge>
                      : <Badge variant="default">limpio</Badge>
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {results.length === 0 && !running && (
            <div
              className="flex items-center justify-center h-32 text-[11px]"
              style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
            >
              configura un ataque y haz clic en iniciar
            </div>
          )}
        </div>
      </div>
    </div>
  )
}