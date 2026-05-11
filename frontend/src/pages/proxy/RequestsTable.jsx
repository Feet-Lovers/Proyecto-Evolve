import { useState } from 'react'
import { Badge } from '@/components/ui'

const METHOD_VARIANTS = {
  GET: 'get', POST: 'post', PUT: 'put', DELETE: 'delete', PATCH: 'patch',
}

const STATUS_COLOR = (status) => {
  if (status >= 200 && status < 300) return 'text-[#4a9a5a]'
  if (status >= 300 && status < 400) return 'text-[#6aafef]'
  if (status >= 400 && status < 500) return 'text-[#dfc050]'
  return 'text-[#ef5a5a]'
}

export function RequestsTable({ requests, onSelect, selectedId }) {
  const [filter, setFilter] = useState('')
  const [methodFilter, setMethodFilter] = useState('ALL')

  const filtered = requests.filter(r => {
    const matchesUrl = r.url.toLowerCase().includes(filter.toLowerCase())
    const matchesMethod = methodFilter === 'ALL' || r.method === methodFilter
    return matchesUrl && matchesMethod
  })

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex gap-2 p-2 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <input
          type="text"
          placeholder="filtrar por url..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="flex-1 px-3 py-1.5 rounded border text-[10px] outline-none"
          style={{
            fontFamily: 'var(--font-mono)',
            background: 'var(--hs-bg)',
            borderColor: 'var(--hs-border-hover)',
            color: 'var(--hs-text-secondary)',
          }}
        />
        <select
          value={methodFilter}
          onChange={e => setMethodFilter(e.target.value)}
          className="px-2 py-1.5 rounded border text-[10px] outline-none cursor-pointer"
          style={{
            fontFamily: 'var(--font-mono)',
            background: 'var(--hs-bg)',
            borderColor: 'var(--hs-border-hover)',
            color: 'var(--hs-text-muted)',
          }}
        >
          {['ALL', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
      </div>

      <div className="flex-1 overflow-auto">
        <table className="w-full text-[10px]" style={{ fontFamily: 'var(--font-mono)' }}>
          <thead
            className="sticky top-0"
            style={{ background: 'var(--hs-surface)', borderBottom: '1px solid var(--hs-border)' }}
          >
            <tr>
              {['método', 'url', 'status', 'size', 'ms'].map(h => (
                <th
                  key={h}
                  className="px-3 py-2 text-left text-[9px] font-semibold tracking-widest uppercase"
                  style={{ color: 'var(--hs-text-dim)' }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map(req => (
              <tr
                key={req.id}
                onClick={() => onSelect(req)}
                className="cursor-pointer transition-colors border-b"
                style={{
                  borderColor: '#13161c',
                  background: selectedId === req.id
                    ? '#0d1a14'
                    : req.vulnerable ? '#1a0d0d'
                    : req.suspicious ? '#161410'
                    : 'transparent',
                }}
              >
                <td className="px-3 py-2">
                  <Badge variant={METHOD_VARIANTS[req.method] || 'default'}>{req.method}</Badge>
                </td>
                <td
                  className="px-3 py-2 max-w-[180px] truncate"
                  style={{ color: 'var(--hs-text-secondary)' }}
                >
                  {req.url}
                </td>
                <td className={`px-3 py-2 font-semibold ${STATUS_COLOR(req.status)}`}>
                  {req.status}
                </td>
                <td className="px-3 py-2" style={{ color: 'var(--hs-text-dim)' }}>
                  {(req.size / 1024).toFixed(1)}KB
                </td>
                <td className="px-3 py-2" style={{ color: 'var(--hs-text-dim)' }}>
                  {req.time}ms
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filtered.length === 0 && (
          <div
            className="flex items-center justify-center h-32 text-[11px]"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
          >
            no hay peticiones interceptadas
          </div>
        )}
      </div>
    </div>
  )
}