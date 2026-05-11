import { useState } from 'react'
import { Button } from '@/components/ui'
import axios from 'axios'
import { config } from '@/services/api'

export function ImportRequest({ onClose, onImport }) {
  const [text, setText] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleParse = async () => {
    if (!text.trim()) return
    setLoading(true)
    setError(null)
    try {
      if (config.USE_MOCKS) {
        onImport({ method: 'GET', url: 'http://example.com', requestHeaders: {}, requestBody: null })
        return
      }
      const res = await axios.post(`${config.API_BASE}/api/repeater/parse`, { text })
      onImport(res.data)
    } catch {
      setError('no se pudo parsear la petición. verifica el formato.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50" style={{ background: 'rgba(0,0,0,0.7)' }}>
      <div
        className="w-full max-w-2xl p-6 rounded-xl border"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <h3
          className="text-[14px] font-bold mb-1"
          style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
        >
          importar petición
        </h3>
        <p
          className="text-[11px] mb-3"
          style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-muted)' }}
        >
          pega una petición en formato raw HTTP o cURL
        </p>
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder={"GET /path HTTP/1.1\nHost: example.com\n\no\n\ncurl -X POST https://example.com -d '{}'"}
          className="w-full h-48 px-3 py-2 rounded border resize-none outline-none text-[11px]"
          style={{
            fontFamily: 'var(--font-mono)',
            background: 'var(--hs-bg)',
            borderColor: 'var(--hs-border-hover)',
            color: 'var(--hs-text-secondary)',
          }}
        />
        {error && (
          <p className="text-[11px] mt-2" style={{ fontFamily: 'var(--font-mono)', color: '#ef5a5a' }}>{error}</p>
        )}
        <div className="flex gap-2 justify-end mt-4">
          <Button variant="ghost" onClick={onClose}>cancelar</Button>
          <Button onClick={handleParse} disabled={loading}>
            {loading ? 'parseando...' : 'parsear y enviar al repeater'}
          </Button>
        </div>
      </div>
    </div>
  )
}